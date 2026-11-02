"""Versões por ecossistema e o algoritmo de faixas do OSV.

Cada ecossistema ordena versões do seu jeito — e errar a ordem gera falso
positivo (ou deixa passar uma versão vulnerável). Comparadores implementados:

- **PyPI**: PEP 440 (época, pré e pós-lançamento, ``dev``, rótulo local;
  ``1.0 == 1.0.0``) — https://peps.python.org/pep-0440/
- **npm, crates.io e Go**: SemVer 2.0 (pré-lançamento com hífen vem antes da versão
  final; pseudo-versões do Go são pré-lançamentos) — https://semver.org/
- **NuGet**: SemVer com até quatro números e rótulos sem diferenciar maiúsculas.
- **Maven**: ordem do ``ComparableVersion`` (alpha < beta < milestone < rc <
  snapshot < final < sp; ``1.0 == 1``; ``.RELEASE``/``.Final`` = versão final) —
  https://maven.apache.org/pom.html#Version_Order_Specification
- **RubyGems**: regras do ``Gem::Version`` (letras marcam pré-lançamento).
- **Packagist**: estabilidades do Composer (dev < alpha < beta < RC < estável < patch).

Versões que um comparador não entende caem na comparação tolerante de
``core.versions``. A avaliação de faixas segue a especificação do OSV
(https://ossf.github.io/osv-schema/): eventos ``introduced``, ``fixed``,
``last_affected`` e ``limit``, além da lista explícita ``versions``.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from functools import cmp_to_key
from typing import Any, TypeAlias

from ...core import versions

SEMVER_ECOSYSTEMS = frozenset({"npm", "Go", "crates.io", "NuGet"})

_SEMVER = re.compile(r"^(\d+(?:\.\d+)*)(?:-([0-9A-Za-z.\-]+))?(?:\+[0-9A-Za-z.\-]*)?$")
_RUBY_PLATFORM = re.compile(r"-(?:x86|x64|arm|aarch|java|universal|mingw|mswin|darwin|linux)", re.I)
#: curingas de versão: ``1.x``, ``1.2.X``, ``2.x-dev`` (branch do Composer), ``1.+`` (Gradle)
_WILDCARD = re.compile(r"\.[xX](?:$|[.\-])|\.\+$|\+$")
#: versões maiores que isto não existem de verdade: entrada hostil ou arquivo corrompido
MAX_VERSION_LENGTH = 128


def _sign(a: Any, b: Any) -> int:
    """-1, 0 ou 1 para dois valores do mesmo tipo."""
    return int(a > b) - int(a < b)


def normalize(ecosystem: str, version: str) -> str:
    """Remove prefixos e sufixos que não fazem parte da versão comparável."""
    text = version.strip().strip("\"'")
    while text.startswith(("=", "v", "V")) and len(text) > 1 and not text[1:2].isalpha():
        text = text[1:].strip()
    if ecosystem == "Go":
        text = text.replace("+incompatible", "")
    if ecosystem == "RubyGems":
        match = _RUBY_PLATFORM.search(text)
        if match:
            text = text[: match.start()]
    return text


def is_exact(version: str) -> bool:
    """Se a versão é um número exato (não uma faixa como ``^1.2``, ``>=2``, ``1.x`` ou ``1.+``)."""
    text = version.strip()
    if not text or not text[0].isdigit():
        return False
    if any(ch in text for ch in "<>^~*|,[]() "):
        return False
    return not _WILDCARD.search(text)


# -- SemVer (npm, crates.io, Go) e NuGet ----------------------------------------------


def _semver_parts(version: str) -> tuple[list[int], list[str]] | None:
    match = _SEMVER.match(version.strip())
    if not match:
        return None
    numbers = [int(n) for n in match.group(1).split(".")]
    pre = match.group(2).split(".") if match.group(2) else []
    return numbers, pre


def _compare_identifiers(a: list[str], b: list[str], ignore_case: bool) -> int:
    if not a or not b:
        return (not a) - (not b)  # versão final (sem rótulo) > pré-lançamento
    for x, y in zip(a, b, strict=False):
        if ignore_case:
            x, y = x.lower(), y.lower()
        if x == y:
            continue
        if x.isdigit() and y.isdigit():
            return _sign(int(x), int(y))
        if x.isdigit() or y.isdigit():
            return -1 if x.isdigit() else 1  # numérico vem antes de alfanumérico
        return _sign(x, y)
    return _sign(len(a), len(b))


def semver_compare(a: str, b: str, *, ignore_case: bool = False) -> int | None:
    """Comparação SemVer 2.0 (aceita mais de três números); ``None`` se não for SemVer."""
    pa, pb = _semver_parts(a), _semver_parts(b)
    if pa is None or pb is None:
        return None
    na, nb = pa[0], pb[0]
    width = max(len(na), len(nb))
    na = na + [0] * (width - len(na))
    nb = nb + [0] * (width - len(nb))
    if na != nb:
        return -1 if na < nb else 1
    return _compare_identifiers(pa[1], pb[1], ignore_case)


def _nuget_compare(a: str, b: str) -> int | None:
    return semver_compare(a, b, ignore_case=True)


# -- PEP 440 (PyPI) -------------------------------------------------------------------

_PEP440 = re.compile(
    r"""^v?(?:(?P<epoch>\d+)!)?(?P<release>\d+(?:\.\d+)*)
    (?:[-_.]?(?P<pre_l>alpha|beta|preview|pre|rc|a|b|c)[-_.]?(?P<pre_n>\d+)?)?
    (?:-(?P<post_n1>\d+)|[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>\d+)?)?
    (?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>\d+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?$""",
    re.X | re.I,
)
_PEP440_PRE = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}
Pep440Key: TypeAlias = "tuple[int, tuple[int, ...], tuple[int, int, int], tuple[int, int], tuple[int, int], tuple[tuple[int, int, str], ...]]"


def pep440_key(version: str) -> Pep440Key | None:
    """Chave de ordenação PEP 440 (``None`` se a versão não seguir a PEP 440)."""
    match = _PEP440.match(version.strip())
    if not match:
        return None
    release = tuple(int(part) for part in match.group("release").split("."))
    while len(release) > 1 and release[-1] == 0:
        release = release[:-1]  # 1.0 == 1.0.0
    has_post = match.group("post_n1") is not None or match.group("post_l") is not None
    has_dev = match.group("dev_l") is not None
    if match.group("pre_l"):
        pre = (0, _PEP440_PRE[match.group("pre_l").lower()], int(match.group("pre_n") or 0))
    elif has_dev and not has_post:
        pre = (-1, 0, 0)  # 1.0.dev0 vem antes de 1.0a0
    else:
        pre = (1, 0, 0)
    post_number = match.group("post_n1") or match.group("post_n2") or "0"
    post = (0, int(post_number)) if has_post else (-1, 0)
    dev = (0, int(match.group("dev_n") or 0)) if has_dev else (1, 0)
    local: tuple[tuple[int, int, str], ...] = ()
    if match.group("local"):
        local = tuple(
            (1, int(part), "") if part.isdigit() else (0, 0, part)
            for part in re.split(r"[-_.]", match.group("local").lower())
        )
    return (int(match.group("epoch") or 0), release, pre, post, dev, local)


def pep440_compare(a: str, b: str) -> int | None:
    ka, kb = pep440_key(a), pep440_key(b)
    if ka is None or kb is None:
        return None
    return _sign(ka, kb)


# -- Maven ----------------------------------------------------------------------------
#
# Porte do algoritmo ``ComparableVersion`` do Maven (licença Apache-2.0): a versão vira
# uma lista de números, qualificadores, combinações (``alpha-1``, ``rc2``) e sublistas.

_MAVEN_QUALIFIERS = ("alpha", "beta", "milestone", "rc", "snapshot", "", "sp")
_MAVEN_RELEASE_WORDS = frozenset({"ga", "final", "release"})
_MAVEN_SHORT = {"a": "alpha", "b": "beta", "m": "milestone"}
_MAVEN_RELEASE = str(_MAVEN_QUALIFIERS.index(""))


@dataclass(frozen=True)
class _MavenCombo:
    """Qualificador seguido de número (``rc2``, ``alpha-1``)."""

    qualifier: str
    number: int


MavenItem: TypeAlias = "int | str | _MavenCombo | list[MavenItem]"


def _maven_rank(qualifier: str) -> str:
    """Forma comparável do qualificador: índice na ordem conhecida ou ``7-texto``."""
    if qualifier in _MAVEN_RELEASE_WORDS:
        return _MAVEN_RELEASE
    if qualifier in _MAVEN_QUALIFIERS:
        return str(_MAVEN_QUALIFIERS.index(qualifier))
    return f"{len(_MAVEN_QUALIFIERS)}-{qualifier}"


def _maven_string(text: str, followed_by_digit: bool = False) -> str:
    if followed_by_digit:
        text = _MAVEN_SHORT.get(text, text)
    return "rc" if text == "cr" else text


def _maven_item(combination: bool, digits: bool, chunk: str) -> MavenItem:
    if combination:
        clean = chunk.replace("-", "")
        first = next(index for index, char in enumerate(clean) if char.isdigit())
        return _MavenCombo(_maven_string(clean[:first], True), int(clean[first:]))
    return int(chunk) if digits else _maven_string(chunk)


def _maven_is_null(item: MavenItem) -> bool:
    if isinstance(item, int):
        return item == 0
    if isinstance(item, str):
        return not item
    return False if isinstance(item, _MavenCombo) else not item


def _maven_normalize(items: list[MavenItem]) -> None:
    """Tira os zeros que não fazem diferença (``1.0.0 == 1``, ``1.0-rc == 1-rc``)."""
    for index in range(len(items) - 1, -1, -1):
        if not _maven_is_null(items[index]):
            continue
        following = items[index + 1] if index + 1 < len(items) else None
        if following is None or isinstance(following, str):
            del items[index]
        elif isinstance(following, list) and isinstance(following[0], (str, _MavenCombo)):
            del items[index]


def maven_items(version: str) -> list[MavenItem]:
    """Itens comparáveis de uma versão Maven (sublistas abertas por ``-`` ou transição)."""
    text = version.strip().lower()
    root: list[MavenItem] = []
    current = root
    stack = [root]
    digits = combination = False
    start = 0

    def open_sublist() -> None:
        nonlocal current
        sub: list[MavenItem] = []
        current.append(sub)
        stack.append(sub)
        current = sub

    for index, char in enumerate(text):
        if char == ".":
            current.append(
                0 if index == start else _maven_item(combination, digits, text[start:index])
            )
            combination = False
            start = index + 1
        elif char == "-":
            if index == start:
                current.append(0)
            elif not digits and index + 1 < len(text) and text[index + 1].isdigit():
                combination = True  # ``X-1`` é tratado como ``X1``
                continue
            else:
                current.append(_maven_item(combination, digits, text[start:index]))
            start = index + 1
            if current:
                open_sublist()
            combination = False
        elif "0" <= char <= "9":
            if not digits and index > start:
                combination = True
                if current:
                    open_sublist()
            digits = True
        else:
            if digits and index > start:
                current.append(_maven_item(combination, True, text[start:index]))
                start = index
                open_sublist()
                combination = False
            digits = False
    if len(text) > start:
        if not digits and current:
            open_sublist()  # ``.X`` vale como ``-X`` para qualquer qualificador
        current.append(_maven_item(combination, digits, text[start:]))
    for items in reversed(stack):
        _maven_normalize(items)
    return root


def _maven_vs_null(item: MavenItem) -> int:
    """Compara um item com "nada" (``1.1 > 1``, ``1-rc < 1``, ``1-sp > 1``)."""
    if isinstance(item, int):
        return 0 if item == 0 else 1
    if isinstance(item, str):
        return _sign(_maven_rank(item), _MAVEN_RELEASE)
    if isinstance(item, _MavenCombo):
        return _sign(_maven_rank(item.qualifier), _MAVEN_RELEASE)
    for sub in item:
        result = _maven_vs_null(sub)
        if result:
            return result
    return 0


def _maven_cmp_list(a: list[MavenItem], b: list[MavenItem]) -> int:
    for index in range(max(len(a), len(b))):
        if index >= len(a):
            result = -_maven_vs_null(b[index])
        elif index >= len(b):
            result = _maven_vs_null(a[index])
        else:
            result = _maven_cmp(a[index], b[index])
        if result:
            return result
    return 0


def _maven_cmp_text(a: str | _MavenCombo, b: str | _MavenCombo) -> int:
    """Qualificadores: ``X1 > X``; entre combinações iguais decide o número."""
    left = a.qualifier if isinstance(a, _MavenCombo) else a
    right = b.qualifier if isinstance(b, _MavenCombo) else b
    result = _sign(_maven_rank(left), _maven_rank(right))
    if result:
        return result
    if isinstance(a, _MavenCombo) and isinstance(b, _MavenCombo):
        return _sign(a.number, b.number)
    return int(isinstance(a, _MavenCombo)) - int(isinstance(b, _MavenCombo))


def _maven_cmp(a: MavenItem, b: MavenItem) -> int:
    if isinstance(a, int):
        return _sign(a, b) if isinstance(b, int) else 1  # número > qualificador e sublista
    if isinstance(a, list):
        if isinstance(b, list):
            return _maven_cmp_list(a, b)
        return -1 if isinstance(b, int) else 1  # 1-1 < 1.0.x e 1-1 > 1-sp
    if isinstance(b, (int, list)):
        return -1  # 1.qualquer < 1.1 e 1.qualquer < 1-1
    return _maven_cmp_text(a, b)


def maven_compare(a: str, b: str) -> int:
    return _maven_cmp(maven_items(a), maven_items(b))


# -- RubyGems -------------------------------------------------------------------------

_GEM_VERSION = re.compile(r"^[0-9]+(?:\.[0-9a-zA-Z]+)*(?:-[0-9A-Za-z\-]+(?:\.[0-9A-Za-z\-]+)*)?$")


def _drop_trailing_zeros(items: list[int | str]) -> list[int | str]:
    out = list(items)
    while out and out[-1] == 0:
        out.pop()
    return out


def gem_segments(version: str) -> list[int | str] | None:
    """Segmentos canônicos do ``Gem::Version`` (``None`` se não for versão de gem)."""
    text = version.strip()
    if not _GEM_VERSION.match(text):
        return None
    text = text.replace("-", ".pre.")
    segments: list[int | str] = [
        int(s) if s.isdigit() else s for s in re.findall(r"[0-9]+|[a-zA-Z]+", text)
    ]
    cut = next((i for i, s in enumerate(segments) if isinstance(s, str)), len(segments))
    return _drop_trailing_zeros(segments[:cut]) + _drop_trailing_zeros(segments[cut:])


def gem_compare(a: str, b: str) -> int | None:
    left, right = gem_segments(a), gem_segments(b)
    if left is None or right is None:
        return None
    for index in range(max(len(left), len(right))):
        x = left[index] if index < len(left) else 0
        y = right[index] if index < len(right) else 0
        if x == y:
            continue
        if isinstance(x, str) != isinstance(y, str):
            return -1 if isinstance(x, str) else 1  # letra = pré-lançamento
        return _sign(x, y)
    return 0


# -- Packagist (Composer) -------------------------------------------------------------

_COMPOSER = re.compile(
    r"^(?P<num>\d+(?:\.\d+){0,3})"
    r"(?:[._\-]?(?P<stab>stable|beta|b|rc|alpha|a|patch|pl|p|dev)"
    r"(?:[._\-]?(?P<sn>\d+(?:\.\d+)*))?)?$",
    re.I,
)
_COMPOSER_RANK = {"dev": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2, "rc": 3, "stable": 4}
_COMPOSER_RANK.update({"patch": 5, "pl": 5, "p": 5})


def composer_key(version: str) -> tuple[tuple[int, ...], int, tuple[int, ...]] | None:
    match = _COMPOSER.match(version.strip())
    if not match:
        return None
    numbers = [int(part) for part in match.group("num").split(".")]
    numbers += [0] * (4 - len(numbers))  # o Composer normaliza para quatro números
    rank = _COMPOSER_RANK[(match.group("stab") or "stable").lower()]
    extra = tuple(int(part) for part in (match.group("sn") or "0").split("."))
    return tuple(numbers), rank, extra


def composer_compare(a: str, b: str) -> int | None:
    ka, kb = composer_key(a), composer_key(b)
    if ka is None or kb is None:
        return None
    return _sign(ka, kb)


# -- despacho por ecossistema ---------------------------------------------------------

_COMPARATORS: dict[str, Callable[[str, str], int | None]] = {
    "PyPI": pep440_compare,
    "Maven": maven_compare,
    "RubyGems": gem_compare,
    "Packagist": composer_compare,
    "NuGet": _nuget_compare,
    "npm": semver_compare,
    "crates.io": semver_compare,
    "Go": semver_compare,
}


def compare(ecosystem: str, a: str, b: str) -> int:
    """-1, 0 ou 1 conforme as regras do ecossistema."""
    left, right = normalize(ecosystem, a), normalize(ecosystem, b)
    comparator = _COMPARATORS.get(ecosystem)
    if comparator is not None:
        try:
            result = comparator(left, right)
        except (ValueError, RecursionError):  # número gigante ou aninhamento absurdo
            result = None
        if result is not None:
            return result
    return versions.compare(left, right)


# -- faixas do OSV --------------------------------------------------------------------


@dataclass(frozen=True)
class VersionRange:
    """Uma faixa do OSV: eventos ``(tipo, versão)`` na ordem em que aparecem."""

    events: tuple[tuple[str, str], ...]


def _sort_events(ecosystem: str, events: Sequence[tuple[str, str]]) -> list[tuple[str, str]]:
    def key(a: tuple[str, str], b: tuple[str, str]) -> int:
        if a[1] == b[1]:
            return 0
        if a[1] == "0":
            return -1
        if b[1] == "0":
            return 1
        return compare(ecosystem, a[1], b[1])

    return sorted(events, key=cmp_to_key(key))


def in_range(ecosystem: str, version: str, rng: VersionRange) -> bool:
    """Avalia uma faixa conforme o pseudocódigo da especificação do OSV."""
    limits = [v for kind, v in rng.events if kind == "limit"]
    if limits and not any(lim == "*" or compare(ecosystem, version, lim) < 0 for lim in limits):
        return False
    affected = False
    for kind, value in _sort_events(ecosystem, [e for e in rng.events if e[0] != "limit"]):
        if kind == "introduced":
            if value == "0" or compare(ecosystem, version, value) >= 0:
                affected = True
        elif kind == "fixed":
            if compare(ecosystem, version, value) >= 0:
                affected = False
        elif kind == "last_affected":
            if compare(ecosystem, version, value) > 0:
                affected = False
    return affected


def fixed_after(ecosystem: str, version: str, rng: VersionRange) -> str | None:
    """Menor versão corrigida acima da versão afetada (para orientar a atualização)."""
    return smallest_fix(ecosystem, version, [rng])


def smallest_fix(ecosystem: str, version: str, ranges: Sequence[VersionRange]) -> str | None:
    """Menor evento ``fixed`` maior que ``version`` entre as faixas informadas."""
    candidates = [
        value
        for rng in ranges
        for kind, value in rng.events
        if kind == "fixed" and compare(ecosystem, value, version) > 0
    ]
    ordered = sort_versions(ecosystem, candidates)
    return ordered[0] if ordered else None


def _listed(ecosystem: str, version: str, explicit: frozenset[str]) -> bool:
    if version in explicit:
        return True
    return any(compare(ecosystem, version, item) == 0 for item in explicit)


def is_affected(
    ecosystem: str,
    version: str,
    ranges: Sequence[VersionRange],
    explicit: frozenset[str] = frozenset(),
) -> tuple[bool, str | None]:
    """``(afetada, versão corrigida sugerida)`` para uma versão instalada."""
    clean = normalize(ecosystem, version)
    if not clean or not clean[0].isdigit() or len(clean) > MAX_VERSION_LENGTH:
        return False, None
    matching = [rng for rng in ranges if in_range(ecosystem, clean, rng)]
    if matching:
        return True, smallest_fix(ecosystem, clean, matching)
    if explicit and _listed(ecosystem, clean, explicit):
        return True, smallest_fix(ecosystem, clean, ranges)
    return False, None


def sort_versions(ecosystem: str, items: Sequence[str]) -> list[str]:
    """Versões em ordem crescente (segundo o ecossistema), sem vazios."""

    def by_version(a: str, b: str) -> int:
        return compare(ecosystem, a, b)

    return sorted((i for i in items if i), key=cmp_to_key(by_version))


def highest(ecosystem: str, items: Sequence[str]) -> str | None:
    """A maior versão de uma lista (segundo o ecossistema)."""
    ordered = sort_versions(ecosystem, items)
    return ordered[-1] if ordered else None
