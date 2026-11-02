"""Comparação de versões tolerante (semver, PEP 440 simples, OpenSSH ``8.9p1``...).

Usada para casar versões detectadas (banner, cabeçalho, manifesto) com faixas
vulneráveis. Pré-lançamentos (``alpha``, ``beta``, ``rc``) ficam antes da versão
final; sufixos de pacote (``p1``, ``post1``) ficam depois.
"""

from __future__ import annotations

import re
from functools import cmp_to_key

_PRE = {
    "dev": 0,
    "snapshot": 0,
    "a": 1,
    "alpha": 1,
    "m": 1,
    "b": 2,
    "beta": 2,
    "pre": 3,
    "preview": 3,
    "c": 4,
    "rc": 4,
    "cr": 4,
}
_RELEASE_WORDS = {"final", "ga", "release", "r"}
_VERSION_IN_TEXT = re.compile(r"\d+(?:\.\d+)+(?:[-._]?(?:p|rc|beta|alpha|b|a)\d*)?", re.I)


def _tokens(version: str) -> list[str]:
    text = version.strip().lower()
    if text.startswith("v") and text[1:2].isdigit():
        text = text[1:]
    text = text.split("+", 1)[0]
    return re.findall(r"\d+|[a-z]+", text)


def _key(token: str | None) -> tuple[float, int, str]:
    if token is None or token in _RELEASE_WORDS:
        return (2.0, 0, "")
    if token.isdigit():
        return (3.0, int(token), "")
    if token in _PRE:
        return (1.0, _PRE[token], token)
    return (2.5, 0, token)  # p, post, patch, sufixos desconhecidos


def compare(a: str, b: str) -> int:
    """-1 se a<b, 0 se iguais, 1 se a>b."""
    ta, tb = _tokens(a), _tokens(b)
    for i in range(max(len(ta), len(tb))):
        x = ta[i] if i < len(ta) else None
        y = tb[i] if i < len(tb) else None
        if x == y:
            continue
        kx, ky = _key(x), _key(y)
        if kx != ky:
            return -1 if kx < ky else 1
    return 0


def lt(a: str, b: str) -> bool:
    return compare(a, b) < 0


def le(a: str, b: str) -> bool:
    return compare(a, b) <= 0


def ge(a: str, b: str) -> bool:
    return compare(a, b) >= 0


def in_range(
    version: str,
    *,
    introduced: str | None = None,
    fixed: str | None = None,
    last_affected: str | None = None,
) -> bool:
    """``introduced <= version < fixed`` (ou ``<= last_affected``). Limites ausentes = abertos."""
    if not version:
        return False
    if introduced and introduced not in ("0", "*") and compare(version, introduced) < 0:
        return False
    if fixed and compare(version, fixed) >= 0:
        return False
    if last_affected and compare(version, last_affected) > 0:
        return False
    return True


def sort_versions(versions: list[str]) -> list[str]:
    return sorted(versions, key=cmp_to_key(compare))


def extract_version(text: str) -> str | None:
    """Primeira versão "x.y[.z]" encontrada em um texto (banner, cabeçalho)."""
    match = _VERSION_IN_TEXT.search(text or "")
    return match.group(0) if match else None
