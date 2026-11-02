"""Manifestos e lockfiles de dependências: como reconhecer e qual leitor usar.

Cada leitor devolve as dependências com a versão **exata** instalada (lockfiles)
ou fixada (``==``/versão literal). Faixas como ``^1.2`` ou ``>=2`` são ignoradas:
sem a versão real não dá para afirmar que a dependência está vulnerável.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

from ...core.models import Confidence
from .files import SourceFile
from .versioning import MAX_VERSION_LENGTH


@dataclass(frozen=True)
class Dependency:
    """Uma dependência instalada/fixada em um manifesto."""

    name: str
    version: str
    line: int = 0
    note: str = ""  # observação de como a versão foi obtida (ex.: herdada do parent)


@dataclass(frozen=True)
class ManifestSpec:
    """Tipo de manifesto reconhecido."""

    kind: str
    ecosystem: str
    lockfile: bool
    label: str


_BY_NAME: dict[str, ManifestSpec] = {
    "package-lock.json": ManifestSpec("package-lock", "npm", True, "package-lock.json"),
    "npm-shrinkwrap.json": ManifestSpec("package-lock", "npm", True, "npm-shrinkwrap.json"),
    "yarn.lock": ManifestSpec("yarn-lock", "npm", True, "yarn.lock"),
    "pnpm-lock.yaml": ManifestSpec("pnpm-lock", "npm", True, "pnpm-lock.yaml"),
    "package.json": ManifestSpec("package-json", "npm", False, "package.json"),
    "pipfile.lock": ManifestSpec("pipfile-lock", "PyPI", True, "Pipfile.lock"),
    "poetry.lock": ManifestSpec("poetry-lock", "PyPI", True, "poetry.lock"),
    "uv.lock": ManifestSpec("uv-lock", "PyPI", True, "uv.lock"),
    "composer.lock": ManifestSpec("composer-lock", "Packagist", True, "composer.lock"),
    "gemfile.lock": ManifestSpec("gemfile-lock", "RubyGems", True, "Gemfile.lock"),
    "gems.locked": ManifestSpec("gemfile-lock", "RubyGems", True, "gems.locked"),
    "go.mod": ManifestSpec("go-mod", "Go", False, "go.mod"),
    "go.sum": ManifestSpec("go-sum", "Go", True, "go.sum"),
    "cargo.lock": ManifestSpec("cargo-lock", "crates.io", True, "Cargo.lock"),
    "packages.lock.json": ManifestSpec("nuget-lock", "NuGet", True, "packages.lock.json"),
    "packages.config": ManifestSpec("packages-config", "NuGet", False, "packages.config"),
    "directory.packages.props": ManifestSpec(
        "nuget-props", "NuGet", False, "Directory.Packages.props"
    ),
    "pom.xml": ManifestSpec("pom", "Maven", False, "pom.xml"),
    "gradle.lockfile": ManifestSpec("gradle-lock", "Maven", True, "gradle.lockfile"),
    "build.gradle": ManifestSpec("gradle-build", "Maven", False, "build.gradle"),
    "build.gradle.kts": ManifestSpec("gradle-build", "Maven", False, "build.gradle.kts"),
}
#: ``requirements.txt``, ``requirements-dev.txt``, ``dev-requirements.txt``, ``constraints.txt``
_REQUIREMENTS = re.compile(r"^(?:[\w.\-]*[._\-])?(?:requirements|constraints)[\w.\-]*\.txt$")
_PROJECT_FILES = (".csproj", ".fsproj", ".vbproj")
#: nomes maiores que isto não existem de verdade (entrada hostil ou arquivo corrompido)
_MAX_NAME_LENGTH = 256
_NOT_NEWLINE = re.compile(r"[^" + chr(92) + "n]")

#: lockfiles que tornam um manifesto sem versões exatas redundante
_NPM_LOCKS = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml")


def identify(file: SourceFile) -> ManifestSpec | None:
    """Reconhece um manifesto/lockfile pelo nome do arquivo."""
    name = file.lname
    spec = _BY_NAME.get(name)
    if spec is not None:
        return spec
    if _REQUIREMENTS.match(name):
        return ManifestSpec("requirements", "PyPI", False, file.name)
    parent = file.rel.lower().rsplit("/", 2)
    if name.endswith(".txt") and len(parent) >= 2 and parent[-2] == "requirements":
        return ManifestSpec("requirements", "PyPI", False, file.name)
    if name.endswith(".lockfile") and "dependency-locks" in file.rel.lower():
        return ManifestSpec("gradle-lock", "Maven", True, file.name)
    if name.endswith(_PROJECT_FILES):
        return ManifestSpec("csproj", "NuGet", False, file.name)
    return None


def spec_for(path: Path, rel: str = "") -> ManifestSpec | None:
    return identify(SourceFile(path, rel or path.name, 0))


def superseded_by(path: Path, kind: str, project_root: Path | None) -> str | None:
    """Nome do lockfile que torna este manifesto redundante (ou ``None``)."""
    folder = path.parent
    if kind == "package-json":
        for current in _ancestors(folder, project_root):
            for lock in _NPM_LOCKS:
                if (current / lock).is_file():
                    return lock
    elif kind == "go-sum" and (folder / "go.mod").is_file():
        return "go.mod"
    elif kind == "csproj" and (folder / "packages.lock.json").is_file():
        return "packages.lock.json"
    elif kind == "gradle-build" and (folder / "gradle.lockfile").is_file():
        return "gradle.lockfile"
    return None


def _ancestors(folder: Path, root: Path | None) -> list[Path]:
    chain = [folder]
    if root is None:
        return chain
    try:
        resolved_root = root.resolve()
        current = folder.resolve()
    except OSError:
        return chain
    while current != resolved_root and resolved_root in current.parents:
        current = current.parent
        chain.append(current)
    return chain


def confidence_for(spec: ManifestSpec) -> Confidence:
    """Lockfile = versão instalada; manifesto fixado = provável; go.sum = indício."""
    if spec.kind == "go-sum":
        return Confidence.TENTATIVE
    return Confidence.CONFIRMED if spec.lockfile else Confidence.FIRM


Parser = Callable[[str], list[Dependency]]


def parser_for(kind: str) -> Parser | None:
    from . import parsers_js, parsers_jvm, parsers_misc, parsers_py

    table: dict[str, Parser] = {
        "package-lock": parsers_js.parse_package_lock,
        "yarn-lock": parsers_js.parse_yarn_lock,
        "pnpm-lock": parsers_js.parse_pnpm_lock,
        "package-json": parsers_js.parse_package_json,
        "requirements": parsers_py.parse_requirements,
        "pipfile-lock": parsers_py.parse_pipfile_lock,
        "poetry-lock": parsers_py.parse_toml_lock,
        "uv-lock": parsers_py.parse_toml_lock,
        "composer-lock": parsers_misc.parse_composer_lock,
        "gemfile-lock": parsers_misc.parse_gemfile_lock,
        "go-mod": parsers_misc.parse_go_mod,
        "go-sum": parsers_misc.parse_go_sum,
        "cargo-lock": parsers_misc.parse_cargo_lock,
        "nuget-lock": parsers_misc.parse_nuget_lock,
        "csproj": parsers_misc.parse_csproj,
        "packages-config": parsers_misc.parse_packages_config,
        "nuget-props": parsers_misc.parse_nuget_props,
        "pom": parsers_jvm.parse_pom,
        "gradle-lock": parsers_jvm.parse_gradle_lock,
        "gradle-build": parsers_jvm.parse_gradle_build,
    }
    return table.get(kind)


def unique(deps: list[Dependency]) -> list[Dependency]:
    """Remove repetições ``nome@versão`` e valores absurdos, mantendo a primeira ocorrência."""
    seen: set[tuple[str, str]] = set()
    out: list[Dependency] = []
    for dep in deps:
        key = (dep.name, dep.version)
        if not dep.name or not dep.version or key in seen:
            continue
        if len(dep.name) > _MAX_NAME_LENGTH or len(dep.version) > MAX_VERSION_LENGTH:
            continue
        seen.add(key)
        out.append(dep)
    return out


def blank_xml_comments(text: str) -> str:
    """Troca comentários XML por espaços (mantém as posições para contar linhas).

    Busca linear (``str.find``): um ``<!--`` sem fechamento apaga até o fim, sem varrer o
    texto de novo a cada abertura (a expressão regular preguiçosa era quadrática).
    """
    if "<!--" not in text:
        return text
    pieces: list[str] = []
    cursor = 0
    while True:
        start = text.find("<!--", cursor)
        if start < 0:
            break
        end = text.find("-->", start + 4)
        end = len(text) if end < 0 else end + 3
        pieces.append(text[cursor:start])
        pieces.append(_NOT_NEWLINE.sub(" ", text[start:end]))
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


def iter_elements(text: str, name: str) -> Iterator[tuple[int, str, str | None]]:
    """``<name ...>corpo</name>`` ou ``<name .../>``: (posição, atributos, corpo ou ``None``).

    Linear no tamanho do texto: se não há ``>`` ou ``</name>`` adiante, não há para os
    próximos também, então a busca não se repete (entrada hostil não vira quadrática).
    """
    opening, closing = f"<{name}", f"</{name}>"
    cursor, no_close = 0, False
    while True:
        start = text.find(opening, cursor)
        if start < 0:
            return
        after = start + len(opening)
        if after < len(text) and not (text[after].isspace() or text[after] in "/>"):
            cursor = after  # outro elemento com o mesmo prefixo (``<PackageReferenceX``)
            continue
        end = text.find(">", after)
        if end < 0:
            return
        attrs = text[after:end]
        cursor = end + 1
        if attrs.endswith("/"):
            yield start, attrs[:-1], None
            continue
        close = -1 if no_close else text.find(closing, cursor)
        if close < 0:
            no_close = True
            yield start, attrs, None
            continue
        yield start, attrs, text[cursor:close]
        cursor = close + len(closing)


def strip_elements(text: str, name: str) -> str:
    """Remove ``<name>...</name>`` (busca linear); sem fechamento, o resto fica como está."""
    opening, closing = f"<{name}>", f"</{name}>"
    pieces: list[str] = []
    cursor = 0
    while True:
        start = text.find(opening, cursor)
        end = text.find(closing, start) if start >= 0 else -1
        if start < 0 or end < 0:
            break
        pieces.append(text[cursor:start])
        cursor = end + len(closing)
    pieces.append(text[cursor:])
    return "".join(pieces)


def line_starts(text: str) -> list[int]:
    """Posições de início de cada linha (para converter índice em número de linha)."""
    starts = [0]
    starts.extend(m.end() for m in re.finditer("\n", text))
    return starts


def index_to_line(starts: list[int], index: int) -> int:
    from bisect import bisect_right

    return bisect_right(starts, index)
