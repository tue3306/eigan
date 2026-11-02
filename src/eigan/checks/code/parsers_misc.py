"""Leitores de dependências de PHP, Ruby, Go, Rust e .NET."""

from __future__ import annotations

import json
import re
import tomllib

from .manifests import (
    Dependency,
    blank_xml_comments,
    index_to_line,
    iter_elements,
    line_starts,
    unique,
)
from .parsers_py import toml_name_lines
from .versioning import is_exact

_GEM_SPEC = re.compile(r"^    ([A-Za-z0-9_.\-]+) \(([^)]+)\)\s*$")
_GO_REQ = re.compile(r"^\s*(?:require\s+)?([^\s()]+)\s+(v[0-9][^\s]*)")
_GO_REPLACE = re.compile(
    r"^\s*(?:replace\s+)?([^\s()]+)(?:\s+(v[^\s]+))?\s+=>\s+([^\s]+)(?:\s+(v[^\s]+))?"
)
_XML_ATTR = re.compile(r'([A-Za-z]+)\s*=\s*"([^"]*)"')
_PKG_REF = re.compile(r"<PackageReference\b([^>]*?)(?:/>|>(.*?)</PackageReference>)", re.S)
_INNER_VERSION = re.compile(r"<Version>([^<]+)</Version>")
_PKG_CONFIG = re.compile(r"<package\b([^>]*?)/?>")
_PKG_VERSION = re.compile(r"<PackageVersion\b([^>]*?)/?>")
_NUGET_PINNED = re.compile(r"^\[\s*([^,\[\]\s]+)\s*\]$")
#: índices oficiais do crates.io no Cargo.lock (git e registros alternativos ficam de fora)
_CRATES_IO = (
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
)


def parse_composer_lock(text: str) -> list[Dependency]:
    """composer.lock (packages e packages-dev)."""
    data = json.loads(text)
    if not isinstance(data, dict):
        return []
    lines: dict[str, int] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        match = re.match(r'^\s*"name"\s*:\s*"([^"]+)"', line)
        if match:
            lines.setdefault(match.group(1), number)
    deps: list[Dependency] = []
    for section in ("packages", "packages-dev"):
        for entry in data.get(section) or []:
            if not isinstance(entry, dict):
                continue
            dist = entry.get("dist")
            if isinstance(dist, dict) and dist.get("type") == "path":
                continue  # pacote de uma pasta local (repositório do tipo path)
            name = str(entry.get("name") or "")
            version = str(entry.get("version") or "").lstrip("vV")
            if name and is_exact(version):  # branches (``dev-main``, ``2.x-dev``) ficam de fora
                deps.append(Dependency(name, version, lines.get(name, 0)))
    return unique(deps)


def parse_gemfile_lock(text: str) -> list[Dependency]:
    """Gemfile.lock: especificações da seção GEM (indentação de 4 espaços).

    Como no Bundler, o que vem depois do primeiro ``-`` é a plataforma
    (``nokogiri (1.16.2-x86_64-linux)``), não parte da versão.
    """
    deps: list[Dependency] = []
    in_gem = False
    for number, line in enumerate(text.splitlines(), start=1):
        if line and not line[0].isspace():
            in_gem = line.strip() == "GEM"
            continue
        if not in_gem:
            continue
        match = _GEM_SPEC.match(line)
        if match:
            version = match.group(2).split("-", 1)[0]
            deps.append(Dependency(match.group(1), version, number))
    return unique(deps)


def parse_go_mod(text: str) -> list[Dependency]:
    """go.mod: diretivas ``require`` (com as substituições de ``replace``)."""
    requires: list[Dependency] = []
    replaces: dict[tuple[str, str], tuple[str, str]] = {}
    block = ""
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("//", 1)[0].rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.endswith("(") and stripped.split()[0] in (
            "require",
            "replace",
            "exclude",
            "retract",
        ):
            block = stripped.split()[0]
            continue
        if stripped == ")":
            block = ""
            continue
        directive = block or stripped.split()[0]
        if directive == "require":
            match = _GO_REQ.match(stripped)
            if match:
                requires.append(Dependency(match.group(1), match.group(2), number))
        elif directive == "replace":
            match = _GO_REPLACE.match(stripped)
            if match:
                old = (match.group(1), match.group(2) or "")  # versão vazia = todas
                replaces[old] = (match.group(3), match.group(4) or "")
    deps: list[Dependency] = []
    for dep in requires:
        target = replaces.get((dep.name, dep.version)) or replaces.get((dep.name, ""))
        if target is None:
            deps.append(dep)
        elif target[1] and not target[0].startswith((".", "/")):
            deps.append(Dependency(target[0], target[1], dep.line, "substituído por replace"))
    return unique(deps)


def parse_go_sum(text: str) -> list[Dependency]:
    """go.sum: módulos baixados (sem as linhas ``/go.mod``). Usado só sem go.mod."""
    deps: list[Dependency] = []
    for number, line in enumerate(text.splitlines(), start=1):
        parts = line.split()
        if len(parts) >= 2 and not parts[1].endswith("/go.mod"):
            deps.append(Dependency(parts[0], parts[1], number))
    return unique(deps)


def parse_cargo_lock(text: str) -> list[Dependency]:
    """Cargo.lock: só pacotes baixados do crates.io (workspace, git e outros registros ficam de fora)."""
    data = tomllib.loads(text)
    lines = toml_name_lines(text)
    deps: list[Dependency] = []
    for entry in data.get("package", []) or []:
        if not isinstance(entry, dict) or not str(entry.get("source", "")).startswith(_CRATES_IO):
            continue
        name, version = str(entry.get("name") or ""), str(entry.get("version") or "")
        deps.append(Dependency(name, version, lines.get(name, 0)))
    return unique(deps)


def parse_nuget_lock(text: str) -> list[Dependency]:
    """packages.lock.json do NuGet (versões resolvidas por framework)."""
    data = json.loads(text)
    if not isinstance(data, dict):
        return []
    lines: dict[str, int] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        match = re.match(r'^\s*"([^"]+)"\s*:\s*\{', line)
        if match:
            lines.setdefault(match.group(1), number)
    deps: list[Dependency] = []
    for framework in (data.get("dependencies") or {}).values():
        if not isinstance(framework, dict):
            continue
        for name, meta in framework.items():
            if not isinstance(meta, dict) or meta.get("type") == "Project":
                continue
            version = str(meta.get("resolved") or "")
            if version:
                deps.append(Dependency(str(name), version, lines.get(str(name), 0)))
    return unique(deps)


def _nuget_version(raw: str) -> str:
    """Versão exata do NuGet: ``1.2.3`` ou ``[1.2.3]`` (faixas e curingas viram ``""``)."""
    text = raw.strip()
    pinned = _NUGET_PINNED.match(text)
    if pinned:
        text = pinned.group(1)
    return text if is_exact(text) else ""


def _attrs(raw: str) -> dict[str, str]:
    return {k.lower(): v for k, v in _XML_ATTR.findall(raw)}


def parse_csproj(text: str) -> list[Dependency]:
    """*.csproj/*.fsproj/*.vbproj: ``<PackageReference>`` com versão exata."""
    clean = blank_xml_comments(text)
    starts = line_starts(clean)
    deps: list[Dependency] = []
    for position, raw_attrs, body in iter_elements(clean, "PackageReference"):
        attrs = _attrs(raw_attrs)
        name = attrs.get("include") or attrs.get("update") or ""
        version = attrs.get("version") or attrs.get("versionoverride") or ""
        if not version and body:
            inner = _INNER_VERSION.search(body)
            version = inner.group(1).strip() if inner else ""
        version = _nuget_version(version)
        if name and version:
            deps.append(Dependency(name, version, index_to_line(starts, position)))
    return unique(deps)


def parse_packages_config(text: str) -> list[Dependency]:
    """packages.config (formato antigo do NuGet)."""
    clean = blank_xml_comments(text)
    starts = line_starts(clean)
    deps: list[Dependency] = []
    for position, raw_attrs, _ in iter_elements(clean, "package"):
        attrs = _attrs(raw_attrs)
        name, version = attrs.get("id", ""), _nuget_version(attrs.get("version", ""))
        if name and version:
            deps.append(Dependency(name, version, index_to_line(starts, position)))
    return unique(deps)


def parse_nuget_props(text: str) -> list[Dependency]:
    """Directory.Packages.props (gestão central de versões do NuGet)."""
    clean = blank_xml_comments(text)
    starts = line_starts(clean)
    deps: list[Dependency] = []
    for position, raw_attrs, _ in iter_elements(clean, "PackageVersion"):
        attrs = _attrs(raw_attrs)
        name, version = attrs.get("include", ""), _nuget_version(attrs.get("version", ""))
        if name and version:
            deps.append(Dependency(name, version, index_to_line(starts, position)))
    return unique(deps)
