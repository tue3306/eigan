"""Leitores de dependências Java/JVM (pom.xml, gradle.lockfile, build.gradle).

O ``pom.xml`` é lido com expressões regulares (sem montar a árvore XML): só se
aproveitam versões literais ou resolvidas pelas ``<properties>`` do próprio
arquivo. Dependências sem versão herdam a do ``<parent>`` quando são do mesmo
grupo (caso típico dos starters do Spring Boot). BOMs externos não são resolvidos.
"""

from __future__ import annotations

import re

from .manifests import (
    Dependency,
    blank_xml_comments,
    index_to_line,
    iter_elements,
    line_starts,
    strip_elements,
    unique,
)
from .versioning import is_exact

_BLOCK = re.compile(r"<dependency>(.*?)</dependency>", re.S)
_EXCLUSIONS = re.compile(r"<exclusions>.*?</exclusions>", re.S)
_PARENT = re.compile(r"<parent>(.*?)</parent>", re.S)
_PROPERTIES = re.compile(r"<properties>(.*?)</properties>", re.S)
_PROPERTY = re.compile(r"<([A-Za-z0-9_.\-]+)>\s*([^<]*?)\s*</\1>")
_TAG = {
    name: re.compile(rf"<{name}>\s*([^<]+?)\s*</{name}>")
    for name in ("groupId", "artifactId", "version")
}
_VAR = re.compile(r"\$\{([^}]+)\}")
_GRADLE_COORD = re.compile(
    r"""\b(?:implementation|api|compile|compileOnly|runtimeOnly|runtime|testImplementation|"""
    r"""testCompile|testRuntimeOnly|annotationProcessor|kapt|classpath)\b\s*\(?\s*"""
    r"""['"]([\w.\-]+):([\w.\-]+):([\w.\-+]+)['"]"""
)
_GRADLE_MAP = re.compile(
    r"""group\s*[:=]\s*['"]([\w.\-]+)['"]\s*,\s*name\s*[:=]\s*['"]([\w.\-]+)['"]\s*,\s*"""
    r"""version\s*[:=]\s*['"]([\w.\-+]+)['"]"""
)


def _tag(block: str, name: str) -> str:
    match = _TAG[name].search(block)
    return match.group(1).strip() if match else ""


def _resolve(value: str, props: dict[str, str]) -> str:
    for _ in range(4):
        if "${" not in value:
            return value
        value = _VAR.sub(lambda m: props.get(m.group(1), m.group(0)), value)
    return value


def parse_pom(text: str) -> list[Dependency]:
    """pom.xml: dependências com versão literal, por propriedade ou herdada do parent."""
    clean = blank_xml_comments(text)
    starts = line_starts(clean)
    props: dict[str, str] = {}
    for _, _, body in iter_elements(clean, "properties"):
        for key, value in _PROPERTY.findall(body or ""):
            props.setdefault(key, value.strip())
    parent = next((body or "" for _, _, body in iter_elements(clean, "parent")), "")
    parent_group = _tag(parent, "groupId")
    parent_version = _tag(parent, "version")
    if parent_version:
        props.setdefault("project.parent.version", parent_version)
        props.setdefault("parent.version", parent_version)
    deps: list[Dependency] = []
    for position, _, body in iter_elements(clean, "dependency"):
        if body is None:
            continue
        block = strip_elements(body, "exclusions")  # coordenadas de <exclusion> não contam
        group, artifact = _tag(block, "groupId"), _tag(block, "artifactId")
        if not group or not artifact:
            continue
        version, note = _resolve(_tag(block, "version"), props), ""
        if not version and group == parent_group and parent_version:
            version, note = parent_version, "versão herdada do <parent>"
        if not is_exact(version):
            continue
        offset = position + len("<dependency>") + max(body.find("<artifactId>"), 0)
        deps.append(Dependency(f"{group}:{artifact}", version, index_to_line(starts, offset), note))
    return unique(deps)


def parse_gradle_lock(text: str) -> list[Dependency]:
    """gradle.lockfile: ``grupo:artefato:versão=configurações``."""
    deps: list[Dependency] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("empty="):
            continue
        coords = line.split("=", 1)[0].split(":")
        if len(coords) >= 3 and is_exact(coords[2]):
            deps.append(Dependency(f"{coords[0]}:{coords[1]}", coords[2], number))
    return unique(deps)


def parse_gradle_build(text: str) -> list[Dependency]:
    """build.gradle(.kts): coordenadas literais ``"grupo:artefato:versão"``."""
    deps: list[Dependency] = []
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith(("//", "*", "/*")):
            continue
        for match in list(_GRADLE_COORD.finditer(line)) + list(_GRADLE_MAP.finditer(line)):
            group, artifact, version = match.groups()
            if is_exact(version):
                deps.append(Dependency(f"{group}:{artifact}", version, number))
    return unique(deps)
