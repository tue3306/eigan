"""Leitores de dependências do ecossistema npm (package-lock, yarn, pnpm, package.json)."""

from __future__ import annotations

import json
import re
from typing import Any

from .manifests import Dependency, unique
from .versioning import is_exact

_JSON_KEY = re.compile(r'^\s*"((?:[^"\\]|\\.)+)"\s*:\s*\{')
_PNPM_KEY = re.compile(r"""^  ['"]?/?((?:@[^/@\s'"]+/)?[^/@\s'"()]+)[@/](\d[^:'"()_\s]*)""")
_YARN_VERSION = re.compile(r"""^\s+version:?\s+"?([^"\s]+)"?\s*$""")
#: protocolos de pacotes que não vêm do registro npm (pasta local, git, tarball...)
_NON_REGISTRY = (
    "file:",
    "link:",
    "portal:",
    "workspace:",
    "exec:",
    "git",
    "github:",
    "gitlab:",
    "bitbucket:",
    "http:",
    "https:",
)


def json_key_lines(text: str) -> dict[str, int]:
    """Primeira linha de cada chave de objeto JSON (``"chave": {``) — uma passada só."""
    lines: dict[str, int] = {}
    for number, line in enumerate(text.splitlines(), start=1):
        match = _JSON_KEY.match(line)
        if match:
            lines.setdefault(match.group(1), number)
    return lines


def _split_alias(name: str, version: str) -> tuple[str, str]:
    """``"npm:pacote@1.2.3"`` (alias do npm) vira ``("pacote", "1.2.3")``."""
    if version.startswith("npm:"):
        target = version[4:]
        at = target.rfind("@")
        if at > 0:
            return target[:at], target[at + 1 :]
    return name, version


def _from_registry(meta: dict[str, Any], version: str) -> bool:
    """Versão publicada no registro (não pasta local, link, git ou tarball avulso)."""
    resolved = str(meta.get("resolved") or "")
    if resolved and not resolved.startswith(("http://", "https://")):
        return False
    if "codeload.github.com/" in resolved:  # tarball de um repositório, não do registro
        return False
    return bool(version) and version[0].isdigit()


def parse_package_lock(text: str) -> list[Dependency]:
    """package-lock.json / npm-shrinkwrap.json (formatos 1, 2 e 3)."""
    data = json.loads(text)
    if not isinstance(data, dict):
        return []
    lines = json_key_lines(text)
    deps: list[Dependency] = []
    packages = data.get("packages")
    if isinstance(packages, dict) and any("node_modules/" in key for key in packages):
        for key, meta in packages.items():
            if "node_modules/" not in key or not isinstance(meta, dict) or meta.get("link"):
                continue  # raiz do projeto, workspaces locais e links não são pacotes do registro
            name = str(meta.get("name") or key.rsplit("node_modules/", 1)[-1])
            name, version = _split_alias(name, str(meta.get("version") or ""))
            if _from_registry(meta, version):
                deps.append(Dependency(name, version, lines.get(key, 0)))
        return unique(deps)
    _walk_v1(data.get("dependencies"), lines, deps, depth=0)
    return unique(deps)


def _walk_v1(tree: Any, lines: dict[str, int], out: list[Dependency], depth: int) -> None:
    if not isinstance(tree, dict) or depth > 64:
        return
    for name, meta in tree.items():
        if not isinstance(meta, dict):
            continue
        real, version = _split_alias(str(name), str(meta.get("version") or ""))
        if _from_registry(meta, version):
            out.append(Dependency(real, version, lines.get(str(name), 0)))
        _walk_v1(meta.get("dependencies"), lines, out, depth + 1)


def _yarn_name(header: str) -> str:
    """Nome do pacote no cabeçalho de uma entrada do yarn.lock (``""`` se não é do registro)."""
    first = header.rstrip(":").split(",")[0].strip().strip('"')
    if "@npm:" in first:
        alias, target = first.split("@npm:", 1)
        at = target.find("@", 1)
        return target[:at] if at > 0 else alias
    at = first.find("@", 1)
    if at <= 0:
        return first
    if first[at + 1 :].startswith(_NON_REGISTRY):
        return ""
    return first[:at]


def parse_yarn_lock(text: str) -> list[Dependency]:
    """yarn.lock nos formatos clássico (v1) e Berry (v2+)."""
    deps: list[Dependency] = []
    name = ""
    header_line = 0
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            name = "" if line.startswith("__metadata") else _yarn_name(line)
            header_line = number
            continue
        if not name:
            continue
        match = _YARN_VERSION.match(line)
        if match:
            version = match.group(1)
            if "use.local" not in version:
                deps.append(Dependency(name, version, header_line))
            name = ""
    return unique(deps)


def parse_pnpm_lock(text: str) -> list[Dependency]:
    """pnpm-lock.yaml (formatos 5, 6 e 9): chaves das seções packages/snapshots."""
    deps: list[Dependency] = []
    in_section = False
    for number, line in enumerate(text.splitlines(), start=1):
        if line and not line[0].isspace():
            in_section = line.split(":", 1)[0].strip() in ("packages", "snapshots")
            continue
        if not in_section:
            continue
        match = _PNPM_KEY.match(line)
        if match:
            deps.append(Dependency(match.group(1), match.group(2), number))
    return unique(deps)


def _line_in_section(rows: list[str], section: str, name: str) -> int:
    """Linha de ``"nome"`` dentro do bloco ``"seção": {`` (0 se não achar)."""
    header = f'"{section}"'
    start = next((i for i, row in enumerate(rows) if row.lstrip().startswith(header)), -1)
    if start < 0:
        return 0
    needle = f'"{name}"'
    for index in range(start + 1, len(rows)):
        if rows[index].lstrip().startswith(needle):
            return index + 1
        if rows[index].strip().startswith("}"):
            break
    return 0


def parse_package_json(text: str) -> list[Dependency]:
    """package.json: só versões exatas (sem ^, ~, >=...) — usado quando não há lockfile."""
    data = json.loads(text)
    if not isinstance(data, dict):
        return []
    rows = text.splitlines()
    deps: list[Dependency] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            real, version = _split_alias(str(name), str(spec))
            version = version.strip().lstrip("=").lstrip("v").strip()
            if is_exact(version):
                deps.append(Dependency(real, version, _line_in_section(rows, section, str(name))))
    return unique(deps)
