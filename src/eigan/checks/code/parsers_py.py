"""Leitores de dependências Python (requirements, Pipfile.lock, poetry.lock, uv.lock)."""

from __future__ import annotations

import json
import re
import tomllib

from .manifests import Dependency, unique
from .parsers_js import json_key_lines

#: ``pacote[extras]==1.2.3`` até o fim do requisito (``==1.2.*`` é faixa e não casa)
_REQ = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\s*\[[^\]]*\])?\s*===?\s*"
    r"([A-Za-z0-9][A-Za-z0-9.!+_-]*)\s*(?:$|[,\\]|--)"
)
_MAX_LINE = 2000
_TOML_NAME = re.compile(r'^\s*name\s*=\s*"([^"]+)"')


def parse_requirements(text: str) -> list[Dependency]:
    """requirements*.txt: só pacotes fixados com ``==`` (ou ``===``)."""
    deps: list[Dependency] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        if len(raw) > _MAX_LINE:
            continue  # linha absurda (arquivo corrompido ou hostil)
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("#", "-", "git+", "http:", "https:", "file:", ".")):
            continue
        line = line.split(";", 1)[0]  # marcadores de ambiente
        match = _REQ.match(line)
        if match:
            deps.append(Dependency(match.group(1), match.group(2), number))
    return unique(deps)


def parse_pipfile_lock(text: str) -> list[Dependency]:
    """Pipfile.lock (seções default e develop)."""
    data = json.loads(text)
    if not isinstance(data, dict):
        return []
    lines = json_key_lines(text)
    deps: list[Dependency] = []
    for section in ("default", "develop"):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, meta in block.items():
            if not isinstance(meta, dict):
                continue
            version = str(meta.get("version") or "").lstrip("=").strip()
            if version:
                deps.append(Dependency(str(name), version, lines.get(str(name), 0)))
    return unique(deps)


def toml_name_lines(text: str) -> dict[str, int]:
    """Linha do ``name = "..."`` de cada tabela ``[[package]]``."""
    lines: dict[str, int] = {}
    previous = ""
    for number, line in enumerate(text.splitlines(), start=1):
        if previous.strip() == "[[package]]":
            match = _TOML_NAME.match(line)
            if match:
                lines.setdefault(match.group(1), number)
        previous = line
    return lines


#: chaves do ``source`` do uv.lock e tipos do ``[package.source]`` do poetry.lock
#: que não são um índice de pacotes
_UV_LOCAL = frozenset({"editable", "virtual", "path", "directory", "git", "url"})
_POETRY_LOCAL = frozenset({"directory", "file", "git", "url"})


def _local_source(source: object) -> bool:
    """Pacote que não veio de um índice de pacotes (PyPI ou espelho)."""
    if not isinstance(source, dict):
        return False
    if "type" in source:  # poetry.lock: um índice privado também tem ``url``
        return str(source["type"]) in _POETRY_LOCAL
    return bool(_UV_LOCAL & set(source))


def parse_toml_lock(text: str) -> list[Dependency]:
    """poetry.lock e uv.lock: tabelas ``[[package]]`` com ``name`` e ``version``."""
    data = tomllib.loads(text)
    lines = toml_name_lines(text)
    deps: list[Dependency] = []
    for entry in data.get("package", []) or []:
        if not isinstance(entry, dict):
            continue
        if _local_source(entry.get("source")):
            continue  # o próprio projeto, pastas locais, git ou URL avulsa
        name, version = str(entry.get("name") or ""), str(entry.get("version") or "")
        if name and version:
            deps.append(Dependency(name, version, lines.get(name, 0)))
    return unique(deps)
