"""Dados embarcados (offline): catálogos e bases usados pelas checagens.

Os arquivos ficam ao lado deste módulo e vão junto no executável. Cada arquivo
de terceiros traz a origem e a licença em ``FONTES.md``.
"""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from typing import Any


@lru_cache(maxsize=64)
def load_json(name: str) -> Any:
    """Carrega ``eigan/data/<name>`` (JSON) uma única vez."""
    ref = resources.files(__name__).joinpath(name)
    return json.loads(ref.read_text(encoding="utf-8"))


@lru_cache(maxsize=64)
def load_text(name: str) -> str:
    return resources.files(__name__).joinpath(name).read_text(encoding="utf-8")


def exists(name: str) -> bool:
    return resources.files(__name__).joinpath(name).is_file()
