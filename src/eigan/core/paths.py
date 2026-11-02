"""Onde o EIGAN guarda dados (histórico, configurações, relatórios e logs).

Ordem de escolha:

1. ``EIGAN_HOME`` (variável de ambiente), se definida;
2. modo portátil: uma pasta ``EIGAN-dados`` ao lado do executável (útil em pendrive);
3. padrão do sistema — Windows: ``%LOCALAPPDATA%\\EIGAN``; Linux/macOS:
   ``$XDG_DATA_HOME/eigan`` ou ``~/.local/share/eigan``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

PORTABLE_DIRNAME = "EIGAN-dados"


def _executable_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[3]


def data_dir() -> Path:
    override = os.environ.get("EIGAN_HOME")
    if override:
        base = Path(override).expanduser()
    else:
        portable = _executable_dir() / PORTABLE_DIRNAME
        if portable.is_dir():
            base = portable
        elif os.name == "nt":
            root = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
            base = Path(root) / "EIGAN"
        else:
            root = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
            base = Path(root) / "eigan"
    base.mkdir(parents=True, exist_ok=True)
    return base


def reports_dir() -> Path:
    path = data_dir() / "relatorios"
    path.mkdir(parents=True, exist_ok=True)
    return path


def cache_dir() -> Path:
    path = data_dir() / "cache"
    path.mkdir(parents=True, exist_ok=True)
    return path


def db_path() -> Path:
    return data_dir() / "eigan.db"


def settings_path() -> Path:
    return data_dir() / "configuracoes.json"


def log_path() -> Path:
    path = data_dir() / "logs"
    path.mkdir(parents=True, exist_ok=True)
    return path / "eigan.log"
