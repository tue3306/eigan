"""Registro técnico em arquivo (``logs/eigan.log`` no diretório de dados)."""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler

from . import paths

_configured = False


def setup_logging(level: int = logging.INFO) -> None:
    """Grava o log técnico em arquivo rotativo; o terminal fica só com a saída da CLI."""
    global _configured
    if _configured:
        return
    _configured = True
    root = logging.getLogger("eigan")
    root.setLevel(level)
    root.propagate = False
    try:
        path = paths.log_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        handler: logging.Handler = RotatingFileHandler(
            path, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
        )
    except OSError:
        handler = logging.NullHandler()
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S")
    )
    root.addHandler(handler)
