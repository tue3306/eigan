"""Relatório HTML autocontido: um arquivo só, sem JavaScript e sem recursos externos.

O modelo (``templates/report.html.j2``) recebe o modelo de apresentação de
:mod:`eigan.reports.view` e escapa todo texto dinâmico (``autoescape``). O emblema é
um arquivo do próprio pacote (``templates/emblem.svg``) incluído pelo modelo, nunca
texto do alvo. A política de conteúdo (CSP) do arquivo bloqueia scripts, fontes e
imagens de fora.
"""

from __future__ import annotations

from functools import lru_cache
from importlib import resources
from pathlib import Path

from jinja2 import BaseLoader, Environment, FileSystemLoader, FunctionLoader, StrictUndefined

from ..core.models import ScanResult
from .view import build_view

TEMPLATE = "report.html.j2"


def render(result: ScanResult) -> str:
    """HTML completo do relatório (calcula a análise se ainda não existir)."""
    template = _environment().get_template(TEMPLATE)
    return template.render(**build_view(result))


@lru_cache(maxsize=1)
def _environment() -> Environment:
    return Environment(
        loader=_loader(),
        autoescape=True,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )


def _loader() -> BaseLoader:
    """Carrega os modelos do pacote, inclusive dentro do executável (PyInstaller)."""
    root = resources.files("eigan.reports").joinpath("templates")
    if isinstance(root, Path) and root.is_dir():
        return FileSystemLoader(str(root))

    # Instalação compactada (zip): lê pelo importlib.resources, sem pasta no disco.
    def load(name: str) -> str | None:
        node = root.joinpath(name)
        return node.read_text(encoding="utf-8") if node.is_file() else None

    return FunctionLoader(load)
