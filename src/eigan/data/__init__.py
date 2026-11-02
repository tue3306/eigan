"""Dados embarcados (offline): catálogos e bases usados pelas checagens.

Os arquivos ficam ao lado deste módulo e vão junto no executável. Cada arquivo
de terceiros traz a origem e a licença em ``FONTES.md``.

Três catálogos (``ATUALIZAVEIS``) podem ser renovados pelo comando ``eigan
atualizar``, só quando o usuário pede. A cópia baixada fica em
``<dados do EIGAN>/dados/<nome>.json`` e vale mais que a embarcada apenas se for
legível, tiver a estrutura esperada (inclusive dentro dos itens), não for mais antiga
que a embarcada nem tiver data no futuro; assim, trocar o executável por uma versão
mais nova nunca deixa dados velhos presos.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, date, datetime, timedelta
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

from . import formato

log = logging.getLogger(__name__)

#: catálogo -> (campo com a data, campos obrigatórios) da cópia baixada
ATUALIZAVEIS: dict[str, tuple[str, tuple[str, ...]]] = {
    "kev.json": ("publicado", ("itens",)),
    "web_retire.json": ("atualizado", ("bibliotecas",)),
    "dns_sufixos.json": ("atualizado", ("icann", "privado")),
}
#: dias de folga entre o relógio e a data de um catálogo (fuso e publicação no mesmo dia)
FOLGA_DATA_FUTURA_DIAS = 1
#: acima disto a cópia baixada é ignorada (arquivo suspeito)
MAX_OVERLAY_BYTES = 64 * 1024 * 1024


def overlay_dir() -> Path:
    """Pasta das cópias baixadas (não é criada aqui)."""
    from ..core import paths

    return paths.data_dir() / "dados"


def data_do_catalogo(name: str, data: Any) -> str:
    """Data (``AAAA-MM-DD``) do conteúdo de um catálogo atualizável; vazio se não houver."""
    campo = ATUALIZAVEIS.get(name, ("atualizado", ()))[0]
    if not isinstance(data, dict):
        return ""
    texto = str(data.get(campo) or "")[:10]
    ok = (
        len(texto) == 10
        and texto[4] == "-"
        and texto[7] == "-"
        and texto.replace("-", "").isdigit()
    )
    return texto if ok else ""


def hoje() -> date:
    """O dia de hoje em UTC (separado para os testes fixarem o relógio)."""
    return datetime.now(UTC).date()


def data_futura(texto: str, referencia: date | None = None) -> bool:
    """``AAAA-MM-DD`` depois do dia de referência (padrão: hoje) mais a folga.

    Datas ilegíveis não contam como futuras (quem chama já as trata como inválidas).
    """
    try:
        dia = referencia or hoje()
        return date.fromisoformat(texto) > dia + timedelta(days=FOLGA_DATA_FUTURA_DIAS)
    except ValueError:
        return False


def estrutura_valida(name: str, data: Any) -> bool:
    if name not in ATUALIZAVEIS or not isinstance(data, dict):
        return False
    return (
        all(
            isinstance(data.get(campo), (dict, list)) and data[campo]
            for campo in ATUALIZAVEIS[name][1]
        )
        and formato.problema(name, data) is None
    )


def _embarcado(name: str) -> Any:
    ref = resources.files(__name__).joinpath(name)
    return json.loads(ref.read_text(encoding="utf-8"))


def _baixado(name: str, embarcado: Any) -> Any | None:
    """A cópia baixada, se existir e valer mais que a embarcada; ``None`` caso contrário."""
    try:
        caminho = overlay_dir() / name
        if not caminho.is_file():
            return None
        if caminho.stat().st_size > MAX_OVERLAY_BYTES:
            raise ValueError("arquivo grande demais")
        dados = json.loads(caminho.read_text(encoding="utf-8"))
        if not estrutura_valida(name, dados):
            raise ValueError(formato.problema(name, dados) or "estrutura inesperada")
        nova, base = data_do_catalogo(name, dados), data_do_catalogo(name, embarcado)
        if not nova:
            raise ValueError("sem data válida")
        if data_futura(nova):
            raise ValueError(f"data {nova} no futuro")
    except (OSError, ValueError, RecursionError, MemoryError) as exc:
        log.warning("Dados baixados de %s ignorados (%s); usando os embarcados.", name, exc)
        return None
    # Mais antiga que a embarcada: o executável foi atualizado depois do download.
    return dados if nova >= base else None


@lru_cache(maxsize=64)
def _resolver(name: str) -> tuple[Any, str]:
    embarcado = _embarcado(name)
    if name in ATUALIZAVEIS:
        baixado = _baixado(name, embarcado)
        if baixado is not None:
            return baixado, "baixado"
    return embarcado, "embarcado"


def load_json(name: str) -> Any:
    """Carrega ``eigan/data/<name>`` (JSON) uma única vez, preferindo a cópia baixada válida."""
    return _resolver(name)[0]


def origem(name: str) -> str:
    """``"baixado"`` ou ``"embarcado"``: de onde vêm os dados que ``load_json`` entrega."""
    return _resolver(name)[1]


def load_embedded_json(name: str) -> Any:
    """Sempre o arquivo embarcado, ignorando qualquer cópia baixada."""
    return _embarcado(name)


def limpar_cache() -> None:
    """Esquece o que foi carregado (use depois de baixar ou apagar uma cópia)."""
    _resolver.cache_clear()
    load_text.cache_clear()


@lru_cache(maxsize=64)
def load_text(name: str) -> str:
    return resources.files(__name__).joinpath(name).read_text(encoding="utf-8")


def exists(name: str) -> bool:
    return resources.files(__name__).joinpath(name).is_file()
