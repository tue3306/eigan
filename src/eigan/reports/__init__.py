"""Relatórios: HTML, PDF, JSON, SARIF e CSV.

Uso típico::

    from eigan.reports import write_reports

    arquivos = write_reports(resultado)                    # todos, na pasta padrão
    arquivos = write_reports(resultado, ["html", "pdf"])  # só alguns

Cada ``render_*`` devolve o conteúdo em memória (o painel usa para download). Se o
resultado ainda não tiver análise, ela é calculada antes (``intel.analysis.analyze``).
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Callable, Iterable
from datetime import datetime
from pathlib import Path

from ..core.models import ScanResult
from ..core.paths import reports_dir
from .common import ensure_analysis, local_moment, slugify, target_slug
from .exports import render_csv, render_json
from .sarif import render_sarif

FORMATS = ("html", "pdf", "json", "sarif", "csv")
FILENAMES = {
    "html": "eigan-relatorio.html",
    "pdf": "eigan-relatorio.pdf",
    "json": "eigan-resultado.json",
    "sarif": "eigan-resultado.sarif",
    "csv": "eigan-achados.csv",
}

__all__ = [
    "FILENAMES",
    "FORMATS",
    "default_outdir",
    "render_csv",
    "render_html",
    "render_json",
    "render_pdf",
    "render_sarif",
    "write_reports",
]


def render_html(result: ScanResult) -> str:
    """Relatório completo em um único HTML (sem JavaScript nem recursos externos)."""
    from .html import render

    return render(result)


def render_pdf(result: ScanResult) -> bytes:
    """Relatório executivo em PDF (A4)."""
    from .pdf import render

    return render(result)


def default_outdir(result: ScanResult) -> Path:
    """``<relatórios>/AAAA-MM-DD_HHMM-<alvo>-<id>`` (data de início, no fuso local)."""
    moment = local_moment(result.started_at) or datetime.now().astimezone()
    safe_id = slugify(result.id, limit=64, fallback="auditoria")
    name = f"{moment:%Y-%m-%d_%H%M}-{target_slug(result.target)}-{safe_id}"
    return reports_dir() / name


def write_reports(
    result: ScanResult,
    formats: Iterable[str] | str | None = None,
    outdir: str | os.PathLike[str] | None = None,
) -> dict[str, Path]:
    """Grava os relatórios pedidos e devolve ``{formato: caminho}``.

    ``formats`` aceita uma lista (``["html", "pdf"]``) ou texto (``"html,pdf"``);
    ``None`` grava todos. Formato desconhecido gera ``ValueError`` antes de gravar.
    """
    chosen = _formats(formats)
    ensure_analysis(result)
    renderers: dict[str, Callable[[ScanResult], str | bytes]] = {
        "html": render_html,
        "pdf": render_pdf,
        "json": render_json,
        "sarif": render_sarif,
        "csv": render_csv,
    }
    contents = {name: renderers[name](result) for name in chosen}
    folder = Path(outdir) if outdir is not None else default_outdir(result)
    folder.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}
    for name, content in contents.items():
        data = content.encode("utf-8") if isinstance(content, str) else content
        written[name] = _write_atomic(folder / FILENAMES[name], data)
    return written


def _formats(formats: Iterable[str] | str | None) -> list[str]:
    if formats is None:
        return list(FORMATS)
    items = formats.split(",") if isinstance(formats, str) else list(formats)
    chosen: list[str] = []
    for item in items:
        name = str(item).strip().lower()
        if not name:
            continue
        if name not in FORMATS:
            raise ValueError(
                f"Formato de relatório desconhecido: {item!r}. Use html, pdf, json, sarif ou csv."
            )
        if name not in chosen:
            chosen.append(name)
    if not chosen:
        raise ValueError(
            "Nenhum formato de relatório informado. Use html, pdf, json, sarif ou csv."
        )
    return chosen


def _write_atomic(path: Path, data: bytes) -> Path:
    """Grava num arquivo temporário e troca no fim: nunca fica relatório pela metade."""
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temp = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)
    return path
