"""Relatório executivo em PDF (reportlab): veredito, resumo, plano e principais achados.

As regras de texto ficam em :mod:`.pdf_text` (só a fonte padrão cp1252 e toda marcação
escapada); as partes do documento, em :mod:`.pdf_front` (capa, veredito, resumo,
cenários e plano) e :mod:`.pdf_back` (achados, KEV, comparação, pontos fortes,
conformidade e fecho).
"""

from __future__ import annotations

import io
from typing import Any

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.platypus import BaseDocTemplate, Flowable, Frame, PageTemplate

from ..core.models import ScanResult
from . import pdf_back, pdf_front
from .common import clip
from .pdf_blocks import Kit
from .pdf_canvas import footer_canvas
from .pdf_styles import MARGIN
from .pdf_text import pdf_text
from .view import build_view


def render(result: ScanResult) -> bytes:
    """PDF executivo do resultado (calcula a análise se ainda não existir)."""
    view = build_view(result)
    meta = view["meta"]
    buffer = io.BytesIO()
    doc = BaseDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=MARGIN,
        bottomMargin=MARGIN + 4 * mm,
        title=pdf_text(f"Relatório de auditoria de segurança — {clip(meta['target'], 120)[0]}"),
        author=pdf_text(f"EIGAN {meta['generator']}"),
        subject="Auditoria de segurança (análise local por regras, sem IA)",
        creator=pdf_text(f"EIGAN {meta['generator']}"),
        lang="pt-BR",
        displayDocTitle=1,
    )
    # Sem recuo interno no quadro: as tabelas usam exatamente a largura útil da página.
    frame = Frame(
        doc.leftMargin,
        doc.bottomMargin,
        doc.width,
        doc.height,
        id="corpo",
        leftPadding=0,
        rightPadding=0,
        topPadding=0,
        bottomPadding=0,
    )
    doc.addPageTemplates([PageTemplate(id="pagina", frames=[frame])])
    footer = pdf_text(f"EIGAN {meta['generator']} · {clip(meta['target'], 80)[0]}")
    doc.build(build_story(view, doc.width), canvasmaker=footer_canvas(footer))
    return buffer.getvalue()


def build_story(view: dict[str, Any], width: float) -> list[Flowable]:
    """Sequência de blocos do PDF, na ordem de leitura do relatório."""
    kit = Kit(width)
    pdf_front.cover(view, kit)
    pdf_front.verdict(view, kit)
    pdf_front.summary(view, kit)
    pdf_front.scenarios(view, kit)
    pdf_front.plan(view, kit)
    pdf_back.top_findings(view, kit)
    pdf_back.kev(view, kit)
    pdf_back.comparison(view, kit)
    if view["verdict"]["evaluated"]:
        pdf_back.strengths(view, kit)
        pdf_back.compliance(view, kit)
    pdf_back.unfinished(view, kit)
    pdf_back.closing(view, kit)
    return kit.flow
