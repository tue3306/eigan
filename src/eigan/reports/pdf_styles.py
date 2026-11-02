"""Cores e estilos do PDF — os mesmos tokens do painel e do relatório HTML."""

from __future__ import annotations

from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_RIGHT
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import TableStyle

MARGIN = 18 * mm
INDENT = 8 * mm

INK = colors.HexColor("#0f172a")
INK_2 = colors.HexColor("#334155")
MUTED = colors.HexColor("#5b6b82")
LINE = colors.HexColor("#e2e8f0")
TINT = colors.HexColor("#f8fafc")
BRAND = colors.HexColor("#1f4fd1")
BRAND_INK = colors.HexColor("#1a3fa8")
WHITE = colors.HexColor("#ffffff")
INK_HEX = "#0f172a"
MUTED_HEX = "#5b6b82"
SEVERITY_FG = {
    "critical": "#b42318",
    "high": "#c4320a",
    "medium": "#b54708",
    "low": "#175cd3",
    "info": "#475467",
}
SEVERITY_BG = {
    "critical": "#fef3f2",
    "high": "#fff4ed",
    "medium": "#fffaeb",
    "low": "#eff8ff",
    "info": "#f2f4f7",
}
#: faixa de prioridade: (cor do texto, fundo) — P1 cheio, como no painel
BAND_COLORS = {
    "p1": ("#ffffff", "#b42318"),
    "p2": ("#c4320a", "#fff4ed"),
    "p3": ("#b54708", "#fffaeb"),
    "p4": ("#334155", "#f1f5f9"),
    "info": ("#5b6b82", "#ffffff"),
}
#: cor da faixa quando aparece só como texto (sem fundo)
BAND_TEXT = {"p1": "#b42318", "p2": "#c4320a", "p3": "#b54708", "p4": "#334155", "info": "#5b6b82"}
GRADE_COLOR = {
    "a": "#067647",
    "b": "#3b7c0f",
    "c": "#b54708",
    "d": "#c4320a",
    "f": "#b42318",
    "none": "#5b6b82",
}
GRADE_BG = {
    "a": "#ecfdf3",
    "b": "#f3fee7",
    "c": "#fffaeb",
    "d": "#fff4ed",
    "f": "#fef3f2",
    "none": "#f1f5f9",
}
KEV_HEX = "#7a271a"
QUICK_HEX = "#067647"


def styles() -> dict[str, ParagraphStyle]:
    """Estilos de parágrafo do relatório (Helvetica; código em Courier)."""
    base = ParagraphStyle(
        "corpo", fontName="Helvetica", fontSize=9.5, leading=13.5, textColor=INK_2
    )

    def style(name: str, **kwargs: Any) -> ParagraphStyle:
        return ParagraphStyle(name, parent=base, **kwargs)

    def heading(name: str, size: float, leading: float, **kwargs: Any) -> ParagraphStyle:
        return style(
            name,
            fontName="Helvetica-Bold",
            fontSize=size,
            leading=leading,
            textColor=INK,
            keepWithNext=1,
            **kwargs,
        )

    return {
        "body": base,
        "ink": style("ink", textColor=INK),
        "small": style("small", fontSize=8, leading=10.5, textColor=MUTED),
        "brand": style(
            "brand", fontName="Helvetica-Bold", fontSize=12, leading=14, textColor=BRAND_INK
        ),
        "title": style("title", fontName="Helvetica-Bold", fontSize=20, leading=24, textColor=INK),
        "target": style(
            "target", fontName="Helvetica-Bold", fontSize=12, leading=15, spaceBefore=4
        ),
        "h1": heading("h1", 14, 18, spaceBefore=4, spaceAfter=6),
        "h2": heading("h2", 11, 14.5, spaceBefore=10, spaceAfter=2),
        "h3": heading("h3", 9.5, 13, leftIndent=INDENT, spaceBefore=7, spaceAfter=1),
        "h3_flush": heading("h3_flush", 9.5, 13, spaceBefore=8, spaceAfter=2),
        "indent": style("indent", leftIndent=INDENT),
        "band": style("band", leftIndent=INDENT, keepWithNext=1),
        "indent_small": style(
            "indent_small", leftIndent=INDENT, fontSize=8, leading=10.5, textColor=MUTED
        ),
        "headline": style(
            "headline", fontName="Helvetica-Bold", fontSize=13, leading=17, textColor=INK
        ),
        "grade": style(
            "grade", fontName="Helvetica-Bold", fontSize=40, leading=44, alignment=TA_CENTER
        ),
        "score": style("score", fontSize=12, leading=15, textColor=INK, alignment=TA_CENTER),
        "grade_label": style(
            "grade_label", fontName="Helvetica-Bold", fontSize=9.5, leading=12, alignment=TA_CENTER
        ),
        "count": style("count", fontName="Helvetica-Bold", fontSize=16, leading=19),
        "count_label": style("count_label", fontSize=7.5, leading=9.5, textColor=MUTED),
        "cell": style("cell", fontSize=8.5, leading=11, textColor=INK),
        "cell_right": style(
            "cell_right", fontSize=8.5, leading=11, textColor=INK, alignment=TA_RIGHT
        ),
        "cell_muted": style("cell_muted", fontSize=8.5, leading=11, textColor=MUTED),
        "cell_head": style(
            "cell_head", fontName="Helvetica-Bold", fontSize=7.5, leading=10, textColor=MUTED
        ),
        "chip": style(
            "chip", fontName="Helvetica-Bold", fontSize=8, leading=10, alignment=TA_CENTER
        ),
        "fix_label": style(
            "fix_label",
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10.5,
            textColor=INK_2,
            leftIndent=INDENT,
            spaceBefore=6,
            spaceAfter=2,
            keepWithNext=1,
        ),
        "code": style("code", fontName="Courier", fontSize=7.5, leading=9.4, textColor=INK),
        "footnote": style("footnote", fontSize=8, leading=11, textColor=MUTED),
        "footnote_strong": style("footnote_strong", fontSize=8, leading=11, textColor=INK_2),
    }


def grid_style() -> TableStyle:
    """Tabela de dados: cabeçalho com linha mais forte e linhas finas entre as linhas."""
    return TableStyle(
        [
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LINEBELOW", (0, 0), (-1, 0), 0.75, MUTED),
            ("LINEBELOW", (0, 1), (-1, -1), 0.4, LINE),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]
    )


def plain_style(**paddings: float) -> TableStyle:
    """Tabela só para alinhar (sem linhas), com recuos zerados ou os informados."""
    commands: list[Any] = [("VALIGN", (0, 0), (-1, -1), "TOP")]
    for side in ("LEFT", "RIGHT", "TOP", "BOTTOM"):
        commands.append((f"{side}PADDING", (0, 0), (-1, -1), paddings.get(side.lower(), 0)))
    return TableStyle(commands)
