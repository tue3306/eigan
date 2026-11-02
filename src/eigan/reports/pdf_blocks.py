"""Blocos reutilizáveis do PDF: seção, aviso, passos numerados, código e chips.

Tudo que entra num ``Paragraph`` aqui já chega escapado por
:func:`~eigan.reports.pdf_text.markup` (ou é texto fixo deste pacote).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    CondPageBreak,
    Flowable,
    ListFlowable,
    Paragraph,
    Preformatted,
    Table,
    TableStyle,
)
from reportlab.platypus.flowables import HRFlowable

from ..core import fmt
from .common import clip
from .pdf_styles import (
    BAND_COLORS,
    BAND_TEXT,
    INDENT,
    INK_2,
    LINE,
    SEVERITY_BG,
    SEVERITY_FG,
    TINT,
    styles,
)
from .pdf_text import markup, pdf_text

MAX_CODE_LINES = 25  # linhas do exemplo original
MAX_CODE_ROWS = 40  # linhas desenhadas (depois de quebrar as longas): cabe numa página
MAX_CODE_LINE = 400


@dataclass
class Kit:
    """Largura útil, estilos e a lista de blocos do PDF em construção."""

    width: float
    s: dict[str, ParagraphStyle] = field(default_factory=styles)
    flow: list[Flowable] = field(default_factory=list)

    def add(self, *items: Flowable) -> None:
        self.flow.extend(items)

    def para(self, text: str, style: str = "body") -> Paragraph:
        """Parágrafo com marcação já segura (texto escapado ou fixo deste pacote)."""
        return Paragraph(text, self.s[style])

    def text(self, value: object, style: str = "body", limit: int | None = None) -> Paragraph:
        """Parágrafo de texto dinâmico: escapado e seguro para a fonte padrão."""
        return Paragraph(markup(value, limit), self.s[style])

    def section(self, title: str) -> None:
        """Título de seção com uma linha fina acima (sem cartões nem sombras)."""
        rule = HRFlowable(width="100%", thickness=0.6, color=LINE, spaceBefore=6 * mm, spaceAfter=7)
        # A linha acompanha o título (e o título, o primeiro bloco da seção): ela nunca
        # fica sozinha no pé da página.
        rule.keepWithNext = 1
        self.add(CondPageBreak(45 * mm), rule, self.text(title, "h1"))

    def notice(self, text: str) -> Table:
        """Aviso em destaque (ex.: auditoria cancelada, resultado parcial)."""
        box = Table([[self.text(text, "ink")]], colWidths=[self.width])
        box.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(SEVERITY_BG["medium"])),
                    ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#fedf89")),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        box.spaceBefore = 8
        return box

    def count_row(self, items: list[tuple[int, str, str]]) -> Table:
        """Linha de números grandes com o rótulo embaixo: ``(número, rótulo, cor)``."""
        cells = [
            [self.para(colored(str(n), color), "count"), self.text(label, "count_label")]
            for n, label, color in items
        ]
        table = Table([cells], colWidths=[self.width / len(cells)] * len(cells))
        table.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LINEABOVE", (0, 0), (-1, 0), 0.6, LINE),
                    ("LINEBELOW", (0, 0), (-1, 0), 0.6, LINE),
                    ("LINEBEFORE", (1, 0), (-1, 0), 0.6, LINE),
                    ("LEFTPADDING", (0, 0), (0, 0), 0),
                    ("LEFTPADDING", (1, 0), (-1, 0), 9),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        return table

    def steps(self, steps: list[str]) -> ListFlowable:
        """Passos numerados, alinhados ao texto recuado do problema."""
        return ListFlowable(
            [self.text(step) for step in steps],
            bulletType="1",
            bulletFormat="%s.",
            leftIndent=INDENT + 6 * mm,
            bulletDedent=6 * mm,
            bulletFontName="Helvetica",
            bulletFontSize=9,
            bulletColor=INK_2,
        )

    def code(self, code: str) -> Table:
        """Trecho de código em Courier, com altura limitada para caber numa página."""
        style = self.s["code"]
        width = self.width - INDENT
        padding = 6
        per_line = max(20, int((width - 2 * padding) / (0.6 * style.fontSize)))
        block = Preformatted("\n".join(code_rows(code, per_line)), style)
        table = Table([[block]], colWidths=[width], hAlign="RIGHT")
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), TINT),
                    ("BOX", (0, 0), (-1, -1), 0.5, LINE),
                    ("LEFTPADDING", (0, 0), (-1, -1), padding),
                    ("RIGHTPADDING", (0, 0), (-1, -1), padding),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        return table


def code_rows(code: str, per_line: int) -> list[str]:
    """Linhas desenhadas de um exemplo: quebra as longas com "» " e corta o excesso."""
    source = pdf_text(code).split("\n")
    rows: list[str] = []
    for index, line in enumerate(source):
        pieces = wrap_line(clip(line, MAX_CODE_LINE)[0], per_line)
        if index >= MAX_CODE_LINES or len(rows) + len(pieces) > MAX_CODE_ROWS:
            hidden = len(source) - index
            rows.append(f"... mais {fmt.plural(hidden, 'linha', 'linhas')} no relatório HTML")
            break
        rows.extend(pieces)
    return rows


def wrap_line(line: str, width: int) -> list[str]:
    """Quebra uma linha de código em pedaços de ``width`` caracteres (Courier é monoespaçada)."""
    if len(line) <= width:
        return [line]
    pieces = [line[:width]]
    step = max(1, width - 2)
    rest = line[width:]
    while rest:
        pieces.append("» " + rest[:step])
        rest = rest[step:]
    return pieces


def colored(text: str, color: str, *, bold: bool = False) -> str:
    """Trecho colorido de marcação; ``text`` já precisa estar escapado."""
    body = f"<b>{text}</b>" if bold else text
    return f'<font color="{color}">{body}</font>'


def severity_markup(severity: dict[str, str]) -> str:
    """Rótulo de severidade na cor da severidade (para parágrafos e células)."""
    value = severity.get("value", "info")
    return colored(markup(severity.get("label", "")), SEVERITY_FG.get(value, SEVERITY_FG["info"]))


def band_markup(band: dict[str, str]) -> str:
    """Faixa de prioridade (P1...P4) em negrito, na cor da faixa."""
    color = BAND_TEXT.get(band.get("css", "info"), BAND_TEXT["info"])
    return colored(markup(band.get("value", "")), color, bold=True)


def band_cell(band: dict[str, str], style: ParagraphStyle) -> tuple[Paragraph, Any]:
    """Célula de faixa com fundo (P1 cheio, como no painel) e o comando de cor de fundo."""
    fg, bg = BAND_COLORS.get(band.get("css", "info"), BAND_COLORS["info"])
    return Paragraph(colored(markup(band.get("value", "")), fg), style), colors.HexColor(bg)
