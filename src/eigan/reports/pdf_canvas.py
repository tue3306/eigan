"""Elementos desenhados do PDF: o emblema do EIGAN e o rodapé com "Página N de M"."""

from __future__ import annotations

from typing import Any

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.pdfgen import canvas as pdfcanvas
from reportlab.platypus import Flowable

from .pdf_styles import BRAND, LINE, MARGIN, MUTED, WHITE

# Retângulos do "E" no desenho de 64x64 do emblema (x, y, largura, altura).
_E_BARS = ((22, 20, 21, 5), (22, 29.5, 15, 5), (22, 39, 21, 5), (22, 20, 5, 24))


class Emblem(Flowable):
    """O escudo com "E" do painel, desenhado em vetor (o PDF não lê SVG)."""

    def __init__(self, size: float) -> None:
        super().__init__()
        self.size = size
        self.width = size
        self.height = size

    def wrap(self, available_width: float, available_height: float) -> tuple[float, float]:
        return self.size, self.size

    def draw(self) -> None:
        scale = self.size / 64.0

        def point(x: float, y: float) -> tuple[float, float]:
            return x * scale, (64 - y) * scale

        canvas = self.canv
        canvas.saveState()
        canvas.setFillColor(BRAND)
        path = canvas.beginPath()
        path.moveTo(*point(32, 3.5))
        path.lineTo(*point(55, 11.8))
        path.lineTo(*point(55, 30))
        path.curveTo(*point(55, 44.4), *point(45.4, 55.3), *point(32, 60.5))
        path.curveTo(*point(18.6, 55.3), *point(9, 44.4), *point(9, 30))
        path.lineTo(*point(9, 11.8))
        path.close()
        canvas.drawPath(path, stroke=0, fill=1)
        canvas.setFillColor(WHITE)
        for x, y, w, h in _E_BARS:
            canvas.roundRect(
                x * scale, (64 - y - h) * scale, w * scale, h * scale, 2.5 * scale, stroke=0, fill=1
            )
        canvas.restoreState()


def _fit(text: str, width: float, font: str, size: float) -> str:
    """Corta o texto com "..." até caber na largura (o alvo pode ter letras muito largas)."""
    if stringWidth(text, font, size) <= width:
        return text
    cut = len(text)
    while cut > 0 and stringWidth(text[:cut] + "...", font, size) > width:
        cut -= 1
    return text[:cut].rstrip() + "..."


def footer_canvas(footer: str) -> type[pdfcanvas.Canvas]:
    """Canvas que escreve o rodapé com "Página N de M" depois de saber o total."""

    class FooterCanvas(pdfcanvas.Canvas):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self._pages: list[dict[str, Any]] = []

        def showPage(self) -> None:
            self._pages.append(dict(self.__dict__))
            self._startPage()

        def save(self) -> None:
            total = len(self._pages)
            for number, state in enumerate(self._pages, 1):
                self.__dict__.update(state)
                self._footer(number, total)
                pdfcanvas.Canvas.showPage(self)
            pdfcanvas.Canvas.save(self)

        def _footer(self, number: int, total: int) -> None:
            width, _height = A4
            y = MARGIN - 6 * mm
            self.saveState()
            self.setStrokeColor(LINE)
            self.setLineWidth(0.5)
            self.line(MARGIN, y + 9, width - MARGIN, y + 9)
            self.setFont("Helvetica", 7.5)
            self.setFillColor(MUTED)
            page = f"Página {number} de {total}"
            room = width - 2 * MARGIN - stringWidth(page, "Helvetica", 7.5) - 12
            self.drawString(MARGIN, y, _fit(footer, room, "Helvetica", 7.5))
            self.drawRightString(width - MARGIN, y, page)
            self.restoreState()

    return FooterCanvas
