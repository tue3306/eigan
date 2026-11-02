"""Gera o ícone do EIGAN (escudo com "E") em .ico e .png, sem arquivos externos.

Uso: python packaging/make_icon.py  →  packaging/eigan.ico e packaging/eigan.png

Desenha o mesmo emblema de ``src/eigan/panel/static/eigan.svg`` com o Pillow
(dependência do reportlab), em alta resolução e reduzido com antisserrilhamento.
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw

HERE = Path(__file__).resolve().parent
BRAND = (31, 79, 209, 255)  # #1f4fd1
WHITE = (255, 255, 255, 255)
SIZE = 1024
SCALE = SIZE / 64


def _bezier(p0, p1, p2, p3, steps=48):
    points = []
    for i in range(steps + 1):
        t = i / steps
        mt = 1 - t
        x = mt**3 * p0[0] + 3 * mt**2 * t * p1[0] + 3 * mt * t**2 * p2[0] + t**3 * p3[0]
        y = mt**3 * p0[1] + 3 * mt**2 * t * p1[1] + 3 * mt * t**2 * p2[1] + t**3 * p3[1]
        points.append((x, y))
    return points


def _shield() -> list[tuple[float, float]]:
    # Mesmo contorno do SVG: M32 3.5 55 11.8V30c0 14.4-9.6 25.3-23 30.5C18.6 55.3 9 44.4 9 30V11.8Z
    outline = [(32, 3.5), (55, 11.8), (55, 30)]
    outline += _bezier((55, 30), (55, 44.4), (45.4, 55.3), (32, 60.5))[1:]
    outline += _bezier((32, 60.5), (18.6, 55.3), (9, 44.4), (9, 30))[1:]
    outline += [(9, 11.8)]
    return [(x * SCALE, y * SCALE) for x, y in outline]


def _bar(draw: ImageDraw.ImageDraw, x: float, y: float, w: float, h: float) -> None:
    draw.rounded_rectangle(
        (x * SCALE, y * SCALE, (x + w) * SCALE, (y + h) * SCALE), radius=2.5 * SCALE, fill=WHITE
    )


def render(size: int) -> Image.Image:
    image = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.polygon(_shield(), fill=BRAND)
    _bar(draw, 22, 20, 21, 5)
    _bar(draw, 22, 29.5, 15, 5)
    _bar(draw, 22, 39, 21, 5)
    _bar(draw, 22, 20, 5, 24)
    return image.resize((size, size), Image.Resampling.LANCZOS)


def main() -> None:
    big = render(512)
    big.save(HERE / "eigan.png")
    sizes = [(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    render(256).save(HERE / "eigan.ico", sizes=sizes)
    print(f"Ícones gerados em {HERE}")


if __name__ == "__main__":
    main()
