"""Texto seguro para o PDF: só caracteres da fonte padrão (cp1252) e sem marcação.

O relatório usa as fontes padrão do PDF (Helvetica e Courier, codificação cp1252),
sem nada para baixar ou embutir. Por isso todo texto passa por :func:`pdf_text`:
caracteres fora do cp1252 viram equivalentes seguros (``≥`` vira ``>=``) ou ``?``.
E todo texto dinâmico passa por :func:`markup` antes de entrar num ``Paragraph``: o
``Paragraph`` do reportlab interpreta marcação, que nunca pode vir do alvo auditado.
"""

from __future__ import annotations

import re
import unicodedata
from functools import lru_cache

from .common import clip

# Caracteres comuns fora do cp1252 e o equivalente seguro na fonte padrão do PDF.
_REPLACEMENTS = {
    "≥": ">=",
    "≤": "<=",
    "≠": "!=",
    "→": "->",
    "←": "<-",
    "↔": "<->",
    "⇒": "=>",
    "✓": "OK",
    "✔": "OK",
    "✗": "X",
    "✘": "X",
    "−": "-",
    "‐": "-",
    "‑": "-",
    "‒": "-",
    "―": "-",
    "★": "*",
    "●": "•",
    "▪": "•",
    "■": "•",
    "◦": "•",
    "⚠": "!",
    "\xad": "",
    "\u200b": "",
    "\u200c": "",
    "\u200d": "",
    "\u2060": "",
    "\ufeff": "",
    "\u2002": " ",
    "\u2003": " ",
    "\u2007": " ",
    "\u2009": " ",
    "\u200a": " ",
    "\u202f": " ",
    "\u2028": "\n",
    "\u2029": "\n",
    "\t": "    ",
    "\n": "\n",
}
_LINE_BREAKS = re.compile(r"\s*\n\s*")


def pdf_text(value: object) -> str:
    """Texto que a fonte padrão do PDF (cp1252) consegue desenhar, sem controles."""
    text = unicodedata.normalize("NFC", str(value)).replace("\r\n", "\n").replace("\r", "\n")
    return "".join(_safe_char(ch) for ch in text)


@lru_cache(maxsize=4096)
def _safe_char(ch: str) -> str:
    if ch in _REPLACEMENTS:
        return _REPLACEMENTS[ch]
    category = unicodedata.category(ch)
    if category == "Cc":
        return ""
    if category in ("Cs", "Co", "Cn"):
        return "?"
    try:
        ch.encode("cp1252")
        return ch
    except UnicodeEncodeError:
        pass
    # Letra acentuada fora do cp1252 (ex.: "ő"): usa a letra base.
    base = "".join(c for c in unicodedata.normalize("NFKD", ch) if not unicodedata.combining(c))
    try:
        base.encode("cp1252")
    except UnicodeEncodeError:
        return "?"
    return base or "?"


def escape(text: str) -> str:
    """Escapa ``&``, ``<`` e ``>`` (o mínimo para o texto não virar marcação do reportlab)."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def markup(value: object, limit: int | None = None) -> str:
    """Texto dinâmico pronto para ``Paragraph``: seguro no cp1252 e sem marcação.

    Com ``limit``, é um campo curto (título, ativo, célula de tabela): as quebras de linha
    viram espaços, porque uma célula alta demais não atravessa a página e derrubaria o PDF.
    """
    text = pdf_text(value)
    if limit is not None:
        text = clip(_LINE_BREAKS.sub(" ", text.strip()), limit)[0]
    return escape(text).replace("\n", "<br/>")
