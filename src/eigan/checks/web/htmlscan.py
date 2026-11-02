"""Leitura tolerante de HTML (stdlib ``html.parser``) para as checagens web.

Extrai só o que as checagens usam: scripts (externos e embutidos), formulários,
metadados (``<meta>``), links e recursos carregados pela página. O HTML de sites
reais costuma ser malformado; o leitor nunca levanta exceção — devolve o que
conseguiu entender.

O que está dentro de ``<noscript>`` e ``<template>`` fica marcado como inerte: um
navegador com JavaScript ligado não baixa nem executa esse conteúdo, então ele não
entra na lista de recursos e scripts da página (seria falso positivo de conteúdo
misto, por exemplo).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

MAX_HTML_CHARS = 2_000_000
MAX_INLINE_CHARS = 400_000
#: URLs distintas consideradas por página (HTML hostil pode ter dezenas de milhares)
MAX_URLS = 2_000

#: elementos que carregam recursos ou que as checagens inspecionam
_ELEMENTS = frozenset(
    {
        "a",
        "link",
        "img",
        "iframe",
        "frame",
        "object",
        "embed",
        "source",
        "video",
        "audio",
        "track",
        "applet",
    }
)
_IGNORED_SCHEMES = ("javascript:", "data:", "mailto:", "tel:", "about:", "blob:")
#: elementos cujo conteúdo o navegador (com JavaScript ligado) não carrega
_INERT_ELEMENTS = frozenset({"noscript", "template"})
#: atributos que fazem o navegador baixar um recurso (``<a href>`` não conta)
_RESOURCE_ATTRS: dict[str, tuple[str, ...]] = {
    "link": ("href",),
    "img": ("src",),
    "iframe": ("src",),
    "frame": ("src",),
    "object": ("data",),
    "embed": ("src",),
    "source": ("src",),
    "video": ("src", "poster"),
    "audio": ("src",),
    "track": ("src",),
}


@dataclass
class Script:
    """Um ``<script>``: ``src`` absoluto (externo) ou ``None`` (embutido, com ``text``)."""

    src: str | None
    attrs: dict[str, str]
    text: str = ""
    inert: bool = False  # dentro de <noscript> ou <template>: não executa


@dataclass
class FormInput:
    tag: str
    type: str
    name: str
    value: str


@dataclass
class Form:
    action: str  # URL absoluta de destino (a própria página quando omitida)
    method: str  # GET | POST
    inputs: list[FormInput] = field(default_factory=list)
    attrs: dict[str, str] = field(default_factory=dict)  # atributos do <form> como escritos
    inert: bool = False  # dentro de <noscript> ou <template>: o navegador não o mostra

    @property
    def has_password(self) -> bool:
        return any(i.type == "password" for i in self.inputs)

    @property
    def scripted(self) -> bool:
        """Envio feito por JavaScript (``action="javascript:..."``), não pelo navegador."""
        return self.attrs.get("action", "").strip().lower().startswith("javascript:")

    def hidden_names(self) -> list[str]:
        return [i.name for i in self.inputs if i.type == "hidden" and i.name]


@dataclass
class Element:
    tag: str
    attrs: dict[str, str]
    inert: bool = False  # dentro de <noscript> ou <template>: não carrega


@dataclass
class HtmlDoc:
    url: str
    title: str = ""
    scripts: list[Script] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    metas: list[dict[str, str]] = field(default_factory=list)
    elements: list[Element] = field(default_factory=list)
    base: str = ""
    orphan_inputs: list[FormInput] = field(default_factory=list)  # campos fora de um <form>

    def resolve(self, value: str | None) -> str | None:
        """URL absoluta de um atributo (``None`` para vazio, âncora ou esquema não HTTP)."""
        text = (value or "").strip()
        if not text or text.startswith("#") or text.lower().startswith(_IGNORED_SCHEMES):
            return None
        try:
            absolute = urljoin(self.base or self.url, text)
            if urlsplit(absolute).scheme not in ("http", "https"):
                return None
        except ValueError:  # ex.: "http://[::1" — endereço quebrado não é recurso
            return None
        return absolute.split("#", 1)[0]

    def srcset(self, value: str | None) -> list[str]:
        """URLs absolutas de um ``srcset`` (``a.png 1x, b.png 2x``)."""
        found: dict[str, None] = {}
        for candidate in (value or "").split(",", MAX_URLS):
            parts = candidate.split()
            url = self.resolve(parts[0]) if parts else None
            if url:
                found.setdefault(url)
        return list(found)

    def meta_values(self, name: str) -> list[str]:
        """Conteúdo dos ``<meta name=...>`` com esse nome (sem diferenciar maiúsculas)."""
        wanted = name.lower()
        return [m.get("content", "") for m in self.metas if m.get("name", "").lower() == wanted]

    def meta_names(self) -> list[str]:
        """Nomes (``name``) de todos os ``<meta>``, em minúsculas."""
        return [m["name"].lower() for m in self.metas if m.get("name")]

    def http_equiv(self, name: str) -> list[str]:
        wanted = name.lower()
        return [
            m.get("content", "") for m in self.metas if m.get("http-equiv", "").lower() == wanted
        ]

    def tags(self, *names: str) -> list[Element]:
        return [e for e in self.elements if e.tag in names]

    def links(self) -> list[str]:
        """Destinos absolutos dos ``<a href>`` (sem repetição, na ordem da página)."""
        seen: dict[str, None] = {}
        for element in self.tags("a"):
            url = self.resolve(element.attrs.get("href"))
            if url:
                seen.setdefault(url)
            if len(seen) >= MAX_URLS:
                break
        return list(seen)

    def script_urls(self) -> list[str]:
        seen: dict[str, None] = {}
        for script in self.scripts:
            if script.src and not script.inert:
                seen.setdefault(script.src)
            if len(seen) >= MAX_URLS:
                break
        return list(seen)

    def inline_scripts(self) -> list[str]:
        return [s.text for s in self.scripts if s.src is None and not s.inert and s.text.strip()]

    def has_orphan_password(self) -> bool:
        """Há campo de senha fora de qualquer ``<form>`` (enviado por JavaScript)?"""
        return any(i.type == "password" for i in self.orphan_inputs)

    def resources(self) -> list[tuple[Element, str]]:
        """Recursos que a página carrega (scripts, estilos, imagens, frames...), já absolutos."""
        found: list[tuple[Element, str]] = []
        for script in self.scripts:
            if script.src and not script.inert:
                found.append((Element("script", script.attrs), script.src))
        for element in self.elements:
            if element.inert:
                continue
            for attr in _RESOURCE_ATTRS.get(element.tag, ()):
                url = self.resolve(element.attrs.get(attr))
                if url:
                    found.append((element, url))
        return found


class _Parser(HTMLParser):
    def __init__(self, url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.doc = HtmlDoc(url=url, base=url)
        self._script: Script | None = None
        self._form: Form | None = None
        self._in_title = False
        self._inline_total = 0
        self._inert_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {k.lower(): (v or "") for k, v in attrs}
        if tag == "base" and values.get("href") and self.doc.base == self.doc.url:
            self._set_base(values["href"])
        elif tag == "script":
            self._open_script(values)
        elif tag == "form":
            self._open_form(values)
        elif tag in ("input", "select", "textarea", "button"):
            self._add_input(tag, values)
        elif tag == "meta":
            self.doc.metas.append(values)
        elif tag == "title":
            self._in_title = True
        elif tag in _INERT_ELEMENTS:
            self._inert_depth += 1
        if tag in _ELEMENTS:
            self.doc.elements.append(Element(tag, values, inert=self._inert_depth > 0))

    def _add_input(self, tag: str, values: dict[str, str]) -> None:
        kind = values.get("type", "text" if tag == "input" else tag).strip().lower()
        item = FormInput(tag, kind, values.get("name", ""), values.get("value", ""))
        if self._inert_depth > 0 and self._form is None:
            return  # campo solto num <template>/<noscript>: não existe para o navegador
        if self._form is not None:
            self._form.inputs.append(item)
        else:
            self.doc.orphan_inputs.append(item)

    def _set_base(self, href: str) -> None:
        try:
            base = urljoin(self.doc.url, href.strip())
        except ValueError:
            return
        if urlsplit(base).scheme in ("http", "https"):
            self.doc.base = base

    def _open_script(self, values: dict[str, str]) -> None:
        src = values.get("src", "").strip()
        script = Script(self.doc.resolve(src) if src else None, values, inert=self._inert_depth > 0)
        if src and script.src is None:
            return  # data:, javascript: — nada a baixar
        self.doc.scripts.append(script)
        self._script = script if not src else None

    def _open_form(self, values: dict[str, str]) -> None:
        action = values.get("action", "").strip()
        target = self.doc.resolve(action) if action else self.doc.url
        method = values.get("method", "get").strip().upper() or "GET"
        form = Form(target or self.doc.url, method, attrs=values, inert=self._inert_depth > 0)
        self.doc.forms.append(form)
        self._form = form

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self._script = None
        elif tag == "form":
            self._form = None
        elif tag == "title":
            self._in_title = False
        elif tag in _INERT_ELEMENTS and self._inert_depth > 0:
            self._inert_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._script is not None:
            room = MAX_INLINE_CHARS - self._inline_total
            if room > 0:
                piece = data[:room]
                self._script.text += piece
                self._inline_total += len(piece)
        elif self._in_title and len(self.doc.title) < 500:
            self.doc.title += data


def parse_html(text: str, url: str) -> HtmlDoc:
    """Lê o HTML e devolve o que foi possível extrair (nunca levanta)."""
    parser = _Parser(url)
    try:
        parser.feed(text[:MAX_HTML_CHARS])
        parser.close()
    except Exception:  # noqa: BLE001 — HTML hostil não pode derrubar a checagem
        pass
    parser.doc.title = " ".join(parser.doc.title.split())
    return parser.doc
