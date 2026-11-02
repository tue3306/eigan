"""Leitor mínimo de YAML para docker-compose e manifestos Kubernetes (sem PyYAML).

Cobre o subconjunto usado na prática nesses arquivos: mapas e listas em bloco,
escalares simples ou entre aspas, listas/mapas em linha (``[a, b]``, ``{a: b}``,
inclusive quebrados em várias linhas), blocos de texto (``|`` e ``>``),
comentários, vários documentos (``---``), âncoras, aliases e chaves de mescla
(``<<: *base``, comuns no compose). Tags (``!!str``) são descartadas.

Cada nó guarda a linha de origem para o relatório. O que não for entendido vira
texto — as regras tratam isso como valor desconhecido, nunca como problema.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

_KEY = re.compile(
    r"""^(?P<key>"(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^\s#'"\-\[\]{}][^#]*?|-[^\s#][^#]*?)"""
    r"""\s*:(?:\s+|$)(?P<rest>.*)$"""
)
_LONG_SPACES = re.compile(r"\s{100}")
_MAX_KEY_LINE = 4000


def _match_key(content: str) -> re.Match[str] | None:
    """``_KEY.match`` com proteção: linhas enormes ou com longas corridas de espaços (tempo
    quadrático da expressão) são tratadas como valores, não como ``chave: valor``."""
    if ":" not in content or len(content) > _MAX_KEY_LINE or _LONG_SPACES.search(content):
        return None
    return _KEY.match(content)


_PROPS = re.compile(r"^(?:(?:&(?P<anchor>[^\s,\[\]{}]+)|![^\s]*)\s*)+")
_ALIAS = re.compile(r"^\*(?P<name>[^\s,\[\]{}]+)$")
_BLOCK_SCALAR = re.compile(r"^[|>](?:[+\-]?\d?|\d[+\-])$")
_NULLS = frozenset({"~", "null", "Null", "NULL", ""})
MAX_DEPTH = 200


@dataclass
class Node:
    """Um nó do documento: ``value`` é dict[str, Node], list[Node] ou str/None."""

    value: Any
    line: int
    children_lines: dict[str, int] = field(default_factory=dict)

    # -- navegação -------------------------------------------------------------------
    def get(self, *path: str) -> Node | None:
        node: Node | None = self
        for key in path:
            if node is None or not isinstance(node.value, dict):
                return None
            node = node.value.get(key)
        return node

    def text(self, *path: str) -> str:
        """Valor escalar como texto ("" se não existir ou não for escalar)."""
        node = self.get(*path) if path else self
        if node is None or isinstance(node.value, (dict, list)) or node.value is None:
            return ""
        return str(node.value)

    def items(self) -> list[tuple[str, Node]]:
        return list(self.value.items()) if isinstance(self.value, dict) else []

    def seq(self, *path: str) -> list[Node]:
        node = self.get(*path) if path else self
        if node is None or not isinstance(node.value, list):
            return []
        return list(node.value)

    def has(self, key: str) -> bool:
        return isinstance(self.value, dict) and key in self.value

    def line_of(self, key: str) -> int:
        """Linha onde a chave aparece (ou a linha do próprio nó)."""
        return self.children_lines.get(key, self.line)

    @property
    def is_map(self) -> bool:
        return isinstance(self.value, dict)

    @property
    def is_seq(self) -> bool:
        return isinstance(self.value, list)

    def flag(self, *path: str) -> bool | None:
        """Booleano YAML (true/false/yes/no/on/off) ou ``None`` se ausente/desconhecido."""
        value = self.text(*path).strip().lower()
        if value in ("true", "yes", "on", "y"):
            return True
        if value in ("false", "no", "off", "n"):
            return False
        return None


@dataclass
class _Line:
    indent: int
    content: str
    number: int


# -- linhas e documentos ------------------------------------------------------------------


def strip_comment(line: str) -> str:
    """Remove o comentário ``# ...`` que não esteja dentro de um escalar entre aspas.

    Uma aspa só abre um trecho citado no começo de um valor (``key: 'x'``,
    ``- "y"``, ``[a, 'b']``): o apóstrofo de ``don't`` não engole o comentário.
    Dentro das aspas valem os escapes do YAML (barra invertida e aspa simples dobrada).
    """
    quote = ""
    previous = " "
    skip = False
    for index, char in enumerate(line):
        if skip:
            skip = False
            continue
        if quote:
            if quote == '"' and char == "\\":
                skip = True
            elif char == quote:
                if quote == "'" and line[index + 1 : index + 2] == "'":
                    skip = True
                else:
                    quote = ""
            previous = char
            continue
        if char in "'\"" and previous in " \t:-[{,":
            quote = char
        elif char == "#" and previous in " \t":
            return line[:index].rstrip()
        previous = char
    return line.rstrip()


def split_documents(text: str) -> list[list[_Line]]:
    """Divide o texto em documentos (``---``) já sem comentários e linhas vazias."""
    documents: list[list[_Line]] = [[]]
    for number, raw in enumerate(text.splitlines(), start=1):
        if raw.startswith("---") and raw[3:4] in ("", " ", "\t"):
            documents.append([])
            rest = strip_comment(raw[3:]).strip()
            if rest:
                documents[-1].append(_Line(0, rest, number))
            continue
        if raw.startswith("...") or (raw.startswith("%") and not documents[-1]):
            continue  # fim de documento ou diretiva (%YAML)
        clean = strip_comment(raw.replace("\t", "  "))
        if not clean.strip():
            continue
        indent = len(clean) - len(clean.lstrip(" "))
        documents[-1].append(_Line(indent, clean.strip(), number))
    return [doc for doc in documents if doc]


def parse_documents(text: str) -> list[Node]:
    """Todos os documentos do arquivo (documento malformado vira nó vazio)."""
    nodes: list[Node] = []
    for lines in split_documents(text):
        parser = _Parser(lines)
        try:
            nodes.append(parser.block())
        except (IndexError, ValueError, RecursionError):
            nodes.append(Node(None, lines[0].number))
    return nodes


def blank_template_actions(text: str) -> str:
    """Apaga as linhas que só têm ações de template (``{{- if ... }}``), mantendo a numeração.

    Sem isso, um manifesto de Helm pararia de ser lido na primeira ação; os
    valores com ``{{ }}`` continuam como texto (valor desconhecido para as regras).
    """
    lines = []
    for raw in text.splitlines():
        stripped = raw.strip()
        action = stripped.startswith("{{") and stripped.endswith("}}")
        lines.append("" if action else raw)
    return "\n".join(lines)


# -- analisador -------------------------------------------------------------------------


class _Parser:
    def __init__(self, lines: list[_Line]) -> None:
        self.lines = lines
        self.pos = 0
        self.depth = 0
        self.anchors: dict[str, Node] = {}

    def _current(self) -> _Line | None:
        return self.lines[self.pos] if self.pos < len(self.lines) else None

    def block(self) -> Node:
        line = self._current()
        if line is None:
            return Node(None, 0)
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise RecursionError("YAML aninhado demais")
        try:
            if _is_dash(line.content):
                return self._sequence(line.indent)
            if _match_key(line.content):
                return self._mapping(line.indent)
            self.pos += 1
            return self._scalar_or_flow(line.content, line)
        finally:
            self.depth -= 1

    def _mapping(self, indent: int) -> Node:
        start = self._current()
        result: dict[str, Node] = {}
        node = Node(result, start.number if start else 0)
        merges: list[Node] = []
        while (line := self._current()) is not None and line.indent == indent:
            match = _match_key(line.content)
            if match is None or _is_dash(line.content):
                break
            key = unquote(match.group("key").strip())
            rest, anchor = _props(match.group("rest").strip())
            self.pos += 1
            value = self._value_after_key(line, rest)
            if anchor:
                self.anchors[anchor] = value
            if key == "<<":
                merges.extend(self._merge_sources(value))
            else:
                result[key] = value
                node.children_lines[key] = line.number
            self._skip_deeper(indent)
        for source in merges:  # chaves explícitas sempre vencem as mescladas
            for key, child in source.items():
                if key not in result:
                    result[key] = child
                    node.children_lines[key] = source.line_of(key)
        return node

    def _merge_sources(self, value: Node) -> list[Node]:
        if value.is_map:
            return [value]
        return [item for item in value.seq() if item.is_map]

    def _skip_deeper(self, indent: int) -> None:
        """Pula linhas mais recuadas que sobraram (continuação de texto em várias linhas)."""
        while (line := self._current()) is not None and line.indent > indent:
            self.pos += 1

    def _value_after_key(self, line: _Line, rest: str) -> Node:
        if _BLOCK_SCALAR.match(rest):
            return self._block_scalar(line)
        if rest:
            return self._scalar_or_flow(rest, line)
        following = self._current()
        if following is None:
            return Node(None, line.number)
        if following.indent > line.indent:
            return self.block()
        if following.indent == line.indent and _is_dash(following.content):
            return self._sequence(line.indent)  # lista no mesmo recuo da chave (comum no compose)
        return Node(None, line.number)

    def _block_scalar(self, line: _Line) -> Node:
        parts: list[str] = []
        while (current := self._current()) is not None and current.indent > line.indent:
            parts.append(current.content)
            self.pos += 1
        return Node("\n".join(parts), line.number)

    def _scalar_or_flow(self, text: str, line: _Line) -> Node:
        """Escalar, alias ou coleção em linha (que pode continuar nas linhas seguintes)."""
        alias = _ALIAS.match(text)
        if alias:
            target = self.anchors.get(alias.group("name"))
            return target if target is not None else Node(None, line.number)
        if text[:1] in "[{" and _flow_depth(text) > 0:
            text = self._gather_flow(text, line.indent)
        return Node(parse_inline(text, line.number, self.anchors), line.number)

    def _gather_flow(self, text: str, indent: int) -> str:
        """Junta as linhas de uma lista/mapa em linha quebrado (``[`` ... ``]``)."""
        parts = [text]
        depth, quote = _flow_state(text)
        while depth > 0 and (current := self._current()) is not None:
            if current.indent <= indent and current.content[:1] not in ("]", "}"):
                break
            parts.append(current.content)
            depth, quote = _flow_state(current.content, depth, quote)
            self.pos += 1
        return " ".join(parts)

    def _sequence(self, indent: int) -> Node:
        start = self._current()
        items: list[Node] = []
        node = Node(items, start.number if start else 0)
        while (line := self._current()) is not None and line.indent == indent:
            if not _is_dash(line.content):
                break
            body, anchor = _props(line.content[1:].strip())
            offset = len(line.content) - len(line.content[1:].lstrip()) + indent
            if not body:
                self.pos += 1
                following = self._current()
                if following is not None and following.indent > indent:
                    item = self.block()
                else:
                    item = Node(None, line.number)
            elif _BLOCK_SCALAR.match(body):
                self.pos += 1
                item = self._block_scalar(line)
            elif _is_dash(body):  # lista dentro de lista (``- - a``)
                self.lines[self.pos] = _Line(offset, body, line.number)
                item = self._sequence(offset)
            elif _is_mapping_item(body):
                self.lines[self.pos] = _Line(offset, body, line.number)
                item = self._mapping(offset)
            else:
                self.pos += 1
                item = self._scalar_or_flow(body, line)
                self._skip_deeper(indent)
            if anchor:
                self.anchors[anchor] = item
            items.append(item)
        return node


# -- escalares e coleções em linha ---------------------------------------------------------


def _is_dash(content: str) -> bool:
    return content == "-" or content.startswith("- ")


def _props(text: str) -> tuple[str, str | None]:
    """Separa tags/âncoras do começo do valor: ``&base !!map x`` -> (``x``, ``base``)."""
    match = _PROPS.match(text)
    if match is None:
        return text, None
    return text[match.end() :].strip(), match.group("anchor")


def _is_mapping_item(body: str) -> bool:
    """O item de lista começa um mapa (``- nome: x``)? Escalares entre aspas não."""
    match = _match_key(body)
    if match is None or body.startswith(("[", "{")):
        return False
    return not body.startswith(("'", '"')) or match.group("key")[:1] in "'\""


def unquote(text: str) -> str:
    if len(text) >= 2 and text[0] == text[-1] == '"':
        inner = text[1:-1]
        return inner.replace('\\"', '"').replace("\\n", "\n").replace("\\\\", "\\")
    if len(text) >= 2 and text[0] == text[-1] == "'":
        return text[1:-1].replace("''", "'")
    return text


def parse_scalar(text: str) -> str | None:
    value, _anchor = _props(text.strip())
    if value in _NULLS:
        return None
    return unquote(value)


def parse_inline(text: str, line: int = 0, anchors: dict[str, Node] | None = None) -> Any:
    """Escalar ou coleção em linha (``[a, b]`` / ``{a: b}``), com a linha de origem."""
    value, _anchor = _props(text.strip())
    if value.startswith("{{"):
        return value  # expressão de template (Helm), não um mapa em linha
    if value.startswith("[") and value.endswith("]"):
        return [_inline_node(part, line, anchors) for part in _split_flow(value[1:-1])]
    if value.startswith("{") and value.endswith("}"):
        result: dict[str, Any] = {}
        for part in _split_flow(value[1:-1]):
            key, _, rest = _split_pair(part)
            if key.strip():
                result[unquote(key.strip())] = _inline_node(rest, line, anchors)
        return result
    return parse_scalar(value)


def _inline_node(text: str, line: int, anchors: dict[str, Node] | None) -> Node:
    alias = _ALIAS.match(text.strip())
    if alias and anchors is not None and alias.group("name") in anchors:
        return anchors[alias.group("name")]
    return Node(parse_inline(text, line, anchors), line)


def _split_pair(part: str) -> tuple[str, str, str]:
    """``"a:b": c`` -> (``"a:b"``, ``:``, `` c``): o separador é o primeiro ``:`` fora de aspas."""
    quote = ""
    for index, char in enumerate(part):
        if quote:
            if char == quote:
                quote = ""
        elif char in "'\"":
            quote = char
        elif char == ":" and (index + 1 == len(part) or part[index + 1] in " \t"):
            return part[:index], ":", part[index + 1 :]
    return part, "", ""


def _flow_state(text: str, depth: int = 0, quote: str = "") -> tuple[int, str]:
    """Quantos ``[``/``{`` seguem abertos no fim do texto e a aspa ainda aberta (se houver)."""
    for char in text:
        if quote:
            if char == quote:
                quote = ""
        elif char in "'\"":
            quote = char
        elif char in "[{":
            depth += 1
        elif char in "]}":
            depth -= 1
    return depth, quote


def _flow_depth(text: str) -> int:
    return _flow_state(text)[0]


def _split_flow(text: str) -> list[str]:
    """Divide ``a, [b, c], "d,e"`` nas vírgulas de primeiro nível."""
    parts: list[str] = []
    depth = 0
    quote = ""
    current: list[str] = []
    for char in text:
        if quote:
            current.append(char)
            if char == quote:
                quote = ""
            continue
        if char in "'\"":
            quote = char
        elif char in "[{":
            depth += 1
        elif char in "]}":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return [p for p in parts if p]


def to_python(node: Node | None) -> Any:
    """Converte para dict/list/str puros (útil em testes e depuração)."""
    if node is None:
        return None
    if isinstance(node.value, dict):
        return {k: to_python(v) for k, v in node.value.items()}
    if isinstance(node.value, list):
        return [to_python(v) for v in node.value]
    return node.value
