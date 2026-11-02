"""Leitor tolerante de HCL2 (a linguagem do Terraform), sem dependências.

Entende o que as regras de IaC precisam: blocos com rótulos, atributos, textos
(inclusive heredocs e interpolação), números, booleanos, listas, objetos e chamadas
de função. Tudo o que não for um valor simples vira :class:`Ref` — "valor
desconhecido" para as regras, nunca um problema. Erro de sintaxe não interrompe a
leitura: o leitor pula a linha e continua, e nunca levanta exceção.
"""

from __future__ import annotations

import re
from bisect import bisect_left
from dataclasses import dataclass, field
from typing import Any

MAX_DEPTH = 64
_NAME = re.compile(r"[A-Za-z_][\w\-.]*")
_IDENT = re.compile(r"[A-Za-z_][\w\-]*")
_SEGMENT = re.compile(r"[\w\-*]+")
_NUMBER = re.compile(r"-?\d+(?:\.\d+)?(?:[eE][+\-]?\d+)?")
_HEREDOC = re.compile(r"<<-?([A-Za-z_][\w\-]*)[ \t]*\r?\n")
_FOR = re.compile(r"for\s+[A-Za-z_]")
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\"}
_LITERALS: dict[str, bool | None] = {"true": True, "false": False, "null": None}


@dataclass(frozen=True)
class Ref:
    """Expressão não avaliada: ``var.x``, ``aws_s3_bucket.b.id``, ``a ? b : c``..."""

    raw: str


@dataclass(frozen=True)
class Call:
    """Chamada de função: ``jsonencode({...})``, ``file("x")``."""

    name: str
    args: tuple[Any, ...]


@dataclass(frozen=True)
class Attr:
    """Atributo ``nome = valor``. ``value`` é str, int, float, bool, None, list, dict, Ref ou Call."""

    name: str
    value: Any
    line: int


@dataclass
class Block:
    """Bloco ``tipo "rótulo" "rótulo" { ... }`` com seus atributos e blocos internos."""

    type: str
    labels: list[str]
    line: int
    attrs: dict[str, Attr] = field(default_factory=dict)
    blocks: list[Block] = field(default_factory=list)

    def get(self, name: str) -> Any:
        attr = self.attrs.get(name)
        return attr.value if attr is not None else None

    def has(self, name: str) -> bool:
        return name in self.attrs

    def line_of(self, name: str) -> int:
        attr = self.attrs.get(name)
        return attr.line if attr is not None else self.line

    def children(self, kind: str) -> list[Block]:
        return [block for block in self.blocks if block.type == kind]

    def label(self, index: int) -> str:
        return self.labels[index] if index < len(self.labels) else ""


def parse_hcl(text: str) -> list[Block]:
    """Blocos de primeiro nível do arquivo (o que não foi entendido fica de fora)."""
    reader = _Reader(text)
    root = Block("", [], 0)
    try:
        reader.body(root, 0, top=True)
    except RecursionError:
        pass  # aninhamento absurdo: fica o que já foi lido
    return root.blocks


class _Reader:
    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0
        self.size = len(text)
        self._newlines = [match.start() for match in re.finditer("\n", text)]

    def _line(self, position: int) -> int:
        return bisect_left(self._newlines, position) + 1

    def _peek(self) -> str:
        return self.text[self.pos] if self.pos < self.size else ""

    # -- espaços e comentários ----------------------------------------------------------
    def _skip_blank(self, newlines: bool) -> None:
        while self.pos < self.size:
            char = self.text[self.pos]
            if char in " \t\r﻿" or (newlines and char == "\n"):
                self.pos += 1
            elif char == "#" or self.text.startswith("//", self.pos):
                end = self.text.find("\n", self.pos)
                self.pos = self.size if end < 0 else end
            elif self.text.startswith("/*", self.pos):
                end = self.text.find("*/", self.pos + 2)
                self.pos = self.size if end < 0 else end + 2
            else:
                return

    def _skip_line(self, start: int) -> None:
        """Pula o resto da linha que não foi entendida (sempre avança)."""
        end = self.text.find("\n", max(self.pos, start + 1))
        self.pos = self.size if end < 0 else end + 1

    def _skip_closing(self) -> None:
        """Avança até fechar o ``[``, ``{`` ou ``(`` já aberto."""
        depth = 1
        while self.pos < self.size and depth:
            char = self.text[self.pos]
            if char == '"':
                self._string()
                continue
            if char in "([{":
                depth += 1
            elif char in ")]}":
                depth -= 1
            self.pos += 1

    # -- corpo de bloco -----------------------------------------------------------------
    def body(self, block: Block, depth: int, *, top: bool = False) -> None:
        while True:
            self._skip_blank(True)
            if self.pos >= self.size:
                return
            if self.text[self.pos] == "}":
                self.pos += 1
                if top:
                    continue  # "}" sobrando no arquivo
                return
            start = self.pos
            name = self._name()
            if name is None:
                self._skip_line(start)
                continue
            self._skip_blank(False)
            if self._at_assign():
                self.pos += 1
                block.attrs[name] = Attr(name, self._expression(depth), self._line(start))
                continue
            labels = self._labels()
            if self._peek() != "{":
                self._skip_line(start)
                continue
            self.pos += 1
            child = Block(name, labels, self._line(start))
            if depth + 1 >= MAX_DEPTH:
                self._skip_closing()
            else:
                self.body(child, depth + 1)
            block.blocks.append(child)

    def _name(self) -> str | None:
        if self._peek() == '"':
            return self._string()[0]
        match = _NAME.match(self.text, self.pos)
        if match is None:
            return None
        self.pos = match.end()
        return match.group(0)

    def _labels(self) -> list[str]:
        labels: list[str] = []
        while True:
            self._skip_blank(False)
            label = self._name()
            if label is None:
                return labels
            labels.append(label)

    def _at_assign(self) -> bool:
        return self._peek() == "=" and self.text[self.pos + 1 : self.pos + 2] != "="

    # -- expressões -----------------------------------------------------------------------
    def _expression(self, depth: int) -> Any:
        self._skip_blank(False)
        start = self.pos
        value = self._primary(depth)
        self._skip_blank(False)
        if self.pos >= self.size or self.text[self.pos] in "\n,)]}":
            return value
        self._skip_expression()  # há um operador depois do primeiro termo
        return Ref(self.text[start : self.pos].strip())

    def _skip_expression(self) -> None:
        """Vai até o fim da expressão: quebra de linha ou vírgula fora de parênteses e colchetes."""
        depth = 0
        while self.pos < self.size:
            char = self.text[self.pos]
            if char == '"':
                self._string()
                continue
            if char == "#" or self.text.startswith(("//", "/*"), self.pos):
                self._skip_blank(False)
                continue
            if char in "([{":
                depth += 1
            elif char in ")]}":
                if depth == 0:
                    return
                depth -= 1
            elif depth == 0 and char in ",\n":
                return
            self.pos += 1

    def _primary(self, depth: int) -> Any:
        char = self._peek()
        if char == '"':
            text, only_template = self._string()
            return Ref(text[2:-1].strip()) if only_template else text
        if char == "<":
            heredoc = self._heredoc()
            return heredoc if heredoc is not None else Ref("")
        if char and char in "[{" and depth + 1 >= MAX_DEPTH:
            start = self.pos
            self.pos += 1
            self._skip_closing()
            return Ref(self.text[start : self.pos])
        if char == "[":
            return self._list(depth + 1)
        if char == "{":
            return self._object(depth + 1)
        number = _NUMBER.match(self.text, self.pos)
        if number is not None:
            self.pos = number.end()
            raw = number.group(0)
            return int(raw) if raw.lstrip("-").isdigit() else float(raw)
        identifier = _IDENT.match(self.text, self.pos)
        if identifier is not None:
            return self._path_or_call(identifier.group(0), depth + 1)
        return Ref("")

    def _path_or_call(self, name: str, depth: int) -> Any:
        start = self.pos
        self.pos += len(name)
        following = self._peek()
        if following == "(":
            return Call(name, tuple(self._call_args(depth)))
        if following not in (".", "[") and name in _LITERALS:
            return _LITERALS[name]
        while (following := self._peek()) and following in ".[":
            self.pos += 1
            if following == "[":
                self._skip_closing()
                continue
            segment = _SEGMENT.match(self.text, self.pos)
            if segment is not None:
                self.pos = segment.end()
        return Ref(self.text[start : self.pos])

    def _call_args(self, depth: int) -> list[Any]:
        self.pos += 1
        args: list[Any] = []
        while True:
            self._skip_blank(True)
            char = self._peek()
            if not char:
                return args
            if char == ")":
                self.pos += 1
                return args
            if char == ",":
                self.pos += 1
                continue
            before = self.pos
            value = self._expression(depth)
            if self.pos == before:
                self.pos += 1  # nunca fica parado num caractere inesperado
            else:
                args.append(value)

    def _list(self, depth: int) -> Any:
        start = self.pos
        self.pos += 1
        self._skip_blank(True)
        if _FOR.match(self.text, self.pos):
            self._skip_closing()
            return Ref(self.text[start : self.pos])
        items: list[Any] = []
        while True:
            self._skip_blank(True)
            char = self._peek()
            if not char:
                return items
            if char == "]":
                self.pos += 1
                return items
            if char == ",":
                self.pos += 1
                continue
            before = self.pos
            value = self._expression(depth)
            if self.pos == before:
                self.pos += 1
            else:
                items.append(value)

    def _object(self, depth: int) -> Any:
        start = self.pos
        self.pos += 1
        self._skip_blank(True)
        if _FOR.match(self.text, self.pos):
            self._skip_closing()
            return Ref(self.text[start : self.pos])
        result: dict[str, Any] = {}
        while True:
            self._skip_blank(True)
            char = self._peek()
            if not char:
                return result
            if char == "}":
                self.pos += 1
                return result
            if char == ",":
                self.pos += 1
                continue
            key = self._object_key()
            if key is None:
                self.pos += 1
                continue
            self._skip_blank(False)
            if self._peek() == ":" or self._at_assign():
                self.pos += 1
                result[key] = self._expression(depth)

    def _object_key(self) -> str | None:
        if self._peek() == "(":
            start = self.pos
            self.pos += 1
            self._skip_closing()
            return self.text[start : self.pos]
        return self._name()

    # -- textos ---------------------------------------------------------------------------
    def _string(self) -> tuple[str, bool]:
        """Texto entre aspas: (conteúdo, é só uma interpolação ``"${...}"``)."""
        self.pos += 1
        parts: list[str] = []
        templates = literals = 0
        while self.pos < self.size:
            char = self.text[self.pos]
            if char == '"':
                self.pos += 1
                break
            if char == "\n":
                break  # aspas sem fechar: o texto termina na linha
            if char == "\\":
                escaped = self.text[self.pos + 1 : self.pos + 2]
                parts.append(_ESCAPES.get(escaped, "\\" + escaped))
                self.pos += 2
                literals += 1
            elif self.text.startswith(("$${", "%%{"), self.pos):
                parts.append(self.text[self.pos + 1 : self.pos + 3])
                self.pos += 3
                literals += 1
            elif self.text.startswith(("${", "%{"), self.pos):
                start = self.pos
                self._skip_template()
                parts.append(self.text[start : self.pos])
                templates += 1
            else:
                parts.append(char)
                self.pos += 1
                literals += 1
        return "".join(parts), templates == 1 and literals == 0 and parts[0].startswith("${")

    def _skip_template(self) -> None:
        """Pula ``${ ... }`` (com chaves e textos aninhados)."""
        self.pos += 2
        depth = 1
        while self.pos < self.size and depth:
            char = self.text[self.pos]
            if char == '"':
                self._string()
                continue
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            self.pos += 1

    def _heredoc(self) -> str | None:
        match = _HEREDOC.match(self.text, self.pos)
        if match is None:
            return None
        marker = match.group(1)
        index = match.end()
        lines: list[str] = []
        while index < self.size:
            end = self.text.find("\n", index)
            end = self.size if end < 0 else end
            line = self.text[index:end]
            if line.strip() == marker:
                self.pos = end
                return "\n".join(lines)
            lines.append(line.rstrip("\r"))
            index = end + 1
        self.pos = self.size
        return "\n".join(lines)
