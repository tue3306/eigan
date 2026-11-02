"""Visões do código-fonte usadas pelas regras de SAST.

Um leitor simples por linguagem separa comentários e strings do código, sem
interpretar nem executar nada, e produz duas cópias do texto **com o mesmo tamanho
e as mesmas quebras de linha** (uma posição vale para as três versões):

- ``code``: comentários apagados, strings preservadas;
- ``nostr``: comentários apagados e o conteúdo das strings também; ficam só as aspas
  e as expressões interpoladas (``f"{x}"``, ``${x}``, ``#{x}``, ``"$x"``, ``$"{x}"``).

Assim ``eval(x)`` dentro de um comentário ou de um texto não dispara regra nenhuma,
e uma regra consegue distinguir ``os.system("ls")`` de ``os.system(f"ls {pasta}")``.
O leitor erra para o lado seguro: quando se perde (texto de JSX com apóstrofo, por
exemplo), esconde código até o fim da linha em vez de inventar um achado.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

_NOT_NEWLINE = re.compile(r"[^\n]")
_MAX_NESTING = 16

PYTHON = "python"
JAVASCRIPT = "javascript"
PHP = "php"
JAVA = "java"
CSHARP = "csharp"
GO = "go"
RUBY = "ruby"


@dataclass(frozen=True)
class MaskedSource:
    """O texto original e as duas visões (ver o início do módulo)."""

    raw: str
    code: str
    nostr: str


class _Scan:
    """Acumula, em ordem, os trechos a apagar em cada visão."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.comments: list[tuple[int, int]] = []
        self.blanks: list[tuple[int, int]] = []

    def comment(self, start: int, end: int) -> None:
        if end > start:
            self.comments.append((start, end))
            self.blanks.append((start, end))

    def literal(self, start: int, end: int, holes: list[tuple[int, int]] | None = None) -> None:
        """Conteúdo de string: some da visão ``nostr``, menos as expressões interpoladas."""
        cursor = start
        for hole_start, hole_end in holes or ():
            if hole_start > cursor:
                self.blanks.append((cursor, hole_start))
            cursor = max(cursor, hole_end)
        if end > cursor:
            self.blanks.append((cursor, end))


def _apply(text: str, spans: list[tuple[int, int]]) -> str:
    if not spans:
        return text
    parts: list[str] = []
    cursor = 0
    for start, end in spans:
        parts.append(text[cursor:start])
        parts.append(_NOT_NEWLINE.sub(" ", text[start:end]))
        cursor = end
    parts.append(text[cursor:])
    return "".join(parts)


def mask_source(text: str, language: str) -> MaskedSource:
    """Monta as visões de ``text`` para a linguagem (chaves: as constantes deste módulo)."""
    scanner = _SCANNERS.get(language)
    if scanner is None:
        return MaskedSource(text, text, text)
    try:
        scan = scanner(text)
    except RecursionError:  # aninhamento absurdo: melhor não analisar do que inventar
        return MaskedSource(text, _apply(text, [(0, len(text))]), _apply(text, [(0, len(text))]))
    return MaskedSource(text, _apply(text, scan.comments), _apply(text, scan.blanks))


# -- peças comuns --------------------------------------------------------------------


def _line_end(text: str, start: int) -> int:
    end = text.find("\n", start)
    return len(text) if end < 0 else end


_STOPS: dict[tuple[str, bool], re.Pattern[str]] = {}


def _stop_pattern(quote: str, multiline: bool) -> re.Pattern[str]:
    key = (quote, multiline)
    pattern = _STOPS.get(key)
    if pattern is None:
        tail = "" if multiline else r"|\n"
        pattern = re.compile(rf"\\|{re.escape(quote)}{tail}")
        _STOPS[key] = pattern
    return pattern


def _string_end(text: str, start: int, quote: str, *, multiline: bool) -> int:
    """Posição da aspa final; sem fechamento, o fim da linha (ou do arquivo se multilinha)."""
    pattern = _stop_pattern(quote, multiline)
    cursor = start
    while True:
        match = pattern.search(text, cursor)
        if match is None:
            return len(text)
        if match.group() == "\\":
            cursor = match.end() + 1
            continue
        return match.start()


def _after(text: str, end: int, quote: str) -> int:
    """Onde continuar a leitura depois de uma string que terminou em ``end``."""
    return end + len(quote) if text.startswith(quote, end) else end


def _balanced(text: str, start: int, limit: int, *, nesting: int = 0) -> int:
    """Fecha-chaves que casa com a chave aberta logo antes de ``start`` (ou ``limit``)."""
    if nesting > _MAX_NESTING:
        raise RecursionError
    depth = 1
    cursor = start
    while cursor < limit:
        char = text[cursor]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return cursor
        elif char == "`":
            cursor = _template_end(text, cursor + 1, [], nesting=nesting + 1)
        elif char in "'\"":
            cursor = _string_end(text, cursor + 1, char, multiline=False)
        cursor += 1
    return limit


def _brace_holes(text: str, start: int, end: int) -> list[tuple[int, int]]:
    """Expressões de ``f"{x}"`` (Python) e ``$"{x}"`` (C#); ``{{`` é chave literal."""
    holes: list[tuple[int, int]] = []
    cursor = start
    while True:
        cursor = text.find("{", cursor, end)
        if cursor < 0:
            return holes
        if text.startswith("{{", cursor):
            cursor += 2
            continue
        close = text.find("}", cursor, end)
        if close < 0:
            return holes
        holes.append((cursor, close + 1))
        cursor = close + 1


# -- Python ---------------------------------------------------------------------------

_PY_TOKEN = re.compile(r"""#|(?P<prefix>\b[rRbBuUfF]{1,2})?(?P<quote>\"\"\"|'''|"|')""")


def _scan_python(text: str) -> _Scan:
    scan = _Scan(text)
    cursor = 0
    while True:
        match = _PY_TOKEN.search(text, cursor)
        if match is None:
            return scan
        if match.group() == "#":
            cursor = _line_end(text, match.start())
            scan.comment(match.start(), cursor)
            continue
        quote = match.group("quote")
        end = _string_end(text, match.end(), quote, multiline=len(quote) == 3)
        prefix = (match.group("prefix") or "").lower()
        scan.literal(
            match.end(), end, _brace_holes(text, match.end(), end) if "f" in prefix else None
        )
        cursor = _after(text, end, quote)


# -- JavaScript / TypeScript -----------------------------------------------------------

_JS_TOKEN = re.compile(r"""//|/\*|`|"|'|/""")
_TEMPLATE_STOP = re.compile(r"\\|`|\$\{")
_REGEX_STOP = re.compile(r"[\\/\[\]\n]")
_BEFORE_REGEX = frozenset("(,=:[!&|?{};+-*%~^\n")
_KEYWORDS_BEFORE_VALUE = frozenset(
    {
        "return",
        "typeof",
        "case",
        "in",
        "of",
        "delete",
        "void",
        "throw",
        "new",
        "else",
        "do",
        "yield",
        "await",
    }
)


def _template_end(text: str, start: int, holes: list[tuple[int, int]], *, nesting: int = 0) -> int:
    """Crase final de um template; ``${...}`` (inclusive aninhado) vira expressão preservada."""
    if nesting > _MAX_NESTING:
        raise RecursionError
    cursor = start
    while True:
        match = _TEMPLATE_STOP.search(text, cursor)
        if match is None:
            return len(text)
        token = match.group()
        if token == "\\":
            cursor = match.end() + 1
        elif token == "`":
            return match.start()
        else:
            close = _balanced(text, match.end(), len(text), nesting=nesting)
            holes.append((match.start(), min(close + 1, len(text))))
            cursor = close + 1


def _value_position(text: str, index: int, keywords: frozenset[str]) -> bool:
    """Em ``index`` começa um valor (e não um operador de divisão, por exemplo)?"""
    cursor = index - 1
    while cursor >= 0 and text[cursor] in " \t":
        cursor -= 1
    if cursor < 0 or text[cursor] in _BEFORE_REGEX:
        return True
    if not (text[cursor].isalnum() or text[cursor] in "_$"):
        return False
    start = cursor
    while start >= 0 and (text[start].isalnum() or text[start] in "_$"):
        start -= 1
    return text[start + 1 : cursor + 1] in keywords


def _regex_end(text: str, start: int) -> int:
    """Barra final de uma expressão regular na mesma linha, ou ``-1`` se não houver."""
    in_class = False
    cursor = start
    while True:
        match = _REGEX_STOP.search(text, cursor)
        if match is None:
            return -1
        token = match.group()
        if token == "\n":
            return -1
        if token == "\\":
            cursor = match.end() + 1
            continue
        if token == "[":
            in_class = True
        elif token == "]":
            in_class = False
        elif not in_class:
            return match.start()
        cursor = match.end()


def _scan_javascript(text: str) -> _Scan:
    scan = _Scan(text)
    cursor = 0
    while True:
        match = _JS_TOKEN.search(text, cursor)
        if match is None:
            return scan
        cursor = _js_token(scan, text, match)


def _js_token(scan: _Scan, text: str, match: re.Match[str]) -> int:
    token = match.group()
    if token == "//":
        end = _line_end(text, match.start())
        scan.comment(match.start(), end)
        return end
    if token == "/*":
        return _block_comment(scan, text, match.start())
    if token == "`":
        holes: list[tuple[int, int]] = []
        end = _template_end(text, match.end(), holes)
        scan.literal(match.end(), end, holes)
        return _after(text, end, "`")
    if token == "/":
        if not _value_position(text, match.start(), _KEYWORDS_BEFORE_VALUE):
            return match.end()
        end = _regex_end(text, match.end())
        if end < 0:
            return match.end()
        scan.literal(match.end(), end)
        return end + 1
    end = _string_end(text, match.end(), token, multiline=False)
    scan.literal(match.end(), end)
    return _after(text, end, token)


def _block_comment(scan: _Scan, text: str, start: int) -> int:
    end = text.find("*/", start + 2)
    end = len(text) if end < 0 else end + 2
    scan.comment(start, end)
    return end


# -- Java e Go --------------------------------------------------------------------------

_JAVA_TOKEN = re.compile(r'''//|/\*|"""|"|\'''')
_GO_TOKEN = re.compile(r"""//|/\*|`|"|'""")


def _scan_java(text: str) -> _Scan:
    scan = _Scan(text)
    cursor = 0
    while True:
        match = _JAVA_TOKEN.search(text, cursor)
        if match is None:
            return scan
        token = match.group()
        if token == "//":
            cursor = _line_end(text, match.start())
            scan.comment(match.start(), cursor)
        elif token == "/*":
            cursor = _block_comment(scan, text, match.start())
        else:
            end = _string_end(text, match.end(), token, multiline=token == '"""')
            scan.literal(match.end(), end)
            cursor = _after(text, end, token)


def _scan_go(text: str) -> _Scan:
    scan = _Scan(text)
    cursor = 0
    while True:
        match = _GO_TOKEN.search(text, cursor)
        if match is None:
            return scan
        token = match.group()
        if token == "//":
            cursor = _line_end(text, match.start())
            scan.comment(match.start(), cursor)
        elif token == "/*":
            cursor = _block_comment(scan, text, match.start())
        elif token == "`":
            end = text.find("`", match.end())
            end = len(text) if end < 0 else end
            scan.literal(match.end(), end)
            cursor = _after(text, end, "`")
        else:
            end = _string_end(text, match.end(), token, multiline=False)
            scan.literal(match.end(), end)
            cursor = _after(text, end, token)


# -- C# ---------------------------------------------------------------------------------

_CS_TOKEN = re.compile(r'''//|/\*|\$@"|@\$"|\$"""|"""|\$"|@"|"|\'''')


def _verbatim_end(text: str, start: int) -> int:
    """Aspa final de ``@"..."``: não há escape com barra e ``""`` é uma aspa literal."""
    cursor = start
    while True:
        end = text.find('"', cursor)
        if end < 0:
            return len(text)
        if text.startswith('""', end):
            cursor = end + 2
            continue
        return end


def _scan_csharp(text: str) -> _Scan:
    scan = _Scan(text)
    cursor = 0
    while True:
        match = _CS_TOKEN.search(text, cursor)
        if match is None:
            return scan
        cursor = _cs_token(scan, text, match)


def _cs_token(scan: _Scan, text: str, match: re.Match[str]) -> int:
    token = match.group()
    if token == "//":
        end = _line_end(text, match.start())
        scan.comment(match.start(), end)
        return end
    if token == "/*":
        return _block_comment(scan, text, match.start())
    interpolated = "$" in token
    if token.endswith('"""'):
        end = text.find('"""', match.end())
        end = len(text) if end < 0 else end
        closer = '"""'
    elif "@" in token:
        end = _verbatim_end(text, match.end())
        closer = '"'
    else:
        closer = token[-1]
        end = _string_end(text, match.end(), closer, multiline=False)
    scan.literal(match.end(), end, _brace_holes(text, match.end(), end) if interpolated else None)
    return _after(text, end, closer)


# -- PHP --------------------------------------------------------------------------------

_PHP_OPEN = re.compile(r"<\?(?:php\b|=|(?=\s))", re.I)
_PHP_TOKEN = re.compile(
    r"""\?>|//|\#(?!\[)|/\*|<<<[ \t]*(?:'(?P<now>\w+)'|"?(?P<here>\w+)"?)|'|"|`"""
)
_PHP_HOLE = re.compile(
    r"(?<!\\)(?:\$[A-Za-z_]\w*(?:\[[^\]\n]*\]|->\w+)*|\{\$[^}\n]*\}|\$\{[^}\n]*\})"
)


def _php_holes(text: str, start: int, end: int) -> list[tuple[int, int]]:
    return [match.span() for match in _PHP_HOLE.finditer(text, start, end)]


def _scan_php(text: str) -> _Scan:
    scan = _Scan(text)
    cursor = 0
    while cursor < len(text):
        opening = _PHP_OPEN.search(text, cursor)
        if opening is None:
            scan.comment(cursor, len(text))  # o resto é HTML
            return scan
        scan.comment(cursor, opening.start())
        cursor = _php_code(scan, text, opening.end())
    return scan


def _php_code(scan: _Scan, text: str, start: int) -> int:
    """Lê código PHP a partir de ``start`` e devolve a posição depois de ``?>`` (ou o fim)."""
    cursor = start
    while True:
        match = _PHP_TOKEN.search(text, cursor)
        if match is None:
            return len(text)
        token = match.group()
        if token == "?>":
            return match.end()
        if token in ("//", "#"):
            cursor = _php_line_comment(scan, text, match.start())
        elif token == "/*":
            cursor = _block_comment(scan, text, match.start())
        elif token.startswith("<<<"):
            cursor = _php_heredoc(scan, text, match)
        else:
            end = _string_end(text, match.end(), token, multiline=True)
            scan.literal(
                match.end(), end, None if token == "'" else _php_holes(text, match.end(), end)
            )
            cursor = _after(text, end, token)


def _php_line_comment(scan: _Scan, text: str, start: int) -> int:
    """Comentário de linha do PHP termina na quebra de linha ou em ``?>``."""
    end = _line_end(text, start)
    closing = text.find("?>", start, end)
    if closing >= 0:
        end = closing
    scan.comment(start, end)
    return end


def _php_heredoc(scan: _Scan, text: str, match: re.Match[str]) -> int:
    label = match.group("now") or match.group("here")
    body = _line_end(text, match.end()) + 1
    closing = re.compile(rf"^[ \t]*{re.escape(label)}\b", re.M).search(text, body)
    end = closing.start() if closing else len(text)
    holes = None if match.group("now") else _php_holes(text, body, end)
    scan.literal(body, end, holes)
    return closing.end() if closing else end


# -- Ruby -------------------------------------------------------------------------------

_RUBY_TOKEN = re.compile(
    r"""^=begin\b|^__END__\s*$|\#|"|'|`|/|<<[~-]?(?P<hq>['"`]?)(?P<label>[A-Za-z_]\w*)(?P=hq)|"""
    r"""%(?P<kind>[qQwWiIxrs]?)(?P<open>[\(\[\{<|!/])""",
    re.M,
)
_RUBY_KEYWORDS = frozenset(
    {
        "if",
        "unless",
        "and",
        "or",
        "not",
        "when",
        "while",
        "until",
        "return",
        "puts",
        "print",
        "p",
        "raise",
        "then",
    }
)
_RUBY_CLOSERS = {"(": ")", "[": "]", "{": "}", "<": ">"}
_RUBY_HOLE = re.compile(r"(?<!\\)#\{")


def _ruby_holes(text: str, start: int, end: int) -> list[tuple[int, int]]:
    holes: list[tuple[int, int]] = []
    cursor = start
    while True:
        match = _RUBY_HOLE.search(text, cursor, end)
        if match is None:
            return holes
        close = _balanced(text, match.end(), end)
        holes.append((match.start(), min(close + 1, end)))
        cursor = close + 1


def _scan_ruby(text: str) -> _Scan:
    scan = _Scan(text)
    cursor = 0
    jump: tuple[int, int] | None = None  # (fim da linha do heredoc, depois do terminador)
    while True:
        match = _RUBY_TOKEN.search(text, cursor)
        if match is None:
            return scan
        if jump is not None and match.start() > jump[0]:
            cursor, jump = jump[1], None
            continue
        cursor, jump = _ruby_token(scan, text, match, jump)


def _ruby_token(
    scan: _Scan, text: str, match: re.Match[str], jump: tuple[int, int] | None
) -> tuple[int, tuple[int, int] | None]:
    token = match.group()
    start = match.start()
    if token == "=begin":
        closing = re.compile(r"^=end\b.*$", re.M).search(text, start)
        end = closing.end() if closing else len(text)
        scan.comment(start, end)
        return end, jump
    if token.startswith("__END__"):
        scan.comment(start, len(text))
        return len(text), None
    if token == "#":
        end = _line_end(text, start)
        scan.comment(start, end)
        return end, jump
    if token in ('"', "'", "`"):
        end = _string_end(text, match.end(), token, multiline=True)
        scan.literal(
            match.end(), end, None if token == "'" else _ruby_holes(text, match.end(), end)
        )
        return _after(text, end, token), jump
    if token == "/":
        return _ruby_regex(scan, text, match), jump
    if token.startswith("<<"):
        return _ruby_heredoc(scan, text, match, jump)
    return _ruby_percent(scan, text, match), jump


def _ruby_regex(scan: _Scan, text: str, match: re.Match[str]) -> int:
    if not _value_position(text, match.start(), _RUBY_KEYWORDS):
        return match.end()
    end = _regex_end(text, match.end())
    if end < 0:
        return match.end()
    scan.literal(match.end(), end, _ruby_holes(text, match.end(), end))
    return end + 1


def _ruby_heredoc(
    scan: _Scan, text: str, match: re.Match[str], jump: tuple[int, int] | None
) -> tuple[int, tuple[int, int] | None]:
    """``<<~SQL``: o corpo começa na linha seguinte (o resto desta linha ainda é código)."""
    label = match.group("label")
    squiggly = match.group().startswith(("<<~", "<<-"))
    if not squiggly and not label.isupper() and not match.group("hq"):
        return match.end(), jump  # ``lista << item``: operador, não heredoc
    if not _value_position(text, match.start(), _RUBY_KEYWORDS) and not _identifier_call(
        text, match.start()
    ):
        return match.end(), jump
    line_end = jump[0] if jump else _line_end(text, match.end())
    body = jump[1] if jump else line_end + 1
    closing = re.compile(rf"^[ \t]*{re.escape(label)}[ \t]*$", re.M).search(text, body)
    end = closing.start() if closing else len(text)
    scan_holes = None if match.group("hq") == "'" else _ruby_holes(text, body, end)
    scan.literal(body, end, scan_holes)
    return match.end(), (line_end, closing.end() if closing else len(text))


def _identifier_call(text: str, index: int) -> bool:
    """``execute <<~SQL``: identificador, espaço e o heredoc como argumento."""
    return (
        index > 0
        and text[index - 1] in " \t("
        and (index < 2 or text[index - 2].isalnum() or text[index - 2] == "_")
    )


def _ruby_percent(scan: _Scan, text: str, match: re.Match[str]) -> int:
    """``%w[...]``, ``%q(...)``, ``%x(...)``, ``%r{...}``; ``a % b`` é só o operador."""
    if not _value_position(text, match.start(), _RUBY_KEYWORDS):
        return match.end()
    opener, kind = match.group("open"), match.group("kind")
    closer = _RUBY_CLOSERS.get(opener, opener)
    end = _percent_end(text, match.end(), opener, closer)
    holes = None if kind in ("q", "w", "i", "s") else _ruby_holes(text, match.end(), end)
    scan.literal(match.end(), end, holes)
    return end + 1 if end < len(text) else end


def _percent_end(text: str, start: int, opener: str, closer: str) -> int:
    depth = 1
    cursor = start
    while cursor < len(text):
        char = text[cursor]
        if char == "\\":
            cursor += 2
            continue
        if char == closer:
            depth -= 1
            if depth == 0:
                return cursor
        elif char == opener:
            depth += 1
        cursor += 1
    return len(text)


_SCANNERS: dict[str, Callable[[str], _Scan]] = {
    PYTHON: _scan_python,
    JAVASCRIPT: _scan_javascript,
    PHP: _scan_php,
    JAVA: _scan_java,
    CSHARP: _scan_csharp,
    GO: _scan_go,
    RUBY: _scan_ruby,
}
