"""Leitores de configuração do nginx e do Apache (inclusive ``.htaccess``).

Os dois leitores transformam o arquivo em uma lista de :class:`Directive` (nome,
argumentos, linha e blocos onde a diretiva está) respeitando comentários, aspas
e continuação de linha, e depois avaliam só diretivas **explícitas** — o que vale
por padrão só vira achado quando o padrão é inseguro e documentado (``server_tokens``
do nginx e ``ServerTokens`` do Apache), e mesmo assim com confiança TENTATIVE.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from ...core.models import Confidence, Severity
from .config_common import (
    ERRORS,
    LISTING,
    TLS_OLD,
    TRACE,
    URL_INCLUDE,
    VERSION,
    ConfigIssue,
    ConfigResult,
    Directive,
    clip,
    truthy,
)

#: protocolos obsoletos -> severidade (SSLv2/SSLv3 proibidos; TLS 1.0/1.1 descontinuados)
OLD_PROTOCOLS: dict[str, Severity] = {
    "sslv2": Severity.HIGH,
    "sslv3": Severity.HIGH,
    "tlsv1": Severity.MEDIUM,
    "tlsv1.1": Severity.MEDIUM,
}
_MODERN = ("tlsv1.2", "tlsv1.3")
_PROTOCOL_LABEL = {
    "sslv2": "SSLv2",
    "sslv3": "SSLv3",
    "tlsv1": "TLS 1.0",
    "tlsv1.1": "TLS 1.1",
    "tlsv1.2": "TLS 1.2",
    "tlsv1.3": "TLS 1.3",
}


def line_text(lines: list[str], number: int) -> str:
    """Texto da linha ``number`` (1-based) pronto para evidência."""
    if 1 <= number <= len(lines):
        return clip(lines[number - 1].strip())
    return ""


# -- nginx ----------------------------------------------------------------------------


def _closing_quote(text: str, start: int) -> int:
    quote = text[start]
    index = start + 1
    while index < len(text):
        if text[index] == "\\":
            index += 2
            continue
        if text[index] == quote:
            return index
        index += 1
    return len(text)


def _nginx_word_end(text: str, start: int) -> int:
    index = start
    while index < len(text) and not text[index].isspace() and text[index] not in "{};'\"":
        if text.startswith("${", index):
            close = text.find("}", index)
            index = len(text) if close < 0 else close + 1
            continue
        index += 1
    return index


def _nginx_tokens(text: str) -> Iterator[tuple[str, int, bool]]:
    """``(token, linha, especial)`` — especial para ``{``, ``}`` e ``;``."""
    index, line = 0, 1
    while index < len(text):
        char = text[index]
        if char == "\n":
            line += 1
            index += 1
        elif char.isspace():
            index += 1
        elif char == "#":
            end = text.find("\n", index)
            index = len(text) if end < 0 else end
        elif char in "{};":
            yield char, line, True
            index += 1
        elif char in "'\"":
            end = _closing_quote(text, index)
            token = text[index + 1 : end]
            yield token, line, False
            line += token.count("\n")
            index = end + 1
        else:
            end = _nginx_word_end(text, index)
            yield text[index:end], line, False
            index = max(end, index + 1)


def parse_nginx(text: str) -> list[Directive]:
    """Diretivas do nginx (inclusive as que abrem blocos, como ``http`` e ``location``)."""
    found: list[Directive] = []
    stack: list[str] = []
    words: list[str] = []
    first = 0
    for token, line, special in _nginx_tokens(text):
        if not special:
            if not words:
                first = line
            words.append(token)
            continue
        if token == "{":
            if words:
                found.append(Directive(words[0], tuple(words[1:]), first, tuple(stack)))
            stack.append(" ".join(words) or "{")
        elif token == ";" and words:
            found.append(Directive(words[0], tuple(words[1:]), first, tuple(stack)))
        elif token == "}" and stack:
            stack.pop()
        words = []
    return found


def nginx_sets_tokens(directives: list[Directive]) -> bool:
    return any(d.name == "server_tokens" for d in directives)


def check_nginx(
    text: str, directives: list[Directive], *, tokens_elsewhere: bool = False
) -> ConfigResult:
    """Avalia um arquivo do nginx já analisado."""
    result = ConfigResult()
    lines = text.splitlines()
    for directive in directives:
        if not directive.args:
            continue
        if directive.name == "server_tokens":
            _nginx_tokens_issue(directive, lines, result)
        elif directive.name == "autoindex" and directive.args[0].lower() == "on":
            result.add(
                _issue(
                    LISTING, directive, lines, "nginx", "autoindex off;", "nginx com autoindex on"
                )
            )
        elif directive.name == "ssl_protocols":
            _protocols(directive, lines, result, "nginx", _nginx_protocols(directive.args))
    http = next((d for d in directives if d.name == "http" and not d.context), None)
    if http is not None and not nginx_sets_tokens(directives) and not tokens_elsewhere:
        result.add(
            ConfigIssue(
                VERSION,
                http.line,
                "nginx sem server_tokens off (o padrão divulga a versão)",
                line_text(lines, http.line),
                confidence=Confidence.TENTATIVE,
                discriminator="nginx:server_tokens",
                details={
                    "tipo": "nginx",
                    "diretiva": "server_tokens",
                    "valor": "(ausente: padrão on)",
                    "recomendado": "server_tokens off;",
                },
            )
        )
    return result


def _nginx_tokens_issue(directive: Directive, lines: list[str], result: ConfigResult) -> None:
    value = directive.args[0].lower()
    if value in ("on", "build"):
        result.add(
            _issue(
                VERSION,
                directive,
                lines,
                "nginx",
                "server_tokens off;",
                f"nginx com server_tokens {value} (versão no cabeçalho Server)",
            )
        )
    elif value == "off":
        result.ok("code.config.versao", "nginx configurado com server_tokens off")


def _nginx_protocols(args: tuple[str, ...]) -> tuple[set[str], bool]:
    return {arg.lower() for arg in args}, True


# -- Apache ---------------------------------------------------------------------------

_WORDS = re.compile(r'"((?:[^"\\]|\\.)*)"|\'([^\']*)\'|(\S+)')


def split_words(text: str) -> list[str]:
    """Palavras de uma linha do Apache, respeitando aspas simples e duplas."""
    return [a or b or c for a, b, c in _WORDS.findall(text)]


def _logical_lines(text: str) -> Iterator[tuple[int, str]]:
    """Linhas lógicas (``\\`` no fim continua na linha seguinte) com o número da primeira."""
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        start, current = index, lines[index]
        while current.rstrip().endswith("\\") and index + 1 < len(lines):
            index += 1
            current = current.rstrip()[:-1] + " " + lines[index]
        index += 1
        yield start + 1, current


def parse_apache(text: str) -> list[Directive]:
    """Diretivas do Apache com as seções (``<Directory>``, ``<VirtualHost>``...) onde estão."""
    found: list[Directive] = []
    stack: list[str] = []
    for number, raw in _logical_lines(text):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("</"):
            if stack:
                stack.pop()
            continue
        if stripped.startswith("<"):
            inner = stripped[1:].rstrip(">").strip()
            words = split_words(inner)
            if words:
                found.append(Directive("<" + words[0], tuple(words[1:]), number, tuple(stack)))
                stack.append(inner)
            continue
        words = split_words(stripped)
        if words:
            found.append(Directive(words[0], tuple(words[1:]), number, tuple(stack)))
    return found


def apache_sets_tokens(directives: list[Directive]) -> bool:
    return any(d.lname == "servertokens" for d in directives)


_LEAKY_TOKENS = frozenset({"full", "os", "min", "minimal", "minor", "major"})
_SAFE_TOKENS = frozenset({"prod", "productonly"})
_PHP_SETTERS = frozenset({"php_flag", "php_value", "php_admin_flag", "php_admin_value"})


def check_apache(
    text: str,
    directives: list[Directive],
    *,
    main: bool = False,
    htaccess: bool = False,
    tokens_elsewhere: bool = False,
) -> ConfigResult:
    """Avalia um arquivo do Apache (``main``: httpd.conf/apache2.conf)."""
    result = ConfigResult()
    lines = text.splitlines()
    indexes_on: dict[str, Directive] = {}
    for directive in directives:
        if not directive.args:
            continue
        name = directive.lname
        if name == "servertokens":
            _server_tokens(directive, lines, result)
        elif name == "serversignature" and directive.args[0].lower() in ("on", "email"):
            result.add(
                _issue(
                    VERSION,
                    directive,
                    lines,
                    "apache",
                    "ServerSignature Off",
                    "Apache com ServerSignature On (versão no rodapé das páginas de erro)",
                )
            )
        elif name == "traceenable":
            _trace(directive, lines, result)
        elif name == "options":
            # vale o último Options do mesmo bloco: "Options Indexes" + "Options -Indexes" não lista
            key = directive.where or ""
            if _enables_indexes(directive.args, key in indexes_on):
                indexes_on[key] = directive
            else:
                indexes_on.pop(key, None)
        elif name == "sslprotocol":
            _protocols(directive, lines, result, "Apache", _apache_protocols(directive.args))
        elif name in _PHP_SETTERS and len(directive.args) >= 2:
            _php_setter(directive, lines, result, htaccess=htaccess)
    for directive in indexes_on.values():
        result.add(
            _issue(
                LISTING,
                directive,
                lines,
                "apache",
                "Options -Indexes",
                "Apache com Options Indexes",
            )
        )
    if main and directives and not apache_sets_tokens(directives) and not tokens_elsewhere:
        result.add(
            ConfigIssue(
                VERSION,
                0,
                "Apache sem ServerTokens Prod (o padrão Full divulga a versão)",
                "",
                confidence=Confidence.TENTATIVE,
                discriminator="apache:ServerTokens",
                details={
                    "tipo": "apache",
                    "diretiva": "ServerTokens",
                    "valor": "(ausente: padrão Full)",
                    "recomendado": "ServerTokens Prod",
                },
            )
        )
    return result


def _server_tokens(directive: Directive, lines: list[str], result: ConfigResult) -> None:
    value = directive.args[0].lower()
    if value in _LEAKY_TOKENS:
        result.add(
            _issue(
                VERSION,
                directive,
                lines,
                "apache",
                "ServerTokens Prod",
                f"Apache com ServerTokens {directive.args[0]} (versão no cabeçalho Server)",
            )
        )
    elif value in _SAFE_TOKENS:
        result.ok("code.config.versao", "Apache configurado com ServerTokens Prod")


def _trace(directive: Directive, lines: list[str], result: ConfigResult) -> None:
    value = directive.args[0].lower()
    if value in ("on", "extended"):
        result.add(
            _issue(
                TRACE,
                directive,
                lines,
                "apache",
                "TraceEnable Off",
                f"Apache com TraceEnable {directive.args[0]}",
            )
        )
    elif value == "off":
        result.ok("code.config.trace", "Apache configurado com TraceEnable Off")


def _enables_indexes(args: tuple[str, ...], inherited: bool = False) -> bool:
    """Estado final de Indexes após ``Options`` (tokens aplicados da esquerda para a direita).

    ``All`` e ``+Indexes`` ligam; ``-Indexes`` e ``-All`` desligam; sem nenhum sinal, a
    lista substitui a herdada.
    """
    lowered = [arg.lower() for arg in args]
    state = inherited and all(arg[:1] in ("+", "-") for arg in lowered)
    for arg in lowered:
        if arg in ("indexes", "+indexes", "all", "+all"):
            state = True
        elif arg in ("-indexes", "-all"):
            state = False
    return state


def _apache_protocols(args: tuple[str, ...]) -> tuple[set[str], bool]:
    """Protocolos resultantes de ``SSLProtocol`` (``all``, ``+X``, ``-X`` em sequência).

    Devolve também se a leitura é segura: várias palavras sem ``+``/``-`` têm
    semântica ambígua (o mod_ssl avisa que uma pode sobrescrever a outra).
    """
    enabled: set[str] = set()
    explicit: set[str] = set()
    bare = 0
    for raw in args:
        word = raw.lower()
        sign = word[0] if word[:1] in ("+", "-") else ""
        name = word[1:] if sign else word
        protocols = {"tlsv1", "tlsv1.1", "tlsv1.2", "tlsv1.3"} if name == "all" else {name}
        if sign == "-":
            enabled -= protocols
            continue
        if not sign:
            bare += 1
        enabled |= protocols
        if name != "all":
            explicit |= protocols
    # só o atalho "all": a política do sistema (MinProtocol do OpenSSL) pode desligar TLS 1.0/1.1
    return enabled, bare <= 1 and bool(enabled & explicit & set(OLD_PROTOCOLS))


def _php_setter(
    directive: Directive, lines: list[str], result: ConfigResult, *, htaccess: bool
) -> None:
    """``php_flag display_errors on`` e ``php_admin_flag allow_url_include on``."""
    setting = directive.args[0].lower()
    value = directive.args[1]
    if setting == "display_errors" and (truthy(value) or value.lower() == "stdout"):
        result.add(
            _issue(
                ERRORS,
                directive,
                lines,
                "apache",
                f"{directive.name} display_errors off",
                "PHP com display_errors ligado na configuração do Apache",
                discriminator="apache:display_errors",
            )
        )
    admin = directive.lname.startswith("php_admin_")
    if setting == "allow_url_include" and truthy(value) and admin and not htaccess:
        result.add(
            _issue(
                URL_INCLUDE,
                directive,
                lines,
                "apache",
                f"{directive.name} allow_url_include off",
                "PHP com allow_url_include ligado na configuração do Apache",
                discriminator="apache:allow_url_include",
            )
        )


# -- comuns ----------------------------------------------------------------------------


def _protocols(
    directive: Directive,
    lines: list[str],
    result: ConfigResult,
    server: str,
    parsed: tuple[set[str], bool],
) -> None:
    enabled, certain = parsed
    old = sorted((p for p in enabled if p in OLD_PROTOCOLS), key=list(OLD_PROTOCOLS).index)
    if not old:
        if enabled & set(_MODERN):
            result.ok("code.config.tls", f"{server} aceita só TLS 1.2/1.3 ({directive.text()})")
        return
    severity = max((OLD_PROTOCOLS[p] for p in old), key=lambda s: s.rank)
    labels = ", ".join(_PROTOCOL_LABEL[p] for p in old)
    kind = "nginx" if server == "nginx" else "apache"
    recommended = (
        "ssl_protocols TLSv1.2 TLSv1.3;"
        if kind == "nginx"
        else "SSLProtocol -all +TLSv1.2 +TLSv1.3"
    )
    issue = _issue(TLS_OLD, directive, lines, kind, recommended, f"{server} aceita {labels}")
    issue.severity = severity
    issue.confidence = Confidence.FIRM if certain else Confidence.TENTATIVE
    issue.details["protocolos_antigos"] = [_PROTOCOL_LABEL[p] for p in old]
    result.add(issue)


def _issue(
    finding: str,
    directive: Directive,
    lines: list[str],
    kind: str,
    recommended: str,
    title: str,
    *,
    discriminator: str = "",
) -> ConfigIssue:
    details: dict[str, Any] = {
        "tipo": kind,
        "diretiva": directive.name,
        "valor": " ".join(directive.args),
        "recomendado": recommended,
    }
    if directive.where:
        details["bloco"] = directive.where
    return ConfigIssue(
        finding,
        directive.line,
        title,
        line_text(lines, directive.line),
        discriminator=discriminator or f"{kind}:{directive.lname}",
        details=details,
    )
