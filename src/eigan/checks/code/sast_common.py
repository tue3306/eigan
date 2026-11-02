"""Peças comuns do SAST por regras: ids dos achados, a regra e as confirmações.

Uma regra é uma expressão regular que acha o ponto perigoso (o *sink*) em uma das
visões do código (``sast_mask``) mais uma confirmação opcional, que olha os
argumentos da chamada. A pergunta central é sempre a mesma: o valor que chega ali é
constante, é uma variável ou é um texto montado com variáveis? E há sinal de que veio
direto da requisição? As respostas definem severidade e confiança; sem evidência de
entrada externa o achado é um pedido de revisão, nunca uma vulnerabilidade confirmada.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import cached_property

from ...core.models import Confidence, Severity
from .sast_mask import CSHARP, GO, JAVA, JAVASCRIPT, PHP, PYTHON, RUBY, MaskedSource

EVAL = "code.sast.execucao_dinamica"
COMMAND = "code.sast.comando_shell"
DESER = "code.sast.desserializacao_insegura"
SQL = "code.sast.sql_concatenado"
TLS = "code.sast.tls_sem_verificacao"
WEAK_HASH = "code.sast.hash_fraco_senha"
WEAK_RANDOM = "code.sast.aleatorio_inseguro"
XSS = "code.sast.xss_dom"
PHP_INCLUDE = "code.sast.php_include_entrada"
PHP_EXTRACT = "code.sast.php_extract_entrada"
JWT = "code.sast.jwt_sem_verificacao"
XXE = "code.sast.xxe_parser_xml"

SAST_FINDINGS = (
    EVAL,
    COMMAND,
    DESER,
    SQL,
    TLS,
    WEAK_HASH,
    WEAK_RANDOM,
    XSS,
    PHP_INCLUDE,
    PHP_EXTRACT,
    JWT,
    XXE,
)

#: achado -> (CWE, OWASP Top 10 2021); CWE-621 não está mapeada: A03 é a categoria mais próxima
CLASSIFICATION: dict[str, tuple[str, str]] = {
    EVAL: ("CWE-95", "A03:2021"),
    COMMAND: ("CWE-78", "A03:2021"),
    DESER: ("CWE-502", "A08:2021"),
    SQL: ("CWE-89", "A03:2021"),
    TLS: ("CWE-295", "A07:2021"),
    WEAK_HASH: ("CWE-916", "A02:2021"),
    WEAK_RANDOM: ("CWE-338", "A02:2021"),
    XSS: ("CWE-79", "A03:2021"),
    PHP_INCLUDE: ("CWE-98", "A03:2021"),
    PHP_EXTRACT: ("CWE-621", "A03:2021"),
    JWT: ("CWE-347", "A02:2021"),
    XXE: ("CWE-611", "A05:2021"),
}

CONSTANT = "constante"
VARIABLE = "variavel"
INTERPOLATED = "interpolado"

#: de onde vem a entrada externa, por linguagem (só requisições: argumentos de linha de
#: comando são de quem já executa o programa e não contam como fronteira de confiança)
_INPUT_SOURCES: dict[str, str] = {
    PYTHON: (
        r"\brequest\.(?:args|form|values|json|data|files|cookies|headers|GET|POST|COOKIES|META|FILES|body|"
        r"query_params|query_string|get_json|get_data|path_params)\b"
    ),
    JAVASCRIPT: (
        r"\b(?:req|request)\.(?:body|query|params|headers|cookies|url|originalUrl|files)\b|"
        r"\bctx\.(?:query|params|request\.body)\b|"
        r"\blocation\.(?:search|hash|href|pathname)\b|"
        r"\bdocument\.(?:URL|documentURI|referrer|cookie|baseURI)\b|"
        r"\bwindow\.name\b|\bURLSearchParams\b"
    ),
    PHP: (
        r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b|"
        r"\$HTTP_(?:GET|POST|COOKIE)_VARS\b"
    ),
    JAVA: (
        r"\.getParameter(?:Values|Map)?\s*\(|\.getHeader\s*\(|\.getQueryString\s*\(|\.getCookies\s*\(|"
        r"\b(?:request|req|httpRequest|servletRequest)\.get(?:InputStream|Reader|PathInfo|RequestURI)\s*\(|"
        r"\bsocket\.getInputStream\s*\("
    ),
    CSHARP: (
        r"\bRequest\.(?:Query|Form|Cookies|Headers|QueryString|Params|Body|RouteValues|InputStream)\b|"
        r"\bHttpContext\.Request\b"
    ),
    GO: (
        r"\b(?:r|req|request)\.(?:URL|Form|PostForm|FormValue|PostFormValue|Header|Body|Cookie|MultipartForm)\b|"
        r"\b(?:c|ctx)\.(?:Query|DefaultQuery|Param|PostForm|DefaultPostForm|FormValue|GetHeader)\s*\("
    ),
    RUBY: (
        r"\bparams\[|\bparams\.(?:fetch|require|permit|dig)\b|"
        r"\brequest\.(?:params|env|headers|body|query_string|cookies|referer|url)\b|\bcookies\["
    ),
}
_SERVER_ATTACKER_KEY = re.compile(
    r"""\$_SERVER\s*\[\s*['"](?:HTTP_\w+|REQUEST_URI|QUERY_STRING|PATH_INFO|PHP_SELF|PATH_TRANSLATED|argv)['"]"""
)
_FUNCTION_START = re.compile(
    r"^\s*(?:(?:async\s+)?def\s|(?:export\s+)?(?:async\s+)?function\b|func\s|"
    r"(?:public|private|protected|static|internal)\b[^=;]*\)\s*\{?\s*$)"
)
INPUT_SOURCES: dict[str, re.Pattern[str]] = {
    key: re.compile(value) for key, value in _INPUT_SOURCES.items()
}

#: valores saneados não contam como entrada: número convertido, escape do banco etc.
_SANITIZED_LINE = re.compile(
    r"\b(?:intval|floatval|int|float|parseInt|parseFloat|Number|Integer\.parseInt|Long\.parseLong|"
    r"int\.Parse|long\.Parse|strconv\.Atoi|htmlspecialchars|htmlentities|escapeshellarg|"
    r"filter_input|filter_var|mysqli_real_escape_string|shlex\.quote|basename)\s*\(|"
    r"\(int\)\s*\$|\.to_i\b|\.to_f\b"
)

_ASSIGNED = re.compile(
    r"^\s*(?:(?:const|let|var|final|public|private|protected|static|val|auto)\s+)*"
    r"(?P<lhs>[^=\n]+?)\s*(?::=|(?<![=!<>+\-*/%|&^~.])=(?![=>~]))"
)
_NAME = re.compile(r"[$@]*[A-Za-z_][\w$]*")
_LAST_NAME = re.compile(r"([$@]*[A-Za-z_][\w$]*)\s*(?:\[[^\]]*\])?\s*$")
_PREFIX = re.compile(r"(?<![\w$.])(?:[rRbBuUfF]{1,2}|\$@|@\$|\$|@)(?=[\"'`])")
_QUOTES = re.compile(r"[\"'`]")
_NOT_NAMES = frozenset(
    {
        "None",
        "True",
        "False",
        "null",
        "true",
        "false",
        "nil",
        "undefined",
        "NULL",
        "this",
        "self",
        "new",
        "and",
        "or",
        "not",
        "in",
        "as",
        "string",
    }
)
_DEFINITION_BEFORE = re.compile(r"\b(?:def|functionb|func|fun|sub)\s+$")
_MAX_ARGS_SPAN = 6000


@dataclass(frozen=True)
class Arg:
    """Um argumento de chamada: posição e texto nas duas visões."""

    start: int
    end: int
    nostr: str
    code: str


@dataclass(frozen=True)
class Verdict:
    """Resultado da confirmação de uma regra."""

    input_kind: str = ""  # "direta", "indireta" ou "" (sem evidência de entrada externa)
    interpolated: bool = False
    index: int | None = None  # outra posição para reportar (senão, o início do casamento)
    severity: Severity | None = None
    confidence: Confidence | None = None


class Hit:
    """Um casamento de regra em um arquivo, com acesso preguiçoso aos argumentos."""

    def __init__(
        self,
        source: MaskedSource,
        match: re.Match[str],
        language: str,
        tainted: Callable[[], dict[str, int]],
    ) -> None:
        self.source = source
        self.match = match
        self.language = language
        self._tainted = tainted

    @cached_property
    def args(self) -> list[Arg]:
        """Argumentos da primeira chamada que começa no casamento (ou lista vazia)."""
        begin = self.match.start()
        if "call" in self.match.re.groupindex and self.match.start("call") >= 0:
            begin = self.match.start("call")  # grupo nomeado: abre na chamada que importa
        opening = self.source.nostr.find("(", begin, self.match.end() + 1)
        if opening < 0:
            return []
        return call_args(self.source, opening)

    def input_kind(self, text: str) -> str:
        """``direta``/``indireta`` se ``text`` (visão sem strings) traz entrada externa."""
        pattern = INPUT_SOURCES.get(self.language)
        if pattern is not None and pattern.search(text) and not _SANITIZED_LINE.search(text):
            return "direta"
        if self.language == PHP and "$_SERVER" in text and self._server_input():
            return "direta"
        tainted = self._tainted()
        if not tainted:
            return ""
        position = self.match.start()
        for name in _NAME.findall(text):
            first = tainted.get(name)
            if (
                first is not None
                and first < position
                and self._still_tainted(name, first, position)
            ):
                return "indireta"
        return ""

    def _still_tainted(self, name: str, first: int, position: int) -> bool:
        """Entre a origem e o uso não há outra função nem reatribuição do nome."""
        between = self.source.nostr[first:position]
        lines = between.split("\n")[1:]
        for line in lines:
            if _FUNCTION_START.match(line):
                return False
        bare = re.escape(name.lstrip("$@"))
        assign = re.compile(
            r"^\s*[$@]?(?:(?:var|let|const|final|String)\s+)?[$@]?"
            + bare
            + r"\s*=(?!=)(?P<rhs>.*)$"
        )
        inputs = INPUT_SOURCES[self.language]
        for line in lines:
            found = assign.match(line)
            if found is None:
                continue
            rhs = found.group("rhs")
            if inputs.search(rhs):
                continue
            if re.search(r"[$@]?" + bare + r"\b", rhs) and not _SANITIZED_LINE.search(rhs):
                continue  # d = d + "x": continua contaminado
            return False
        return True

    def _server_input(self) -> bool:
        """``$_SERVER`` só conta quando a chave é controlada por quem faz a requisição."""
        start = self.match.start()
        end = self.source.code.find(";", start)
        window = self.source.code[start : start + 400 if end < 0 else min(end, start + 400)]
        return _SERVER_ATTACKER_KEY.search(window) is not None

    def is_definition(self) -> bool:
        """O casamento é a definição de uma função com esse nome (``def eval(...)``)."""
        start = self.match.start()
        return _DEFINITION_BEFORE.search(self.source.nostr[max(0, start - 16) : start]) is not None


Confirm = Callable[[Hit], Verdict | None]


@dataclass(frozen=True)
class SastRule:
    """Uma regra: id, linguagens, padrão, severidade, confiança e classificação."""

    id: str
    finding: str
    languages: tuple[str, ...]
    pattern: re.Pattern[str]
    title: str
    keywords: tuple[str, ...]
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.TENTATIVE
    severity_input: Severity = Severity.HIGH
    view: str = "nostr"  # "nostr" ou "code"
    requires: re.Pattern[str] | None = None  # só vale se o arquivo tiver isto (biblioteca)
    unless: re.Pattern[str] | None = None  # não vale se o arquivo tiver isto (defesa)
    confirm: Confirm | None = None
    tags: tuple[str, ...] = field(default=())

    @property
    def cwe(self) -> str:
        return CLASSIFICATION[self.finding][0]

    @property
    def owasp(self) -> str:
        return CLASSIFICATION[self.finding][1]


def make_rule(
    rule_id: str,
    finding: str,
    language: str,
    pattern: str,
    title: str,
    *,
    keywords: tuple[str, ...],
    severity: Severity = Severity.MEDIUM,
    confidence: Confidence = Confidence.TENTATIVE,
    severity_input: Severity = Severity.HIGH,
    view: str = "nostr",
    requires: str | None = None,
    unless: str | None = None,
    confirm: Confirm | None = None,
) -> SastRule:
    """Atalho para montar uma regra compilando as expressões."""
    return SastRule(
        rule_id,
        finding,
        (language,),
        re.compile(pattern),
        title,
        keywords,
        severity,
        confidence,
        severity_input,
        view,
        re.compile(requires) if requires else None,
        re.compile(unless) if unless else None,
        confirm,
    )


# -- argumentos -------------------------------------------------------------------------

_OPENERS = "([{"
_CLOSERS = ")]}"


def call_args(source: MaskedSource, opening: int) -> list[Arg]:
    """Argumentos da chamada cujo ``(`` está em ``opening``, separados por vírgula de nível zero."""
    nostr = source.nostr
    limit = min(len(nostr), opening + _MAX_ARGS_SPAN)
    depth = 0
    start = opening + 1
    args: list[Arg] = []
    for index in range(opening + 1, limit):
        char = nostr[index]
        if char in _OPENERS:
            depth += 1
        elif char in _CLOSERS:
            if depth == 0:
                _append_arg(args, source, start, index)
                return args
            depth -= 1
        elif char == "," and depth == 0:
            _append_arg(args, source, start, index)
            start = index + 1
    return args


def _append_arg(args: list[Arg], source: MaskedSource, start: int, end: int) -> None:
    if source.nostr[start:end].strip():
        args.append(Arg(start, end, source.nostr[start:end], source.code[start:end]))


def statement_arg(source: MaskedSource, start: int, *, stops: str = ";") -> Arg:
    """Expressão que começa em ``start`` e vai até ``;``/fim de linha fora de parênteses.

    Continua na linha seguinte se a linha termina (ou a próxima começa) com operador.
    """
    nostr = source.nostr
    limit = min(len(nostr), start + _MAX_ARGS_SPAN)
    depth = 0
    index = start
    while index < limit:
        char = nostr[index]
        if char in _OPENERS:
            depth += 1
        elif char in _CLOSERS:
            if depth == 0:
                break
            depth -= 1
        elif depth == 0 and char in stops:
            break
        elif depth == 0 and char == "\n" and not _continues(nostr, start, index):
            break
        index += 1
    return Arg(start, index, nostr[start:index], source.code[start:index])


def _continues(nostr: str, start: int, newline: int) -> bool:
    """A expressão continua depois desta quebra de linha?"""
    before = nostr[start:newline].rstrip()
    after = nostr[newline + 1 : newline + 80].lstrip(" \t")
    return before.endswith(("+", ".", ",", "%", "(", "\\")) or after.startswith(("+", ".", "%"))


def classify(nostr: str, neutralize: re.Pattern[str] | None = None) -> str:
    """Constante, variável pura ou texto montado com variáveis (ver ``sast_mask``)."""
    text = neutralize.sub(" ", nostr) if neutralize is not None else nostr
    text = _PREFIX.sub("", text)
    quoted = _QUOTES.search(text) is not None
    names = [name for name in _NAME.findall(_QUOTES.sub(" ", text)) if not _is_constant_name(name)]
    if not names:
        return CONSTANT
    return INTERPOLATED if quoted else VARIABLE


def _is_constant_name(name: str) -> bool:
    if name in _NOT_NAMES:
        return True
    return name[0] not in "$@" and name.upper() == name and any(c.isalpha() for c in name)


def tainted_names(source: MaskedSource, language: str) -> dict[str, int]:
    """Nomes que recebem entrada externa direto (``x = request.args["y"]``) -> posição."""
    pattern = INPUT_SOURCES.get(language)
    if pattern is None:
        return {}
    nostr = source.nostr
    found: dict[str, int] = {}
    last_line = -1
    for match in pattern.finditer(nostr):
        line_start = nostr.rfind("\n", 0, match.start()) + 1
        if line_start == last_line:
            continue
        last_line = line_start
        line_end = nostr.find("\n", match.start())
        line = nostr[line_start : len(nostr) if line_end < 0 else line_end]
        if _SANITIZED_LINE.search(line):
            continue
        for name in _assigned_names(line):
            found.setdefault(name, line_start)
    return found


def _assigned_names(line: str) -> list[str]:
    """Nomes à esquerda de uma atribuição (``a = ...``, ``String a = ...``, ``{a, b} = ...``)."""
    match = _ASSIGNED.match(line)
    if match is None:
        return []
    lhs = match.group("lhs").strip()
    if lhs.startswith("{"):
        return _NAME.findall(lhs)
    names: list[str] = []
    for part in lhs.split(","):
        last = _LAST_NAME.search(part)
        if last is not None:
            names.append(last.group(1))
    return names


# -- confirmações reutilizáveis -----------------------------------------------------------


def dynamic_arg(
    index: int = 0,
    *,
    needs: str | None = None,
    avoid: str | None = None,
    neutralize: re.Pattern[str] | None = None,
) -> Confirm:
    """O argumento ``index`` não é constante; ``needs``/``avoid`` olham os argumentos todos."""
    needs_re = re.compile(needs) if needs else None
    avoid_re = re.compile(avoid) if avoid else None

    def confirm(hit: Hit) -> Verdict | None:
        if hit.is_definition() or len(hit.args) <= index:
            return None
        whole = " ".join(arg.nostr for arg in hit.args)
        if needs_re is not None and not needs_re.search(whole):
            return None
        if avoid_re is not None and avoid_re.search(whole):
            return None
        kind = classify(hit.args[index].nostr, neutralize)
        if kind == CONSTANT:
            return None
        return Verdict(hit.input_kind(hit.args[index].nostr), kind == INTERPOLATED)

    return confirm


def any_dynamic_arg(neutralize: re.Pattern[str] | None = None) -> Confirm:
    """Algum argumento não é constante (``new Function("a", corpo)``)."""

    def confirm(hit: Hit) -> Verdict | None:
        if hit.is_definition():
            return None
        kinds = [classify(arg.nostr, neutralize) for arg in hit.args]
        if not kinds or all(kind == CONSTANT for kind in kinds):
            return None
        whole = " ".join(arg.nostr for arg in hit.args)
        return Verdict(hit.input_kind(whole), INTERPOLATED in kinds)

    return confirm


def last_arg_dynamic(neutralize: re.Pattern[str] | None = None) -> Confirm:
    """O último argumento não é constante (``exec.Command("sh", "-c", comando)``)."""

    def confirm(hit: Hit) -> Verdict | None:
        if not hit.args:
            return None
        last = hit.args[-1]
        kind = classify(last.nostr, neutralize)
        if kind == CONSTANT:
            return None
        return Verdict(hit.input_kind(last.nostr), kind == INTERPOLATED)

    return confirm


def input_required(index: int | None = None) -> Confirm:
    """Só vale com entrada externa no argumento (ou em qualquer um, sem ``index``)."""

    def confirm(hit: Hit) -> Verdict | None:
        if hit.is_definition() or not hit.args:
            return None
        if index is not None and len(hit.args) <= index:
            return None
        text = (
            hit.args[index].nostr if index is not None else " ".join(arg.nostr for arg in hit.args)
        )
        kind = hit.input_kind(text)
        return Verdict(kind) if kind else None

    return confirm


_NOT_FOR_SECURITY = re.compile(r"usedforsecurity\s*=\s*False")
_KEY_OPEN = r"""(?:\[\s*:?["']|\b(?:FormValue|PostFormValue|getParameter|get|Get|Query|PostForm|param|fetch)\s*\(\s*:?["'])"""


def _keyed_password(hit: Hit, pattern: str) -> bool:
    """A senha vem por chave de texto (``form["password"]``), invisível na visão sem strings."""
    if pattern != PASSWORD_NAME:
        return False
    key = re.compile(_KEY_OPEN + PASSWORD_NAME)
    return any(key.search(arg.code) for arg in hit.args)


def args_mention(pattern: str, *, avoid: str | None = None) -> Confirm:
    """Os argumentos (visão sem strings) citam algo, como uma variável com "password" no nome."""
    wanted = re.compile(pattern)
    avoid_re = re.compile(avoid) if avoid else None

    def confirm(hit: Hit) -> Verdict | None:
        if hit.is_definition():
            return None
        whole = " ".join(arg.nostr for arg in hit.args)
        if wanted.search(whole) is None and not _keyed_password(hit, pattern):
            return None
        if avoid_re is not None and avoid_re.search(whole):
            return None
        if pattern == PASSWORD_NAME and _NOT_FOR_SECURITY.search(whole):
            return None
        return Verdict(hit.input_kind(whole))

    return confirm


def value_dynamic(neutralize: re.Pattern[str] | None = None) -> Confirm:
    """Atribuição (``x.innerHTML = valor``): o valor depois do casamento não é constante."""

    def confirm(hit: Hit) -> Verdict | None:
        value = statement_arg(hit.source, hit.match.end())
        kind = classify(value.nostr, neutralize)
        if kind == CONSTANT:
            return None
        return Verdict(hit.input_kind(value.nostr), kind == INTERPOLATED)

    return confirm


#: partes seguras de um comando: argumento escapado para o shell ou número convertido
SHELL_NEUTRAL = re.compile(
    r"\b(?:shlex\.quote|pipes\.quote|escapeshellarg|escapeshellcmd|Shellwords\.(?:escape|shellescape)|"
    r"shellescape|quote|int|float|intval|parseInt|parseFloat|Number|str\(int)\s*\((?:[^()]|\([^()]*\))*\)|"
    r"\.shellescape\b|\.to_i\b|\(int\)\s*\$\w+"
)
#: partes seguras de um HTML: texto escapado ou limpo por uma biblioteca de sanitização
HTML_NEUTRAL = re.compile(
    r"\b(?:DOMPurify\.sanitize|sanitizeHtml|sanitize|escapeHtml|escapeHTML|escape|encodeURIComponent|encodeURI|"
    r"htmlspecialchars|htmlentities|_\.escape|he\.encode|xss|filterXSS|Number|parseInt|String\(Number)\s*\((?:[^()]|\([^()]*\))*\)"
)


# -- SQL ----------------------------------------------------------------------------------

SQL_TEXT = re.compile(
    r"(?is)\b(?:select\b.{1,400}?\bfrom\b|insert\s+into\b|update\s+[\w.\[\]`\"]+\s+set\b|"
    r"delete\s+from\b|drop\s+table\b|truncate\s+table\b|replace\s+into\b)"
)
#: partes seguras de uma consulta: número convertido, escape do driver e marcadores ``?``
SQL_NEUTRAL = re.compile(
    r"\b(?:int|float|intval|floatval|parseInt|parseFloat|Number|Integer\.parseInt|Long\.parseLong|"
    r"int\.Parse|long\.Parse|strconv\.Itoa|mysqli_real_escape_string|esc_sql|sanitize_sql\w*|"
    r"[\w.$>-]*(?:->|\.)(?:escape|escapeId|escapeLiteral|escapeIdentifier|real_escape_string|quote|prepare))"
    r"\s*\((?:[^()]|\([^()]*\))*\)|"
    r"\(int\)\s*\$\w+(?:\[[^\]]*\])?|"
    r"#\{[^{}]*\.to_[if]\}|"
    r"\b(?:placeholders?|qmarks|question_marks|bind_?vars|bindings|param_?list|in_?clause)\b"
)
_TAGGED_TEMPLATE = re.compile(r"[\w$]\s*`")


def sql_dynamic(arg: Arg, *, need_sql: bool) -> bool:
    """O argumento é um texto SQL montado com variáveis?"""
    if need_sql and SQL_TEXT.search(arg.code) is None:
        return False
    if _TAGGED_TEMPLATE.search(arg.nostr):  # sql`...${x}` parametriza sozinho
        return False
    text = _SAFE_WRAPPER.sub(" ", arg.nostr)
    return classify(text, SQL_NEUTRAL) == INTERPOLATED


#: funções que só embrulham um texto fixo (``text("...")``, ``sql.SQL("...")``, ``dedent``)
_SAFE_WRAPPER = re.compile(
    r"(?<![\w.])(?:text|dedent|gettext|_|(?:sql\.)?SQL|Q\.get|sqlalchemy\.text)\s*\("
)


def sql_call(*, need_sql: bool = True, max_args: int = 3) -> Confirm:
    """Algum dos primeiros argumentos é SQL montado com variáveis."""

    def confirm(hit: Hit) -> Verdict | None:
        if hit.is_definition():
            return None
        for arg in hit.args[:max_args]:
            if sql_dynamic(arg, need_sql=need_sql):
                return Verdict(hit.input_kind(arg.nostr), True)
        return None

    return confirm


def sql_value(*, need_sql: bool = True) -> Confirm:
    """Atribuição (``cmd.CommandText = valor``): o valor é SQL montado com variáveis."""

    def confirm(hit: Hit) -> Verdict | None:
        value = statement_arg(hit.source, hit.match.end())
        if sql_dynamic(value, need_sql=need_sql):
            return Verdict(hit.input_kind(value.nostr), True)
        return None

    return confirm


def sql_variable(sinks: str) -> Confirm:
    """``q = "SELECT ... " + x`` e depois ``.execute(q)``: a variável chega a um sink do arquivo."""
    template = sinks

    def confirm(hit: Hit) -> Verdict | None:
        name = hit.match.group("var")
        value = statement_arg(hit.source, hit.match.end())
        if not sql_dynamic(value, need_sql=True):
            return None
        used = re.compile(template.format(name=re.escape(name)))
        if used.search(hit.source.nostr, hit.match.end()) is None:
            return None
        return Verdict(hit.input_kind(value.nostr), True)

    return confirm


#: linha que atribui a uma variável um texto que começa a parecer SQL
SQL_ASSIGNMENT = (
    r"(?m)^[ \t]*(?:(?:final|var|const|let|string|String|auto|static)[ \t]+)*(?P<var>[$\w]+)[ \t]*"
    r"(?::=|\+=|=(?![=>]))[ \t]*(?=[^\n]*(?i:select|insert|update|delete|replace))"
)


# -- nomes sensíveis ----------------------------------------------------------------------

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_SENSITIVE_WORDS = frozenset(
    {
        "token",
        "secret",
        "senha",
        "password",
        "passwd",
        "pwd",
        "otp",
        "nonce",
        "csrf",
        "xsrf",
        "sessionid",
        "sessid",
        "apikey",
        "salt",
    }
)
_SENSITIVE_PAIRS = frozenset(
    {
        ("session", "id"),
        ("sess", "id"),
        ("api", "key"),
        ("access", "key"),
        ("auth", "code"),
        ("reset", "code"),
        ("reset", "key"),
        ("verification", "code"),
        ("confirmation", "code"),
    }
)
_HARMLESS_WORDS = frozenset(
    {
        "count",
        "len",
        "length",
        "size",
        "limit",
        "max",
        "min",
        "num",
        "number",
        "total",
        "type",
        "name",
        "index",
        "idx",
        "lifetime",
        "expiry",
        "ttl",
        "timeout",
        "delay",
        "position",
        "pos",
        "field",
        "header",
        "label",
        "url",
    }
)


def is_sensitive_name(name: str) -> bool:
    """O identificador parece guardar um segredo (``resetToken``, ``session_id``, ``$senha``)."""
    words = [word for word in re.split(r"[^a-z0-9]+", _CAMEL.sub("_", name).lower()) if word]
    if not words or _HARMLESS_WORDS.intersection(words):
        return False
    if _SENSITIVE_WORDS.intersection(words):
        return True
    return any(pair in _SENSITIVE_PAIRS for pair in zip(words, words[1:], strict=False))


#: variável/atributo com "senha" no nome, para as regras de hash fraco
PASSWORD_NAME = (
    r"(?i:passw(?:or)?d|passphrase|senha|(?<![a-z])pwd(?![a-z])|(?<![a-z])pass(?![a-z])|"
    r"(?<=[a-z])Pass(?![a-z]))"
)


_COMPARISON = re.compile(r"[<>]=?|[=!]==?|\?")


def sensitive_assignment(weak: str) -> Confirm:
    """Atribuição a um nome sensível cujo valor usa o gerador fraco (mesma instrução)."""
    weak_re = re.compile(weak)

    def confirm(hit: Hit) -> Verdict | None:
        if not is_sensitive_name(hit.match.group("name")):
            return None
        value = statement_arg(hit.source, hit.match.end())
        found = weak_re.search(value.nostr)
        if found is None or _COMPARISON.search(value.nostr):
            return None  # "token = Math.random() > 0.5" é um booleano, não um segredo
        return Verdict(index=value.start + found.start())

    return confirm


def sensitive_function(weak: str, *, next_definition: str, span: int = 700) -> Confirm:
    """Função com nome sensível (``generate_token``) cujo corpo usa o gerador fraco."""
    weak_re = re.compile(weak)
    stop = re.compile(next_definition)

    def confirm(hit: Hit) -> Verdict | None:
        if not is_sensitive_name(hit.match.group("name")):
            return None
        nostr = hit.source.nostr
        start = hit.match.end()
        body = nostr[start : start + span]
        following = stop.search(body)
        if following is not None:
            body = body[: following.start()]
        found = weak_re.search(body)
        if found is None:
            return None
        return Verdict(index=start + found.start())

    return confirm
