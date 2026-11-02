"""Regras de SAST para PHP e Ruby. As strings abaixo são padrões de busca: nada é executado."""

from __future__ import annotations

import re

from ...core.models import Confidence, Severity
from .sast_common import (
    COMMAND,
    CONSTANT,
    DESER,
    EVAL,
    INTERPOLATED,
    JWT,
    PASSWORD_NAME,
    PHP_EXTRACT,
    PHP_INCLUDE,
    SHELL_NEUTRAL,
    SQL,
    SQL_ASSIGNMENT,
    SQL_NEUTRAL,
    TLS,
    WEAK_HASH,
    WEAK_RANDOM,
    XXE,
    Arg,
    Confirm,
    Hit,
    SastRule,
    Verdict,
    any_dynamic_arg,
    args_mention,
    call_args,
    classify,
    dynamic_arg,
    make_rule,
    sensitive_assignment,
    sensitive_function,
    sql_call,
    sql_dynamic,
    sql_variable,
    statement_arg,
)
from .sast_mask import PHP, RUBY

_HIGH = Severity.HIGH
_CRITICAL = Severity.CRITICAL
_FIRM = Confidence.FIRM

# -- PHP -------------------------------------------------------------------------------

#: função nativa: não é método (``->exec``), nem estática (``::exec``), nem variável
_BARE = r"(?<![\w>:$\\])"
_PHP_WEAK_RANDOM = _BARE + r"(?:rand|mt_rand|uniqid|lcg_value|str_shuffle|array_rand)\s*\("
_PHP_ALLOWLIST = r"(?:in_array|array_key_exists|isset|preg_match)\s*\([^;\n]*{name}\b"


def _php_unserialize(hit: Hit) -> Verdict | None:
    """``unserialize`` com ``allowed_classes`` restrito é a mitigação documentada pelo PHP."""
    if len(hit.args) >= 2 and re.search(r"allowed_classes", hit.args[1].code):
        if not re.search(r"allowed_classes[\"']\s*=>\s*true", hit.args[1].code, re.I):
            return None
    return dynamic_arg(0)(hit)


def _php_include(hit: Hit) -> Verdict | None:
    """``include`` com entrada externa; variável conferida numa lista antes do uso não conta."""
    value = statement_arg(hit.source, hit.match.end())
    kind = hit.input_kind(value.nostr)
    if not kind:
        return None
    if kind == "indireta" and _checked_before(hit, value):
        return None
    return Verdict(kind)


def _checked_before(hit: Hit, value: Arg) -> bool:
    start = hit.match.start()
    before = hit.source.nostr[max(0, start - 600) : start]
    for name in re.findall(r"\$\w+", value.nostr):
        if re.search(_PHP_ALLOWLIST.format(name=re.escape(name)), before):
            return True
    return False


def _php_extract(hit: Hit) -> Verdict | None:
    """``extract($_GET)``; ``EXTR_SKIP`` não sobrescreve variáveis, mas segue desaconselhado."""
    if hit.is_definition() or not hit.args:
        return None
    kind = hit.input_kind(hit.args[0].nostr)
    if not kind:
        return None
    flags = " ".join(arg.nostr for arg in hit.args[1:])
    if re.search(r"\bEXTR_(?:SKIP|PREFIX_ALL|PREFIX_INVALID|PREFIX_SAME|IF_EXISTS)\b", flags):
        return Verdict(severity=Severity.MEDIUM, confidence=Confidence.TENTATIVE)
    return Verdict(kind)


def _php_exec_like(hit: Hit) -> Verdict | None:
    """Crase do PHP executa um comando: basta ter uma variável dentro."""
    return Verdict(hit.input_kind(hit.match.group()), True)


_PHP_RULES: tuple[SastRule, ...] = (
    make_rule(
        "php.eval",
        EVAL,
        PHP,
        _BARE + r"eval\s*\(",
        "PHP: eval executa um valor que não é constante",
        keywords=("eval",),
        severity_input=_CRITICAL,
        confirm=dynamic_arg(0),
    ),
    make_rule(
        "php.assert",
        EVAL,
        PHP,
        _BARE + r"assert\s*\(",
        "PHP: assert recebe entrada externa (avaliado como código em versões antigas)",
        keywords=("assert",),
        severity=_HIGH,
        confidence=_FIRM,
        severity_input=_CRITICAL,
        confirm=lambda hit: (lambda kind: Verdict(kind) if kind else None)(
            hit.input_kind(hit.args[0].nostr) if hit.args else ""
        ),
    ),
    make_rule(
        "php.create_function",
        EVAL,
        PHP,
        _BARE + r"create_function\s*\(",
        "PHP: create_function com um valor não constante",
        keywords=("create_function",),
        severity_input=_CRITICAL,
        confirm=any_dynamic_arg(),
    ),
    make_rule(
        "php.preg_e",
        EVAL,
        PHP,
        _BARE + r"""preg_replace\s*\(\s*(['"])([^\w\s\\])(?:(?!\2)[^\n])*\2[a-zA-Z]*e[a-zA-Z]*\1""",
        "PHP: preg_replace com o modificador /e (executa o resultado como código)",
        keywords=("preg_replace",),
        severity=_HIGH,
        confidence=_FIRM,
        severity_input=_CRITICAL,
        view="code",
    ),
    make_rule(
        "php.exec",
        COMMAND,
        PHP,
        _BARE + r"(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(",
        "PHP: comando de shell com um valor não constante",
        keywords=("system", "exec", "passthru", "popen", "proc_open"),
        severity_input=_CRITICAL,
        confirm=dynamic_arg(0, neutralize=SHELL_NEUTRAL),
    ),
    make_rule(
        "php.backtick",
        COMMAND,
        PHP,
        r"`[^`\n]*\$[A-Za-z_{][^`\n]*`",
        "PHP: operador de crase executa um comando montado com variáveis",
        keywords=("`",),
        severity_input=_CRITICAL,
        confirm=_php_exec_like,
    ),
    make_rule(
        "php.unserialize",
        DESER,
        PHP,
        _BARE + r"unserialize\s*\(",
        "PHP: unserialize de um valor não constante",
        keywords=("unserialize",),
        severity_input=_CRITICAL,
        confirm=_php_unserialize,
    ),
    make_rule(
        "php.sql",
        SQL,
        PHP,
        _BARE
        + r"(?:mysql_query|mysqli_query|mysqli_multi_query|pg_query|pg_send_query|sqlite_query|odbc_exec)\s*\(|"
        r"->(?:query|exec|prepare|multi_query|real_query|get_results|get_row|get_var|get_col|"
        r"executeQuery|executeStatement)\s*\(|\bDB::(?:select|insert|update|delete|statement|unprepared)\s*\(",
        "PHP: SQL montado com variáveis (concatenação ou interpolação)",
        keywords=("query", "exec", "prepare", "get_", "executeStatement", "DB::"),
        severity_input=_CRITICAL,
        confirm=sql_call(),
    ),
    make_rule(
        "php.sql_raw",
        SQL,
        PHP,
        r"->(?:whereRaw|orWhereRaw|havingRaw|orderByRaw|selectRaw|groupByRaw)\s*\(|\bDB::raw\s*\(",
        "PHP: trecho de SQL bruto montado com variáveis (Laravel)",
        keywords=("Raw", "DB::raw"),
        severity_input=_CRITICAL,
        confirm=sql_call(need_sql=False, max_args=1),
    ),
    make_rule(
        "php.sql_var",
        SQL,
        PHP,
        SQL_ASSIGNMENT,
        "PHP: SQL montado com variáveis em uma variável usada na consulta",
        keywords=("query", "exec", "prepare", "get_"),
        severity_input=_CRITICAL,
        view="code",
        confirm=sql_variable(
            r"(?:mysql_query|mysqli_query|pg_query|->query|->exec|->prepare|->multi_query|->get_results|"
            r"->get_row|->get_var)\s*\([^;\n]*{name}\b"
        ),
    ),
    make_rule(
        "php.curl_verify",
        TLS,
        PHP,
        r"(?i:CURLOPT_SSL_VERIFY(?:PEER|HOST))\s*(?:,|=>)\s*(?i:false|0)\b",
        "PHP: cURL sem validar o certificado (CURLOPT_SSL_VERIFYPEER/HOST desligado)",
        keywords=("CURLOPT_SSL_VERIFY",),
        severity=_HIGH,
        confidence=_FIRM,
    ),
    make_rule(
        "php.stream_verify",
        TLS,
        PHP,
        r"""['"]verify_peer(?:_name)?['"]\s*=>\s*(?i:false|0)\b""",
        "PHP: stream TLS sem validar o certificado (verify_peer desligado)",
        keywords=("verify_peer",),
        severity=_HIGH,
        confidence=_FIRM,
        view="code",
    ),
    make_rule(
        "php.guzzle_verify",
        TLS,
        PHP,
        r"""['"]verify['"]\s*=>\s*(?i:false)\b""",
        "PHP: cliente HTTP (Guzzle) sem validar o certificado (verify => false)",
        keywords=("verify",),
        severity=_HIGH,
        confidence=_FIRM,
        view="code",
        requires=r"Guzzle",
    ),
    make_rule(
        "php.hash_password",
        WEAK_HASH,
        PHP,
        _BARE + r"(?:md5|sha1)\s*\(",
        "PHP: senha protegida com MD5 ou SHA-1",
        keywords=("md5", "sha1"),
        severity=_HIGH,
        confidence=_FIRM,
        confirm=args_mention(PASSWORD_NAME),
    ),
    make_rule(
        "php.hash_function",
        WEAK_HASH,
        PHP,
        _BARE + r"""hash\s*\(\s*['"](?:md5|sha1)['"]""",
        "PHP: senha protegida com MD5 ou SHA-1",
        keywords=("hash",),
        severity=_HIGH,
        confidence=_FIRM,
        view="code",
        confirm=args_mention(PASSWORD_NAME),
    ),
    make_rule(
        "php.random_assign",
        WEAK_RANDOM,
        PHP,
        r"(?P<name>\$[\w]+)['\"\]]*\s*\.?=(?!=)\s*(?=[^\n;]*" + _PHP_WEAK_RANDOM + ")",
        "PHP: segredo gerado com rand/mt_rand/uniqid (previsível)",
        keywords=("rand", "uniqid", "lcg_value", "shuffle"),
        confidence=_FIRM,
        confirm=sensitive_assignment(_PHP_WEAK_RANDOM),
    ),
    make_rule(
        "php.random_function",
        WEAK_RANDOM,
        PHP,
        r"\bfunction\s+&?(?P<name>\w+)\s*\(",
        "PHP: função que gera segredo usa rand/mt_rand/uniqid (previsível)",
        keywords=("rand", "uniqid", "lcg_value", "shuffle"),
        confirm=sensitive_function(_PHP_WEAK_RANDOM, next_definition=r"\bfunction\s"),
    ),
    make_rule(
        "php.include",
        PHP_INCLUDE,
        PHP,
        _BARE + r"(?:include|require)(?:_once)?\b\s*",
        "PHP: include/require com entrada externa",
        keywords=("include", "require"),
        severity=_HIGH,
        confidence=_FIRM,
        severity_input=_CRITICAL,
        confirm=_php_include,
    ),
    make_rule(
        "php.extract",
        PHP_EXTRACT,
        PHP,
        _BARE + r"extract\s*\(",
        "PHP: extract() com entrada externa pode sobrescrever variáveis",
        keywords=("extract",),
        severity=_HIGH,
        confidence=_FIRM,
        confirm=_php_extract,
    ),
    make_rule(
        "php.libxml_noent",
        XXE,
        PHP,
        r"\bLIBXML_(?:NOENT|DTDLOAD)\b",
        "PHP: parser XML com LIBXML_NOENT/LIBXML_DTDLOAD (entidades e DTD externos)",
        keywords=("LIBXML_",),
        severity=_HIGH,
        confidence=_FIRM,
    ),
    make_rule(
        "php.entity_loader",
        XXE,
        PHP,
        _BARE
        + r"libxml_disable_entity_loader\s*\(\s*(?i:false)\b|->\s*substituteEntities\s*=\s*(?i:true)\b",
        "PHP: carregamento de entidades XML externas ligado",
        keywords=("libxml_disable_entity_loader", "substituteEntities"),
        severity=_HIGH,
        confidence=_FIRM,
    ),
)

# -- Ruby ------------------------------------------------------------------------------

_RB_WEAK_RANDOM = (
    r"(?<![\w.:])(?:rand|srand)\s*[\(\s]|\bRandom\.(?:rand|new|bytes)\b|\.(?:sample|shuffle)\b"
)
_RB_BARE = r"(?<![\w.:])"


def ruby_args(hit: Hit) -> list[Arg]:
    """Argumentos em Ruby: com parênteses ou até o fim da instrução (``system "ls", x``)."""
    source = hit.source
    end = hit.match.end()
    if source.nostr[end : end + 1] == "(":
        return call_args(source, end)
    value = statement_arg(source, end, stops=";")
    args: list[Arg] = []
    depth = 0
    start = value.start
    for index in range(value.start, value.end):
        char = source.nostr[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            args.append(_slice_arg(hit, start, index))
            start = index + 1
    if source.nostr[start : value.end].strip():
        args.append(_slice_arg(hit, start, value.end))
    return args


def _slice_arg(hit: Hit, start: int, end: int) -> Arg:
    return Arg(start, end, hit.source.nostr[start:end], hit.source.code[start:end])


def _ruby_first_dynamic(
    neutralize: re.Pattern[str] | None = None, avoid: str | None = None
) -> _RubyConfirm:
    avoid_re = re.compile(avoid) if avoid else None

    def confirm(hit: Hit) -> Verdict | None:
        if hit.is_definition():
            return None
        args = ruby_args(hit)
        if not args:
            return None
        if avoid_re is not None and any(avoid_re.search(arg.nostr) for arg in args):
            return None
        kind = classify(args[0].nostr, neutralize)
        if kind == CONSTANT:
            return None
        return Verdict(hit.input_kind(args[0].nostr), kind == INTERPOLATED)

    return confirm


_RubyConfirm = Confirm


def _ruby_block_form(hit: Hit) -> bool:
    following = hit.source.nostr[hit.match.end() : hit.match.end() + 8].lstrip()
    return following.startswith(("do", "{", "&"))


_RB_EVAL_ARG = _ruby_first_dynamic()


def _ruby_eval(hit: Hit) -> Verdict | None:
    """``class_eval do ... end`` usa bloco (código normal); só texto é avaliado como código."""
    return None if _ruby_block_form(hit) else _RB_EVAL_ARG(hit)


def _ruby_sql(*, need_sql: bool) -> _RubyConfirm:
    def confirm(hit: Hit) -> Verdict | None:
        for arg in ruby_args(hit)[:2]:
            if sql_dynamic(arg, need_sql=need_sql):
                return Verdict(hit.input_kind(arg.nostr), True)
        return None

    return confirm


def _ruby_mentions_password(hit: Hit) -> Verdict | None:
    pattern = re.compile(PASSWORD_NAME)
    for arg in ruby_args(hit):
        if pattern.search(arg.code) and classify(arg.nostr) != CONSTANT:
            return Verdict(hit.input_kind(arg.nostr))
    return None


def _ruby_jwt(hit: Hit) -> Verdict | None:
    """``JWT.decode(token, chave, false)``: o terceiro argumento desliga a verificação."""
    args = ruby_args(hit)
    if len(args) >= 3 and args[2].nostr.strip() == "false":
        return Verdict()
    return None


def _ruby_backtick(hit: Hit) -> Verdict | None:
    text = SQL_NEUTRAL.sub(" ", SHELL_NEUTRAL.sub(" ", hit.match.group()))
    if "#{" not in text:
        return None
    return Verdict(hit.input_kind(text), True)


_RB_RULES: tuple[SastRule, ...] = (
    make_rule(
        "rb.eval",
        EVAL,
        RUBY,
        _RB_BARE
        + r"eval\b[ \t]*|\b(?:Kernel|binding)\.eval\b[ \t]*|\b(?:instance_eval|class_eval|module_eval)\b[ \t]*",
        "Ruby: eval executa um valor que não é constante",
        keywords=("eval",),
        severity_input=_CRITICAL,
        confirm=_ruby_eval,
    ),
    make_rule(
        "rb.system",
        COMMAND,
        RUBY,
        _RB_BARE + r"(?:system|exec|spawn)\b[ \t]*|\bKernel\.(?:system|exec|spawn)\b[ \t]*|"
        r"\bIO\.popen\b[ \t]*|\bOpen3\.(?:popen3|popen2|popen2e|capture2|capture2e|capture3)\b[ \t]*",
        "Ruby: comando de shell com um valor não constante",
        keywords=("system", "exec", "spawn", "popen", "Open3"),
        severity_input=_CRITICAL,
        confirm=_ruby_first_dynamic(SHELL_NEUTRAL),
    ),
    make_rule(
        "rb.backtick",
        COMMAND,
        RUBY,
        r"`[^`\n]*#\{[^`\n]*`|%x[\(\[\{<|!/][^\n]*#\{[^\n]*",
        "Ruby: crase/%x executa um comando montado com variáveis",
        keywords=("`", "%x"),
        severity_input=_CRITICAL,
        confirm=_ruby_backtick,
    ),
    make_rule(
        "rb.marshal",
        DESER,
        RUBY,
        r"\bMarshal\.(?:load|restore)\b[ \t]*",
        "Ruby: Marshal.load de um valor não constante",
        keywords=("Marshal",),
        severity_input=_CRITICAL,
        confirm=_ruby_first_dynamic(),
    ),
    make_rule(
        "rb.yaml_unsafe",
        DESER,
        RUBY,
        r"\b(?:YAML|Psych)\.(?:unsafe_load|unsafe_load_file)\b[ \t]*",
        "Ruby: YAML.unsafe_load de um valor não constante",
        keywords=("unsafe_load",),
        confidence=_FIRM,
        severity_input=_CRITICAL,
        confirm=_ruby_first_dynamic(),
    ),
    make_rule(
        "rb.yaml_load",
        DESER,
        RUBY,
        r"\b(?:YAML|Psych)\.(?:load|load_file|load_stream)\b[ \t]*",
        "Ruby: YAML.load de um valor não constante (inseguro antes do Psych 4)",
        keywords=("YAML.load", "Psych.load"),
        severity=Severity.LOW,
        severity_input=_CRITICAL,
        confirm=_ruby_first_dynamic(avoid=r"\bpermitted_classes\b|\bsafe\b"),
    ),
    make_rule(
        "rb.sql",
        SQL,
        RUBY,
        r"\.(?:find_by_sql|count_by_sql|execute|exec_query|exec_params|exec|query|select_all|select_one|"
        r"select_value|select_values|select_rows)\b[ \t]*",
        "Ruby: SQL montado com variáveis (interpolação ou concatenação)",
        keywords=("sql", "execute", "exec", "query", "select_"),
        severity_input=_CRITICAL,
        confirm=_ruby_sql(need_sql=True),
    ),
    make_rule(
        "rb.active_record",
        SQL,
        RUBY,
        r"\.(?:where|not|rewhere|having|order|reorder|group|joins|from|pluck|update_all|delete_all|lock)\b[ \t]*(?=\(|[\"'])",
        "Ruby: trecho de SQL do ActiveRecord montado com variáveis",
        keywords=(
            "where",
            "having",
            "order",
            "group",
            "joins",
            "from",
            "pluck",
            "update_all",
            "delete_all",
        ),
        severity_input=_CRITICAL,
        confirm=_ruby_sql(need_sql=False),
    ),
    make_rule(
        "rb.sql_var",
        SQL,
        RUBY,
        SQL_ASSIGNMENT,
        "Ruby: SQL montado com variáveis em uma variável usada na consulta",
        keywords=("find_by_sql", "execute", "exec", "query"),
        severity_input=_CRITICAL,
        view="code",
        confirm=sql_variable(
            r"\.(?:find_by_sql|execute|exec_query|exec_params|exec|query)\b[ \t]*\(?\s*{name}\b"
        ),
    ),
    make_rule(
        "rb.verify_none",
        TLS,
        RUBY,
        r"\bOpenSSL::SSL::VERIFY_NONE\b",
        "Ruby: TLS sem validar o certificado (VERIFY_NONE)",
        keywords=("VERIFY_NONE",),
        severity=_HIGH,
        confidence=_FIRM,
    ),
    make_rule(
        "rb.client_verify",
        TLS,
        RUBY,
        r"(?::verify_ssl\s*=>|\bverify_ssl:)\s*false\b|(?::ssl_verifypeer\s*=>|\bssl_verifypeer:)\s*(?:false|0)\b|"
        r"\bssl:\s*\{[^}\n]*\bverify:\s*false\b|:ssl\s*=>\s*\{[^}\n]*:verify\s*=>\s*false\b",
        "Ruby: cliente HTTP sem validar o certificado",
        keywords=("verify",),
        severity=_HIGH,
        confidence=_FIRM,
    ),
    make_rule(
        "rb.httparty_verify",
        TLS,
        RUBY,
        r"(?::verify\s*=>|\bverify:)\s*false\b",
        "Ruby: HTTParty sem validar o certificado (verify: false)",
        keywords=("verify",),
        severity=_HIGH,
        confidence=_FIRM,
        requires=r"\bHTTParty\b",
    ),
    make_rule(
        "rb.hash_password",
        WEAK_HASH,
        RUBY,
        r"\bDigest::(?:MD5|SHA1)\.(?:hexdigest|digest|base64digest)\b[ \t]*",
        "Ruby: senha protegida com MD5 ou SHA-1",
        keywords=("Digest::",),
        severity=_HIGH,
        confidence=_FIRM,
        confirm=_ruby_mentions_password,
    ),
    make_rule(
        "rb.random_assign",
        WEAK_RANDOM,
        RUBY,
        r"(?P<name>@{0,2}[\w.]+)\s*(?:\|\|)?=(?![=~>])\s*(?=[^\n]*(?:" + _RB_WEAK_RANDOM + "))",
        "Ruby: segredo gerado com rand/Random/sample (previsível)",
        keywords=("rand", "Random", "sample", "shuffle"),
        confidence=_FIRM,
        unless=r"\bSecureRandom\.(?:hex|base64|urlsafe_base64|uuid|random_bytes|alphanumeric)\b[^\n]*\b(?:sample|shuffle)\b",
        confirm=sensitive_assignment(_RB_WEAK_RANDOM),
    ),
    make_rule(
        "rb.random_function",
        WEAK_RANDOM,
        RUBY,
        r"\bdef\s+(?:self\.)?(?P<name>\w+[?!]?)",
        "Ruby: método que gera segredo usa rand/Random/sample (previsível)",
        keywords=("rand", "Random", "sample", "shuffle"),
        confirm=sensitive_function(_RB_WEAK_RANDOM, next_definition=r"\bdef\s"),
    ),
    make_rule(
        "rb.jwt",
        JWT,
        RUBY,
        r"\bJWT\.decode\b[ \t]*",
        "Ruby: JWT lido sem verificar a assinatura (terceiro argumento false)",
        keywords=("JWT.decode",),
        severity=_HIGH,
        confidence=_FIRM,
        confirm=_ruby_jwt,
    ),
    make_rule(
        "rb.nokogiri",
        XXE,
        RUBY,
        r"\bconfig\.(?:noent|dtdload)\b|\bParseOptions::(?:NOENT|DTDLOAD)\b",
        "Ruby: Nokogiri com NOENT/DTDLOAD (inseguro para XML não confiável)",
        keywords=("noent", "dtdload", "NOENT", "DTDLOAD"),
        severity=_HIGH,
        confidence=_FIRM,
    ),
)

WEB_RULES: tuple[SastRule, ...] = (*_PHP_RULES, *_RB_RULES)
