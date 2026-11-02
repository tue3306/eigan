"""Regras de SAST para Python e JavaScript/TypeScript.

Ideias inspiradas no bandit (Apache-2.0) e nos alertas oficiais de cada biblioteca;
as expressões e os textos são próprios. As strings abaixo são padrões de busca: nada
aqui é executado.
"""

from __future__ import annotations

import re

from ...core.models import Confidence, Severity
from .sast_common import (
    COMMAND,
    CONSTANT,
    DESER,
    EVAL,
    HTML_NEUTRAL,
    JWT,
    PASSWORD_NAME,
    SHELL_NEUTRAL,
    SQL,
    SQL_ASSIGNMENT,
    TLS,
    WEAK_HASH,
    WEAK_RANDOM,
    XSS,
    XXE,
    Hit,
    SastRule,
    Verdict,
    any_dynamic_arg,
    args_mention,
    classify,
    dynamic_arg,
    make_rule,
    sensitive_assignment,
    sensitive_function,
    sql_call,
    sql_variable,
    value_dynamic,
)
from .sast_mask import JAVASCRIPT, PYTHON

_HIGH = Severity.HIGH
_CRITICAL = Severity.CRITICAL
_FIRM = Confidence.FIRM

# -- Python -----------------------------------------------------------------------------

_PY_WEAK_RANDOM = r"(?<![\w.])random\.(?:random|randint|randrange|randbytes|choice|choices|sample|getrandbits|uniform|shuffle)\s*\("
_YAML_UNSAFE_LOADERS = re.compile(
    r"\b(?:Loader|UnsafeLoader|FullLoader|CLoader|CUnsafeLoader|CFullLoader)\b"
)
_YAML_LOADER_ARG = re.compile(r"\bLoader\s*=")


def _yaml_load(hit: Hit) -> Verdict | None:
    """``yaml.load`` sem ``Loader`` (ou com um dos inseguros); os seguros e os próprios passam."""
    if not hit.args or classify(hit.args[0].nostr) == CONSTANT:
        return None
    if len(hit.args) >= 2:
        loader = hit.args[1].nostr
        if _YAML_LOADER_ARG.search(loader) is not None or loader.strip():
            name = loader.split("=", 1)[-1].strip().rsplit(".", 1)[-1]
            if _YAML_UNSAFE_LOADERS.fullmatch(name) is None:
                return None
            if name in ("FullLoader", "CFullLoader"):  # PyYAML >= 5.4 não constrói objetos livres
                return Verdict(hit.input_kind(hit.args[0].nostr), confidence=Confidence.TENTATIVE)
    return Verdict(hit.input_kind(hit.args[0].nostr))


def _py_verify_false(hit: Hit) -> Verdict | None:
    """``verify=False`` numa chamada HTTP (e não em ``jwt.decode(..., verify=False)``)."""
    start = hit.match.start()
    before = hit.source.nostr[max(0, start - 400) : start]
    opening = before.rfind("(")
    callee = before[max(0, opening - 40) : opening] if opening >= 0 else ""
    return None if re.search(r"(?:jwt|jws|jose)\.\w+\s*$|\bdecode\s*$", callee) else Verdict()


_JS_SHELL_BIN = re.compile(
    r"""^\s*["'](?:/bin/|/usr/bin/)?(?:ba|z|da)?sh["']|^\s*["'](?:cmd|powershell|pwsh)(?:\.exe)?["']""",
    re.I,
)
_JS_SHELL_SWITCH = re.compile(r"""["'](?:-c|/c|-Command)["']""", re.I)
_JS_FN_EDGE = re.compile(r"(?:\bfunction\b|=>\s*\{)")


def _js_spawn(hit: Hit) -> Verdict | None:
    """``spawn`` com ``shell: true`` ou chamando um shell com ``-c`` e texto não constante."""
    args = hit.args
    if (
        len(args) >= 2
        and _JS_SHELL_BIN.search(args[0].code)
        and _JS_SHELL_SWITCH.search(args[1].code)
    ):
        if classify(args[1].nostr) == CONSTANT:
            return None
        return Verdict(hit.input_kind(args[1].nostr))
    return dynamic_arg(0, needs=r"\bshell\s*:\s*true\b", neutralize=SHELL_NEUTRAL)(hit)


def _js_jwt_decode(hit: Hit) -> Verdict | None:
    """``jwt.decode`` sem um ``verify`` na mesma função (outra função verificar não conta)."""
    nostr = hit.source.nostr
    start = hit.match.start()
    before = [m.end() for m in _JS_FN_EDGE.finditer(nostr, max(0, start - 3000), start)]
    after = _JS_FN_EDGE.search(nostr, hit.match.end())
    scope = nostr[
        (before[-1] if before else max(0, start - 3000)) : after.start() if after else len(nostr)
    ]
    return None if re.search(r"\b(?:jwt|jsonwebtoken)\.verify\s*\(", scope) else Verdict()


_PY_RULES: tuple[SastRule, ...] = (
    make_rule(
        "py.eval",
        EVAL,
        PYTHON,
        r"(?<![\w.])(?:eval|exec)\s*\(",
        "Python: eval/exec executa um valor que não é constante",
        keywords=("eval", "exec"),
        severity_input=_CRITICAL,
        confirm=dynamic_arg(0),
    ),
    make_rule(
        "py.shell_true",
        COMMAND,
        PYTHON,
        r"\b(?:subprocess\.(?:run|call|check_call|check_output|Popen)|(?<![\w.])(?:Popen|check_output|check_call))\s*\(",
        "Python: subprocess com shell=True e comando não constante",
        keywords=("shell",),
        severity_input=_CRITICAL,
        confirm=dynamic_arg(0, needs=r"\bshell\s*=\s*True\b", neutralize=SHELL_NEUTRAL),
    ),
    make_rule(
        "py.os_system",
        COMMAND,
        PYTHON,
        r"\b(?:os\.(?:system|popen)|subprocess\.(?:getoutput|getstatusoutput)|asyncio\.create_subprocess_shell)\s*\(",
        "Python: comando de shell (os.system e afins) com valor não constante",
        keywords=(
            "os.system",
            "os.popen",
            "getoutput",
            "getstatusoutput",
            "create_subprocess_shell",
        ),
        severity_input=_CRITICAL,
        confirm=dynamic_arg(0, neutralize=SHELL_NEUTRAL),
    ),
    make_rule(
        "py.pickle",
        DESER,
        PYTHON,
        r"\b(?:pickle|cPickle|_pickle|dill|marshal|jsonpickle|shelve)\.(?:loads?|decode|open|Unpickler)\s*\(|"
        r"\b(?:pd|pandas)\.read_pickle\s*\(",
        "Python: desserialização insegura (pickle e afins) de um valor não constante",
        keywords=("pickle", "dill", "marshal", "shelve"),
        severity_input=_CRITICAL,
        confirm=dynamic_arg(0),
    ),
    make_rule(
        "py.yaml_load",
        DESER,
        PYTHON,
        r"\byaml\.(?:load|load_all)\s*\(",
        "Python: yaml.load sem SafeLoader",
        keywords=("yaml",),
        confidence=_FIRM,
        severity_input=_CRITICAL,
        unless=r"\bruamel\b",
        confirm=_yaml_load,
    ),
    make_rule(
        "py.yaml_unsafe",
        DESER,
        PYTHON,
        r"\byaml\.(?:unsafe_load|unsafe_load_all|full_load|full_load_all)\s*\(",
        "Python: yaml.unsafe_load/full_load com um valor não constante",
        keywords=("yaml",),
        confidence=_FIRM,
        severity_input=_CRITICAL,
        unless=r"\bruamel\b",
        confirm=dynamic_arg(0),
    ),
    make_rule(
        "py.sql",
        SQL,
        PYTHON,
        r"\.(?:execute|executemany|executescript|mogrify|raw)\s*\(|(?<![\w.])(?:RawSQL|text)\s*\(|\.text\s*\(|"
        r"\bread_sql(?:_query)?\s*\(",
        "Python: SQL montado com variáveis (concatenação, format ou f-string)",
        keywords=("execute", "raw", "RawSQL", "text(", "read_sql", "mogrify"),
        severity_input=_CRITICAL,
        confirm=sql_call(),
    ),
    make_rule(
        "py.sql_var",
        SQL,
        PYTHON,
        SQL_ASSIGNMENT,
        "Python: SQL montado com variáveis em uma variável usada na consulta",
        keywords=("execute", "raw"),
        severity_input=_CRITICAL,
        view="code",
        confirm=sql_variable(r"\.(?:execute|executemany|executescript|raw)\s*\(\s*{name}\b"),
    ),
    make_rule(
        "py.verify_false",
        TLS,
        PYTHON,
        r"\bverify\s*=\s*False\b",
        "Python: requisição HTTP com verify=False (certificado não é validado)",
        keywords=("verify",),
        severity=_HIGH,
        confidence=_FIRM,
        requires=r"\b(?:requests|httpx|urllib3|aiohttp|session|Session)\b",
        confirm=_py_verify_false,
    ),
    make_rule(
        "py.session_verify",
        TLS,
        PYTHON,
        r"\b\w+\.verify\s*=\s*False\b",
        "Python: sessão HTTP com verify = False (certificado não é validado)",
        keywords=("verify",),
        severity=_HIGH,
        confidence=_FIRM,
        requires=r"\b(?:requests|httpx)\b",
    ),
    make_rule(
        "py.ssl_unverified",
        TLS,
        PYTHON,
        r"\bssl\._create_unverified_context\b|\bssl\.CERT_NONE\b|\bcheck_hostname\s*=\s*False\b|"
        r"\bverify_ssl\s*=\s*False\b|\bTCPConnector\s*\([^)\n]*\bssl\s*=\s*False\b",
        "Python: contexto TLS sem validação de certificado ou de nome",
        keywords=("ssl", "check_hostname"),
        severity=_HIGH,
        confidence=_FIRM,
    ),
    make_rule(
        "py.cert_reqs",
        TLS,
        PYTHON,
        r"""\bcert_reqs\s*=\s*["']CERT_NONE["']""",
        "Python: urllib3 com cert_reqs='CERT_NONE' (certificado não é validado)",
        keywords=("cert_reqs",),
        severity=_HIGH,
        confidence=_FIRM,
        view="code",
    ),
    make_rule(
        "py.hash_password",
        WEAK_HASH,
        PYTHON,
        r"\bhashlib\.(?:md5|sha1)\s*\(",
        "Python: senha protegida com MD5 ou SHA-1",
        keywords=("md5", "sha1"),
        severity=_HIGH,
        confidence=_FIRM,
        confirm=args_mention(PASSWORD_NAME),
    ),
    make_rule(
        "py.hash_update",
        WEAK_HASH,
        PYTHON,
        r"\bhashlib\.(?:md5|sha1)\s*\(\s*\)(?:[^\n]*\n){0,3}?[^\n]*\.update\s*\([^)\n]*"
        + PASSWORD_NAME,
        "Python: senha protegida com MD5 ou SHA-1",
        keywords=("md5", "sha1"),
        severity=_HIGH,
        confidence=_FIRM,
    ),
    make_rule(
        "py.hash_new",
        WEAK_HASH,
        PYTHON,
        r"""\bhashlib\.new\s*\(\s*["'](?:md5|sha1)["']""",
        "Python: senha protegida com MD5 ou SHA-1",
        keywords=("hashlib.new",),
        severity=_HIGH,
        confidence=_FIRM,
        view="code",
        confirm=args_mention(PASSWORD_NAME),
    ),
    make_rule(
        "py.random_assign",
        WEAK_RANDOM,
        PYTHON,
        r"(?P<name>[\w.]+)['\"\]]*\s*=(?!=)\s*(?=[^\n]*" + _PY_WEAK_RANDOM + ")",
        "Python: segredo gerado com o módulo random (previsível)",
        keywords=("random",),
        confidence=_FIRM,
        confirm=sensitive_assignment(_PY_WEAK_RANDOM),
    ),
    make_rule(
        "py.random_function",
        WEAK_RANDOM,
        PYTHON,
        r"(?m)^[ \t]*(?:async[ \t]+)?def[ \t]+(?P<name>\w+)[ \t]*\(",
        "Python: função que gera segredo usa o módulo random (previsível)",
        keywords=("random",),
        confirm=sensitive_function(
            _PY_WEAK_RANDOM, next_definition=r"\n[ \t]*(?:async[ \t]+)?def[ \t]"
        ),
    ),
    make_rule(
        "py.jwt_options",
        JWT,
        PYTHON,
        r"""["']verify_signature["']\s*:\s*False\b""",
        "Python: JWT lido sem verificar a assinatura (verify_signature: False)",
        keywords=("verify_signature",),
        severity=_HIGH,
        confidence=_FIRM,
        view="code",
        requires=r"\b(?:jwt|jose)\b",
    ),
    make_rule(
        "py.jwt_verify_false",
        JWT,
        PYTHON,
        r"\bjwt\.decode\s*\(",
        "Python: JWT lido sem verificar a assinatura (verify=False)",
        keywords=("jwt",),
        severity=_HIGH,
        confidence=_FIRM,
        confirm=dynamic_arg(0, needs=r"\bverify\s*=\s*False\b"),
    ),
    make_rule(
        "py.jose_unverified",
        JWT,
        PYTHON,
        r"\b(?:jwt|jws)\.get_unverified_claims\s*\(",
        "Python: declarações de JWT lidas sem verificação (get_unverified_claims)",
        keywords=("get_unverified_claims",),
    ),
    make_rule(
        "py.lxml_entities",
        XXE,
        PYTHON,
        r"\bXMLParser\s*\([^)]*\bresolve_entities\s*=\s*True\b",
        "Python: parser XML (lxml) com resolve_entities=True",
        keywords=("resolve_entities",),
        severity=_HIGH,
        confidence=_FIRM,
    ),
    make_rule(
        "py.sax_external",
        XXE,
        PYTHON,
        r"\bsetFeature\s*\(\s*(?:[\w.]*\.)?feature_external_(?:ges|pes)\s*,\s*(?:True|1)\b",
        "Python: parser SAX com entidades externas ligadas",
        keywords=("feature_external",),
        severity=_HIGH,
        confidence=_FIRM,
    ),
)

# -- JavaScript / TypeScript ---------------------------------------------------------------

_JS_WEAK_RANDOM = r"\bMath\.random\s*\("
_CP_ALIAS = re.compile(
    r"""(?:const|let|var)\s+([\w$]+)\s*=\s*require\(\s*["'](?:node:)?child_process["']\s*\)|"""
    r"""import\s+(?:\*\s+as\s+)?([\w$]+)\s+from\s+["'](?:node:)?child_process["']"""
)
_CP_DESTRUCTURED = re.compile(r"\{[^}]*\bexec(?:Sync)?\b[^}]*\}\s*(?:=\s*require\s*\(|from\s)")
_JS_DYNAMIC_EXEC = dynamic_arg(0, neutralize=SHELL_NEUTRAL)


def _js_exec(hit: Hit) -> Verdict | None:
    """``exec`` só conta se vier do ``child_process`` (``regex.exec(texto)`` é outra coisa)."""
    receiver = hit.match.groupdict().get("recv")
    code = hit.source.code
    if receiver is None:
        direct = hit.match.group().startswith("require")
        if not direct and _CP_DESTRUCTURED.search(code) is None:
            return None
    elif receiver != "child_process":
        aliases = {name for pair in _CP_ALIAS.findall(code) for name in pair if name}
        if receiver not in aliases:
            return None
    return _JS_DYNAMIC_EXEC(hit)


def _vue_html(hit: Hit) -> Verdict | None:
    """``v-html="valor"``: só um texto literal entre aspas simples é constante."""
    value = hit.match.group("value").strip()
    if value[:1] in ("'", "`") and value[-1:] == value[:1]:
        return None
    return Verdict(hit.input_kind(value))


_JS_FUNCTION = (
    r"(?m)\bfunction\s*\*?\s*(?P<name>[\w$]+)\s*\(|"
    r"\b(?:const|let|var)\s+(?P<name2>[\w$]+)\s*=\s*(?:async\s*)?(?:\(|[\w$]+\s*=>|function\b)|"
    r"^[ \t]*(?:(?:async|static|public|private|protected)[ \t]+)*(?P<name3>[\w$]+)\([^()\n]*\)[ \t]*(?::[^\n{]*)?\{"
)

_JS_RULES: tuple[SastRule, ...] = (
    make_rule(
        "js.eval",
        EVAL,
        JAVASCRIPT,
        r"(?<![\w.$])eval\s*\(|\b(?:window|globalThis|global)\.eval\s*\(|\bnew\s+Function\s*\(|"
        r"\bvm\.(?:runInContext|runInNewContext|runInThisContext|compileFunction)\s*\(",
        "JavaScript: eval/new Function executa um valor que não é constante",
        keywords=("eval", "Function", "vm."),
        severity_input=_CRITICAL,
        confirm=any_dynamic_arg(),
    ),
    make_rule(
        "js.child_process",
        COMMAND,
        JAVASCRIPT,
        r"""require\(\s*["'](?:node:)?child_process["']\s*\)\s*\.\s*(?:exec|execSync)\s*\(|"""
        r"(?:\b(?P<recv>[\w$]+)\s*\.\s*|(?<![\w.$]))(?:exec|execSync)\s*\(",
        "JavaScript: child_process.exec com comando não constante",
        keywords=("child_process",),
        severity_input=_CRITICAL,
        view="code",
        requires=r"child_process",
        confirm=_js_exec,
    ),
    make_rule(
        "js.spawn_shell",
        COMMAND,
        JAVASCRIPT,
        r"(?:\b[\w$]+\s*\.\s*|(?<![\w.$]))(?:spawn|spawnSync|execFile|execFileSync)\s*\(",
        "JavaScript: spawn/execFile com shell: true e comando não constante",
        keywords=("child_process",),
        severity_input=_CRITICAL,
        requires=r"child_process",
        confirm=_js_spawn,
    ),
    make_rule(
        "js.node_serialize",
        DESER,
        JAVASCRIPT,
        r"\.unserialize\s*\(",
        "JavaScript: node-serialize.unserialize com um valor não constante",
        keywords=("node-serialize",),
        severity=_HIGH,
        severity_input=_CRITICAL,
        requires=r"node-serialize",
        confirm=dynamic_arg(0),
    ),
    make_rule(
        "js.sql",
        SQL,
        JAVASCRIPT,
        r"\.\$?(?:query|execute|raw|run|all|exec|prepare|queryRawUnsafe|executeRawUnsafe|unsafe)\s*\(",
        "JavaScript: SQL montado com variáveis (concatenação ou template)",
        keywords=(
            "query",
            "execute",
            "raw",
            "run(",
            "all(",
            "exec(",
            "prepare",
            "unsafe",
            "Unsafe",
        ),
        severity_input=_CRITICAL,
        confirm=sql_call(),
    ),
    make_rule(
        "js.sql_var",
        SQL,
        JAVASCRIPT,
        SQL_ASSIGNMENT,
        "JavaScript: SQL montado com variáveis em uma variável usada na consulta",
        keywords=("query", "execute", "raw", "run(", "all(", "prepare"),
        severity_input=_CRITICAL,
        view="code",
        confirm=sql_variable(r"\.(?:query|execute|raw|run|all|get|prepare)\s*\(\s*{name}\b"),
    ),
    make_rule(
        "js.reject_unauthorized",
        TLS,
        JAVASCRIPT,
        r"\brejectUnauthorized\s*:\s*false\b|\bstrictSSL\s*:\s*false\b",
        "JavaScript: TLS sem validar o certificado (rejectUnauthorized: false)",
        keywords=("rejectUnauthorized", "strictSSL"),
        severity=_HIGH,
        confidence=_FIRM,
    ),
    make_rule(
        "js.node_tls_env",
        TLS,
        JAVASCRIPT,
        r"""\bprocess\.env(?:\.NODE_TLS_REJECT_UNAUTHORIZED|\[\s*["']NODE_TLS_REJECT_UNAUTHORIZED["']\s*\])\s*=\s*["']?0\b""",
        "JavaScript: validação TLS desligada no processo todo (NODE_TLS_REJECT_UNAUTHORIZED=0)",
        keywords=("NODE_TLS_REJECT_UNAUTHORIZED",),
        severity=_HIGH,
        confidence=_FIRM,
        view="code",
    ),
    make_rule(
        "js.check_server_identity",
        TLS,
        JAVASCRIPT,
        r"\bcheckServerIdentity\s*:\s*(?:\([^)\n]*\)|[\w$]+)\s*=>\s*(?:undefined|null|\{\s*\})",
        "JavaScript: nome do servidor não é validado (checkServerIdentity vazio)",
        keywords=("checkServerIdentity",),
        severity=_HIGH,
        confidence=_FIRM,
    ),
    make_rule(
        "js.hash_password",
        WEAK_HASH,
        JAVASCRIPT,
        # o casamento começa em ".update(" para que os argumentos lidos sejam os do update
        r"""(?:(?<=createHash\("md5"\))|(?<=createHash\('md5'\))|"""
        r"""(?<=createHash\("sha1"\))|(?<=createHash\('sha1'\)))\s*\.\s*update\s*\(""",
        "JavaScript: senha protegida com MD5 ou SHA-1",
        keywords=("createHash",),
        severity=_HIGH,
        confidence=_FIRM,
        view="code",
        confirm=args_mention(PASSWORD_NAME),
    ),
    make_rule(
        "js.hash_helper",
        WEAK_HASH,
        JAVASCRIPT,
        r"(?<![\w.$])(?:md5|sha1)\s*\(|\bCryptoJS\.(?:MD5|SHA1)\s*\(",
        "JavaScript: senha protegida com MD5 ou SHA-1",
        keywords=("md5", "sha1", "MD5", "SHA1"),
        severity=_HIGH,
        confidence=_FIRM,
        confirm=args_mention(PASSWORD_NAME),
    ),
    make_rule(
        "js.random_assign",
        WEAK_RANDOM,
        JAVASCRIPT,
        r"(?P<name>[\w$]+)['\"\]]*\s*(?:=(?![=>])|:)\s*(?=[^\n;]*" + _JS_WEAK_RANDOM + ")",
        "JavaScript: segredo gerado com Math.random (previsível)",
        keywords=("Math.random",),
        confidence=_FIRM,
        confirm=sensitive_assignment(_JS_WEAK_RANDOM),
    ),
    make_rule(
        "js.random_function",
        WEAK_RANDOM,
        JAVASCRIPT,
        _JS_FUNCTION,
        "JavaScript: função que gera segredo usa Math.random (previsível)",
        keywords=("Math.random",),
        confirm=sensitive_function(
            _JS_WEAK_RANDOM,
            next_definition=r"\bfunction\b|\n[ \t]*(?:async[ \t]+)?[\w$]+\([^()\n]*\)[ \t]*\{",
        ),
    ),
    make_rule(
        "js.inner_html",
        XSS,
        JAVASCRIPT,
        r"\.(?:innerHTML|outerHTML)\s*\+?=(?!=)",
        "JavaScript: innerHTML/outerHTML recebe um valor não constante",
        keywords=("innerHTML", "outerHTML"),
        severity=Severity.LOW,
        confirm=value_dynamic(HTML_NEUTRAL),
    ),
    make_rule(
        "js.document_write",
        XSS,
        JAVASCRIPT,
        r"\bdocument\.write(?:ln)?\s*\(",
        "JavaScript: document.write com um valor não constante",
        keywords=("document.write",),
        severity=Severity.LOW,
        confirm=dynamic_arg(0, neutralize=HTML_NEUTRAL),
    ),
    make_rule(
        "js.insert_adjacent",
        XSS,
        JAVASCRIPT,
        r"\.insertAdjacentHTML\s*\(",
        "JavaScript: insertAdjacentHTML com um valor não constante",
        keywords=("insertAdjacentHTML",),
        severity=Severity.LOW,
        confirm=dynamic_arg(1, neutralize=HTML_NEUTRAL),
    ),
    make_rule(
        "js.dangerously_set",
        XSS,
        JAVASCRIPT,
        r"\bdangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:",
        "React: dangerouslySetInnerHTML com um valor não constante",
        keywords=("dangerouslySetInnerHTML",),
        severity=Severity.LOW,
        confirm=value_dynamic(HTML_NEUTRAL),
    ),
    make_rule(
        "js.vue_html",
        XSS,
        JAVASCRIPT,
        r"""\bv-html\s*=\s*"(?P<value>[^"\n]+)\"""",
        "Vue: v-html com um valor não constante",
        keywords=("v-html",),
        severity=Severity.LOW,
        view="code",
        confirm=_vue_html,
    ),
    make_rule(
        "js.angular_bypass",
        XSS,
        JAVASCRIPT,
        r"\.bypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)\s*\(",
        "Angular: bypassSecurityTrust com um valor não constante",
        keywords=("bypassSecurityTrust",),
        severity=Severity.LOW,
        confirm=dynamic_arg(0, neutralize=HTML_NEUTRAL),
    ),
    make_rule(
        "js.jwt_decode",
        JWT,
        JAVASCRIPT,
        r"\b(?:jwt|jsonwebtoken)\.decode\s*\(",
        "JavaScript: JWT lido com jwt.decode, que não verifica a assinatura",
        keywords=("jsonwebtoken",),
        requires=r"jsonwebtoken",
        confirm=_js_jwt_decode,
    ),
    make_rule(
        "js.jwt_none",
        JWT,
        JAVASCRIPT,
        r"""\balgorithms\s*:\s*\[[^\]\n]*["']none["']""",
        "JavaScript: verificação de JWT aceita o algoritmo none",
        keywords=("none",),
        severity=_HIGH,
        confidence=_FIRM,
        view="code",
        requires=r"jsonwebtoken|\bjose\b",
    ),
    make_rule(
        "js.libxml_noent",
        XXE,
        JAVASCRIPT,
        r"\bparseXml(?:String)?\s*\([^)]*\bnoent\s*:\s*true\b",
        "JavaScript: libxmljs com noent: true (substitui entidades externas)",
        keywords=("noent",),
        severity=_HIGH,
        confidence=_FIRM,
    ),
)

SCRIPT_RULES: tuple[SastRule, ...] = (*_PY_RULES, *_JS_RULES)
