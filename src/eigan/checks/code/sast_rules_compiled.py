"""Regras de SAST para Java, C# e Go. As strings abaixo são padrões de busca: nada é executado."""

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
    input_required,
    make_rule,
    sensitive_assignment,
    sensitive_function,
    sql_call,
    sql_value,
    sql_variable,
    statement_arg,
)
from .sast_mask import CSHARP, GO, JAVA

_HIGH = Severity.HIGH
_CRITICAL = Severity.CRITICAL
_FIRM = Confidence.FIRM

_SHELL_WORD = re.compile(
    r"""["'](?:/bin/|/usr/bin/)?(?:ba|z|da)?sh["']|["'](?:cmd|powershell|pwsh)(?:\.exe)?["']""",
    re.I,
)
_SHELL_SWITCH = re.compile(r"""["'](?:-c|/c|-Command)["']""", re.I)


def _shell_verdict(hit: Hit) -> Verdict | None:
    """Comando passado a um shell (``sh -c``/``cmd /c``) com o último argumento não constante."""
    if hit.is_definition() or len(hit.args) < 2:
        return None
    code = " ".join(arg.code for arg in hit.args)
    if _SHELL_WORD.search(code) is None or _SHELL_SWITCH.search(code) is None:
        return None
    last = hit.args[-1].nostr
    kind = classify(last)
    if kind == CONSTANT:
        return None
    return Verdict(hit.input_kind(last), kind != "variavel")


def _escape_then_input(hit: Hit) -> Verdict | None:
    """Saída HTML: só vale se, depois de remover o que foi escapado, ainda sobra entrada externa."""
    if hit.is_definition() or not hit.args:
        return None
    text = HTML_NEUTRAL.sub(" ", hit.args[0].nostr)
    kind = hit.input_kind(text)
    return Verdict(kind) if kind else None


# -- Java -------------------------------------------------------------------------------

_JAVA_WEAK_RANDOM = (
    r"\bMath\.random\s*\(|\bnew\s+Random\s*\([^)]*\)\s*\.\s*next\w*\s*\(|"
    r"\b(?:rnd|random|rand|rng|generator|r)\.next(?:Int|Long|Double|Float|Bytes|Boolean)\s*\(|"
    r"\bThreadLocalRandom\.current\s*\(\s*\)"
)
_JAVA_XML_SAFE = (
    r"disallow-doctype-decl|FEATURE_SECURE_PROCESSING|IS_SUPPORTING_EXTERNAL_ENTITIES|SUPPORT_DTD|"
    r"ACCESS_EXTERNAL_DTD|ACCESS_EXTERNAL_SCHEMA|external-general-entities|setExpandEntityReferences\s*\(\s*false"
)


def _java_exec(hit: Hit) -> Verdict | None:
    """``Runtime.exec``: texto único dinâmico, ou matriz que chama um shell com ``-c``."""
    if hit.is_definition() or not hit.args:
        return None
    first = hit.args[0]
    if "{" in first.nostr or "new String" in first.nostr:
        return _shell_array(hit)
    kind = classify(first.nostr)
    if kind == CONSTANT:
        return None
    return Verdict(hit.input_kind(first.nostr), kind != "variavel")


def _shell_array(hit: Hit) -> Verdict | None:
    code = hit.args[0].code
    if _SHELL_WORD.search(code) is None or _SHELL_SWITCH.search(code) is None:
        return None
    parts = code.rsplit(",", 1)[-1]
    if classify(re.sub(r"[\"'][^\"']*[\"']", '""', parts).replace("}", " ")) == CONSTANT:
        return None
    return Verdict(hit.input_kind(hit.args[0].nostr))


_JAVA_RULES: tuple[SastRule, ...] = (
    make_rule(
        "java.script_eval",
        EVAL,
        JAVA,
        r"\.\s*(?:eval|evaluate|parseExpression)\s*\(",
        "Java: motor de script ou de expressões executa um valor que não é constante",
        keywords=("eval", "evaluate", "parseExpression"),
        severity_input=_CRITICAL,
        requires=r"\b(?:ScriptEngine|GroovyShell|SpelExpressionParser|ExpressionParser|Ognl|MVEL|Binding)\b",
        confirm=dynamic_arg(0),
    ),
    make_rule(
        "java.runtime_exec",
        COMMAND,
        JAVA,
        r"\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*(?P<call>exec)\s*\(",
        "Java: Runtime.exec com comando não constante",
        keywords=("getRuntime",),
        severity_input=_CRITICAL,
        view="code",
        confirm=_java_exec,
    ),
    make_rule(
        "java.process_builder",
        COMMAND,
        JAVA,
        r"\bnew\s+ProcessBuilder\s*\(",
        "Java: ProcessBuilder chama um shell com comando não constante",
        keywords=("ProcessBuilder",),
        severity_input=_CRITICAL,
        view="code",
        confirm=_shell_verdict,
    ),
    make_rule(
        "java.object_input_stream",
        DESER,
        JAVA,
        r"\bnew\s+(?:ObjectInputStream|XMLDecoder)\s*\(|\bnew\s+XStream\s*\(|\.\s*fromXML\s*\(",
        "Java: desserialização nativa (ObjectInputStream, XMLDecoder, XStream) sem lista de classes permitidas",
        keywords=("ObjectInputStream", "XMLDecoder", "XStream"),
        severity_input=_CRITICAL,
        unless=r"\b(?:ObjectInputFilter|setObjectInputFilter|ValidatingObjectInputStream|allowTypes|addPermission|allowTypeHierarchy)\b",
    ),
    make_rule(
        "java.sql",
        SQL,
        JAVA,
        r"\.\s*(?:executeQuery|executeUpdate|execute|prepareStatement|prepareCall|addBatch|createQuery|createNativeQuery|"
        r"createSQLQuery|queryForList|queryForObject|queryForMap|queryForRowSet|query|update|batchUpdate|nativeQuery)\s*\(",
        "Java: SQL montado com variáveis (concatenação ou String.format)",
        keywords=(
            "execute",
            "prepareStatement",
            "createQuery",
            "createNativeQuery",
            "query",
            "update",
            "addBatch",
        ),
        severity_input=_CRITICAL,
        confirm=sql_call(),
    ),
    make_rule(
        "java.sql_var",
        SQL,
        JAVA,
        SQL_ASSIGNMENT,
        "Java: SQL montado com variáveis em uma variável usada na consulta",
        keywords=("execute", "prepareStatement", "createQuery", "createNativeQuery", "query"),
        severity_input=_CRITICAL,
        view="code",
        confirm=sql_variable(
            r"\.\s*(?:executeQuery|executeUpdate|execute|prepareStatement|createQuery|createNativeQuery|createSQLQuery|"
            r"queryForList|queryForObject|query|update)\s*\(\s*{name}\b"
        ),
    ),
    make_rule(
        "java.trust_manager",
        TLS,
        JAVA,
        r"\bcheck(?:Server|Client)Trusted\s*\([^)]*\)\s*(?:throws\s+[\w.,\s]+)?\{\s*(?:return\s*;\s*)?\}",
        "Java: TrustManager que aceita qualquer certificado (checkServerTrusted vazio)",
        keywords=("checkServerTrusted", "checkClientTrusted"),
        severity=_HIGH,
        confidence=_FIRM,
    ),
    make_rule(
        "java.insecure_factory",
        TLS,
        JAVA,
        r"\bInsecureTrustManagerFactory\b|\bTrustAllStrategy\b|\bTrustSelfSignedStrategy\b|"
        r"\bNoopHostnameVerifier\b|\bALLOW_ALL_HOSTNAME_VERIFIER\b|\bTrustAllCerts\b",
        "Java: cliente TLS configurado para confiar em qualquer certificado ou nome",
        keywords=(
            "InsecureTrustManagerFactory",
            "TrustAll",
            "TrustSelfSigned",
            "Noop",
            "ALLOW_ALL",
        ),
        severity=_HIGH,
        confidence=_FIRM,
    ),
    make_rule(
        "java.hostname_verifier",
        TLS,
        JAVA,
        r"\bverify\s*\(\s*(?:final\s+)?String\s+\w+\s*,\s*(?:final\s+)?SSLSession\s+\w+\s*\)\s*\{\s*return\s+true\s*;|"
        r"\b(?:setHostnameVerifier|setDefaultHostnameVerifier|hostnameVerifier)\s*\(\s*(?:\([^)]*\)|\w+)\s*->\s*true\b|"
        r"\bHostnameVerifier\s+\w+\s*=\s*(?:\([^)]*\)|\w+)\s*->\s*true\b",
        "Java: verificador de nome do servidor que sempre aceita (HostnameVerifier retorna true)",
        keywords=("HostnameVerifier", "verify", "setHostnameVerifier"),
        severity=_HIGH,
        confidence=_FIRM,
    ),
    make_rule(
        "java.hash_digest",
        WEAK_HASH,
        JAVA,
        r"""\bMessageDigest\s*\.\s*getInstance\s*\(\s*"(?i:md5|sha-?1)"\s*\)(?:[^\n]*\n){0,5}?[^\n]*\.\s*(?:digest|update)\s*\([^)\n]*"""
        + PASSWORD_NAME,
        "Java: senha protegida com MD5 ou SHA-1",
        keywords=("MessageDigest",),
        severity=_HIGH,
        confidence=_FIRM,
        view="code",
    ),
    make_rule(
        "java.hash_codec",
        WEAK_HASH,
        JAVA,
        r"\bDigestUtils\s*\.\s*(?:md5|sha1|sha|md5Hex|sha1Hex|shaHex)\w*\s*\(|\bHashing\s*\.\s*(?:md5|sha1)\s*\(\s*\)",
        "Java: senha protegida com MD5 ou SHA-1",
        keywords=("DigestUtils", "Hashing"),
        severity=_HIGH,
        confidence=_FIRM,
        confirm=args_mention(PASSWORD_NAME),
    ),
    make_rule(
        "java.random_assign",
        WEAK_RANDOM,
        JAVA,
        r"(?P<name>[\w.]+)\s*=(?!=)\s*(?=[^\n;]*(?:" + _JAVA_WEAK_RANDOM + "))",
        "Java: segredo gerado com java.util.Random (previsível)",
        keywords=("Random", "Math.random"),
        confidence=_FIRM,
        unless=r"\bSecureRandom\b",
        confirm=sensitive_assignment(_JAVA_WEAK_RANDOM),
    ),
    make_rule(
        "java.random_function",
        WEAK_RANDOM,
        JAVA,
        r"(?m)^[ \t]*(?:(?:public|private|protected|static|final|synchronized)[ \t]+)+[\w<>\[\], ?]+?[ \t]+(?P<name>\w+)[ \t]*\([^)]*\)[ \t]*(?:throws[^{;]*)?\{",
        "Java: método que gera segredo usa java.util.Random (previsível)",
        keywords=("Random", "Math.random"),
        unless=r"\bSecureRandom\b",
        confirm=sensitive_function(
            _JAVA_WEAK_RANDOM, next_definition=r"\n[ \t]*(?:public|private|protected)[ \t]"
        ),
    ),
    make_rule(
        "java.jwt_decode",
        JWT,
        JAVA,
        r"(?<![\w.])JWT\s*\.\s*decode\s*\(",
        "Java: JWT lido com JWT.decode, que não verifica a assinatura",
        keywords=("JWT.decode",),
        requires=r"\bcom\.auth0\.jwt\b",
    ),
    make_rule(
        "java.jwt_none",
        JWT,
        JAVA,
        r"\bAlgorithm\s*\.\s*none\s*\(\s*\)|\bSignatureAlgorithm\s*\.\s*NONE\b",
        "Java: JWT sem assinatura (algoritmo none)",
        keywords=("Algorithm.none", "SignatureAlgorithm.NONE"),
        severity=_HIGH,
        confidence=_FIRM,
    ),
    make_rule(
        "java.xxe_factory",
        XXE,
        JAVA,
        r"\b(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|SchemaFactory|TransformerFactory)\s*\.\s*(?:newInstance|newFactory)\s*\(|"
        r"\bnew\s+(?:SAXBuilder|SAXReader|SAXTransformerFactory)\s*\(|\bXMLReaderFactory\s*\.\s*createXMLReader\s*\(",
        "Java: parser XML sem desligar entidades externas (XXE)",
        keywords=(
            "DocumentBuilderFactory",
            "SAXParserFactory",
            "XMLInputFactory",
            "SchemaFactory",
            "TransformerFactory",
            "SAXBuilder",
            "SAXReader",
            "createXMLReader",
        ),
        severity=Severity.MEDIUM,
        severity_input=_HIGH,
        unless=_JAVA_XML_SAFE,
    ),
    make_rule(
        "java.reflected_xss",
        XSS,
        JAVA,
        r"\b(?:getWriter\s*\(\s*\)|out|writer|pw)\s*\.\s*(?:print|println|write|append|printf)\s*\(",
        "Java: entrada da requisição escrita na resposta sem escapar",
        keywords=("getWriter", "println", "print", "write"),
        severity=Severity.MEDIUM,
        confirm=_escape_then_input,
    ),
)

# -- C# ---------------------------------------------------------------------------------

_CS_WEAK_RANDOM = r"\bnew\s+Random\s*\(|\b(?:rnd|random|rand|rng|generator)\.Next(?:Bytes|Double|Int64)?\s*\(|\bRandom\.Shared\b"
_CS_HASH_CLASS = r"(?:MD5|SHA1)(?:CryptoServiceProvider|Managed|Cng)?"


def _cs_arguments(hit: Hit) -> Verdict | None:
    value = statement_arg(hit.source, hit.match.end())
    kind = classify(value.nostr)
    if kind == CONSTANT:
        return None
    return Verdict(hit.input_kind(value.nostr), kind != "variavel")


def _cs_hash_password(hit: Hit) -> Verdict | None:
    """``MD5.HashData(x)`` só conta se ``x`` parece uma senha; as outras formas já casaram pelo nome."""
    if "HashData" in hit.match.group():
        return args_mention(PASSWORD_NAME)(hit)
    return Verdict()


_CS_RULES: tuple[SastRule, ...] = (
    make_rule(
        "cs.script_eval",
        EVAL,
        CSHARP,
        r"\bCSharpScript\s*\.\s*(?:EvaluateAsync|RunAsync)\s*(?:<[^>(]+>)?\s*\(|\.\s*CompileAssemblyFromSource\s*\(",
        "C#: compilação ou avaliação de código a partir de um valor que não é constante",
        keywords=("CSharpScript", "CompileAssemblyFromSource"),
        severity_input=_CRITICAL,
        confirm=any_dynamic_arg(),
    ),
    make_rule(
        "cs.process_start",
        COMMAND,
        CSHARP,
        r"\bProcess\s*\.\s*Start\s*\(",
        "C#: Process.Start com comando não constante",
        keywords=("Process.Start",),
        severity_input=_CRITICAL,
        confirm=dynamic_arg(0),
    ),
    make_rule(
        "cs.shell_arguments",
        COMMAND,
        CSHARP,
        r"\bArguments\s*=(?!=)\s*",
        "C#: argumentos de um shell (cmd /c, sh -c) montados com variáveis",
        keywords=("Arguments",),
        severity_input=_CRITICAL,
        requires=r"""["'](?:cmd(?:\.exe)?|/bin/(?:ba)?sh|powershell(?:\.exe)?|pwsh)["']""",
        confirm=_cs_arguments,
    ),
    make_rule(
        "cs.binary_formatter",
        DESER,
        CSHARP,
        r"\bnew\s+(?:BinaryFormatter|SoapFormatter|NetDataContractSerializer|LosFormatter|ObjectStateFormatter)\s*\(",
        "C#: formatador binário da plataforma (BinaryFormatter e parentes) é inseguro por projeto",
        keywords=(
            "BinaryFormatter",
            "SoapFormatter",
            "NetDataContractSerializer",
            "LosFormatter",
            "ObjectStateFormatter",
        ),
        severity=_HIGH,
        confidence=_FIRM,
        severity_input=_CRITICAL,
    ),
    make_rule(
        "cs.type_name_handling",
        DESER,
        CSHARP,
        r"\bTypeNameHandling\s*(?:=|:)\s*TypeNameHandling\.(?:All|Auto|Objects|Arrays)\b|\bSimpleTypeResolver\b",
        "C#: JSON que carrega o tipo do objeto (TypeNameHandling) permite criar classes escolhidas pelo remetente",
        keywords=("TypeNameHandling", "SimpleTypeResolver"),
        severity=_HIGH,
        confidence=_FIRM,
        severity_input=_CRITICAL,
    ),
    make_rule(
        "cs.sql",
        SQL,
        CSHARP,
        r"\bnew\s+(?:Sql|MySql|Npgsql|Oracle|Sqlite|OleDb|Odbc|Fb|DB2)\w*Command\s*\(|"
        r"\.\s*(?:ExecuteSqlRaw|ExecuteSqlRawAsync|FromSqlRaw|SqlQuery|SqlQueryRaw|Query|QueryAsync|QueryFirst\w*|QuerySingle\w*|Execute|ExecuteAsync|ExecuteScalar|ExecuteReader)"
        r"\s*(?:<[^>(]+>)?\s*\(",
        "C#: SQL montado com variáveis (concatenação ou interpolação)",
        keywords=("Command", "ExecuteSqlRaw", "FromSqlRaw", "SqlQuery", "Query", "Execute"),
        severity_input=_CRITICAL,
        confirm=sql_call(),
    ),
    make_rule(
        "cs.command_text",
        SQL,
        CSHARP,
        r"\bCommandText\s*=(?!=)\s*",
        "C#: CommandText montado com variáveis",
        keywords=("CommandText",),
        severity_input=_CRITICAL,
        confirm=sql_value(),
    ),
    make_rule(
        "cs.cert_callback",
        TLS,
        CSHARP,
        r"\b(?:ServerCertificateValidationCallback|ServerCertificateCustomValidationCallback|RemoteCertificateValidationCallback)\s*\+?=\s*"
        r"(?:[^;{]*=>\s*(?:true\b|\{\s*return\s+true\s*;\s*\})|delegate\s*(?:\([^)]*\))?\s*\{\s*return\s+true\s*;\s*\})|"
        r"\bDangerousAcceptAnyServerCertificateValidator\b",
        "C#: validação de certificado TLS que aceita tudo (callback retorna true)",
        keywords=(
            "CertificateValidationCallback",
            "CertificateCustomValidationCallback",
            "DangerousAcceptAny",
        ),
        severity=_HIGH,
        confidence=_FIRM,
    ),
    make_rule(
        "cs.hash_password",
        WEAK_HASH,
        CSHARP,
        r"\b"
        + _CS_HASH_CLASS
        + r"\s*\.\s*(?:HashData\s*\(|Create\s*\(\s*\)(?:[^\n]*\n){0,5}?[^\n]*\.\s*ComputeHash\s*\([^)\n]*"
        + PASSWORD_NAME
        + r")|"
        r"\bnew\s+"
        + _CS_HASH_CLASS
        + r"\s*\(\s*\)(?:[^\n]*\n){0,5}?[^\n]*\.\s*ComputeHash\s*\([^)\n]*"
        + PASSWORD_NAME,
        "C#: senha protegida com MD5 ou SHA-1",
        keywords=("MD5", "SHA1"),
        severity=_HIGH,
        confidence=_FIRM,
        confirm=_cs_hash_password,
    ),
    make_rule(
        "cs.random_assign",
        WEAK_RANDOM,
        CSHARP,
        r"(?P<name>[\w.]+)\s*=(?!=)\s*(?=[^\n;]*(?:" + _CS_WEAK_RANDOM + "))",
        "C#: segredo gerado com System.Random (previsível)",
        keywords=("Random",),
        confidence=_FIRM,
        unless=r"\bRandomNumberGenerator\b|\bRNGCryptoServiceProvider\b",
        confirm=sensitive_assignment(_CS_WEAK_RANDOM),
    ),
    make_rule(
        "cs.random_function",
        WEAK_RANDOM,
        CSHARP,
        r"(?m)^[ \t]*(?:(?:public|private|protected|internal|static|async|override)[ \t]+)+[\w<>\[\],?. ]+?[ \t]+(?P<name>\w+)[ \t]*\([^)]*\)[ \t]*\{",
        "C#: método que gera segredo usa System.Random (previsível)",
        keywords=("Random",),
        unless=r"\bRandomNumberGenerator\b|\bRNGCryptoServiceProvider\b",
        confirm=sensitive_function(
            _CS_WEAK_RANDOM, next_definition=r"\n[ \t]*(?:public|private|protected|internal)[ \t]"
        ),
    ),
    make_rule(
        "cs.xxe",
        XXE,
        CSHARP,
        r"\bXmlResolver\s*=\s*new\s+XmlUrlResolver\s*\(|\bDtdProcessing\s*=\s*DtdProcessing\.Parse\b|\bProhibitDtd\s*=\s*false\b",
        "C#: parser XML que resolve entidades externas (XXE)",
        keywords=("XmlUrlResolver", "DtdProcessing", "ProhibitDtd"),
        severity=_HIGH,
        confidence=_FIRM,
    ),
    make_rule(
        "cs.jwt_validation",
        JWT,
        CSHARP,
        r"\b(?:ValidateIssuerSigningKey|RequireSignedTokens)\s*=\s*false\b",
        "C#: validação de JWT sem exigir assinatura confiável",
        keywords=("ValidateIssuerSigningKey", "RequireSignedTokens"),
        severity=_HIGH,
        confidence=_FIRM,
    ),
    make_rule(
        "cs.jwt_signature_validator",
        JWT,
        CSHARP,
        r"\bSignatureValidator\s*=\s*(?:delegate|\([^)]*\)\s*=>)",
        "C#: JWT com validador de assinatura próprio que pode aceitar qualquer token",
        keywords=("SignatureValidator",),
        severity=_HIGH,
    ),
    make_rule(
        "cs.html_raw",
        XSS,
        CSHARP,
        r"\bHtml\s*\.\s*Raw\s*\(|\bResponse\s*\.\s*Write\s*\(|\bnew\s+HtmlString\s*\(",
        "C#: entrada da requisição escrita como HTML sem codificar",
        keywords=("Html.Raw", "Response.Write", "HtmlString"),
        confirm=_escape_then_input,
    ),
)


# -- Go ---------------------------------------------------------------------------------

_GO_WEAK_RANDOM = r"\brand\.(?:Int|Intn|Int31|Int31n|Int63|Int63n|Uint32|Uint64|Float32|Float64|Read|Perm|Shuffle|N)\w*\s*\("
_GO_SINKS = r"\.\s*(?:Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext|Prepare|PrepareContext|Raw|Select|Get|NamedQuery)\s*\(\s*(?:ctx\s*,\s*)?{name}\b"


def _go_command(hit: Hit) -> Verdict | None:
    """``exec.Command``: shell com texto dinâmico, ou programa escolhido pela requisição."""
    shell = _shell_verdict(hit)
    if shell is not None:
        return shell
    if hit.is_definition() or not hit.args:
        return None
    first = hit.args[0].nostr
    if classify(first) == CONSTANT:
        return None
    kind = hit.input_kind(first)
    return Verdict(kind) if kind else None


_GO_RULES: tuple[SastRule, ...] = (
    make_rule(
        "go.exec_command",
        COMMAND,
        GO,
        r"\bexec\.Command(?:Context)?\s*\(",
        "Go: exec.Command chama um shell com comando não constante",
        keywords=("exec.Command",),
        severity_input=_CRITICAL,
        view="code",
        confirm=_go_command,
    ),
    make_rule(
        "go.sql",
        SQL,
        GO,
        r"\.\s*(?:Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext|Prepare|PrepareContext|Raw|Select|Get|NamedQuery)\s*\(",
        "Go: SQL montado com variáveis (fmt.Sprintf ou concatenação)",
        keywords=("Query", "Exec", "Prepare", "Raw", "Select", "Get"),
        severity_input=_CRITICAL,
        confirm=sql_call(),
    ),
    make_rule(
        "go.sql_var",
        SQL,
        GO,
        SQL_ASSIGNMENT,
        "Go: SQL montado com variáveis em uma variável usada na consulta",
        keywords=("Query", "Exec", "Prepare", "Raw"),
        severity_input=_CRITICAL,
        view="code",
        confirm=sql_variable(_GO_SINKS),
    ),
    make_rule(
        "go.insecure_skip_verify",
        TLS,
        GO,
        r"\bInsecureSkipVerify\s*(?::|=)\s*true\b",
        "Go: cliente TLS sem validar o certificado (InsecureSkipVerify: true)",
        keywords=("InsecureSkipVerify",),
        severity=_HIGH,
        confidence=_FIRM,
    ),
    make_rule(
        "go.hash_sum",
        WEAK_HASH,
        GO,
        r"\b(?:md5|sha1)\.Sum\s*\(",
        "Go: senha protegida com MD5 ou SHA-1",
        keywords=("md5.Sum", "sha1.Sum"),
        severity=_HIGH,
        confidence=_FIRM,
        confirm=args_mention(PASSWORD_NAME),
    ),
    make_rule(
        "go.hash_write",
        WEAK_HASH,
        GO,
        r"\b(?:md5|sha1)\.New\s*\(\s*\)(?:[^\n]*\n){0,5}?[^\n]*\.Write\s*\([^)\n]*" + PASSWORD_NAME,
        "Go: senha protegida com MD5 ou SHA-1",
        keywords=("md5.New", "sha1.New"),
        severity=_HIGH,
        confidence=_FIRM,
    ),
    make_rule(
        "go.random_assign",
        WEAK_RANDOM,
        GO,
        r"(?P<name>[\w.]+)\s*(?::=|=(?!=))\s*(?=[^\n;]*" + _GO_WEAK_RANDOM + ")",
        "Go: segredo gerado com math/rand (previsível)",
        keywords=("rand.",),
        confidence=_FIRM,
        requires=r"\"math/rand(?:/v2)?\"",
        unless=r"\"crypto/rand\"",
        confirm=sensitive_assignment(_GO_WEAK_RANDOM),
    ),
    make_rule(
        "go.random_function",
        WEAK_RANDOM,
        GO,
        r"(?m)^func[ \t]+(?:\([^)]*\)[ \t]*)?(?P<name>\w+)[ \t]*\(",
        "Go: função que gera segredo usa math/rand (previsível)",
        keywords=("rand.",),
        requires=r"\"math/rand(?:/v2)?\"",
        unless=r"\"crypto/rand\"",
        confirm=sensitive_function(_GO_WEAK_RANDOM, next_definition=r"\nfunc\s"),
    ),
    make_rule(
        "go.jwt_unverified",
        JWT,
        GO,
        r"\.\s*ParseUnverified\s*\(|\bjwt\.UnsafeAllowNoneSignatureType\b",
        "Go: JWT lido sem verificar a assinatura (ParseUnverified ou algoritmo none)",
        keywords=("ParseUnverified", "UnsafeAllowNoneSignatureType"),
        severity=_HIGH,
        requires=r"\bjwt\b",
    ),
    make_rule(
        "go.template_html",
        XSS,
        GO,
        r"\btemplate\.(?:HTML|JS|HTMLAttr|URL)\s*\(",
        "Go: entrada da requisição marcada como HTML confiável (template.HTML) e escrita sem escapar",
        keywords=("template.HTML", "template.JS", "template.HTMLAttr", "template.URL"),
        requires=r"\"html/template\"",
        confirm=input_required(0),
    ),
)

COMPILED_RULES: tuple[SastRule, ...] = (*_JAVA_RULES, *_CS_RULES, *_GO_RULES)
