"""Assinaturas de páginas: diagnóstico, documentação de API, painéis, logs, manifestos e metarquivos.

Complementa :mod:`signatures` (segredos, backups e controle de versão). Mesmo contrato:
cada função recebe a resposta de uma sonda e devolve um :class:`~.signatures.Match` ou
``None``. As assinaturas dos CMS ficam em :mod:`cms`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime

from ...core.http import Response
from ...core.models import Confidence, Severity
from .common import looks_html
from .signatures import Match, htmlish, json_body

# -- páginas de diagnóstico ----------------------------------------------------------


def phpinfo(resp: Response) -> Match | None:
    text = resp.text[:65_536]
    if "phpinfo()</title>" not in text and not (
        "PHP Version" in text and ("PHP Extension" in text or "Zend Engine" in text)
    ):
        return None
    version = re.search(r"PHP Version\s*(?:</[^>]+>\s*<[^>]+>\s*)?([\d.]+)", text)
    shown = f" (PHP {version.group(1)})" if version else ""
    return Match(
        f"Página phpinfo() exposta{shown}", details={"php": version.group(1) if version else None}
    )


def apache_status(resp: Response) -> Match | None:
    text = resp.text[:65_536]
    if "Apache Server Status for" in text:
        return Match(
            "Apache server-status exposto (requisições em andamento, IPs de clientes e URLs)"
        )
    if "Apache Server Information" in text:
        return Match("Apache server-info exposto (módulos e configuração do servidor)")
    return None


def nginx_status(resp: Response) -> Match | None:
    text = resp.text[:4_096]
    if re.search(r"Active connections:\s*\d+", text) and "server accepts handled requests" in text:
        return Match("Página de status do nginx (stub_status) exposta", Severity.LOW)
    return None


def php_fpm_status(resp: Response) -> Match | None:
    """Página de status do PHP-FPM (``pm.status_path``) em texto: pool e contadores."""
    text = resp.text[:8_192]
    if htmlish(text) or not re.search(r"^pool:\s+\S+", text, re.M):
        return None
    if "process manager:" not in text or "accepted conn:" not in text:
        return None
    pool = re.search(r"^pool:\s+(\S+)", text, re.M)
    return Match(f"Status do PHP-FPM exposto (pool {pool.group(1) if pool else '?'})", Severity.LOW)


_PROM_HELP = re.compile(r"^# HELP [a-zA-Z_:][a-zA-Z0-9_:]* ", re.M)
_PROM_TYPE = re.compile(
    r"^# TYPE [a-zA-Z_:][a-zA-Z0-9_:]* (?:counter|gauge|histogram|summary|untyped)\s*$", re.M
)


def prometheus_metrics(resp: Response) -> Match | None:
    """Formato de exposição de métricas do Prometheus (linhas ``# HELP`` e ``# TYPE``)."""
    text = resp.text[:65_536]
    if htmlish(text):
        return None
    helps, types = len(_PROM_HELP.findall(text)), len(_PROM_TYPE.findall(text))
    if helps < 2 or types < 2:
        return None
    return Match(
        f"Métricas internas do Prometheus públicas ({types}+ séries descritas)", Severity.LOW
    )


def pprof_index(resp: Response) -> Match | None:
    """Índice do ``net/http/pprof`` do Go (perfis, pilhas e linha de comando do processo)."""
    text = resp.text[:16_384]
    if "<title>/debug/pprof/</title>" in text and "Types of profiles available" in text:
        return Match(
            "Go pprof exposto: linha de comando, pilhas das goroutines e perfis de memória do processo",
            Severity.MEDIUM,
        )
    return None


def ignition_health(resp: Response) -> Match | None:
    """``/_ignition/health-check`` do Laravel Ignition: página de erro de depuração ativa."""
    data = json_body(resp)
    if not isinstance(data, dict) or not isinstance(data.get("can_execute_commands"), bool):
        return None
    runnable = data["can_execute_commands"]
    extra = " e pode executar comandos de solução" if runnable else ""
    return Match(
        f"Laravel Ignition ativo em produção (modo de depuração){extra}",
        details={"can_execute_commands": runnable},
    )


_ACTUATOR_SENSITIVE = (
    "env", "heapdump", "configprops", "mappings", "threaddump", "loggers", "jolokia",
    "httptrace", "httpexchanges", "trace", "logfile", "beans", "shutdown", "gateway",
)  # fmt: skip


def actuator_index(resp: Response) -> Match | None:
    """Índice do Actuator. O ``heapdump`` NUNCA é baixado: só o link no índice já é a prova."""
    data = json_body(resp)
    links = data.get("_links") if isinstance(data, dict) else None
    if not isinstance(links, dict):
        return None
    exposed = sorted(
        name
        for name, link in links.items()
        if name in _ACTUATOR_SENSITIVE and isinstance(link, dict) and "href" in link
    )
    if not exposed:
        return None
    severity = Severity.CRITICAL if "heapdump" in exposed else None
    return Match(
        f"Spring Boot Actuator lista endpoints sensíveis no índice: {', '.join(exposed)} "
        "(o acesso a cada um não foi testado)",
        severity,
        confidence=Confidence.TENTATIVE,
        details={"endpoints": sorted(links)},
    )


def actuator_env(resp: Response) -> Match | None:
    data = json_body(resp)
    if not isinstance(data, dict):
        return None
    if "propertySources" in data or ("profiles" in data and "systemProperties" in data):
        return Match("Actuator /env expõe variáveis de ambiente e propriedades da aplicação")
    return None


def actuator_configprops(resp: Response) -> Match | None:
    text = resp.text[:65_536]
    if re.match(r"\s*\{", text) and '"contexts"' in text and '"beans"' in text:
        return Match("Actuator /configprops expõe a configuração dos componentes")
    return None


def actuator_health(resp: Response) -> Match | None:
    data = json_body(resp)
    if isinstance(data, dict) and "status" in data and ("components" in data or "details" in data):
        parts = data.get("components") or data.get("details") or {}
        names = ", ".join(sorted(parts)[:6]) if isinstance(parts, dict) else ""
        return Match(f"Actuator /health mostra detalhes internos ({names})", Severity.LOW)
    return None


def jenkins_script_console(resp: Response) -> Match | None:
    """Console de scripts do Jenkins sem login: executa Groovy no servidor."""
    if resp.status != 200 or not resp.header("x-jenkins"):
        return None
    if "Script Console" not in resp.text[:65_536]:
        return None
    version = (resp.header("x-jenkins") or "")[:20]
    return Match(
        f"Console de scripts do Jenkins {version} aberto, sem pedir login",
        Severity.CRITICAL,
        details={"jenkins": version},
    )


def jolokia(resp: Response) -> Match | None:
    data = json_body(resp)
    value = data.get("value") if isinstance(data, dict) else None
    if isinstance(value, dict) and "agent" in value and "protocol" in value:
        return Match("Jolokia (JMX via HTTP) exposto: permite operar a JVM remotamente")
    return None


def spring_trace(resp: Response) -> Match | None:
    text = resp.text[:16_384]
    if (
        re.match(r"\s*\[\s*\{", text)
        and '"timestamp"' in text
        and '"info"' in text
        and '"path"' in text
    ):
        return Match("Actuator /trace expõe requisições recentes (com cabeçalhos e cookies)")
    return None


def elmah(resp: Response) -> Match | None:
    text = resp.text[:65_536]
    if "Error Log for" in text and re.search(r"elmah", text, re.I):
        return Match("ELMAH exposto: log de erros com detalhes de requisições e sessões")
    return None


def trace_axd(resp: Response) -> Match | None:
    text = resp.text[:65_536]
    if "Application Trace" in text and (
        "Requests to this Application" in text or "Trace Information" in text
    ):
        return Match("Trace.axd do ASP.NET exposto: requisições com cabeçalhos, cookies e sessão")
    return None


def symfony_profiler(resp: Response) -> Match | None:
    if "Symfony Profiler" in resp.text[:65_536]:
        return Match("Symfony Profiler exposto (modo de depuração ativo)")
    return None


def telescope(resp: Response) -> Match | None:
    text = resp.text[:65_536]
    if "vendor/telescope" in text or "window.Telescope" in text:
        return Match("Laravel Telescope exposto: requisições, consultas e exceções da aplicação")
    return None


# -- documentação de API e painéis ---------------------------------------------------------


def openapi_json(resp: Response) -> Match | None:
    head = resp.text[:65_536]
    if re.search(r'"swagger"\s*:\s*"2\.0"', head) or re.search(r'"openapi"\s*:\s*"3\.\d', head):
        title = re.search(r'"title"\s*:\s*"([^"]{1,80})"', head)
        return Match(
            "Especificação OpenAPI/Swagger pública" + (f" ({title.group(1)})" if title else "")
        )
    return None


def swagger_ui(resp: Response) -> Match | None:
    text = resp.text[:65_536]
    if re.search(
        r"swagger-ui(?:-bundle|\.css|\.js|-standalone)|SwaggerUIBundle|<redoc[\s>]|redoc\.standalone",
        text,
    ):
        return Match("Interface de documentação da API (Swagger UI/ReDoc) pública")
    return None


#: a consulta de introspecção mínima (só o nome do tipo raiz, resposta pequena)
INTROSPECTION_QUERY = '{"query":"{__schema{queryType{name}}}"}'
_GRAPHQL_UI = re.compile(
    r"graphiql|graphql[- ]playground|embeddable-sandbox|apollo-server-landing-page", re.I
)
_GRAPHQL_ERROR = re.compile(r'"errors"\s*:\s*\[.{0,400}?\b(?:query|graphql|operation)', re.I | re.S)


def graphql_hint(resp: Response) -> str | None:
    """A resposta veio de um servidor GraphQL (mesmo recusando a introspecção)? Devolve a pista."""
    text = resp.text[:16_384]
    if resp.is_html and _GRAPHQL_UI.search(text):
        return "interface de testes do GraphQL (GraphiQL/Playground/Apollo) pública"
    if text.lstrip().startswith("{") and _GRAPHQL_ERROR.search(text):
        return "resposta de erro no formato GraphQL"
    return None


def graphql_introspection(resp: Response) -> Match | None:
    data = json_body(resp)
    payload = data.get("data") if isinstance(data, dict) else None
    schema = payload.get("__schema") if isinstance(payload, dict) else None
    root = schema.get("queryType") if isinstance(schema, dict) else None
    if not isinstance(root, dict):
        return None
    return Match(
        f"A consulta de introspecção devolveu o esquema (tipo raiz: {root.get('name') or '?'})"
    )


def phpmyadmin(resp: Response) -> Match | None:
    text = resp.text[:65_536]
    if "phpMyAdmin" in text and re.search(
        r"pma_|pmahomme|phpmyadmin\.css|<title>phpMyAdmin", text, re.I
    ):
        return Match("Tela de acesso do phpMyAdmin acessível pela Internet")
    return None


def adminer(resp: Response) -> Match | None:
    text = resp.text[:65_536]
    if "Adminer" in text and re.search(r"adminer\.org|name=[\"']auth\[|adminer\.css", text):
        return Match("Tela de acesso do Adminer acessível pela Internet")
    return None


def tomcat_manager(resp: Response) -> Match | None:
    realm = (resp.header("www-authenticate") or "").lower()
    if resp.status == 401 and "tomcat manager application" in realm:
        return Match("Tomcat Manager acessível pela Internet (pede usuário e senha)")
    return None


def h2_console(resp: Response) -> Match | None:
    if "<title>H2 Console</title>" in resp.text[:16_384]:
        return Match("Console do banco H2 acessível pela Internet", Severity.HIGH)
    return None


def admin_login(resp: Response) -> Match | None:
    """Painel genérico: página de login (assinatura fraca, exige comparar com o soft 404)."""
    if resp.status == 401 and resp.header("www-authenticate"):
        scheme = (resp.header("www-authenticate") or "").split(" ", 1)[0]
        return Match(
            f"Área restrita protegida só por autenticação HTTP ({scheme})",
            confidence=Confidence.FIRM,
        )
    text = resp.text[:65_536]
    if resp.status != 200 or not resp.is_html:
        return None
    if re.search(r"type=[\"']?password", text, re.I) and re.search(
        r"admin|login|entrar|acesso|sign.?in|log.?in", text, re.I
    ):
        return Match("Página de login administrativa acessível", confidence=Confidence.FIRM)
    return None


# -- logs, manifestos, infraestrutura ---------------------------------------------------

_LOG_PATTERNS = (
    ("Laravel", re.compile(r"^\[\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}[^\]]*\] \w+\.(?:EMERGENCY|ALERT|CRITICAL|ERROR|WARNING|NOTICE|INFO|DEBUG):", re.M)),
    ("PHP", re.compile(r"^\[\d{2}-\w{3}-\d{4} \d{2}:\d{2}:\d{2}[^\]]*\] PHP (?:Fatal error|Warning|Notice|Parse error|Deprecated|Stack trace)", re.M)),
    ("Apache", re.compile(r"^\[(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun) \w{3} \d{1,2} \d{2}:\d{2}:\d{2}(?:\.\d+)? \d{4}\] \[[\w:]+\]", re.M)),
    ("acesso", re.compile(r'^\S+ \S+ \S+ \[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\] "(?:GET|POST|HEAD|PUT|DELETE|OPTIONS) ', re.M)),
    ("aplicação", re.compile(r"^.{0,40}\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}.{0,120}\b(?:ERROR|WARN(?:ING)?|FATAL|CRITICAL|Exception|Traceback)\b", re.M)),
)  # fmt: skip


def log_file(resp: Response) -> Match | None:
    text = resp.text[:65_536]
    if htmlish(text):
        return None
    if text.startswith("0 info it worked if it ends with ok"):
        return Match("Log de depuração do npm legível (caminhos e ambiente do servidor)")
    for name, pattern in _LOG_PATTERNS:
        count = len(pattern.findall(text))
        if count >= 2:
            return Match(
                f"Arquivo de log ({name}) legível: {count}+ registros no início do arquivo"
            )
    return None


def composer_json(resp: Response) -> Match | None:
    data = json_body(resp)
    if isinstance(data, dict) and isinstance(data.get("require"), dict):
        deps = len(data["require"]) + len(data.get("require-dev") or {})
        return Match(f"composer.json legível ({deps} dependências PHP listadas)")
    return None


def composer_lock(resp: Response) -> Match | None:
    head = resp.text[:4_096]
    if not re.match(r"\s*\{", head):
        return None
    if '"content-hash"' in head or ('"_readme"' in head and '"packages"' in resp.text):
        return Match("composer.lock legível (versões exatas de todas as dependências PHP)")
    return None


def package_json(resp: Response) -> Match | None:
    data = json_body(resp)
    if not isinstance(data, dict):
        return None
    deps = data.get("dependencies") or data.get("devDependencies")
    if isinstance(deps, dict) and ("name" in data or "scripts" in data or "version" in data):
        total = len(data.get("dependencies") or {}) + len(data.get("devDependencies") or {})
        return Match(f"package.json legível ({total} dependências Node.js listadas)")
    return None


def package_lock(resp: Response) -> Match | None:
    head = resp.text[:2_048]
    if re.match(r"\s*\{", head) and re.search(r'"lockfileVersion"\s*:\s*\d', head):
        return Match("package-lock.json legível (versões exatas das dependências Node.js)")
    return None


def yarn_lock(resp: Response) -> Match | None:
    head = resp.text[:2_048]
    if "yarn lockfile v1" in head or (
        "__metadata:" in head and "resolution:" in resp.text[:16_384]
    ):
        return Match("yarn.lock legível (versões exatas das dependências Node.js)")
    return None


def other_lock(resp: Response) -> Match | None:
    head = resp.text[:2_048]
    if head.startswith("lockfileVersion:"):
        return Match("pnpm-lock.yaml legível (versões exatas das dependências Node.js)")
    if head.startswith("GEM\n") and "specs:" in head:
        return Match("Gemfile.lock legível (versões exatas das dependências Ruby)")
    return None


_DOCKER_INSTRUCTION = re.compile(
    r"^[ \t]*(FROM|RUN|COPY|ADD|CMD|ENTRYPOINT|WORKDIR|ENV|EXPOSE|ARG|USER)\s+\S", re.M | re.I
)
_INLINE_SECRET = re.compile(
    r"(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|ACCESS_KEY)[A-Z0-9_]{0,30}[ \t]*[:=]\s*['\"]?[^\s'\"$]{4,}",
    re.I,
)


def dockerfile(resp: Response) -> Match | None:
    text = resp.text[:65_536]
    if htmlish(text):
        return None
    found = {m.group(1).upper() for m in _DOCKER_INSTRUCTION.finditer(text)}
    if "FROM" not in found or len(found) < 2:
        return None
    severity = Severity.HIGH if _INLINE_SECRET.search(text) else None
    return Match(
        "Dockerfile legível" + (" com valores que parecem segredos" if severity else ""), severity
    )


def compose_file(resp: Response) -> Match | None:
    text = resp.text[:65_536]
    if htmlish(text) or not re.search(r"^services:\s*$", text, re.M):
        return None
    if not re.search(r"^[ \t]+(?:image|build):", text, re.M):
        return None
    severity = Severity.HIGH if _INLINE_SECRET.search(text) else None
    return Match(
        "docker-compose legível" + (" com valores que parecem segredos" if severity else ""),
        severity,
    )


def crossdomain(resp: Response) -> Match | None:
    text = resp.text[:16_384]
    if "<cross-domain-policy" in text and re.search(
        r"<allow-access-from[^>]*domain=[\"']\*[\"']", text
    ):
        return Match('crossdomain.xml libera qualquer domínio (allow-access-from domain="*")')
    if "<access-policy" in text and re.search(r"<domain[^>]*uri=[\"']\*[\"']", text):
        return Match('clientaccesspolicy.xml libera qualquer domínio (domain uri="*")')
    return None


def sourcemap(resp: Response) -> Match | None:
    text = resp.text[:16_384].lstrip()
    if text.startswith(")]}'"):
        text = text.split("\n", 1)[-1].lstrip()
    if not re.match(r'\{\s*"version"\s*:\s*3', text) and not (
        text.startswith("{") and '"version":3' in text[:400]
    ):
        return None
    if '"mappings"' not in text and '"sources"' not in text:
        return None
    sources = re.search(r'"sources"\s*:\s*\[([^\]]{0,600})', text)
    sample = ""
    if sources:
        names = re.findall(r'"([^"]+)"', sources.group(1))[:3]
        sample = f" (ex.: {', '.join(names)})" if names else ""
    return Match("Mapa de código-fonte (source map) legível" + sample)


# -- listagem, páginas padrão, metarquivos --------------------------------------------------

_LISTING = (
    re.compile(r"<title>\s*Index of /", re.I),
    re.compile(r"<h1>\s*Index of /", re.I),
    re.compile(r"<title>\s*Directory listing for /", re.I),
    re.compile(r"\[To Parent Directory\]", re.I),
    re.compile(r"<title>\s*Directory Listing For \[?/", re.I),
    re.compile(r"<title>\s*listing directory /", re.I),
)
_SENSITIVE_FILE = re.compile(
    r"href=[\"']?([^\"'>\s]{1,200}\.(?:sql|bak|zip|tar|gz|tgz|7z|rar|env|log|old|key|pem|conf|config|ini|csv|xlsx?|db|sqlite|dump))[\"'>\s]",
    re.I,
)


def directory_listing(resp: Response) -> Match | None:
    text = resp.text[:262_144]
    if not any(p.search(text) for p in _LISTING):
        return None
    entries = text.lower().count("<a ")
    sensitive = sorted({m.group(1).rsplit("/", 1)[-1] for m in _SENSITIVE_FILE.finditer(text)})[:5]
    evidence = f"Listagem de diretório ativa ({entries} links)"
    if sensitive:
        evidence += f"; inclui arquivos sensíveis: {', '.join(sensitive)}"
        return Match(evidence, Severity.MEDIUM, details={"arquivos": sensitive})
    return Match(evidence)


_DEFAULT_PAGES = (
    ("IIS", re.compile(r"<title>\s*IIS(?: Windows Server|\d+)?\s*</title>|iisstart\.png", re.I)),
    ("Apache", re.compile(r"Apache2 (?:Ubuntu|Debian) Default Page|Test Page for the (?:Apache )?HTTP Server|<title>\s*Apache HTTP Server Test Page", re.I)),
    ("nginx", re.compile(r"<title>\s*Welcome to nginx!?\s*</title>|Test Page for the Nginx HTTP Server", re.I)),
    ("Tomcat", re.compile(r"If you're seeing this, you've successfully installed Tomcat", re.I)),
    ("OpenResty", re.compile(r"<title>\s*Welcome to OpenResty!", re.I)),
)  # fmt: skip
#: a página curtíssima do Apache: num site de verdade, "It works!" pode ser só um título
_APACHE_IT_WORKS = re.compile(r"<h1>\s*It works!\s*</h1>", re.I)
_IT_WORKS_MAX_BYTES = 2_048


def default_page(resp: Response) -> Match | None:
    text = resp.text[:65_536]
    if len(resp.body) <= _IT_WORKS_MAX_BYTES and _APACHE_IT_WORKS.search(text):
        return Match("Página padrão de instalação do Apache", details={"servidor": "Apache"})
    for server, pattern in _DEFAULT_PAGES:
        if pattern.search(text):
            return Match(f"Página padrão de instalação do {server}", details={"servidor": server})
    return None


#: palavras que, como trecho de um caminho, indicam área interna
_ROBOTS_WORDS = frozenset(
    {"admin", "administrator", "administracao", "backup", "backups", "bak", "old", "orig",
     "private", "privado", "privada", "secret", "secrets", "secreto", "config", "conf",
     "configuration", "database", "db", "sql", "dump", "dumps", "internal", "interno",
     "interna", "intranet", "staging", "stage", "homolog", "homologacao", "test", "tests",
     "teste", "testes", "dev", "debug", "tmp", "temp", "log", "logs", "git", "svn", "env",
     "phpmyadmin", "pma", "adminer", "cpanel", "manager", "console", "credential",
     "credentials", "password", "passwords", "senha", "senhas", "restrito", "restrita",
     "restricted"}
)  # fmt: skip
#: Disallow padrão dos robots.txt do WordPress, do Joomla (robots.txt.dist) e do Drupal 7/11
_ROBOTS_STANDARD = frozenset(
    {"/wp-admin/", "/wp-admin", "/administrator/", "/api/", "/bin/", "/cache/", "/cli/",
     "/components/", "/includes/", "/installation/", "/language/", "/layouts/",
     "/libraries/", "/logs/", "/modules/", "/plugins/", "/misc/", "/profiles/",
     "/scripts/", "/themes/", "/core/", "/CHANGELOG.txt", "/cron.php", "/INSTALL.mysql.txt",
     "/INSTALL.pgsql.txt", "/INSTALL.sqlite.txt", "/install.php", "/INSTALL.txt",
     "/LICENSE.txt", "/MAINTAINERS.txt", "/update.php", "/UPGRADE.txt", "/xmlrpc.php",
     "/admin/", "/?q=admin/", "/index.php/admin/", "/comment/reply/", "/filter/tips/",
     "/filter/tips", "/node/add/", "/search/", "/user/register/", "/user/password/",
     "/user/login/", "/user/logout/", "/user/register", "/user/password", "/user/login",
     "/user/logout"}
)  # fmt: skip


_URL_TMP = "/tmp/"  # nosec B108


def sensitive_robots_path(path: str) -> bool:
    """Algum trecho do caminho (entre barras, hifens, pontos) é uma palavra sensível?"""
    clean = path.split("?", 1)[0].lower()
    for segment in clean.split("/"):
        if any(token in _ROBOTS_WORDS for token in re.split(r"[-_.*~$]+", segment)):
            return True
    return False


def robots_sensitive(resp: Response) -> Match | None:
    text = resp.text[:65_536]
    if looks_html(text) or not re.search(
        r"^[ \t]*(?:user-agent|disallow|allow|sitemap)\s*:", text, re.I | re.M
    ):
        return None
    paths = re.findall(r"^[ \t]*disallow\s*:\s*(\S+)", text, re.I | re.M)
    flagged = [
        p
        for p in dict.fromkeys(paths)
        if p not in _ROBOTS_STANDARD and p != _URL_TMP and sensitive_robots_path(p)
    ]
    if not flagged:
        return None
    return Match(
        f"robots.txt cita {len(flagged)} caminho(s) que parecem sensíveis: {', '.join(flagged[:8])}",
        details={"caminhos": flagged[:30]},
    )


@dataclass(frozen=True)
class SecurityTxt:
    contact: bool
    expires: datetime | None
    expires_raw: str | None


def security_txt(resp: Response) -> SecurityTxt | None:
    text = resp.text[:32_768]
    if resp.status != 200 or looks_html(text):
        return None
    contact = re.search(r"^[ \t]*Contact\s*:\s*\S+", text, re.I | re.M)
    expires = re.search(r"^[ \t]*Expires\s*:\s*(\S+)", text, re.I | re.M)
    if not contact and not expires:
        return None
    when: datetime | None = None
    if expires:
        try:
            when = datetime.fromisoformat(expires.group(1).replace("Z", "+00:00"))
            if when.tzinfo is None:
                when = when.replace(tzinfo=UTC)
        except ValueError:
            when = None
    return SecurityTxt(bool(contact), when, expires.group(1) if expires else None)
