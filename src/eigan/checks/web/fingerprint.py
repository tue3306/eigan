"""Identificação de tecnologias: servidor, linguagem, framework, CMS e CDN/WAF.

Lê a página inicial (cabeçalhos, cookies de sessão e ``<meta name="generator">``)
e a página de erro padrão do site, ensina ao motor os fatos ``tech`` (que disparam
checagens específicas e escolhem o exemplo de correção certo) e aponta quando um
cabeçalho, o ``<meta name="generator">`` ou a página de erro entregam a versão
exata do software.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from ...core import facts, kb
from ...core.context import CheckContext
from ...core.facts import base_url
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Confidence, Fact, Severity
from ...core.registry import check
from ...core.target import is_ip
from ...core.versions import extract_version
from .common import (
    Page,
    baseline,
    detected_techs,
    has_https_counterpart,
    hints,
    https_counterpart_url,
    load_page,
    page_doc,
    short,
)
from .techdetect import (
    VERSION_HEADERS,
    TechHit,
    disclosed_version,
    from_generator,
    from_powered_by,
    from_server,
)

kb.register(
    KBEntry(
        id="web.divulgacao.versao",
        title="Versão do software divulgada",
        category=Category.WEB,
        severity=Severity.LOW,
        summary="O servidor informa o produto e a versão exata do software usado no site.",
        explanation=(
            "Cabeçalhos como Server, X-Powered-By, X-AspNet-Version e X-Generator, a meta tag "
            "generator do HTML e as páginas de erro padrão mostram o nome e a versão do servidor "
            "web, da linguagem ou do CMS. "
            "Não é uma falha por si só, mas entrega de graça o mapa do que atacar: basta cruzar a "
            "versão com as listas públicas de vulnerabilidades. Distribuições Linux costumam "
            "corrigir falhas sem mudar o número da versão, então o número sozinho não prova que "
            "o servidor está vulnerável."
        ),
        risk=(
            "Robôs de ataque varrem a Internet procurando versões vulneráveis pelo cabeçalho e "
            "disparam o exploit certo automaticamente. Ocultar a versão não corrige nada, mas "
            "reduz ataques oportunistas e o reconhecimento barato."
        ),
        steps=(
            "Desligue a assinatura de versão no servidor web (nginx, Apache, IIS, Tomcat).",
            "Desative o X-Powered-By na linguagem ou no framework (PHP, Express, ASP.NET).",
            "Remova X-AspNet-Version, X-AspNetMvc-Version e X-Generator das respostas.",
            'Retire a versão do <meta name="generator"> (CMS, construtores de site e plugins).',
            "Troque as páginas de erro padrão por páginas próprias, sem nome nem versão do servidor.",
            "Continue atualizando o software: esconder a versão não substitui a atualização.",
        ),
        examples=(
            Fix("nginx", "nginx", "server_tokens off;", "nginx"),
            Fix("apache", "Apache", "ServerTokens Prod", "apache"),
            Fix("apache", "Apache (rodapé das páginas de erro)", "ServerSignature Off", "apache"),
            Fix(
                "litespeed",
                "LiteSpeed (.htaccess, remove o X-Powered-By)",
                "Header unset X-Powered-By",
                "apache",
            ),
            Fix(
                "iis",
                "IIS 10+ (web.config, em <system.webServer><security>)",
                '<requestFiltering removeServerHeader="true" />',
                "xml",
            ),
            Fix(
                "iis",
                "IIS (web.config, em <system.webServer><httpProtocol>)",
                '<customHeaders><remove name="X-Powered-By" /></customHeaders>',
                "xml",
            ),
            Fix(
                "aspnet",
                "ASP.NET (web.config, em <system.web>)",
                '<httpRuntime enableVersionHeader="false" />',
                "xml",
            ),
            Fix(
                "aspnet",
                "ASP.NET MVC (Global.asax, Application_Start)",
                "MvcHandler.DisableMvcResponseHeader = true;",
                "csharp",
            ),
            Fix(
                "kestrel",
                "ASP.NET Core / Kestrel (Program.cs)",
                "builder.WebHost.ConfigureKestrel(o => o.AddServerHeader = false);",
                "csharp",
            ),
            Fix("php", "PHP (php.ini)", "expose_php = Off", "ini"),
            Fix("express", "Node.js / Express", "app.disable('x-powered-by');", "javascript"),
            Fix(
                "tomcat",
                "Tomcat (server.xml, dentro de <Host>)",
                '<Valve className="org.apache.catalina.valves.ErrorReportValve" '
                'showReport="false" showServerInfo="false" />',
                "xml",
            ),
            Fix("drupal", "Drupal (Apache/.htaccess)", "Header unset X-Generator", "apache"),
            Fix(
                "wordpress",
                "WordPress (functions.php do tema)",
                "remove_action('wp_head', 'wp_generator');",
                "php",
            ),
            Fix(
                "cloudflare",
                "Cloudflare",
                "Rules > Overview > Create rule > Response Header Transform Rule: Remove 'X-Powered-By'",
                "text",
            ),
        ),
        verify=(
            "curl -sI https://seu-site | grep -iE 'server|x-powered-by|x-aspnet|x-generator' — "
            "nenhum valor deve trazer número de versão; confira o código-fonte da página "
            '(<meta name="generator">) e abra um endereço inexistente para ver a página de erro.'
        ),
        effort="baixo",
        fix_group="divulgacao",
        references=(
            "https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens",
            "https://httpd.apache.org/docs/2.4/mod/core.html#servertokens",
            "https://www.php.net/manual/en/ini.core.php#ini.expose-php",
            "https://learn.microsoft.com/en-us/iis/configuration/system.webserver/security/requestfiltering/",
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server",
            "https://owasp.org/www-project-secure-headers/",
        ),
        cwe="CWE-497",
        owasp="A05:2021",
        cis=("4.1",),
        tags=("divulgacao", "cabecalhos"),
    ),
)

#: cabeçalhos que costumam revelar versão (nome canônico para exibir); lista baseada nos
#: cabeçalhos "a remover" do OWASP Secure Headers Project
DISCLOSURE_HEADERS = (
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Php-Version",
    "X-OWA-Version",
    "X-Umbraco-Version",
    "X-Joomla-Version",
    "Liferay-Portal",
    "X-Powered-CMS",
    "X-Generated-By",
    "X-Server-Powered-By",
)

#: rodapé das páginas de erro padrão -> tecnologia (grupo 1 = texto com a versão)
_ERROR_PAGES: tuple[tuple[re.Pattern[str], str | None], ...] = (
    (
        re.compile(r"<address>\s*([A-Za-z][\w\-]*/\d+(?:\.\d+)+[^<]{0,80}?)\s+Server at", re.I),
        "apache",
    ),
    (
        re.compile(
            r"<center>\s*((nginx|openresty|tengine)/\d+(?:\.\d+)+(?:\s*\([^)<]{1,40}\))?)\s*</center>",
            re.I,
        ),
        None,  # nome vem do grupo 2
    ),
    (re.compile(r"<h3>\s*(Apache Tomcat/\d+(?:\.\d+){1,6}[\w\-]{0,20})\s*</h3>", re.I), "tomcat"),
    (re.compile(r"Powered by (Jetty:// ?\d+(?:\.\d+){1,6}[\w\-]{0,20})", re.I), "jetty"),
)


@dataclass(frozen=True)
class Disclosure:
    header: str  # nome canônico (Server, X-Powered-By...)
    value: str
    version: str


@check(
    id="web.fingerprint",
    name="Identificação de tecnologias",
    category=Category.WEB,
    consumes=facts.HTTP_SERVICE,
    description=(
        "Identifica servidor, linguagem, framework, CMS e CDN/WAF pelos cabeçalhos, cookies e "
        "HTML da página inicial e aponta versões de software divulgadas."
    ),
    findings=("web.divulgacao.versao",),
    facts=(facts.TECH, facts.HTTP_SERVICE, facts.TLS_SERVICE),
    order=5,
)
def check_fingerprint(ctx: CheckContext, fact: Fact) -> None:
    url = str(fact.data["url"])
    page = load_page(ctx, url)
    if page is None:
        ctx.log(f"{url} não respondeu.")
        return
    for hit in detected_techs(ctx, page):
        ctx.add_tech(page.host, hit.name, version=hit.version, kind=hit.kind, evidence=hit.evidence)
    _follow_same_site_redirect(ctx, page)
    found = header_disclosures(page)
    if has_https_counterpart(ctx, page):
        # HTML, página de erro e o veredito ficam com o fato HTTPS do mesmo host: aqui só
        # entra o que a porta 80 revela a mais.
        already = _twin_disclosures(ctx, page)
        for item in found:
            if (item.header, item.value) not in already:
                _report_header(ctx, page, item)
        return
    for item in found:
        _report_header(ctx, page, item)
    generators = generator_disclosures(ctx, page)
    if generators:
        _report_generators(ctx, page, generators)
    in_error_page = _check_error_page(ctx, page, {item.version for item in found})
    if not found and not generators and not in_error_page:
        ctx.passed(
            "web.divulgacao", "Cabeçalhos, HTML e página de erro não revelam versões", page.origin
        )


def header_disclosures(page: Page) -> list[Disclosure]:
    """Cabeçalhos das respostas da página que revelam uma versão (sem repetição)."""
    found: list[Disclosure] = []
    seen: set[tuple[str, str]] = set()
    for resp in page.chain:
        for header in DISCLOSURE_HEADERS:
            for value in resp.headers_all(header):
                version = disclosed_version(header, value)
                shown = short(value)
                if version and (header, shown) not in seen:
                    seen.add((header, shown))
                    found.append(Disclosure(header, shown, version))
    return found


def _twin_disclosures(ctx: CheckContext, page: Page) -> set[tuple[str, str]]:
    """O que a versão HTTPS do mesmo host já revela (é reportado lá, não aqui)."""
    twin = load_page(ctx, https_counterpart_url(page))
    if twin is None:
        return set()
    return {(item.header, item.value) for item in header_disclosures(twin)}


def _header_techs(name: str, value: str) -> list[TechHit]:
    lname = name.lower()
    if lname == "server":
        return from_server(value)
    if lname == "x-powered-by":
        return from_powered_by(value)
    if lname == "x-generator":
        hit = from_generator(value, name)
        return [hit] if hit else []
    if lname.startswith("x-aspnet"):
        return [TechHit("aspnet", "framework", None, name), TechHit("iis", "server", None, name)]
    known = VERSION_HEADERS.get(lname)
    return [TechHit(known[0], known[1], None, name)] if known else []


def _report_header(ctx: CheckContext, page: Page, item: Disclosure) -> None:
    techs = [t.name for t in _header_techs(item.header, item.value)] + hints(ctx, page)
    ctx.report(
        "web.divulgacao.versao",
        asset=page.origin,
        title=f"Versão divulgada no cabeçalho {item.header}",
        evidence=f"{item.header}: {item.value}",
        details={"cabecalho": item.header, "valor": item.value, "versao": item.version},
        # só o número principal ("Drupal 10"): pouco útil a quem ataca
        confidence=Confidence.CONFIRMED if "." in item.version else Confidence.TENTATIVE,
        discriminator=item.header.lower(),
        tech=list(dict.fromkeys(techs)),
    )


def generator_disclosures(ctx: CheckContext, page: Page) -> list[str]:
    """Conteúdos de ``<meta name="generator">`` da página que trazem versão."""
    doc = page_doc(ctx, page)
    found: list[str] = []
    for content in doc.meta_values("generator") if doc is not None else []:
        text = " ".join(content.split())[:120]
        if text and text not in found and disclosed_version("x-generator", text):
            found.append(text)
    return found


def _report_generators(ctx: CheckContext, page: Page, contents: list[str]) -> None:
    hits = [from_generator(text, "meta generator") for text in contents]
    techs = [hit.name for hit in hits if hit is not None] + hints(ctx, page)
    ctx.report(
        "web.divulgacao.versao",
        asset=page.origin,
        title='Versão divulgada no <meta name="generator">',
        evidence="\n".join(f'<meta name="generator" content="{text}">' for text in contents),
        details={
            "origem": "meta-generator",
            "valores": contents,
            "versao": disclosed_version("x-generator", contents[0]),
        },
        confidence=Confidence.CONFIRMED,
        discriminator="meta-generator",
        tech=list(dict.fromkeys(techs)),
    )


def error_page_banner(text: str) -> tuple[str, str] | None:
    """(rodapé com a versão, tecnologia) da página de erro padrão, se houver."""
    text = text[:16_384]  # o rodapé fica no começo; limita o custo das regexes
    for pattern, tech in _ERROR_PAGES:
        match = pattern.search(text)
        if match:
            banner = " ".join(match.group(1).split())
            return banner, tech or match.group(2).lower()
    return None


def _check_error_page(ctx: CheckContext, page: Page, header_versions: set[str]) -> bool:
    """O rodapé da página de erro padrão (Apache, nginx, Tomcat, Jetty) mostra a versão?"""
    base = baseline(ctx, page.origin)
    if base is None or base.status < 400:
        return False
    found = error_page_banner(base.text)
    if found is None:
        return False
    banner, tech = found
    version = extract_version(banner)
    ctx.add_tech(
        page.host, tech, version=version, kind="server", evidence=f"página de erro: {banner}"
    )
    if version in header_versions:
        return True  # a mesma versão já foi reportada pelo cabeçalho
    ctx.report(
        "web.divulgacao.versao",
        asset=page.origin,
        title="Versão divulgada na página de erro padrão",
        evidence=f"GET {base.path} respondeu HTTP {base.status} com o rodapé '{banner}'",
        details={"origem": "pagina-de-erro", "valor": banner, "versao": version},
        confidence=Confidence.CONFIRMED,
        discriminator="pagina-de-erro",
        tech=list(dict.fromkeys([tech, *hints(ctx, page)])),
    )
    return True


def same_site_target(host: str, target: str) -> str | None:
    """Origem do destino quando o redirecionamento é para o mesmo site (host ou www.)."""
    try:
        parts = urlsplit(target)
        port = parts.port
    except ValueError:
        return None
    other = (parts.hostname or "").lower()
    if parts.scheme not in ("http", "https") or not other:
        return None
    if other == host or (not is_ip(host) and (other == f"www.{host}" or host == f"www.{other}")):
        return base_url(parts.scheme, other, port)
    return None


def _follow_same_site_redirect(ctx: CheckContext, page: Page) -> None:
    """Ex.: exemplo.com.br -> www.exemplo.com.br: o site real passa a ser auditado também."""
    if not page.left_to:
        return
    target = same_site_target(page.host, page.left_to)
    if target and target != page.origin:
        ctx.add_http_service(target, reason=f"{page.url} redireciona para {page.left_to}")
