"""Métodos HTTP aceitos: TRACE ativo, WebDAV e PUT/DELETE anunciados.

Não intrusivo: um OPTIONS para ler o cabeçalho ``Allow`` e UM pedido TRACE por
origem (o servidor só devolve o que recebeu). PUT e DELETE nunca são enviados — só
são apontados, como indício, quando o próprio servidor os anuncia.

O TRACE só conta como ativo quando a resposta 200 é mesmo o eco da requisição
(RFC 9110: corpo ``message/http`` começando por ``TRACE``) e traz o cabeçalho de
teste; uma página que apenas repete cabeçalhos não basta.
"""

from __future__ import annotations

import secrets

from ...core import facts, kb
from ...core.context import CheckContext
from ...core.http import Response
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Confidence, Fact, Severity
from ...core.registry import check
from .common import Page, claim, hints, load_page, readable, short, skip_reason

WEBDAV_METHODS = frozenset(
    {"PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "SEARCH"}
)
#: verbos que só existem em WebDAV; COPY, SEARCH, MOVE... também aparecem em APIs comuns
WEBDAV_CORE = frozenset({"PROPFIND", "PROPPATCH", "MKCOL"})
WRITE_METHODS = frozenset({"PUT", "DELETE"})
_METHODS_TEST = (
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/"
    "02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods"
)

kb.register(
    KBEntry(
        id="web.metodos.trace",
        title="Método TRACE habilitado",
        category=Category.WEB,
        severity=Severity.LOW,
        summary="O servidor responde ao método TRACE devolvendo a requisição recebida.",
        explanation=(
            "TRACE é um método de diagnóstico que ecoa a requisição, inclusive cabeçalhos. Não "
            "tem uso em produção. Combinado com outras falhas, já permitiu ler cookies HttpOnly "
            "(Cross-Site Tracing) e revelar cabeçalhos internos adicionados por proxies."
        ),
        risk="Vazamento de cabeçalhos internos e de autenticação; costuma ser cobrado em varreduras de conformidade.",
        steps=(
            "Desative o TRACE no servidor web e no proxy/balanceador. O nginx já recusa TRACE "
            "(405) desde a versão 0.5.17: se ele está na frente, o eco vem do servidor de trás.",
            "Confirme que a resposta passou a ser 405 (ou 403/501).",
        ),
        examples=(
            Fix("apache", "Apache", "TraceEnable off", "apache"),
            Fix(
                "iis",
                "IIS (web.config, em <requestFiltering>)",
                '<verbs><add verb="TRACE" allowed="false" /></verbs>',
                "xml",
            ),
            Fix("tomcat", "Tomcat (server.xml, no <Connector>)", 'allowTrace="false"', "xml"),
            Fix(
                "litespeed",
                "LiteSpeed (.htaccess)",
                "RewriteCond %{REQUEST_METHOD} ^TRACE\nRewriteRule .* - [F]",
                "apache",
            ),
        ),
        verify="curl -si -X TRACE https://seu-site/ deve responder 405, 403 ou 501.",
        effort="baixo",
        fix_group="metodos",
        references=(
            _METHODS_TEST,
            "https://owasp.org/www-community/attacks/Cross_Site_Tracing",
            "https://www.rfc-editor.org/rfc/rfc9110#name-trace",
        ),
        cwe="CWE-749",
        owasp="A05:2021",
        cis=("4.8",),
        tags=("metodos",),
    ),
    KBEntry(
        id="web.metodos.webdav",
        title="WebDAV anunciado pelo servidor",
        category=Category.WEB,
        severity=Severity.MEDIUM,
        summary="O servidor anuncia métodos WebDAV (PROPFIND, MKCOL, MOVE...).",
        explanation=(
            "WebDAV permite listar, criar, mover e gravar arquivos no servidor pela web. Se ficou "
            "ligado sem necessidade, ou com permissões frouxas, vira porta de entrada para "
            "publicar arquivos maliciosos (web shells) ou listar conteúdo privado. O anúncio no "
            "Allow é um indício: confirme a configuração."
        ),
        risk="Envio de arquivos executáveis para o site, listagem de diretórios e alteração de conteúdo.",
        steps=(
            "Confirme se algum sistema usa WebDAV neste endereço.",
            "Se não usa, desinstale/desative o módulo WebDAV (IIS: recurso WebDAV Publishing; "
            "Apache: mod_dav).",
            "Se usa, exija autenticação forte e restrinja a pastas sem execução de scripts.",
        ),
        examples=(
            Fix(
                "iis",
                "IIS (PowerShell)",
                "Uninstall-WindowsFeature Web-DAV-Publishing",
                "powershell",
            ),
            Fix(
                "apache",
                "Apache (Debian/Ubuntu)",
                "sudo a2dismod dav_fs dav && sudo systemctl reload apache2",
                "bash",
            ),
            Fix("nginx", "nginx", "# remova a diretiva dav_methods do bloco location", "nginx"),
        ),
        verify="curl -si -X OPTIONS https://seu-site/ não deve listar PROPFIND/MKCOL no Allow, nem enviar o cabeçalho DAV.",
        effort="baixo",
        fix_group="metodos",
        references=(_METHODS_TEST, "https://cwe.mitre.org/data/definitions/749.html"),
        cwe="CWE-749",
        owasp="A05:2021",
        cis=("4.8",),
        tags=("metodos", "webdav"),
    ),
    KBEntry(
        id="web.metodos.perigosos",
        title="Métodos PUT/DELETE anunciados",
        category=Category.WEB,
        severity=Severity.LOW,
        summary="O servidor anuncia que aceita PUT e/ou DELETE neste endereço.",
        explanation=(
            "PUT grava e DELETE apaga recursos. Em APIs REST isso é normal (com autenticação). Em "
            "sites comuns, o anúncio na raiz pode indicar configuração padrão esquecida. O EIGAN "
            "não testa os métodos (seria intrusivo): é um indício para conferir."
        ),
        risk="Se aceitos sem autenticação, permitem publicar ou apagar arquivos do site.",
        steps=(
            "Confira se a aplicação realmente precisa de PUT/DELETE neste caminho.",
            "Restrinja os métodos aceitos no servidor web ou exija autenticação.",
        ),
        examples=(
            Fix(
                "apache",
                "Apache (dentro do <Directory> do site)",
                "<LimitExcept GET POST HEAD>\n    Require all denied\n</LimitExcept>",
                "apache",
            ),
            Fix(
                "nginx",
                "nginx (dentro de location)",
                "limit_except GET POST HEAD { deny all; }",
                "nginx",
            ),
            Fix(
                "iis",
                "IIS (web.config, em <requestFiltering>)",
                '<verbs allowUnlisted="false"><add verb="GET" allowed="true" /><add verb="POST" allowed="true" /><add verb="HEAD" allowed="true" /></verbs>',
                "xml",
            ),
        ),
        verify="curl -si -X OPTIONS https://seu-site/ deve listar só os métodos necessários.",
        effort="baixo",
        fix_group="metodos",
        references=(_METHODS_TEST,),
        cwe="CWE-749",
        owasp="A05:2021",
        cis=("4.8",),
        tags=("metodos",),
    ),
)


def allowed_methods(resp: Response) -> set[str]:
    """Métodos dos cabeçalhos Allow e Public (IIS)."""
    found: set[str] = set()
    for header in ("allow", "public"):
        for value in resp.headers_all(header):
            found.update(m.strip().upper() for m in value.split(",") if m.strip())
    return found


@check(
    id="web.methods",
    name="Métodos HTTP",
    category=Category.WEB,
    consumes=facts.HTTP_SERVICE,
    description=(
        "Lê os métodos anunciados (OPTIONS) e envia um único TRACE para ver se o servidor ecoa "
        "a requisição. PUT e DELETE nunca são enviados."
    ),
    findings=("web.metodos.trace", "web.metodos.webdav", "web.metodos.perigosos"),
    active=True,
    order=45,
)
def check_methods(ctx: CheckContext, fact: Fact) -> None:
    url = str(fact.data["url"])
    page = load_page(ctx, url)
    if page is None:
        ctx.log(f"{url} não respondeu.")
        return
    reason = skip_reason(ctx, page)
    if reason:
        ctx.log(reason)
        return
    if not claim(ctx, f"web.methods:{page.origin}"):
        ctx.log(f"Métodos de {page.origin} já avaliados por outro fato da mesma origem.")
        return
    target = page.final.url
    tech = hints(ctx, page)
    options = ctx.http.options(target, max_bytes=8_192)
    if options is not None:
        _judge_options(ctx, page, target, options, tech)
    _probe_trace(ctx, page, target, tech)


def _judge_options(
    ctx: CheckContext, page: Page, target: str, resp: Response, tech: list[str]
) -> None:
    methods = allowed_methods(resp)
    dav = short(resp.header("dav") or "") or None
    webdav = sorted(methods & WEBDAV_METHODS)
    shown = short(", ".join(sorted(methods))) or "-"
    is_webdav = bool(dav or methods & WEBDAV_CORE or len(webdav) >= 2)
    if is_webdav:
        evidence = f"OPTIONS {target} -> Allow/Public: {shown}" + (f"; DAV: {dav}" if dav else "")
        ctx.report(
            "web.metodos.webdav",
            asset=page.origin,
            evidence=evidence,
            details={"metodos": sorted(methods)[:40], "dav": dav},
            confidence=Confidence.TENTATIVE,
            tech=tech,
        )
    writes = sorted(methods & WRITE_METHODS)
    if writes:
        ctx.report(
            "web.metodos.perigosos",
            asset=page.origin,
            evidence=f"OPTIONS {target} -> Allow: {shown}",
            details={"metodos": sorted(methods)[:40]},
            confidence=Confidence.TENTATIVE,
            tech=tech,
        )
    elif methods and not is_webdav:
        ctx.passed(
            "web.metodos", f"Sem WebDAV nem PUT/DELETE anunciados (Allow: {shown})", page.origin
        )


def is_trace_echo(resp: Response, token: str) -> bool:
    """A resposta é o eco da requisição TRACE (e não uma página qualquer)?"""
    text = readable(resp).text
    if resp.status != 200 or token not in text:
        return False
    return resp.content_type == "message/http" or text.lstrip().upper().startswith("TRACE ")


def _probe_trace(ctx: CheckContext, page: Page, target: str, tech: list[str]) -> None:
    token = "eigan-" + secrets.token_hex(8)
    resp = ctx.http.request("TRACE", target, headers={"X-Eigan-Trace": token}, max_bytes=16_384)
    if resp is None:
        return
    if is_trace_echo(resp, token):
        ctx.report(
            "web.metodos.trace",
            asset=page.origin,
            evidence=f"TRACE {target} respondeu HTTP 200 ecoando a requisição (cabeçalho de teste devolvido).",
            confidence=Confidence.CONFIRMED,
            tech=tech,
        )
    elif resp.status in (405, 501):  # 400/404 só mostram um tratador genérico de erro
        ctx.passed("web.metodos.trace", f"TRACE recusado (HTTP {resp.status})", page.origin)
