"""CORS: o site libera outros sites para lerem as suas respostas?

Sondas inofensivas: um GET normal com o cabeçalho ``Origin`` de um domínio que não
existe (``.invalid``), outro com ``Origin: null`` (iframes isolados, arquivos
locais) e, fora do perfil rápido, uma origem que só *começa* com o domínio do site
(validação por prefixo). Nada é alterado no servidor.

As respostas são julgadas como o navegador julga (Fetch, "CORS check"): o valor de
``Access-Control-Allow-Origin`` precisa ser IGUAL à origem (várias cópias do
cabeçalho viram ``a, b`` e não valem) e ``Access-Control-Allow-Credentials`` só
libera cookies com o valor exato ``true`` (``True`` é recusado).
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from ...core import facts, kb
from ...core.context import CheckContext
from ...core.http import Response
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Confidence, Fact, Severity
from ...core.registry import check
from ...core.target import is_ip
from .common import Page, hints, load_page, short, skip_reason

TEST_ORIGIN = "https://eigan-auditoria.invalid"
_REFERENCES = (
    "https://developer.mozilla.org/pt-BR/docs/Web/HTTP/CORS",
    "https://portswigger.net/web-security/cors",
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing",
)
_FIXES = (
    Fix(
        "express",
        "Node.js / cors",
        "app.use(require('cors')({ origin: ['https://app.exemplo.com.br'], credentials: true }));",
        "javascript",
    ),
    Fix(
        "nginx",
        "nginx (lista fixa de origens)",
        'if ($http_origin = "https://app.exemplo.com.br") { add_header Access-Control-Allow-Origin $http_origin always; }',
        "nginx",
    ),
    Fix(
        "apache",
        "Apache (lista fixa de origens)",
        'SetEnvIf Origin "^https://app\\.exemplo\\.com\\.br$" CORS_OK=$0',
        "apache",
    ),
    Fix(
        "apache",
        "Apache (cabeçalho só para a origem aprovada)",
        "Header always set Access-Control-Allow-Origin %{CORS_OK}e env=CORS_OK",
        "apache",
    ),
    Fix(
        "aspnet",
        "ASP.NET Core (Program.cs)",
        'builder.Services.AddCors(o => o.AddDefaultPolicy(p => p.WithOrigins("https://app.exemplo.com.br").AllowCredentials()));',
        "csharp",
    ),
    Fix(
        "aspnet", "ASP.NET Core (Program.cs, depois de builder.Build())", "app.UseCors();", "csharp"
    ),
    Fix(
        "django",
        "Django (django-cors-headers)",
        'CORS_ALLOWED_ORIGINS = ["https://app.exemplo.com.br"]',
        "python",
    ),
    Fix(
        "spring",
        "Spring",
        '@CrossOrigin(origins = "https://app.exemplo.com.br")',
        "java",
    ),
    Fix(
        "php",
        "PHP",
        "if (in_array($_SERVER['HTTP_ORIGIN'] ?? '', ['https://app.exemplo.com.br'], true)) "
        "header('Access-Control-Allow-Origin: ' . $_SERVER['HTTP_ORIGIN']);",
        "php",
    ),
)
_STEPS = (
    "Troque a reflexão automática do cabeçalho Origin por uma lista fixa de origens confiáveis, "
    "comparadas por igualdade exata (nada de 'começa com' ou 'contém').",
    "Nunca aceite a origem 'null' em respostas com dados do usuário.",
    "Só envie Access-Control-Allow-Credentials: true para as origens da lista.",
    "Inclua Vary: Origin quando a resposta variar conforme a origem.",
)

kb.register(
    KBEntry(
        id="web.cors.reflete_origem_credenciais",
        title="CORS aceita qualquer origem com credenciais",
        category=Category.WEB,
        severity=Severity.HIGH,
        summary="O servidor devolve a origem de qualquer site e permite enviar cookies (credenciais).",
        explanation=(
            "O cabeçalho Access-Control-Allow-Origin repete a origem recebida e vem acompanhado "
            "de Access-Control-Allow-Credentials: true. Na prática, qualquer site da Internet "
            "pode fazer requisições ao seu com os cookies do visitante e LER a resposta."
        ),
        risk=(
            "Uma página maliciosa aberta por um usuário logado lê dados da conta (perfil, "
            "pedidos, tokens) e pode encadear ações em nome dele. Equivale a desligar a política "
            "de mesma origem do navegador."
        ),
        steps=_STEPS,
        examples=_FIXES,
        verify=(
            "curl -sI -H 'Origin: https://teste.invalid' https://seu-site | grep -i "
            "access-control — a origem de teste não deve ser devolvida."
        ),
        effort="medio",
        fix_group="cors",
        references=_REFERENCES,
        cwe="CWE-942",
        owasp="A01:2021",
        cis=("3.3",),
        lgpd=True,
        tags=("cors",),
    ),
    KBEntry(
        id="web.cors.null_credenciais",
        title="CORS aceita a origem 'null' com credenciais",
        category=Category.WEB,
        severity=Severity.HIGH,
        summary="O servidor libera a origem 'null' e o envio de cookies.",
        explanation=(
            "A origem 'null' é usada por iframes isolados (sandbox), redirecionamentos e "
            "arquivos locais. Qualquer atacante consegue gerar requisições com Origin: null; "
            "liberá-la com credenciais é o mesmo que liberar qualquer site."
        ),
        risk="Páginas maliciosas leem dados da conta do visitante logado usando um iframe com sandbox.",
        steps=_STEPS,
        examples=_FIXES,
        verify="curl -sI -H 'Origin: null' https://seu-site | grep -i access-control — não deve devolver null.",
        effort="medio",
        fix_group="cors",
        references=_REFERENCES,
        cwe="CWE-942",
        owasp="A01:2021",
        cis=("3.3",),
        lgpd=True,
        tags=("cors",),
    ),
    KBEntry(
        id="web.cors.reflete_origem",
        title="CORS aceita qualquer origem (sem credenciais)",
        category=Category.WEB,
        severity=Severity.LOW,
        summary="O servidor devolve a origem de qualquer site, mas sem permitir cookies.",
        explanation=(
            "Sem credenciais, outros sites só conseguem ler o que já é público. O risco aparece "
            "quando a resposta depende de algo que não é cookie: rede interna, endereço IP de "
            "origem ou tokens enviados de outra forma. A reflexão também costuma indicar uma "
            "configuração frouxa que vira grave se alguém ativar credenciais depois."
        ),
        risk="Leitura por terceiros de conteúdo restrito por rede/IP e caminho aberto para um erro futuro.",
        steps=_STEPS,
        examples=_FIXES,
        verify="curl -sI -H 'Origin: https://teste.invalid' https://seu-site | grep -i access-control",
        effort="baixo",
        fix_group="cors",
        references=_REFERENCES,
        cwe="CWE-942",
        owasp="A05:2021",
        cis=("3.3",),
        tags=("cors",),
    ),
    KBEntry(
        id="web.cors.curinga_credenciais",
        title="CORS com curinga (*) e credenciais ao mesmo tempo",
        category=Category.WEB,
        severity=Severity.LOW,
        summary="O servidor envia Access-Control-Allow-Origin: * junto com Allow-Credentials: true.",
        explanation=(
            "Os navegadores recusam essa combinação, então ela não funciona — mas mostra que a "
            "intenção era liberar credenciais para qualquer origem. Uma 'correção' apressada "
            "costuma trocar o * pela reflexão da origem, o que abre uma falha grave."
        ),
        risk="Configuração inconsistente, a um passo de virar CORS aberto com credenciais.",
        steps=_STEPS,
        examples=_FIXES,
        verify="curl -sI https://seu-site | grep -i access-control",
        effort="baixo",
        fix_group="cors",
        references=_REFERENCES,
        cwe="CWE-942",
        owasp="A05:2021",
        cis=("3.3",),
        tags=("cors",),
    ),
    KBEntry(
        id="web.cors.curinga",
        title="CORS público (Access-Control-Allow-Origin: *)",
        category=Category.WEB,
        severity=Severity.INFO,
        summary="Qualquer site pode ler as respostas públicas deste endereço.",
        explanation=(
            "O curinga * sem credenciais é aceitável para conteúdo realmente público (APIs "
            "abertas, fontes, CDN). Confirme que nenhuma resposta com dados restritos (por rede "
            "interna, IP ou token fora de cookie) usa essa configuração."
        ),
        risk="Baixo para conteúdo público; vazamento se dados restritos forem servidos com *.",
        steps=(
            "Confirme que o conteúdo é público.",
            "Para conteúdo restrito, troque * por uma lista de origens confiáveis.",
        ),
        examples=_FIXES,
        verify="curl -sI https://seu-site | grep -i access-control-allow-origin",
        effort="baixo",
        fix_group="cors",
        references=_REFERENCES,
        cwe="CWE-942",
        owasp="A05:2021",
        cis=("3.3",),
        tags=("cors",),
    ),
)


@dataclass(frozen=True)
class CorsAnswer:
    origin: str
    allow_origin: str | None
    credentials: bool
    status: int


@dataclass(frozen=True)
class Verdict:
    finding: str
    discriminator: str  # "" (origem externa), "null" ou "prefixo"
    title: str | None = None


def _combined(resp: Response, name: str) -> str | None:
    """Valor do cabeçalho como o Fetch o lê: todas as cópias unidas por ", "."""
    values = [v.strip() for v in resp.headers_all(name)]
    return ", ".join(values) if values else None


def read_answer(origin: str, resp: Response) -> CorsAnswer:
    allow = _combined(resp, "access-control-allow-origin")
    creds = _combined(resp, "access-control-allow-credentials") == "true"
    return CorsAnswer(origin, allow, creds, resp.status)


def _probe_url(url: str) -> str:
    """URL com um parâmetro descartável: um cache na frente do site não guarda a resposta de teste."""
    parts = urlsplit(url)
    extra = "eigan=" + secrets.token_hex(4)
    query = f"{parts.query}&{extra}" if parts.query else extra
    return urlunsplit(parts._replace(query=query))


def ask(ctx: CheckContext, url: str, origin: str) -> CorsAnswer | None:
    headers = {"Origin": origin, "Cache-Control": "no-cache", "Pragma": "no-cache"}
    try:
        resp = ctx.http.get(_probe_url(url), headers=headers, max_bytes=4_096)
    except (ValueError, UnicodeError):  # origem ou URL que o cliente HTTP não consegue enviar
        return None
    return read_answer(origin, resp) if resp is not None else None


def prefix_origin(host: str) -> str | None:
    """Origem que só COMEÇA com o domínio do site (``https://site.com.eigan-auditoria.invalid``)."""
    bare = host.strip("[]")
    if not bare or is_ip(bare):
        return None  # IP não é validado por prefixo de domínio
    try:
        ascii_host = bare.lower().encode("idna").decode("ascii")  # cabeçalho só leva ASCII
    except UnicodeError:
        return None
    return f"https://{ascii_host}.eigan-auditoria.invalid"


def judge(answer: CorsAnswer) -> Verdict | None:
    """O que a resposta libera, julgada como o navegador faz (``None`` = nada)."""
    allow = answer.allow_origin
    if allow is None:
        return None
    if allow == answer.origin:
        if answer.origin == "null":
            finding = (
                "web.cors.null_credenciais" if answer.credentials else "web.cors.reflete_origem"
            )
            title = None if answer.credentials else "CORS aceita a origem null (sem credenciais)"
            return Verdict(finding, "null", title)
        finding = (
            "web.cors.reflete_origem_credenciais"
            if answer.credentials
            else "web.cors.reflete_origem"
        )
        if answer.origin == TEST_ORIGIN:
            return Verdict(finding, "")
        return Verdict(
            finding, "prefixo", "CORS aceita origens que só começam com o domínio do site"
        )
    if allow == "*" and answer.origin == TEST_ORIGIN:
        return Verdict(
            "web.cors.curinga_credenciais" if answer.credentials else "web.cors.curinga", ""
        )
    return None


@check(
    id="web.cors",
    name="Política de CORS",
    category=Category.WEB,
    consumes=facts.HTTP_SERVICE,
    description=(
        "Envia requisições com o cabeçalho Origin de um domínio inexistente e com Origin: null "
        "para ver se o site libera a leitura das respostas por outros sites."
    ),
    findings=(
        "web.cors.reflete_origem_credenciais",
        "web.cors.null_credenciais",
        "web.cors.reflete_origem",
        "web.cors.curinga_credenciais",
        "web.cors.curinga",
    ),
    active=True,
    order=40,
)
def check_cors(ctx: CheckContext, fact: Fact) -> None:
    url = str(fact.data["url"])
    page = load_page(ctx, url)
    if page is None:
        ctx.log(f"{url} não respondeu.")
        return
    reason = skip_reason(ctx, page)
    if reason:
        ctx.log(reason)
        return
    target = page.final.url
    external = ask(ctx, target, TEST_ORIGIN)
    null = ask(ctx, target, "null")
    answers = [answer for answer in (external, null) if answer is not None]
    prefixed = prefix_origin(page.host)
    if (
        prefixed
        and not ctx.settings.quick
        and not any(a.allow_origin == TEST_ORIGIN for a in answers)
    ):
        answer = ask(ctx, target, prefixed)
        if answer is not None:
            answers.append(answer)
    verdicts = [(answer, verdict) for answer in answers if (verdict := judge(answer))]
    tech = hints(ctx, page) if verdicts else []
    for answer, verdict in verdicts:
        _report(ctx, page, target, answer, verdict, tech)
    if not verdicts and external is not None and null is not None:
        ctx.passed("web.cors", "CORS não libera a leitura por origens externas", page.origin)
    elif not verdicts:
        ctx.log(f"{target} não respondeu a todas as sondas de CORS; a política não foi confirmada.")


def _report(
    ctx: CheckContext,
    page: Page,
    target: str,
    answer: CorsAnswer,
    verdict: Verdict,
    tech: list[str],
) -> None:
    creds = "; Access-Control-Allow-Credentials: true" if answer.credentials else ""
    allow = short(answer.allow_origin or "")
    evidence = (
        f"GET {target} com Origin: {answer.origin} -> HTTP {answer.status}; "
        f"Access-Control-Allow-Origin: {allow}{creds}"
    )
    ctx.report(
        verdict.finding,
        asset=page.origin,
        title=verdict.title,
        evidence=evidence,
        details={
            "origin": answer.origin,
            "allow_origin": allow,
            "credenciais": answer.credentials,
            "status": answer.status,
        },
        # Em resposta de erro o cabeçalho existe, mas pode não haver dado a ler com ele.
        # com credenciais, o dano depende de a página inicial servir dados do usuário
        confidence=(
            Confidence.CONFIRMED
            if answer.status < 400 and not answer.credentials
            else Confidence.FIRM
        ),
        discriminator=verdict.discriminator,
        tech=tech,
    )
