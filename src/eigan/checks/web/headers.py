"""Cabeçalhos de segurança HTTP: CSP, clickjacking, nosniff, Referrer-Policy e afins.

Avaliados na resposta final da página inicial, só quando ela é de sucesso (2xx):
servidores como o nginx não acrescentam ``add_header`` às respostas de erro (sem
``always``), e julgar uma página 404/500 geraria falso positivo. CSP,
clickjacking e as políticas de navegação só importam em páginas HTML;
``X-Content-Type-Options`` vale para qualquer resposta.

Cada cabeçalho é lido como o navegador lê (especificações Fetch, HTML Standard
e Referrer Policy): para ``X-Content-Type-Options`` vale o primeiro valor; em
``Referrer-Policy`` vale o último valor válido; ``X-Frame-Options`` com valores
conflitantes bloqueia o enquadramento; ``frame-ancestors`` na CSP do cabeçalho
anula o ``X-Frame-Options``.
"""

from __future__ import annotations

from ...core import facts
from ...core.context import CheckContext
from ...core.http import Response
from ...core.models import Category, Confidence, Fact, Severity
from ...core.registry import check
from . import kb_headers  # noqa: F401 — registra as entradas da base
from .common import Page, hints, load_page, looks_html, page_doc, short, skip_reason
from .csp import Policy, evaluate, frame_ancestor_lists, is_broad, parse_policies
from .htmlscan import HtmlDoc

REFERRER_POLICIES = frozenset(
    {
        "no-referrer",
        "no-referrer-when-downgrade",
        "same-origin",
        "origin",
        "strict-origin",
        "origin-when-cross-origin",
        "strict-origin-when-cross-origin",
        "unsafe-url",
    }
)
#: valores antigos aceitos no <meta name="referrer"> (HTML Standard)
_META_REFERRER_LEGACY = {
    "never": "no-referrer",
    "default": "strict-origin-when-cross-origin",
    "always": "unsafe-url",
    "origin-when-crossorigin": "origin-when-cross-origin",
}
UNSAFE_REFERRERS = frozenset({"unsafe-url", "no-referrer-when-downgrade"})
ISOLATING_COOP = frozenset({"same-origin", "same-origin-allow-popups", "noopener-allow-popups"})
_HTML_TYPES = frozenset({"text/html", "application/xhtml+xml"})
_FRAME_KEYWORDS = frozenset({"deny", "allowall", "sameorigin"})


@check(
    id="web.headers",
    name="Cabeçalhos de segurança",
    category=Category.WEB,
    consumes=facts.HTTP_SERVICE,
    description=(
        "Confere CSP, proteção contra clickjacking, X-Content-Type-Options, Referrer-Policy, "
        "Permissions-Policy, Cross-Origin-Opener-Policy e X-XSS-Protection da página inicial."
    ),
    findings=(
        "web.csp.ausente",
        "web.csp.fraca",
        "web.clickjacking.ausente",
        "web.nosniff.ausente",
        "web.referrer.ausente",
        "web.referrer.inseguro",
        "web.permissions_policy.ausente",
        "web.coop.ausente",
        "web.xss_protection.ativo",
    ),
    order=20,
)
def check_headers(ctx: CheckContext, fact: Fact) -> None:
    url = str(fact.data["url"])
    page = load_page(ctx, url)
    if page is None:
        ctx.log(f"{url} não respondeu.")
        return
    reason = skip_reason(ctx, page)
    if reason:
        ctx.log(reason)
        return
    resp = page.final
    if not page.ok:
        ctx.log(
            f"{resp.url} respondeu HTTP {resp.status}; os cabeçalhos de segurança só são "
            "avaliados em respostas de sucesso (2xx)."
        )
        return
    tech = hints(ctx, page)
    _check_nosniff(ctx, page, resp, tech)
    if not renders_html(resp):
        ctx.log(
            f"{resp.url} não é HTML ({resp.content_type or 'sem tipo'}): CSP, clickjacking e "
            "políticas de navegação não se aplicam."
        )
        return
    doc = page_doc(ctx, page)
    policies = parse_policies(resp.headers_all("content-security-policy"))
    if doc is not None:
        policies += parse_policies(doc.http_equiv("content-security-policy"), "meta")
    _check_csp(ctx, page, resp, policies, tech)
    _check_framing(ctx, page, resp, policies, tech, doc)
    meta_referrer = doc.meta_values("referrer") if doc is not None else []
    _check_referrer(ctx, page, resp, meta_referrer, tech)
    _check_optional(ctx, page, resp, tech)


def renders_html(resp: Response) -> bool:
    """O navegador vai exibir a resposta como página HTML?"""
    if resp.content_type:
        return resp.content_type in _HTML_TYPES
    return looks_html(resp.text)  # sem Content-Type o navegador "fareja" o conteúdo


def _evidence_missing(resp: Response, header: str) -> str:
    return f"Resposta HTTP {resp.status} de {resp.url} sem o cabeçalho {header}."


def _split_values(resp: Response, name: str) -> list[str]:
    """Valores do cabeçalho como o navegador vê: todas as ocorrências, separadas por vírgula."""
    return [part.strip() for item in resp.headers_all(name) for part in item.split(",")]


# -- X-Content-Type-Options --------------------------------------------------------------


def nosniff_enabled(resp: Response) -> bool:
    """Regra "determine nosniff" do Fetch: só o PRIMEIRO valor conta."""
    values = _split_values(resp, "x-content-type-options")
    return bool(values) and values[0].lower() == "nosniff"


def _check_nosniff(ctx: CheckContext, page: Page, resp: Response, tech: list[str]) -> None:
    if nosniff_enabled(resp):
        ctx.passed("web.nosniff", "X-Content-Type-Options: nosniff", page.origin)
        return
    raw = short(", ".join(resp.headers_all("x-content-type-options")))
    evidence = (
        f"X-Content-Type-Options: {raw} (o navegador só reconhece o valor nosniff como primeiro valor)"
        if raw.strip()
        else _evidence_missing(resp, "X-Content-Type-Options")
    )
    ctx.report(
        "web.nosniff.ausente",
        asset=page.origin,
        evidence=evidence,
        confidence=Confidence.CONFIRMED,
        tech=tech,
    )


# -- Content-Security-Policy --------------------------------------------------------------


def _check_csp(
    ctx: CheckContext, page: Page, resp: Response, policies: list[Policy], tech: list[str]
) -> None:
    if not policies:
        report_only = resp.header("content-security-policy-report-only")
        extra = (
            " Há só Content-Security-Policy-Report-Only, que apenas registra violações e não "
            "bloqueia nada."
            if report_only
            else ""
        )
        ctx.report(
            "web.csp.ausente",
            asset=page.origin,
            evidence=_evidence_missing(resp, "Content-Security-Policy") + extra,
            details={"report_only": bool(report_only)},
            confidence=Confidence.CONFIRMED,
            tech=tech,
        )
        return
    issues = evaluate(policies)
    if not issues:
        ctx.passed("web.csp", "Content-Security-Policy sem brechas evidentes", page.origin)
        return
    grave = any(i.grave for i in issues)
    shown = "\n".join(f"Content-Security-Policy ({p.source}): {p.raw}" for p in policies)[:1200]
    ctx.report(
        "web.csp.fraca",
        asset=page.origin,
        severity=Severity.MEDIUM if grave else None,
        evidence=f"{shown}\nProblemas: " + "; ".join(i.text for i in issues),
        details={
            "problemas": [i.code for i in issues],
            "origem": sorted({p.source for p in policies}),
            "anula_protecao_xss": grave,
        },
        confidence=Confidence.CONFIRMED,
        tech=tech,
    )


# -- clickjacking -----------------------------------------------------------------------


def framing_protection(resp: Response, policies: list[Policy]) -> tuple[bool, str]:
    """(protegida?, descrição) — algoritmo do HTML Standard para enquadramento.

    ``frame-ancestors`` (só no cabeçalho) vale primeiro e anula o X-Frame-Options;
    no X-Frame-Options, valores conflitantes bloqueiam e valores desconhecidos não.
    """
    lists = frame_ancestor_lists(policies)
    if lists:
        strict = [found for found in lists if not is_broad(found)]
        if strict:
            allowed = " ".join(strict[0]) or "'none'"  # lista vazia equivale a 'none'
            return True, f"CSP frame-ancestors {allowed}"
        return False, (
            f"CSP frame-ancestors {' '.join(lists[0])} aceita qualquer site (e faz o navegador "
            "ignorar o X-Frame-Options)"
        )
    values = {v.lower() for v in _split_values(resp, "x-frame-options") if v}
    if not values:
        return False, f"resposta HTTP {resp.status} sem X-Frame-Options e sem CSP frame-ancestors"
    if len(values) > 1:
        if values & _FRAME_KEYWORDS:
            return (
                True,
                "X-Frame-Options com valores conflitantes (o navegador bloqueia o enquadramento)",
            )
        return False, f"X-Frame-Options com valores inválidos: {short(', '.join(sorted(values)))}"
    (only,) = values
    if only in ("deny", "sameorigin"):
        return True, f"X-Frame-Options: {only.upper()}"
    return False, (
        f"X-Frame-Options: {short(only)} — valor inválido ou obsoleto (ALLOW-FROM não é suportado "
        "pelos navegadores atuais) e sem frame-ancestors na CSP"
    )


def _has_state_changing_ui(doc: HtmlDoc | None) -> bool:
    """A página tem login ou formulário POST (algo que um clique enganado pode acionar)?"""
    if doc is None:
        return False
    if doc.has_orphan_password():
        return True
    return any(not f.inert and (f.has_password or f.method == "POST") for f in doc.forms)


def _check_framing(
    ctx: CheckContext,
    page: Page,
    resp: Response,
    policies: list[Policy],
    tech: list[str],
    doc: HtmlDoc | None = None,
) -> None:
    protected, description = framing_protection(resp, policies)
    if protected:
        ctx.passed("web.clickjacking", description, page.origin)
        return
    meta_only = any(
        p.source == "meta" and p.sources("frame-ancestors") is not None for p in policies
    )
    note = " A diretiva frame-ancestors no <meta> é ignorada pelo navegador." if meta_only else ""
    ctx.report(
        "web.clickjacking.ausente",
        asset=page.origin,
        severity=Severity.MEDIUM if _has_state_changing_ui(doc) else None,
        evidence=f"{resp.url}: {description}.{note}",
        confidence=Confidence.CONFIRMED,
        tech=tech,
    )


# -- Referrer-Policy ---------------------------------------------------------------------


def effective_referrer_policy(resp: Response, meta: list[str]) -> str | None:
    """Política efetiva: o último valor VÁLIDO do cabeçalho; depois, o <meta> (que vence)."""
    policy: str | None = None
    for token in _split_values(resp, "referrer-policy"):
        if token.lower() in REFERRER_POLICIES:
            policy = token.lower()
    for content in meta:
        value = content.strip().lower()
        value = _META_REFERRER_LEGACY.get(value, value)
        if value in REFERRER_POLICIES:
            policy = value
    return policy


def _check_referrer(
    ctx: CheckContext, page: Page, resp: Response, meta: list[str], tech: list[str]
) -> None:
    policy = effective_referrer_policy(resp, meta)
    if policy is None:
        raw = short(", ".join(resp.headers_all("referrer-policy")))
        evidence = (
            f"Referrer-Policy: {raw} — nenhum valor válido; vale o padrão do navegador."
            if raw.strip()
            else _evidence_missing(resp, "Referrer-Policy")
        )
        ctx.report(
            "web.referrer.ausente",
            asset=page.origin,
            evidence=evidence,
            confidence=Confidence.CONFIRMED,
            tech=tech,
        )
    elif policy in UNSAFE_REFERRERS:
        ctx.report(
            "web.referrer.inseguro",
            asset=page.origin,
            evidence=f"Referrer-Policy efetiva: {policy}",
            details={"politica": policy},
            confidence=Confidence.CONFIRMED,
            tech=tech,
        )
    else:
        ctx.passed("web.referrer", f"Referrer-Policy: {policy}", page.origin)


# -- defesa em profundidade -----------------------------------------------------------------


def _check_optional(ctx: CheckContext, page: Page, resp: Response, tech: list[str]) -> None:
    """Cabeçalhos de defesa em profundidade (informativos)."""
    if resp.header("permissions-policy") is None and resp.header("feature-policy") is None:
        ctx.report(
            "web.permissions_policy.ausente",
            asset=page.origin,
            evidence=_evidence_missing(resp, "Permissions-Policy"),
            confidence=Confidence.CONFIRMED,
            tech=tech,
        )
    else:
        ctx.passed("web.permissions_policy", "Permissions-Policy definida", page.origin)
    _check_coop(ctx, page, resp, tech)
    xss = (resp.header("x-xss-protection") or "").strip()
    if xss.startswith("1"):
        ctx.report(
            "web.xss_protection.ativo",
            asset=page.origin,
            evidence=f"X-XSS-Protection: {short(xss)}",
            confidence=Confidence.CONFIRMED,
            tech=tech,
        )


def _check_coop(ctx: CheckContext, page: Page, resp: Response, tech: list[str]) -> None:
    raw = (resp.header("cross-origin-opener-policy") or "").strip()
    value = raw.split(";", 1)[0].strip().lower()
    if value in ISOLATING_COOP:
        ctx.passed("web.coop", f"Cross-Origin-Opener-Policy: {value}", page.origin)
        return
    evidence = (
        f"Cross-Origin-Opener-Policy: {short(raw)} — não isola a janela (equivale a unsafe-none)."
        if raw
        else _evidence_missing(resp, "Cross-Origin-Opener-Policy")
    )
    ctx.report(
        "web.coop.ausente",
        asset=page.origin,
        evidence=evidence,
        confidence=Confidence.CONFIRMED,
        tech=tech,
    )
