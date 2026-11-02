"""Conteúdo da página: conteúdo misto, SRI, formulários, segredos, erros e depuração.

Só leituras comuns de um navegador: a página inicial, alguns scripts da mesma origem,
um caminho que não existe (para ver a página de erro) e ``/console`` (o depurador do
Werkzeug). Cada achado é confirmado pelo conteúdo, não pelo código de status: sites que
respondem 200 a tudo (soft 404) não geram falso positivo. Segredos aparecem sempre
mascarados.
"""

from __future__ import annotations

import html
import ipaddress
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit

from ...core import facts, redact
from ...core.context import CheckContext
from ...core.models import Category, Confidence, Fact, Severity
from ...core.registry import check
from ...core.target import is_ip
from . import kb_content  # noqa: F401 — registra as entradas da base
from .common import (
    PAGE_MAX_BYTES,
    TEXT_PROBE_BYTES,
    Page,
    baseline,
    claim,
    fetch_script,
    hints,
    host_of,
    load_page,
    looks_like,
    page_doc,
    probe_url,
    profile_level,
    run_parallel,
    safe_get,
    same_origin,
    short,
    site_of,
    skip_reason,
)
from .htmlscan import Element, Form, HtmlDoc, parse_html

#: scripts da mesma origem lidos em busca de segredos (rápido, padrão, completo)
SCRIPT_LIMITS = (3, 10, 25)
#: páginas da mesma origem examinadas além da inicial (só no perfil completo)
EXTRA_PAGES = 3
MAX_LISTED = 8
MAX_SECRETS = 20

_ACTIVE_TAGS = frozenset({"script", "iframe", "frame", "object", "embed", "applet"})
_PASSIVE_TAGS = frozenset({"img", "audio", "video", "source", "track"})
_ACTIVE_REL = frozenset({"stylesheet", "modulepreload"})
_ACTIVE_AS = frozenset({"script", "style", "font", "fetch", "worker"})
#: scripts que mudam a cada visita por desenho: SRI é impossível, não é falha de quem usa
_DYNAMIC_SCRIPT_HOSTS = (
    "googletagmanager.com",
    "google-analytics.com",
    "connect.facebook.net",
    "platform.twitter.com",
    "maps.googleapis.com",
    "js.stripe.com",
    "www.google.com",
    "www.gstatic.com",
    "apis.google.com",
    "static.hotjar.com",
    "js.hs-scripts.com",
    "snap.licdn.com",
    "cdn.segment.com",
    "widget.intercom.io",
    "js.intercomcdn.com",
)
_SKIP_LINK = re.compile(
    r"logout|logoff|signout|sair|delete|excluir|remove|unsubscribe|cancel", re.I
)
_LINK_PRIORITY = re.compile(
    r"login|entrar|signin|sign-in|acesso|cadastr|regist|account|conta|contato", re.I
)
_STATIC_EXT = re.compile(
    r"\.(?:css|js|png|jpe?g|gif|svg|ico|webp|pdf|zip|gz|mp[34]|woff2?|ttf|xml|json|txt)$", re.I
)
_CSRF_NAME = re.compile(
    r"csrf|xsrf|token|nonce|authenticity|antiforgery|requestverification|form_key|formkey|"
    r"sesskey|__viewstate|_wpnonce",
    re.I,
)
_TOKEN_VALUE = re.compile(r"[A-Za-z0-9+/=_\-]{16,}")
_CSRF_META = ("csrf-token", "csrf-param", "_csrf", "xsrf-token")
_PRIVATE_KEY_BODY = r"(?P<body>[A-Za-z0-9+/=\\\s:.,()\-]{60,})-----END "


@dataclass(frozen=True)
class SecretRule:
    """Formato de credencial reconhecido, com a severidade e a base do achado."""

    key: str
    label: str
    pattern: re.Pattern[str]
    severity: Severity
    check_id: str = "web.conteudo.segredo"
    blob: bool = False  # bloco inteiro (chave privada): mostrar só o cabeçalho
    accept: Callable[[re.Match[str]], bool] | None = None  # confirmação extra do trecho achado


def _real_private_key(match: re.Match[str]) -> bool:
    """O corpo parece chave de verdade, não um exemplo de documentação truncado?"""
    body = re.sub(r"\\[nrt]|\s", "", match.group("body"))
    letters = re.sub(r"[^A-Za-z0-9+/=]", "", body)
    return len(letters) >= 60 and "..." not in body and not _placeholder(letters)


def _rule(key: str, label: str, regex: str, severity: Severity, **kw: object) -> SecretRule:
    return SecretRule(key, label, re.compile(regex, re.ASCII), severity, **kw)  # type: ignore[arg-type]


SECRET_RULES = (
    _rule(
        "aws",
        "identificador de chave de acesso da AWS",
        r"\b(?:AKIA|ASIA)(?=[A-Z2-7]{0,15}[2-7])[A-Z2-7]{16}\b",
        Severity.MEDIUM,
    ),
    _rule(
        "aws_secret",
        "chave secreta de acesso da AWS",
        r"aws_?secret_?(?:access_?)?key[\"'\s:=]{1,8}[A-Za-z0-9/+=]{40}\b",
        Severity.CRITICAL,
    ),
    _rule(
        "stripe",
        "chave secreta do Stripe (modo real)",
        r"\b[sr]k_live_[0-9A-Za-z]{24,}(?![0-9A-Za-z_])",
        Severity.CRITICAL,
    ),
    _rule(
        "slack_token",
        "token do Slack",
        r"\bxox[abpors]-[0-9]{8,}-[0-9A-Za-z\-]{10,}",
        Severity.HIGH,
    ),
    _rule(
        "slack_webhook",
        "webhook do Slack",
        r"https://hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{20,}",
        Severity.MEDIUM,
    ),
    _rule("github", "token do GitHub", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", Severity.HIGH),
    _rule("github_pat", "token do GitHub", r"\bgithub_pat_[A-Za-z0-9_]{60,}", Severity.HIGH),
    _rule(
        "private_key",
        "chave privada",
        r"(?P<head>-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----)"
        + _PRIVATE_KEY_BODY,
        Severity.CRITICAL,
        blob=True,
        accept=_real_private_key,
    ),
    _rule(
        "google",
        "chave de API do Google",
        r"\bAIza[0-9A-Za-z_\-]{35}(?![0-9A-Za-z_\-])",
        Severity.LOW,
        check_id="web.conteudo.chave_google",
    ),
)
_REPEATED = re.compile(r"(.)\1{7,}")


# -- erros e depuração ---------------------------------------------------------------------


@dataclass(frozen=True)
class ErrorRule:
    """Assinatura de página de erro; ``debug`` marca o modo de depuração do framework."""

    label: str
    patterns: tuple[re.Pattern[str], ...]
    debug: bool = False
    minimum: int = 1  # quantas ocorrências do último padrão contam


def _errors(label: str, *regex: str, debug: bool = False, minimum: int = 1) -> ErrorRule:
    flags = re.I | re.S
    return ErrorRule(label, tuple(re.compile(r, flags) for r in regex), debug, minimum)


# Sem ``\s*`` depois da quebra de linha nem ``[^\n]*`` solto: um corpo hostil (só quebras de
# linha ou milhares de parênteses) deixaria a busca quadrática. Tudo aqui é limitado.
_JAVA_FRAME = r"\n[ \t]{0,20}at (?:[\w$]+\.){2,}[\w$<>]+\([\w$]+\.(?:java|kt|scala):\d+\)"
_NODE_FRAME = r"\n[ \t]{0,20}at [^\n(]{0,200}\((?:/|[A-Za-z]:\\|file:///)[^)\n]{1,300}:\d+:\d+\)"
ERROR_RULES = (
    _errors(
        "Django com DEBUG = True",
        r"DEBUG\s*=\s*True\s+in\s+your\s+Django\s+settings|Using the URLconf defined in",
        debug=True,
    ),
    _errors(
        "Laravel (Whoops/Ignition)",
        r"(?:Facade|Spatie)\\{1,2}(?:Laravel)?Ignition",
        debug=True,
    ),
    _errors(
        "Laravel (Whoops)",
        r"Whoops!?\s*There was an error",
        r"Illuminate\\{1,2}|[\\/]vendor[\\/]|Whoops\\{1,2}(?:Run|Handler)",
        debug=True,
    ),
    _errors(
        "Rails em modo de desenvolvimento",
        r"Action Controller: Exception caught|Rails\.root:",
        debug=True,
    ),
    _errors(
        "traceback do Python", r"Traceback \(most recent call last\)", r'File "[^"\n]+", line \d+'
    ),
    _errors("stack trace do Java", _JAVA_FRAME, minimum=2),
    _errors(
        "página de erro do ASP.NET",
        r"Server Error in '[^']*' Application|Erro de Servidor no Aplicativo|"
        r"Error de servidor en la aplicaci[oó]n",
        r"Stack Trace:|Source Error:|Version Information:|Rastreamento de Pilha|"
        r"Informa[cç][õo]es de Vers[ãa]o|Seguimiento de la pila",
    ),
    _errors(
        "erro do PHP com caminho de arquivo",
        r"(?:Fatal error|Warning|Notice|Parse error|Deprecated)\s*(?:</b>)?:\s+[^\n]{1,300}?\s+in\s+"
        r"(?:<b>)?(?:/[\w./\-]+|[A-Za-z]:\\[^\s<]+)(?:</b>)?\s+on line\s+(?:<[bi]>)?\d+",
    ),
    _errors("stack trace do Node.js", _NODE_FRAME, minimum=2),
)
_WERKZEUG_TITLE = re.compile(r"Werkzeug Debugger</title>", re.I)
_WERKZEUG_CONSOLE = re.compile(r"CONSOLE_MODE\s*=\s*true|<h1>Interactive Console</h1>", re.I)
_WERKZEUG_TRUSTED = re.compile(r"EVALEX_TRUSTED\s*=\s*true", re.I)


def _plain(text: str) -> str:
    """Texto da página de erro sem marcação: ``<br>`` vira quebra de linha."""
    flat = re.sub(r"<br\s*/?>|</(?:p|div|li|pre|tr)>", "\n", text[:TEXT_PROBE_BYTES], flags=re.I)
    return html.unescape(flat.replace("&nbsp;", " "))


def _candidates(text: str) -> list[str]:
    """Variações do corpo: bruto, sem marcação e com os ``\\n`` de um JSON desfeitos."""
    raw = text[:TEXT_PROBE_BYTES]
    found = [raw, _plain(text)]
    if "\\n" in raw:  # Spring Boot (``trace``) e frameworks Node (``stack``) devolvem JSON
        found.append(raw.replace("\\r", "").replace("\\n", "\n").replace("\\t", "\t"))
    return found


def match_error(text: str) -> tuple[ErrorRule, str] | None:
    """Primeira assinatura de erro verbosa no texto e o trecho que a revelou."""
    for candidate in _candidates(text):
        for rule in ERROR_RULES:
            found = _match_rule(rule, candidate)
            if found is not None:
                return rule, found
    return None


def _match_rule(rule: ErrorRule, text: str) -> str | None:
    last: list[re.Match[str]] = []
    for pattern in rule.patterns:
        last = list(pattern.finditer(text))
        if not last:
            return None
    if len(last) < rule.minimum:
        return None
    start = max(0, last[0].start() - 40)
    return " ".join(text[start : last[0].end() + 160].split())


def _report_error(
    ctx: CheckContext, url: str, text: str, tech: list[str], status: int, *, home_like: bool = False
) -> None:
    found = match_error(text)
    if found is None:
        return
    rule, snippet = found
    # Um erro de verdade vem com status 4xx/5xx. Um 200 só vale se for a tela de depuração do
    # framework e não a página inicial (site que responde 200 a tudo e mostra um exemplo).
    if status < 400 and (home_like or not rule.debug):
        return
    shown_url = redact.redact(url)
    sample = short(redact.redact(snippet), 300)
    ctx.report(
        "web.debug.modo_debug" if rule.debug else "web.erro.detalhado",
        asset=shown_url,
        title=f"Página de erro revela detalhes internos: {rule.label}",
        evidence=f"{shown_url} respondeu {status} com {rule.label}:\n{sample}",
        details={"assinatura": rule.label, "status": status, "url": shown_url},
        confidence=Confidence.CONFIRMED,
        discriminator=rule.label,
        tech=tech,
    )


def _check_errors(ctx: CheckContext, page: Page, tech: list[str]) -> None:
    """Uma página que não existe (e a própria inicial, se falhar) mostram o erro bruto?"""
    ctx.check_cancel()
    base = baseline(ctx, page.origin)
    if base is not None:
        home_like = looks_like(page.final, base, base.path)
        probe = probe_url(page.origin, base.path)
        _report_error(ctx, probe, base.text, tech, base.status, home_like=home_like)
    if page.final.status >= 500 and page.final.is_html:
        _report_error(ctx, page.final.url, page.final.text, tech, page.final.status)


def _check_werkzeug(ctx: CheckContext, page: Page, tech: list[str]) -> None:
    ctx.check_cancel()
    url = probe_url(page.origin, "/console")
    resp = safe_get(ctx, url, TEXT_PROBE_BYTES)
    if resp is None or resp.status != 200:
        return
    text = resp.text
    if not (_WERKZEUG_TITLE.search(text) and _WERKZEUG_CONSOLE.search(text)):
        return
    open_console = _WERKZEUG_TRUSTED.search(text) is not None
    state = "sem PIN (console liberado)" if open_console else "protegido por PIN"
    ctx.report(
        "web.debug.werkzeug",
        severity=Severity.CRITICAL if open_console else Severity.HIGH,
        asset=url,
        evidence=f"{url} exibe o console interativo do Werkzeug ({state}).",
        details={"url": url, "console_liberado": open_console},
        confidence=Confidence.CONFIRMED,
        tech=tech,
    )


# -- conteúdo misto e SRI -------------------------------------------------------------------


def _loopback(url: str) -> bool:
    host = host_of(url)
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _upgrades_insecure(headers_csp: Iterable[str], doc: HtmlDoc) -> bool:
    values = [*headers_csp, *doc.http_equiv("content-security-policy")]
    return any("upgrade-insecure-requests" in v.lower() for v in values)


def _is_active(element: Element) -> bool:
    rel = set(element.attrs.get("rel", "").lower().split())
    if element.tag in _ACTIVE_TAGS:
        return True
    if element.tag != "link":
        return False
    preload = "preload" in rel and element.attrs.get("as", "").lower() in _ACTIVE_AS
    return bool(rel & _ACTIVE_REL) or preload


def _mixed(doc: HtmlDoc) -> tuple[list[str], list[str]]:
    """Recursos ``http://`` de uma página HTTPS: (ativos, passivos)."""
    active: dict[str, None] = {}
    passive: dict[str, None] = {}
    for element, url in doc.resources():
        if not url.startswith("http://") or _loopback(url):
            continue
        if _is_active(element):
            active.setdefault(url)
        elif element.tag in _PASSIVE_TAGS:
            passive.setdefault(url)
    for element in doc.tags("img", "source"):
        if element.inert:
            continue
        for url in doc.srcset(element.attrs.get("srcset")):
            if url.startswith("http://") and not _loopback(url):
                passive.setdefault(url)
    return list(active), [u for u in passive if u not in active]


def _listing(urls: list[str]) -> str:
    extra = f"\n... e mais {len(urls) - MAX_LISTED}" if len(urls) > MAX_LISTED else ""
    return "\n".join(f"- {u}" for u in urls[:MAX_LISTED]) + extra


def _check_mixed(ctx: CheckContext, page: Page, doc: HtmlDoc, tech: list[str]) -> None:
    if not doc.url.startswith("https://"):
        return
    csp = page.final.headers_all("Content-Security-Policy")
    if _upgrades_insecure(csp, doc):
        ctx.passed(
            "web.conteudo_misto",
            "A página pede ao navegador que troque http:// por https://.",
            doc.url,
        )
        return
    active, passive = _mixed(doc)
    for check_id, urls, label in (
        ("web.conteudo.misto_ativo", active, "ativo (scripts, estilos, frames)"),
        ("web.conteudo.misto_passivo", passive, "passivo (imagens, áudio, vídeo)"),
    ):
        if urls:
            ctx.report(
                check_id,
                asset=doc.url,
                evidence=f"{doc.url} carrega {len(urls)} recurso(s) {label} por HTTP:\n{_listing(urls)}",
                details={"recursos": urls[:50], "total": len(urls)},
                discriminator=doc.url,
                tech=tech,
            )
    if not active and not passive and doc.resources():
        ctx.passed("web.conteudo_misto", "A página HTTPS não carrega recursos por HTTP.", doc.url)


def _third_party(url: str, page_host: str) -> bool:
    host = host_of(url)
    if not host or site_of(host) == site_of(page_host) or is_ip(host):
        return False
    return not any(host == d or host.endswith("." + d) for d in _DYNAMIC_SCRIPT_HOSTS)


def _check_sri(ctx: CheckContext, page: Page, doc: HtmlDoc, tech: list[str]) -> None:
    foreign = [s for s in doc.scripts if s.src and not s.inert and _third_party(s.src, page.host)]
    if not foreign:
        return
    missing = [s.src for s in foreign if s.src and not s.attrs.get("integrity", "").strip()]
    if not missing:
        ctx.passed("web.sri", "Os scripts de terceiros trazem o atributo integrity (SRI).", doc.url)
        return
    urls = list(dict.fromkeys(missing))
    ctx.report(
        "web.conteudo.sri_ausente",
        asset=doc.url,
        evidence=f"{len(urls)} script(s) de terceiros sem integrity em {doc.url}:\n{_listing(urls)}",
        details={"scripts": urls[:50], "total": len(urls), "com_sri": len(foreign) - len(missing)},
        discriminator=doc.url,
        tech=tech,
    )


# -- formulários ------------------------------------------------------------------------------


def _has_csrf_token(form: Form, doc: HtmlDoc) -> bool:
    if any(doc.meta_values(name) for name in _CSRF_META):
        return True
    for item in form.inputs:
        if item.type != "hidden":
            continue
        if _CSRF_NAME.search(item.name) or _looks_random(item.value.strip()):
            return True
    return False


def _looks_random(value: str) -> bool:
    """Valor longo com letras e dígitos misturados (não uma palavra como ``dashboard_page``)."""
    return (
        _TOKEN_VALUE.fullmatch(value) is not None
        and any(c.isdigit() for c in value)
        and any(c.isalpha() for c in value)
    )


def _check_forms(ctx: CheckContext, doc: HtmlDoc, tech: list[str]) -> None:
    secure_page = doc.url.startswith("https://")
    password_forms = [f for f in doc.forms if f.has_password and not f.scripted and not f.inert]
    if not secure_page and (password_forms or doc.has_orphan_password()):
        ctx.report(
            "web.formulario.senha_http",
            asset=doc.url,
            evidence=f"{doc.url} é entregue por HTTP e tem campo de senha"
            + (f"; formulário envia para {password_forms[0].action}" if password_forms else "."),
            details={"formularios": [f.action for f in password_forms][:10]},
            discriminator=doc.url,
            tech=tech,
        )
    for form in doc.forms:
        ctx.check_cancel()
        if form.scripted or form.inert:
            continue
        sends_data = form.method == "POST" or form.has_password
        if (
            secure_page
            and sends_data
            and form.action.startswith("http://")
            and not _loopback(form.action)
        ):
            ctx.report(
                "web.formulario.envio_http",
                asset=doc.url,
                evidence=f"Formulário {form.method} de {doc.url} envia para {form.action} (HTTP).",
                details={
                    "action": form.action,
                    "metodo": form.method,
                    "tem_senha": form.has_password,
                },
                discriminator=f"{doc.url}->{form.action}",
                tech=tech,
            )
        if form.method == "POST" and form.has_password and not _has_csrf_token(form, doc):
            ctx.report(
                "web.formulario.sem_csrf",
                asset=doc.url,
                evidence=(
                    f"Formulário POST com senha em {doc.url} (destino {form.action}) sem campo oculto "
                    "com aparência de token anti-CSRF."
                ),
                details={"action": form.action, "ocultos": form.hidden_names()[:20]},
                confidence=Confidence.TENTATIVE,
                discriminator=f"{doc.url}->{form.action}",
                tech=tech,
            )


# -- segredos ---------------------------------------------------------------------------------


def _placeholder(value: str) -> bool:
    return "EXAMPLE" in value.upper() or bool(_REPEATED.search(value))


def find_secrets(text: str) -> list[tuple[SecretRule, str]]:
    """Credenciais com formato exato no texto: (regra, valor completo; nunca exibir)."""
    found: list[tuple[SecretRule, str]] = []
    for rule in SECRET_RULES:
        values: set[str] = set()
        for match in rule.pattern.finditer(text):
            value = match.group("head") if rule.blob else match.group(0)
            if _placeholder(value) or value in values:
                continue
            if rule.accept is not None and not rule.accept(match):
                continue
            values.add(value)
            found.append((rule, value))
            if len(values) >= MAX_SECRETS:  # o relatório mostra poucos: não vale varrer o resto
                break
    return sorted(found, key=lambda item: item[0].key == "aws")


def _report_secrets(
    ctx: CheckContext, source: str, text: str, tech: list[str], seen: set[str]
) -> None:
    secrets = find_secrets(text)
    has_aws_secret = any(rule.key == "aws_secret" for rule, _ in secrets)
    where = redact.redact(source)
    for rule, value in secrets:
        if len(seen) >= MAX_SECRETS:
            return
        shown = value if rule.blob else redact.mask(value)
        key = f"{rule.key}:{shown}:{source}"
        if key in seen:
            continue
        seen.add(key)
        what = "bloco de chave privada (conteúdo omitido)" if rule.blob else f"valor {shown}"
        # Sozinho, o identificador AKIA/ASIA não dá acesso à conta: precisa da chave secreta.
        lone_aws = rule.key == "aws" and not has_aws_secret
        severity = Severity.HIGH if rule.key == "aws" and has_aws_secret else rule.severity
        ctx.report(
            rule.check_id,
            asset=where,
            title=f"{rule.label[0].upper()}{rule.label[1:]} exposta em {where}"[:200],
            severity=severity,
            evidence=f"{rule.label}: {what} em {where}",
            details={"regra": rule.key, "local": where, "valor": shown},
            confidence=Confidence.TENTATIVE if lone_aws else Confidence.CONFIRMED,
            discriminator=key,
            tech=tech,
        )


def _scripts_for_secrets(ctx: CheckContext, page: Page, doc: HtmlDoc) -> list[tuple[str, str]]:
    local = [u for u in doc.script_urls() if same_origin(u, page.origin)]
    chosen = local[: SCRIPT_LIMITS[profile_level(ctx)]]
    return run_parallel(ctx, chosen, lambda u: _read_script(ctx, u))


def _read_script(ctx: CheckContext, url: str) -> tuple[str, str] | None:
    resp = fetch_script(ctx, url)
    return (url, resp.text) if resp is not None else None


# -- páginas extras (perfil completo) ----------------------------------------------------------


def _extra_links(doc: HtmlDoc, origin: str) -> list[str]:
    links = []
    for url in doc.links():
        path = urlsplit(url).path
        if same_origin(url, origin) and url != doc.url and not _STATIC_EXT.search(path):
            if not _SKIP_LINK.search(url):
                links.append(url)
    links.sort(key=lambda u: 0 if _LINK_PRIORITY.search(u) else 1)
    return links[:EXTRA_PAGES]


def _fetch_doc(ctx: CheckContext, url: str) -> tuple[HtmlDoc, str] | None:
    resp = safe_get(ctx, url, PAGE_MAX_BYTES)
    if resp is None or resp.status != 200 or not resp.is_html:
        return None
    return parse_html(resp.text, resp.url), resp.text


# -- a checagem ----------------------------------------------------------------------------------


@check(
    id="web.content",
    name="Conteúdo das páginas web",
    category=Category.WEB,
    consumes=facts.HTTP_SERVICE,
    description=(
        "Examina a página inicial: conteúdo misto, scripts de terceiros sem SRI, formulários de "
        "senha, segredos no HTML e JavaScript, páginas de erro verbosas e o depurador do Werkzeug."
    ),
    findings=(
        "web.conteudo.misto_ativo",
        "web.conteudo.misto_passivo",
        "web.conteudo.sri_ausente",
        "web.formulario.senha_http",
        "web.formulario.envio_http",
        "web.formulario.sem_csrf",
        "web.conteudo.segredo",
        "web.conteudo.chave_google",
        "web.erro.detalhado",
        "web.debug.modo_debug",
        "web.debug.werkzeug",
    ),
    order=44,
)
def check_content(ctx: CheckContext, fact: Fact) -> None:
    url = str(fact.data["url"])
    page = load_page(ctx, url)
    if page is None:
        ctx.log(f"{url} não respondeu.")
        return
    reason = skip_reason(ctx, page)
    if reason:
        ctx.log(reason)
        return
    tech = hints(ctx, page)
    doc = page_doc(ctx, page)
    if doc is not None:
        _analyze_page(ctx, page, doc, tech)
    if claim(ctx, f"web.content.erros:{page.origin}"):
        _check_errors(ctx, page, tech)
        _check_werkzeug(ctx, page, tech)


def _analyze_page(ctx: CheckContext, page: Page, doc: HtmlDoc, tech: list[str]) -> None:
    pages = [(doc, page.final.text)]
    if profile_level(ctx) >= 2:
        pages += run_parallel(ctx, _extra_links(doc, page.origin), lambda u: _fetch_doc(ctx, u))
    seen: set[str] = set()
    for item, text in pages:
        ctx.check_cancel()
        _check_mixed(ctx, page, item, tech)
        _check_sri(ctx, page, item, tech)
        _check_forms(ctx, item, tech)
        _report_secrets(ctx, item.url, text, tech, seen)
    for script_url, body in _scripts_for_secrets(ctx, page, doc):
        ctx.check_cancel()
        _report_secrets(ctx, script_url, body, tech, seen)
