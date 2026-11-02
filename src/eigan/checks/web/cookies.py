"""Atributos dos cookies: Secure, HttpOnly, SameSite e prefixos ``__Host-``/``__Secure-``.

Lê os ``Set-Cookie`` da página inicial (inclusive nos redirecionamentos dentro da
mesma origem) como o navegador guardaria: o último ``Set-Cookie`` de um mesmo
cookie vale e um cookie apagado (``Max-Age=0`` ou ``Expires`` no passado) sai da
lista. Cookies que parecem de sessão/autenticação pesam mais; cookies de
infraestrutura (CDN, balanceador) ficam de fora porque o dono do site não os
controla. O valor do cookie e atributos desconhecidos nunca aparecem na
evidência.

Regras de leitura (RFC 6265bis): ``Max-Age`` vence ``Expires``; ``SameSite`` com
valor desconhecido é ignorado (conta como ausente); prefixos são comparados sem
diferenciar maiúsculas. O HSTS do site reduz o peso da falta de ``Secure``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

from ...core import facts, kb
from ...core.context import CheckContext
from ...core.http import Response
from ...core.models import Category, Confidence, Fact, Severity
from ...core.registry import check
from . import kb_cookies  # noqa: F401 — registra as entradas da base
from .common import has_https_counterpart, hints, load_page, short

#: nomes típicos de cookies de sessão/autenticação (PHPSESSID, JSESSIONID, connect.sid,
#: SSESS<hash> do Drupal, .AspNetCore.Cookies, wordpress_logged_in_...)
SESSION_NAME = re.compile(
    r"session|sessid|^s?sess(?:[0-9a-f_]|$)|[_.:\-]sess|^sid$|[_.:\-]sid$|auth(?!or(?!iz))|"
    r"(?:access|id|auth|refresh|api|bearer|user|login|jwt)[_.\-]?token|^token$|jwt|"
    r"^login$|login[_.\-](?:id|token|user|session)|remember|logged|^identity$|"
    r"^\.aspnetcore\.(?:cookies|identity)|^wordpress_(?!test_cookie)",
    re.I,
)
#: tokens anti-CSRF são lidos por JavaScript de propósito
CSRF_NAME = re.compile(r"csrf|xsrf|antiforgery|requestverificationtoken", re.I)
#: cookies de CDN/balanceador (o dono do site não controla os atributos)
INFRA_NAME = re.compile(
    r"^(?:__cf_bm|__cflb|cf_clearance|__cfruid|_cfuvid|__cfduid|AWSALB\w*|AWSELB\w*|"
    r"BIGipServer.*|incap_ses_.*|visid_incap_.*|nlbi_.*|ak_bmsc|bm_sv|bm_sz|_abck|"
    r"TS01[0-9a-f]+|ARRAffinity\w*|__stripe_(?:sid|mid))$",
    re.I,
)
SAMESITE_VALUES = frozenset({"strict", "lax", "none"})
#: atributos definidos na RFC 6265bis (e Partitioned/Priority dos navegadores)
KNOWN_ATTRIBUTES = frozenset(
    {
        "expires",
        "max-age",
        "domain",
        "path",
        "secure",
        "httponly",
        "samesite",
        "partitioned",
        "priority",
    }
)


@dataclass
class Cookie:
    name: str
    attrs: dict[str, str] = field(default_factory=dict)  # chaves minúsculas; flags = ""
    raw_attrs: list[str] = field(default_factory=list)

    @property
    def secure(self) -> bool:
        return "secure" in self.attrs

    @property
    def httponly(self) -> bool:
        return "httponly" in self.attrs

    @property
    def samesite_raw(self) -> str | None:
        value = self.attrs.get("samesite")
        return value.strip() if value is not None else None

    @property
    def samesite(self) -> str | None:
        """Valor efetivo: o navegador ignora um SameSite desconhecido (fica como ausente)."""
        value = (self.samesite_raw or "").lower()
        return value if value in SAMESITE_VALUES else None

    @property
    def domain(self) -> str:
        return self.attrs.get("domain", "").strip().lstrip(".").lower()

    @property
    def key(self) -> tuple[str, str, str]:
        """Identidade do cookie no navegador: nome, domínio e caminho."""
        return self.name, self.domain, self.attrs.get("path", "").strip()

    @property
    def is_session(self) -> bool:
        return bool(SESSION_NAME.search(self.name)) and not CSRF_NAME.search(self.name)

    @property
    def expired(self) -> bool:
        """Cookie sendo apagado (Max-Age<=0 ou Expires no passado); Max-Age vence Expires."""
        max_age = self.attrs.get("max-age")
        if max_age is not None:
            try:
                return int(max_age.strip()) <= 0
            except ValueError:
                pass  # Max-Age inválido é ignorado; vale o Expires
        expires = self.attrs.get("expires")
        if expires:
            try:
                when = parsedate_to_datetime(expires.strip())
            except (TypeError, ValueError, IndexError, OverflowError):
                return False  # data ilegível é ignorada pelo navegador (vale como sem Expires)
            if when.tzinfo is None:
                when = when.replace(tzinfo=UTC)
            return when < datetime.now(UTC)
        return False

    def describe(self) -> str:
        """``Set-Cookie`` sem o valor e só com os atributos conhecidos."""
        shown = [
            a for a in self.raw_attrs if a.partition("=")[0].strip().lower() in KNOWN_ATTRIBUTES
        ]
        text = f"Set-Cookie: {short(self.name, 100)}=<valor omitido>"
        text += "".join(f"; {short(a, 100)}" for a in shown)
        hidden = len(self.raw_attrs) - len(shown)
        return text + (f"; <{hidden} atributo(s) desconhecido(s) omitido(s)>" if hidden else "")


def parse_set_cookie(header: str) -> Cookie | None:
    parts = [p.strip() for p in header.split(";")]
    if not parts or "=" not in parts[0]:
        return None
    name = parts[0].split("=", 1)[0].strip()
    if not name:
        return None
    cookie = Cookie(name)
    for item in parts[1:]:
        if not item:
            continue
        key, _, value = item.partition("=")
        cookie.attrs[key.strip().lower()] = value.strip()  # repetido: vale o último
        cookie.raw_attrs.append(item)
    return cookie


def prefix_problem(cookie: Cookie) -> str | None:
    """O que falta para o navegador aceitar um cookie com prefixo de segurança."""
    lowered = cookie.name.lower()
    if lowered.startswith("__host-"):
        missing = []
        if not cookie.secure:
            missing.append("Secure")
        if cookie.attrs.get("path", "").strip() != "/":
            missing.append("Path=/")
        if "domain" in cookie.attrs:
            missing.append("sem Domain")
        return ", ".join(missing) or None
    if lowered.startswith("__secure-") and not cookie.secure:
        return "Secure"
    return None


def collect_cookies(chain: list[Response]) -> list[tuple[Cookie, bool]]:
    """Cookies que o navegador guardaria ao seguir a cadeia: (cookie, veio por HTTPS)."""
    jar: dict[tuple[str, str, str], tuple[Cookie, bool]] = {}
    for resp in chain:
        https = resp.url.lower().startswith("https://")
        for header in resp.headers_all("set-cookie"):
            cookie = parse_set_cookie(header)
            if cookie is None or INFRA_NAME.match(cookie.name):
                continue
            jar.pop(cookie.key, None)
            if not cookie.expired:
                jar[cookie.key] = (cookie, https)
    return list(jar.values())


def hsts_policy(value: str | None) -> tuple[int, bool] | None:
    """(max-age, includeSubDomains) de um Strict-Transport-Security válido (RFC 6797)."""
    max_age: int | None = None
    include = False
    seen: set[str] = set()
    for directive in (value or "").split(";"):
        name, _, raw = directive.partition("=")
        name = name.strip().lower()
        if not name:
            continue
        if name in seen:  # diretiva repetida invalida o cabeçalho inteiro
            return None
        seen.add(name)
        if name == "max-age":
            text = raw.strip().strip('"')
            if not (text.isascii() and text.isdigit() and len(text) <= 12):
                return None
            max_age = int(text)
        elif name == "includesubdomains":
            include = True
    return (max_age, include) if max_age is not None else None


def hsts_covers(chain: list[Response], host: str, cookie: Cookie) -> bool:
    """O HSTS recebido impede o envio deste cookie por HTTP?"""
    policy: tuple[int, bool] | None = None
    for resp in chain:
        values = resp.headers_all("strict-transport-security")
        if resp.url.lower().startswith("https://") and values:
            policy = hsts_policy(values[0])  # o navegador só processa o primeiro
    if policy is None or policy[0] <= 0:
        return False
    if "domain" not in cookie.attrs:
        return True  # cookie só deste host
    return policy[1] and cookie.domain == host.strip("[]").lower()


@check(
    id="web.cookies",
    name="Atributos dos cookies",
    category=Category.WEB,
    consumes=facts.HTTP_SERVICE,
    description=(
        "Confere Secure, HttpOnly e SameSite dos cookies emitidos pela página inicial e o uso "
        "correto dos prefixos __Host- e __Secure-."
    ),
    findings=(
        "web.cookie.sem_secure",
        "web.cookie.sem_httponly",
        "web.cookie.sem_samesite",
        "web.cookie.samesite_none_sem_secure",
        "web.cookie.prefixo_invalido",
    ),
    order=25,
)
def check_cookies(ctx: CheckContext, fact: Fact) -> None:
    url = str(fact.data["url"])
    page = load_page(ctx, url)
    if page is None:
        ctx.log(f"{url} não respondeu.")
        return
    if has_https_counterpart(ctx, page):
        ctx.log(f"{url} também responde em HTTPS; os cookies são avaliados lá.")
        return
    cookies = collect_cookies(page.chain)
    if not cookies:
        ctx.log(f"{page.url} não emitiu cookies na página inicial.")
        return
    tech = hints(ctx, page)
    problems = 0
    for cookie, https in cookies:
        hsts = https and hsts_covers(page.chain, page.host, cookie)
        problems += _audit_cookie(ctx, page.origin, cookie, https, hsts, tech)
    if problems == 0:
        ctx.passed(
            "web.cookies",
            f"{len(cookies)} cookie(s) com atributos de segurança adequados",
            page.origin,
        )


def _audit_cookie(
    ctx: CheckContext, origin: str, cookie: Cookie, https: bool, hsts: bool, tech: list[str]
) -> int:
    """Reporta os problemas de um cookie; devolve quantos foram encontrados."""
    found: list[tuple[str, Severity | None, str]] = []
    session = cookie.is_session
    kind = "cookie de sessão" if session else "cookie"
    if https and not cookie.secure:
        severity: Severity | None
        if hsts:
            severity = Severity.LOW if session else Severity.INFO
            note = f"{kind} sem Secure; o HSTS do site reduz o risco de envio por HTTP"
        else:
            severity = None if session else Severity.LOW
            note = f"{kind} sem Secure em site HTTPS"
        found.append(("web.cookie.sem_secure", severity, note))
    if session and not cookie.httponly:
        found.append(("web.cookie.sem_httponly", None, f"{kind} legível por JavaScript"))
    if session and cookie.samesite is None:
        raw = cookie.samesite_raw
        note = (
            f"{kind} sem SameSite"
            if raw is None
            else f"SameSite={raw} é inválido e o navegador o ignora"
        )
        found.append(("web.cookie.sem_samesite", None, note))
    if cookie.samesite == "none" and not cookie.secure:
        found.append(("web.cookie.samesite_none_sem_secure", None, "SameSite=None exige Secure"))
    missing = prefix_problem(cookie)
    if missing:
        found.append(("web.cookie.prefixo_invalido", None, f"o prefixo exige: {missing}"))
    for finding_id, weight, why in found:
        ctx.report(
            finding_id,
            asset=origin,
            title=f"{kb.require(finding_id).title}: {cookie.name[:60]}",
            severity=weight,
            evidence=f"{cookie.describe()}  ({why})",
            details={"cookie": short(cookie.name, 100), "sessao": session, "hsts": hsts},
            confidence=Confidence.CONFIRMED,
            discriminator=cookie.name,
            tech=tech,
        )
    return len(found)
