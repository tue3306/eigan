"""Identificação de tecnologias pela resposta HTTP (cabeçalhos, cookies e HTML).

Funções puras, sem rede: recebem as respostas da página inicial e devolvem o que
foi reconhecido (servidor, linguagem, framework, CMS, CDN/WAF e sistema). A
checagem ``web.fingerprint`` transforma isso em fatos; as demais usam o mesmo
resultado (memorizado) para escolher o exemplo de correção certo.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit

from ...core.http import Response
from ...core.versions import extract_version
from .htmlscan import HtmlDoc


@dataclass(frozen=True)
class TechHit:
    name: str  # minúsculas (nginx, php, wordpress...)
    kind: str  # um de core.facts.TECH_KINDS
    version: str | None
    evidence: str


#: produto do cabeçalho Server (minúsculas) -> (nome, tipo)
SERVER_PRODUCTS: dict[str, tuple[str, str]] = {
    "nginx": ("nginx", "server"),
    "apache": ("apache", "server"),
    "microsoft-iis": ("iis", "server"),
    "litespeed": ("litespeed", "server"),
    "openlitespeed": ("litespeed", "server"),
    "openresty": ("openresty", "server"),
    "tengine": ("tengine", "server"),
    "apache-coyote": ("tomcat", "server"),
    "tomcat": ("tomcat", "server"),
    "jetty": ("jetty", "server"),
    "caddy": ("caddy", "server"),
    "kestrel": ("kestrel", "server"),
    "microsoft-httpapi": ("windows", "os"),
    "gunicorn": ("gunicorn", "server"),
    "uvicorn": ("uvicorn", "server"),
    "werkzeug": ("werkzeug", "server"),
    "lighttpd": ("lighttpd", "server"),
    "envoy": ("envoy", "server"),
    "cowboy": ("cowboy", "server"),
    "phusion_passenger": ("passenger", "server"),
    "resin": ("resin", "server"),
    "varnish": ("varnish", "server"),
    "cloudflare": ("cloudflare", "cdn"),
    "akamaighost": ("akamai", "cdn"),
    "akamainetstorage": ("akamai", "cdn"),
    "sucuri/cloudproxy": ("sucuri", "waf"),
    "sucuri": ("sucuri", "waf"),
    "amazons3": ("amazon-s3", "service"),
    "awselb": ("aws-elb", "service"),
    "vercel": ("vercel", "cdn"),
    "netlify": ("netlify", "cdn"),
    "github.com": ("github-pages", "service"),
    "openssl": ("openssl", "service"),
    "php": ("php", "language"),
    "python": ("python", "language"),
    "cpython": ("python", "language"),
    "mod_perl": ("perl", "language"),
    "perl": ("perl", "language"),
}

#: produtos cuja "versão" no cabeçalho é fixa ou de especificação — não revela nada:
#: Apache-Coyote/1.1 (conector do Tomcat), Microsoft-HTTPAPI/2.0 (HTTP.sys do Windows),
#: Servlet/3.0 e JSP/2.2 (versões da especificação Java EE)
#: awselb/2.0, Windows-Azure-Web/1.0 e Pepyaka (Wix) são bordas de plataforma gerenciada:
#: o cliente não escolhe nem controla a versão
CONSTANT_VERSIONS = frozenset(
    {
        "apache-coyote",
        "microsoft-httpapi",
        "servlet",
        "jsp",
        "awselb",
        "windows-azure-web",
        "pepyaka",
    }
)
_CONSTANT_TOKEN = re.compile(
    r"\b(?:" + "|".join(re.escape(n) for n in sorted(CONSTANT_VERSIONS)) + r")/[\d.]+", re.I
)
#: geradores de site estático: a versão só diz com qual ferramenta o site foi montado
STATIC_GENERATORS = frozenset(
    {"hugo", "jekyll", "gatsby", "hexo", "docusaurus", "eleventy", "astro"}
)

#: tokens do X-Powered-By (minúsculas) -> (nome, tipo)
POWERED_BY: dict[str, tuple[str, str]] = {
    "php": ("php", "language"),
    "express": ("express", "framework"),
    "asp.net": ("aspnet", "framework"),
    "next.js": ("nextjs", "framework"),
    "nuxt": ("nuxt", "framework"),
    "servlet": ("java", "language"),
    "jsp": ("java", "language"),
    "jboss": ("jboss", "server"),
    "undertow": ("undertow", "server"),
    "plesklin": ("plesk", "service"),
    "pleskwin": ("plesk", "service"),
    "wp engine": ("wordpress", "cms"),
    "w3 total cache": ("wordpress", "cms"),
    "phusion passenger": ("passenger", "server"),
    "craft cms": ("craft", "cms"),
    "laravel": ("laravel", "framework"),
}

#: nome do gerador (meta generator / X-Generator) -> (nome, tipo)
GENERATORS: dict[str, tuple[str, str]] = {
    "wordpress": ("wordpress", "cms"),
    "joomla": ("joomla", "cms"),
    "drupal": ("drupal", "cms"),
    "wix.com": ("wix", "cms"),
    "ghost": ("ghost", "cms"),
    "mediawiki": ("mediawiki", "cms"),
    "typo3": ("typo3", "cms"),
    "hugo": ("hugo", "framework"),
    "jekyll": ("jekyll", "framework"),
    "gatsby": ("gatsby", "framework"),
    "docusaurus": ("docusaurus", "framework"),
    "hexo": ("hexo", "framework"),
    "squarespace": ("squarespace", "cms"),
    "shopify": ("shopify", "cms"),
    "magento": ("magento", "cms"),
    "prestashop": ("prestashop", "cms"),
    "opencart": ("opencart", "cms"),
    "moodle": ("moodle", "cms"),
    "plone": ("plone", "cms"),
    "umbraco": ("umbraco", "cms"),
    "dotnetnuke": ("dnn", "cms"),
    "dnn": ("dnn", "cms"),
    "concrete5": ("concrete", "cms"),
    "concrete cms": ("concrete", "cms"),
    "woocommerce": ("wordpress", "cms"),
    "elementor": ("wordpress", "cms"),
    "site kit by google": ("wordpress", "cms"),
    "powered by slider revolution": ("wordpress", "cms"),
}

#: chaves cuja versão é do componente (plugin, especificação), não da tecnologia mapeada
_FOREIGN_VERSION = frozenset(
    {
        "woocommerce",
        "elementor",
        "site kit by google",
        "powered by slider revolution",
        "servlet",
        "jsp",
        "wp engine",
        "w3 total cache",
        "plesklin",
        "pleskwin",
    }
)

#: cabeçalhos cujo valor inteiro é a versão de um produto -> (nome, tipo)
VERSION_HEADERS: dict[str, tuple[str, str]] = {
    "x-aspnet-version": ("aspnet", "framework"),
    "x-aspnetmvc-version": ("aspnet-mvc", "framework"),
    "x-php-version": ("php", "language"),
    "x-owa-version": ("exchange", "service"),
    "x-umbraco-version": ("umbraco", "cms"),
    "x-joomla-version": ("joomla", "cms"),
}

#: (cabeçalho, regex do valor ou None, nome, tipo)
HEADER_MARKERS: tuple[tuple[str, str | None, str, str], ...] = (
    ("cf-ray", None, "cloudflare", "cdn"),
    ("cf-cache-status", None, "cloudflare", "cdn"),
    ("x-sucuri-id", None, "sucuri", "waf"),
    ("x-sucuri-cache", None, "sucuri", "waf"),
    ("x-akamai-transformed", None, "akamai", "cdn"),
    ("akamai-grn", None, "akamai", "cdn"),
    ("x-akamai-request-id", None, "akamai", "cdn"),
    ("x-amz-cf-id", None, "cloudfront", "cdn"),
    ("x-amz-cf-pop", None, "cloudfront", "cdn"),
    ("x-cache", r"cloudfront", "cloudfront", "cdn"),
    ("via", r"cloudfront", "cloudfront", "cdn"),
    ("x-fastly-request-id", None, "fastly", "cdn"),
    ("fastly-debug-digest", None, "fastly", "cdn"),
    ("x-served-by", r"^cache-", "fastly", "cdn"),
    ("x-iinfo", None, "incapsula", "waf"),
    ("x-cdn", r"incapsula|imperva", "incapsula", "waf"),
    ("x-azure-ref", None, "azure-front-door", "cdn"),
    ("x-msedge-ref", None, "azure-cdn", "cdn"),
    ("x-vercel-id", None, "vercel", "cdn"),
    ("x-nf-request-id", None, "netlify", "cdn"),
    ("x-github-request-id", None, "github-pages", "service"),
    ("x-drupal-cache", None, "drupal", "cms"),
    ("x-drupal-dynamic-cache", None, "drupal", "cms"),
    ("x-varnish", None, "varnish", "server"),
    ("via", r"varnish", "varnish", "server"),
    ("via", r"vegur", "heroku", "service"),
    ("x-litespeed-cache", None, "litespeed", "server"),
    ("x-turbo-charged-by", r"litespeed", "litespeed", "server"),
    ("x-pingback", r"xmlrpc\.php", "wordpress", "cms"),
    ("x-redirect-by", r"wordpress", "wordpress", "cms"),
    ("x-shopify-stage", None, "shopify", "cms"),
    ("x-wix-request-id", None, "wix", "cms"),
    ("liferay-portal", None, "liferay", "cms"),
)

#: (regex do nome do cookie, nome, tipo)
COOKIE_MARKERS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"^PHPSESSID$", re.I), "php", "language"),
    (re.compile(r"^JSESSIONID$", re.I), "java", "language"),
    (re.compile(r"^ASP\.NET_SessionId$", re.I), "aspnet", "framework"),
    (re.compile(r"^\.AspNetCore\.", re.I), "aspnet", "framework"),
    (re.compile(r"^\.ASPXAUTH$", re.I), "aspnet", "framework"),
    (re.compile(r"^ASPSESSIONID", re.I), "asp", "framework"),
    (re.compile(r"^laravel_session$", re.I), "laravel", "framework"),
    (re.compile(r"^connect\.sid$"), "express", "framework"),
    (re.compile(r"^(wordpress_|wp-settings-|wordpress_logged_in_)"), "wordpress", "cms"),
    (re.compile(r"^(S?SESS)[0-9a-f]{32}$"), "drupal", "cms"),
    (re.compile(r"^ci_session$"), "codeigniter", "framework"),
    (re.compile(r"^PLAY_SESSION$"), "play", "framework"),
    (re.compile(r"^(__cf_bm|__cfduid|cf_clearance|__cflb|__cfruid|_cfuvid)$"), "cloudflare", "cdn"),
    (re.compile(r"^(incap_ses_|visid_incap_|nlbi_)"), "incapsula", "waf"),
    (re.compile(r"^(AWSALB|AWSALBCORS|AWSELB)"), "aws-elb", "service"),
    (re.compile(r"^BIGipServer"), "f5-big-ip", "service"),
    (re.compile(r"^(ak_bmsc|bm_sv|bm_sz|_abck)$"), "akamai", "cdn"),
    (re.compile(r"^sucuri_cloudproxy"), "sucuri", "waf"),
)

#: marcas em URLs de recursos DO PRÓPRIO SITE (caminho) — (regex, nome, tipo)
PATH_MARKERS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"/wp-(?:content|includes)/"), "wordpress", "cms"),
    (re.compile(r"/media/(?:jui|system/js)/|/components/com_\w+|option=com_\w+"), "joomla", "cms"),
    (
        re.compile(r"/sites/(?:default|all)/(?:files|themes|modules)/|/core/misc/drupal\.js"),
        "drupal",
        "cms",
    ),
    (re.compile(r"/_next/static/"), "nextjs", "framework"),
    (re.compile(r"/_nuxt/"), "nuxt", "framework"),
)
#: CDNs da plataforma: a URL é de outro host por natureza; exige 2+ recursos para valer
CDN_MARKERS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"^https?://cdn\.shopify\.com/", re.I), "shopify", "cms"),
    (re.compile(r"^https?://static\.wixstatic\.com/", re.I), "wix", "cms"),
)
#: marcas dentro de <script> embutido
SCRIPT_MARKERS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"drupalSettings|Drupal\.settings"), "drupal", "cms"),
    (re.compile(r"Shopify\.theme"), "shopify", "cms"),
    (re.compile(r"window\.__NUXT__"), "nuxt", "framework"),
)
#: marcas em TAGS reais do HTML cru (texto escapado ou citado não casa)
TAG_MARKERS: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile(r"<script[^>]{0,200}id=[\"']?__NEXT_DATA__", re.I), "nextjs", "framework"),
    (re.compile(r"<div[^>]{0,200}id=[\"']?___gatsby", re.I), "gatsby", "framework"),
)

#: sistemas operacionais citados nos comentários do Server
_OS_HINTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"ubuntu", re.I), "ubuntu"),
    (re.compile(r"debian", re.I), "debian"),
    (re.compile(r"centos", re.I), "centos"),
    (re.compile(r"red ?hat", re.I), "rhel"),
    (re.compile(r"fedora", re.I), "fedora"),
    (re.compile(r"win(?:32|64)", re.I), "windows"),
    (re.compile(r"freebsd", re.I), "freebsd"),
    (re.compile(r"amazon", re.I), "amazon-linux"),
)

#: as regexes abaixo ficam quadráticas em valores enormes: o valor do cabeçalho vem do alvo e
#: pode ter 64 KiB, mas nenhum produto legítimo passa disso
MAX_VALUE = 512
_VERSION = re.compile(r"v?(\d+(?:\.\d+)+[\w.\-]*|\d+)")
_PAREN_VERSION = re.compile(r"([A-Za-z][\w.\-]*)\((\d[^)]*)\)")  # Jetty(9.4.43.v2021...)
_COMMENT = re.compile(r"\(([^)]*)\)")
#: produto desconhecido: um nome só, opcionalmente seguido da versão ("HHVM/4.1", "Mono")
_GENERIC = re.compile(r"^([A-Za-z][\w.\-]*?)(?:[ /]v?(\d[\w.\-]*))?\s*(?:$|[;,(])")
#: versão só com o número principal logo depois do nome ("Drupal 10 (https://...)")
_MAJOR_AFTER_NAME = re.compile(r"^[A-Za-z][\w.!\-]*\s+v?(\d{1,4})\b")


def _longest_first(table: dict[str, tuple[str, str]]) -> tuple[str, ...]:
    return tuple(sorted(table, key=len, reverse=True))


_POWERED_KEYS = _longest_first(POWERED_BY)
_GENERATOR_KEYS = _longest_first(GENERATORS)


def parse_product_tokens(value: str) -> list[tuple[str, str | None]]:
    """``Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f`` -> [("apache", "2.4.41"), ("openssl", "1.1.1f")]."""
    tokens: list[tuple[str, str | None]] = []
    text = _PAREN_VERSION.sub(lambda m: f"{m.group(1)}/{m.group(2)}", value[:MAX_VALUE])
    text = _COMMENT.sub(" ", text)
    for raw in text.split():
        raw = raw.strip(",;")
        name, _, version = raw.partition("/")
        if version and not version[0].isdigit():
            name, version = raw, ""  # Sucuri/Cloudproxy: a barra faz parte do nome
        name = name.lower()
        if not name or not name[0].isalpha():
            continue
        tokens.append((name, version or None))
    return tokens


def os_hints(value: str) -> list[str]:
    found: list[str] = []
    for comment in _COMMENT.findall(value[:MAX_VALUE]):
        for pattern, name in _OS_HINTS:
            if pattern.search(comment) and name not in found:
                found.append(name)
    return found


def _version_of(text: str) -> str | None:
    match = _VERSION.search(text)
    return match.group(1) if match else None


def disclosed_version(header: str, value: str) -> str | None:
    """Versão que o valor do cabeçalho revela (``None`` se não revela nenhuma).

    Versões fixas ou de especificação (``Apache-Coyote/1.1``, ``Microsoft-HTTPAPI/2.0``,
    ``Servlet/3.0``) não contam: não ajudam ninguém a escolher um ataque.
    """
    text = value[:MAX_VALUE].strip()
    if not text:
        return None
    lname = header.lower()
    if lname in VERSION_HEADERS:
        return text[:60] if any(ch.isdigit() for ch in text) else None
    cleaned = _CONSTANT_TOKEN.sub(" ", text)
    if (
        lname in ("x-generator", "generator")
        and cleaned.strip().lower().split(" ")[0].split("/")[0] in STATIC_GENERATORS
    ):
        return None
    version = extract_version(cleaned)
    if version:
        return version
    if lname == "x-generator":
        match = _MAJOR_AFTER_NAME.match(cleaned.strip())
        if match:
            return match.group(1)
    return None


def from_server(value: str) -> list[TechHit]:
    hits: list[TechHit] = []
    value = value[:MAX_VALUE]
    evidence = f"Server: {value}"
    for index, (name, version) in enumerate(parse_product_tokens(value)):
        known = SERVER_PRODUCTS.get(name)
        if known is None and index > 0:
            continue  # só o primeiro produto desconhecido entra no inventário
        tech, kind = known or (name, "server")
        hits.append(TechHit(tech, kind, None if name in CONSTANT_VERSIONS else version, evidence))
    hits.extend(TechHit(os_name, "os", None, evidence) for os_name in os_hints(value))
    return hits


def _known_prefix(
    text: str, table: dict[str, tuple[str, str]], keys: Sequence[str], evidence: str
) -> TechHit | None:
    """Casa ``text`` com a chave mais longa da tabela que seja prefixo dele."""
    lowered = text.lower()
    for key in keys:
        if not lowered.startswith(key):
            continue
        rest = text[len(key) :]
        if rest and rest[0] not in "/ (":
            continue  # "phpbb" não é "php"; "Phusion Passenger(R) 6.0.4" tem versão
        tech, kind = table[key]
        version = None if key in _FOREIGN_VERSION or not rest else _version_of(rest)
        return TechHit(tech, kind, version, evidence)
    return None


def _generic(text: str, evidence: str) -> TechHit | None:
    """Produto desconhecido — só quando o texto é claramente "nome[/versão]"."""
    match = _GENERIC.match(text.strip())
    if not match or len(match.group(1)) < 2:
        return None  # frases ("Powered by ...") não viram tecnologia
    return TechHit(match.group(1).lower(), "framework", match.group(2), evidence)


def from_powered_by(value: str) -> list[TechHit]:
    hits: list[TechHit] = []
    value = value[:MAX_VALUE]
    evidence = f"X-Powered-By: {value}"
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        hit = _known_prefix(part, POWERED_BY, _POWERED_KEYS, evidence) or _generic(part, evidence)
        if hit is not None:
            hits.append(hit)
    return hits


def from_generator(value: str, source: str) -> TechHit | None:
    """``WordPress 6.4.2`` / ``Drupal 10 (https://www.drupal.org)`` -> TechHit."""
    text = value[:MAX_VALUE].strip()
    if not text:
        return None
    evidence = f"{source}: {text}"
    if text.lower().startswith("joomla"):
        return TechHit("joomla", "cms", _version_of(text[6:].lstrip("! ")[:12]), evidence)
    known = _known_prefix(text, GENERATORS, _GENERATOR_KEYS, evidence)
    return known or _generic(text, evidence)


def from_headers(resp: Response) -> list[TechHit]:
    hits: list[TechHit] = []
    for value in resp.headers_all("server"):
        hits.extend(from_server(value))
    for value in resp.headers_all("x-powered-by"):
        hits.extend(from_powered_by(value))
    for header, (name, kind) in VERSION_HEADERS.items():
        for value in resp.headers_all(header):
            version = disclosed_version(header, value)
            hits.append(TechHit(name, kind, version, f"{header}: {value[:80]}"))
    for value in resp.headers_all("x-generator"):
        hit = from_generator(value, "X-Generator")
        if hit is not None:
            hits.append(hit)
    for header, pattern, name, kind in HEADER_MARKERS:
        for value in resp.headers_all(header):
            if pattern is None or re.search(pattern, value, re.I):
                hits.append(TechHit(name, kind, None, f"{header}: {value[:80]}"))
                break
    return hits


def cookie_names(resp: Response) -> list[str]:
    names: list[str] = []
    for raw in resp.headers_all("set-cookie"):
        name = raw.split("=", 1)[0].strip()
        if name and name not in names:
            names.append(name)
    return names


def from_cookies(names: Iterable[str]) -> list[TechHit]:
    names = list(names)
    hits: list[TechHit] = []
    # nomes genéricos: só os dois juntos indicam Django (outros stacks usam cada um sozinho)
    if "csrftoken" in names and "sessionid" in names:
        hits.append(TechHit("django", "framework", None, "cookies csrftoken + sessionid"))
    for name in names:
        for pattern, tech, kind in COOKIE_MARKERS:
            if pattern.search(name):
                hits.append(TechHit(tech, kind, None, f"cookie {name}"))
                break
    return hits


def from_html(doc: HtmlDoc, html_text: str) -> list[TechHit]:
    hits: list[TechHit] = []
    for content in doc.meta_values("generator"):
        hit = from_generator(content, "meta generator")
        if hit is not None:
            hits.append(hit)
    hits.extend(_html_markers(doc, html_text[:400_000]))
    return hits


def _html_markers(doc: HtmlDoc, sample: str) -> list[TechHit]:
    """Marcas de CMS/framework só em recursos do próprio site, scripts e tags reais."""
    hits: list[TechHit] = []
    resources = [url for _, url in doc.resources()]
    own = [u for u in resources if same_site_url(u, doc.url)]
    for pattern, tech, kind in PATH_MARKERS:
        for url in own:
            match = pattern.search(urlsplit(url).path + "?" + urlsplit(url).query)
            if match:
                hits.append(
                    TechHit(tech, kind, None, f"recurso do site contém '{match.group(0)[:60]}'")
                )
                break
    for pattern, tech, kind in CDN_MARKERS:
        found = {u for u in resources if pattern.search(u)}
        if len(found) >= 2:
            hits.append(TechHit(tech, kind, None, f"{len(found)} recursos da CDN {tech}"))
    inline = "\n".join(doc.inline_scripts())[:200_000]
    for pattern, tech, kind in SCRIPT_MARKERS:
        match = pattern.search(inline)
        if match:
            hits.append(TechHit(tech, kind, None, f"script contém '{match.group(0)[:60]}'"))
    for pattern, tech, kind in TAG_MARKERS:
        match = pattern.search(sample)
        if match:
            hits.append(TechHit(tech, kind, None, "marca na estrutura do HTML"))
    return hits


def same_site_url(url: str, page_url: str) -> bool:
    """O recurso está no mesmo host da página (ou é relativo)?"""
    try:
        return (urlsplit(url).hostname or "") == (urlsplit(page_url).hostname or "")
    except ValueError:
        return False


def merge(hits: Iterable[TechHit]) -> list[TechHit]:
    """Uma entrada por tecnologia, preferindo a que traz versão (ordem preservada)."""
    merged: dict[str, TechHit] = {}
    for hit in hits:
        current = merged.get(hit.name)
        if current is None or (hit.version and not current.version):
            merged[hit.name] = hit
    return list(merged.values())


def detect(chain: Sequence[Response], doc: HtmlDoc | None, html_text: str = "") -> list[TechHit]:
    """Tudo o que dá para reconhecer nas respostas da página (e no HTML final)."""
    hits: list[TechHit] = []
    for resp in chain:
        hits.extend(from_headers(resp))
        hits.extend(from_cookies(cookie_names(resp)))
    if doc is not None:
        hits.extend(from_html(doc, html_text))
    return merge(hits)
