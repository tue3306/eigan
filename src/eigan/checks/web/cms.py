"""WordPress, Joomla e Drupal: reconhecimento, versão e endurecimento — sem nenhum login.

Reconhece o CMS pela página inicial (e, nos perfis padrão e completo, por arquivos que
só ele tem), registra a tecnologia e confere o que o próprio site entrega a qualquer
visitante: xmlrpc.php, lista de usuários da API REST, readme.html, listagem da pasta de
uploads, manifesto do Joomla e CHANGELOG.txt do Drupal.

A versão é comparada com ``data/web_cms.json``, montado só com fontes oficiais. Nenhuma
falha é testada no site; versão vinda de um banner pode ter sido corrigida pela
hospedagem, por isso esses achados saem como indício.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from ...core import facts, vulndb
from ...core.context import CheckContext
from ...core.http import Response
from ...core.models import Category, Confidence, Fact, Severity
from ...core.registry import check
from . import kb_cms
from .common import (
    REDIRECTS,
    Page,
    claim,
    detected_techs,
    hints,
    is_soft404,
    load_page,
    page_doc,
    probe_url,
    profile_level,
    safe_get,
    safe_location,
    same_origin,
    skip_reason,
    with_aliases,
)
from .signatures import Match, htmlish, json_body
from .signatures_pages import directory_listing

CMS_FINDINGS = (
    "web.cms.versao_vulneravel",
    "web.cms.fim_de_suporte",
    "web.cms.desatualizado",
    "web.cms.xmlrpc",
    "web.cms.usuarios",
    "web.cms.arquivos_padrao",
    "web.cms.uploads_listagem",
    "web.cms.login",
)
PROBE_BYTES = 65_536
LISTING_BYTES = 262_144
MAX_HOPS = 3
LABELS = {"wordpress": "WordPress", "joomla": "Joomla", "drupal": "Drupal"}
#: o CHANGELOG.txt só acompanha cada lançamento até o Drupal 7; depois, vale só a série
_DRUPAL_LAST_EXACT_MAJOR = 7

Signature = Callable[[Response], Match | None]


# -- assinaturas ---------------------------------------------------------------------------

#: mensagem fixa do xmlrpc.php do WordPress para GET (wp-includes/IXR/class-IXR-server.php)
XMLRPC_GET_MESSAGE = "XML-RPC server accepts POST requests only."
_WP_FEED = re.compile(
    r"<generator>\s*https?://wordpress\.org/\?v=([\w.\-]{1,24})\s*</generator>", re.I
)
_WP_README = re.compile(r"<title>\s*WordPress\s*(?:&#8250;|›)\s*ReadMe", re.I)
_WP_ASSETS = re.compile(r"^(/.*?)?/wp-(?:content|includes)/")
_JOOMLA_VERSION = re.compile(r"<version>\s*(\d+\.\d+(?:\.\d+)?[\w.\-]{0,12})\s*</version>")
_DRUPAL_RELEASE = re.compile(r"^Drupal (\d+\.\d+(?:\.\d+)?), \d{4}-\d{2}-\d{2}", re.M)
#: texto do core/CHANGELOG.txt do Drupal 8.9+ (conferido em 8.9.20 e 10.4.0): não traz versão
_DRUPAL_CORE_CHANGELOG = "drupal.org/core/release-cycle-overview"
_DRUPAL_GENERATOR = re.compile(r"^\s*Drupal\s+(\d{1,2})\b", re.I)


def wp_login(resp: Response) -> Match | None:
    text = resp.text[:PROBE_BYTES]
    form = re.search(r"<form[^>]+id=[\"']loginform[\"']", text)
    if resp.status == 200 and form and "wp-login.php" in text:
        return Match("Tela de login do WordPress (wp-login.php) acessível pela Internet")
    return None


def wp_rest_root(resp: Response) -> Match | None:
    """Raiz da API REST: lista o espaço de nomes ``wp/v2`` (WordPress sem HTML no site)."""
    data = json_body(resp)
    names = data.get("namespaces") if isinstance(data, dict) else None
    if resp.status == 200 and isinstance(names, list) and "wp/v2" in names:
        return Match("API REST do WordPress responde em /wp-json/ (espaço de nomes wp/v2)")
    return None


def wp_readme(resp: Response) -> Match | None:
    """O ``readme.html`` da instalação: revela o produto (e a versão, nas muito antigas)."""
    if resp.status == 200 and _WP_README.search(resp.text[:16_384]):
        return Match("readme.html do WordPress legível")
    return None


def wp_readme_version(resp: Response) -> str | None:
    """O readme.html só trazia "Version X.Y" até as versões 4.x antigas."""
    text = resp.text[:16_384]
    if resp.status != 200 or not _WP_README.search(text):
        return None
    found = re.search(r"<br\s*/?>\s*Version\s+(\d+\.\d+(?:\.\d+)?)", text)
    return found.group(1) if found else None


def wp_xmlrpc(resp: Response) -> Match | None:
    if resp.status in (200, 405) and XMLRPC_GET_MESSAGE in resp.text[:2_048]:
        return Match(f'xmlrpc.php ativo (HTTP {resp.status}: "{XMLRPC_GET_MESSAGE}")')
    return None


def wp_rest_users(resp: Response) -> Match | None:
    """Lista de usuários da API REST (``/wp/v2/users``) aberta a visitantes anônimos."""
    data = json_body(resp)
    if resp.status != 200 or not isinstance(data, list) or not data:
        return None
    users = [u for u in data if isinstance(u, dict) and "slug" in u and "id" in u]
    if len(users) != len(data):
        return None
    slugs = [str(u["slug"])[:40] for u in users]
    more = " (primeira página)" if len(users) >= 10 else ""
    return Match(
        f"A API REST lista {len(users)} usuário(s) sem autenticação{more}: {', '.join(slugs[:5])}",
        details={"usuarios": slugs[:20]},
    )


def wp_author_slug(resp: Response) -> Match | None:
    """``/?author=1`` redireciona para ``/author/<login>/`` (enumeração clássica)."""
    if resp.status not in REDIRECTS:
        return None
    found = re.search(r"/author/([^/?#\s]+)/?", resp.header("location") or "")
    if not found:
        return None
    slug = found.group(1)[:40]
    evidence = f"/?author=1 redireciona para o arquivo do autor '{slug}'"
    return Match(evidence, details={"usuarios": [slug]})


def wp_feed_version(resp: Response) -> str | None:
    found = _WP_FEED.search(resp.text[:32_768]) if resp.status == 200 else None
    return found.group(1) if found else None


def joomla_admin(resp: Response) -> Match | None:
    text = resp.text[:PROBE_BYTES]
    marker = re.search(r"name=[\"']passwd[\"']|com_login|mod-login", text)
    if resp.status == 200 and "Joomla" in text and marker:
        return Match("Área administrativa do Joomla (/administrator/) acessível pela Internet")
    return None


def joomla_manifest_version(resp: Response) -> str | None:
    """Versão em ``administrator/manifests/files/joomla.xml`` (ex.: ``4.2.7``)."""
    text = resp.text[:16_384]
    if resp.status != 200 or "<name>files_joomla</name>" not in text:
        return None
    found = _JOOMLA_VERSION.search(text)
    return found.group(1) if found else None


def drupal_login(resp: Response) -> Match | None:
    text = resp.text[:PROBE_BYTES]
    if resp.status != 200 or not re.search(r"id=[\"']user-login(?:-form)?[\"']", text):
        return None
    if re.search(r"name=[\"']pass[\"']", text):
        return Match("Tela de login do Drupal (/user/login) acessível pela Internet")
    return None


def drupal_changelog_version(resp: Response) -> str | None:
    """Primeira versão lançada citada no CHANGELOG.txt (no Drupal 7, a versão instalada)."""
    text = resp.text[:8_192]
    if resp.status != 200 or htmlish(text):
        return None
    found = _DRUPAL_RELEASE.search(text)
    return found.group(1) if found else None


def drupal_core_changelog(resp: Response) -> bool:
    """``core/CHANGELOG.txt`` do Drupal moderno: reconhece o produto, sem revelar a versão."""
    text = resp.text[:4_096]
    return resp.status == 200 and not htmlish(text) and _DRUPAL_CORE_CHANGELOG in text


def drupal_generator_major(value: str) -> str | None:
    """``Drupal 10 (https://www.drupal.org)`` -> ``10`` (o Drupal só divulga a versão maior)."""
    found = _DRUPAL_GENERATOR.match(value)
    return found.group(1) if found else None


# -- reconhecimento --------------------------------------------------------------------------


@dataclass
class Cms:
    """Um CMS reconhecido em uma origem."""

    name: str
    evidence: str
    version: str | None = None  # versão exata conhecida
    branch: str | None = None  # só a série é conhecida (ex.: "10" do Drupal)
    source: str = ""  # de onde veio a versão
    confidence: Confidence = Confidence.TENTATIVE
    base: str = ""  # subpasta da instalação ("/blog")

    @property
    def label(self) -> str:
        return LABELS[self.name]

    def set_version(self, version: str, source: str, confidence: Confidence) -> None:
        """``10`` (sem ponto) é só a série; ``10.3.1`` é a versão exata."""
        if "." in version:
            self.version = version
        else:
            self.branch = version
        self.source = source
        self.confidence = confidence


def _fetch(
    ctx: CheckContext, page: Page, path: str, max_bytes: int = PROBE_BYTES
) -> Response | None:
    ctx.check_cancel()
    return safe_get(ctx, probe_url(page.origin, path), max_bytes)


def _follow(ctx: CheckContext, page: Page, path: str) -> Response | None:
    """GET seguindo redirecionamentos só dentro da mesma origem (nunca para outro site)."""
    resp = _fetch(ctx, page, path)
    for _ in range(MAX_HOPS):
        target = safe_location(resp) if resp is not None and resp.status in REDIRECTS else None
        if not target or not same_origin(target, page.origin):
            break
        ctx.check_cancel()
        resp = safe_get(ctx, target, PROBE_BYTES)
    return resp


def _probe(
    ctx: CheckContext, page: Page, path: str, signature: Signature, *, follow: bool = False
) -> tuple[tuple[Response, Match] | None, bool]:
    """Como ``_confirm``, mais: a resposta foi conclusiva (e não bloqueio, limite ou falha)?"""
    resp = _follow(ctx, page, path) if follow else _fetch(ctx, page, path)
    if resp is None:
        return None, False
    conclusive = resp.status < 400 or resp.status in (404, 410)
    match = signature(resp)
    if match is None:
        return None, conclusive
    if resp.is_html and is_soft404(ctx, page, path, resp):
        return None, conclusive
    return (resp, match), conclusive


def _confirm(
    ctx: CheckContext, page: Page, path: str, signature: Signature, *, follow: bool = False
) -> tuple[Response, Match] | None:
    """Busca o caminho e confirma pela assinatura; descarta a página genérica do site."""
    return _probe(ctx, page, path, signature, follow=follow)[0]


def _wordpress_base(ctx: CheckContext, page: Page) -> str:
    """Subpasta da instalação, pelos recursos que a própria página carrega (``/blog``)."""
    doc = page_doc(ctx, page)
    for _element, url in doc.resources() if doc is not None else []:
        if same_origin(url, page.origin):
            found = _WP_ASSETS.match(url.split(page.origin.rstrip("/"), 1)[-1])
            if found:
                return (found.group(1) or "").rstrip("/")
    return ""


def _drupal_major(ctx: CheckContext, page: Page) -> str | None:
    """Versão maior anunciada no cabeçalho ``X-Generator`` ou na meta tag ``generator``."""
    doc = page_doc(ctx, page)
    values = [value for resp in page.chain for value in resp.headers_all("x-generator")]
    values += doc.meta_values("generator") if doc is not None else []
    return next(filter(None, map(drupal_generator_major, values)), None)


def _from_home(ctx: CheckContext, page: Page) -> dict[str, Cms]:
    found: dict[str, Cms] = {}
    for hit in detected_techs(ctx, page):
        if hit.name not in LABELS:
            continue
        cms = Cms(hit.name, hit.evidence)
        if hit.version:
            cms.set_version(hit.version, hit.evidence, Confidence.TENTATIVE)
        if hit.name == "drupal":
            major = _drupal_major(ctx, page)
            if major and not cms.version:
                cms.set_version(major, f"generator: Drupal {major}", Confidence.TENTATIVE)
        if hit.name == "wordpress":
            cms.base = _wordpress_base(ctx, page)
        found[hit.name] = cms
    return found


def _probe_new(ctx: CheckContext, page: Page, found: dict[str, Cms]) -> None:
    """Sites que não se identificam na página inicial: arquivos que só o CMS tem."""
    if "wordpress" not in found:
        for path, signature in (("/wp-login.php", wp_login), ("/wp-json/", wp_rest_root)):
            hit = _confirm(ctx, page, path, signature)
            if hit is not None:
                found["wordpress"] = Cms("wordpress", f"GET {path}: {hit[1].evidence}")
                break
    if "joomla" not in found:
        path = "/administrator/manifests/files/joomla.xml"
        resp = _fetch(ctx, page, path)
        if resp is not None and joomla_manifest_version(resp):
            found["joomla"] = Cms("joomla", f"GET {path}: manifesto files_joomla")
    if "drupal" not in found:
        resp = _fetch(ctx, page, "/CHANGELOG.txt")
        if resp is not None and drupal_changelog_version(resp):
            found["drupal"] = Cms("drupal", "GET /CHANGELOG.txt: histórico de versões do Drupal")
            return
        resp = _fetch(ctx, page, "/core/CHANGELOG.txt")
        if resp is not None and drupal_core_changelog(resp):
            found["drupal"] = Cms("drupal", "GET /core/CHANGELOG.txt: texto do Drupal 8.9+")


# -- a checagem --------------------------------------------------------------------------


@check(
    id="web.cms",
    name="WordPress, Joomla e Drupal",
    category=Category.WEB,
    consumes=facts.HTTP_SERVICE,
    description=(
        "Reconhece WordPress, Joomla e Drupal e compara a versão com fontes oficiais (fim de "
        "suporte, falhas exploradas). Confere xmlrpc.php, lista de usuários, arquivos de "
        "instalação, listagem de uploads e tela de login, sem nenhuma tentativa de login."
    ),
    findings=CMS_FINDINGS,
    facts=(facts.TECH,),
    order=55,
)
def check_cms(ctx: CheckContext, fact: Fact) -> None:
    url = str(fact.data["url"])
    page = load_page(ctx, url)
    if page is None:
        ctx.log(f"{url} não respondeu.")
        return
    reason = skip_reason(ctx, page)
    if reason:
        ctx.log(reason)
        return
    if not claim(ctx, f"web.cms:{page.origin}"):
        return  # outra URL da mesma origem já foi auditada
    level = profile_level(ctx)
    found = _from_home(ctx, page)
    if level >= 1:
        _probe_new(ctx, page, found)
    for cms in found.values():
        tech = with_aliases([cms.name, *hints(ctx, page)])
        AUDITS[cms.name](ctx, page, cms, level, tech)
        ctx.add_tech(
            page.host,
            cms.name,
            version=cms.version or cms.branch,
            kind="cms",
            evidence=cms.source or cms.evidence,
        )
        _evaluate_version(ctx, page, cms, tech)


def _report_file(
    ctx: CheckContext,
    page: Page,
    path: str,
    evidence: str,
    tech: list[str],
    severity: Severity | None = None,
) -> None:
    ctx.report(
        "web.cms.arquivos_padrao",
        asset=page.origin,
        severity=severity,
        evidence=f"GET {probe_url(page.origin, path)}: {evidence}",
        details={"caminho": path},
        confidence=Confidence.CONFIRMED,
        discriminator=path,
        tech=tech,
    )


def _report_login(
    ctx: CheckContext, page: Page, cms: Cms, hit: tuple[Response, Match], tech: list[str]
) -> None:
    ctx.report(
        "web.cms.login",
        asset=page.origin,
        title=f"Tela de login do {cms.label} aberta para a Internet",
        evidence=f"GET {hit[0].url}: {hit[1].evidence}",
        details={"cms": cms.name},
        confidence=Confidence.CONFIRMED,
        discriminator=cms.name,
        tech=tech,
    )


# -- WordPress -----------------------------------------------------------------------------


def _audit_wordpress(ctx: CheckContext, page: Page, cms: Cms, level: int, tech: list[str]) -> None:
    _wp_xmlrpc(ctx, page, cms, tech)
    _wp_users(ctx, page, cms, level, tech)
    if level >= 1:
        _wp_files(ctx, page, cms, tech)
        _wp_uploads(ctx, page, cms, tech)
        _wp_login_page(ctx, page, cms, tech)
    if not cms.version:
        resp = _follow(ctx, page, f"{cms.base}/?feed=rss2")
        version = wp_feed_version(resp) if resp is not None else None
        if version:
            cms.set_version(version, f"feed RSS: generator {version}", Confidence.TENTATIVE)


def _wp_xmlrpc(ctx: CheckContext, page: Page, cms: Cms, tech: list[str]) -> None:
    hit, conclusive = _probe(ctx, page, f"{cms.base}/xmlrpc.php", wp_xmlrpc)
    if hit is None:
        if conclusive:
            ctx.passed("web.cms.xmlrpc", "O xmlrpc.php do WordPress não responde", page.origin)
        else:
            ctx.log(f"{page.origin}: xmlrpc.php não avaliado (bloqueio ou falha)")
        return
    ctx.report(
        "web.cms.xmlrpc",
        asset=page.origin,
        evidence=(
            f"GET {hit[0].url}: {hit[1].evidence} (o arquivo responde; um plugin ou filtro "
            "ainda pode desativar os métodos)"
        ),
        confidence=Confidence.FIRM,
        tech=tech,
    )


def _wp_users(ctx: CheckContext, page: Page, cms: Cms, level: int, tech: list[str]) -> None:
    """A lista da API REST (com ou sem URLs amigáveis) e, fora do perfil rápido, o ``?author=1``."""
    rest, ok = _probe(ctx, page, f"{cms.base}/wp-json/wp/v2/users", wp_rest_users)
    if rest is None:
        rest, ok2 = _probe(ctx, page, f"{cms.base}/?rest_route=/wp/v2/users", wp_rest_users)
        ok = ok or ok2
    author = None
    if level >= 1:
        author, ok3 = _probe(ctx, page, f"{cms.base}/?author=1", wp_author_slug)
        ok = ok or ok3
    hits = [hit for hit in (rest, author) if hit is not None]
    if not hits and ok:
        ctx.passed("web.cms.usuarios", "O WordPress não revela nomes de usuário", page.origin)
    elif not hits:
        ctx.log(f"{page.origin}: usuários do WordPress não avaliados (bloqueio ou falha)")
    for resp, match in hits:
        ctx.report(
            "web.cms.usuarios",
            asset=page.origin,
            evidence=f"GET {resp.url}: {match.evidence}",
            details=match.details,
            confidence=Confidence.CONFIRMED,
            tech=tech,
        )


def _wp_files(ctx: CheckContext, page: Page, cms: Cms, tech: list[str]) -> None:
    path = f"{cms.base}/readme.html"
    hit = _confirm(ctx, page, path, wp_readme)
    if hit is None:
        return
    version = wp_readme_version(hit[0])
    if version is None:
        _report_file(ctx, page, path, hit[1].evidence, tech, Severity.INFO)
        return
    if not cms.version:
        cms.set_version(version, f"readme.html: Version {version}", Confidence.TENTATIVE)
    _report_file(ctx, page, path, f"{hit[1].evidence}; informa a versão {version}", tech)


def _wp_uploads(ctx: CheckContext, page: Page, cms: Cms, tech: list[str]) -> None:
    path = f"{cms.base}/wp-content/uploads/"
    resp = _fetch(ctx, page, path, LISTING_BYTES)
    match = directory_listing(resp) if resp is not None and resp.status == 200 else None
    if resp is None or match is None or is_soft404(ctx, page, path, resp):
        return
    ctx.report(
        "web.cms.uploads_listagem",
        asset=page.origin,
        evidence=f"GET {resp.url} -> {match.evidence}",
        details=match.details,
        confidence=Confidence.CONFIRMED,
        tech=tech,
    )


def _wp_login_page(ctx: CheckContext, page: Page, cms: Cms, tech: list[str]) -> None:
    hit = _confirm(ctx, page, f"{cms.base}/wp-login.php", wp_login)
    if hit is None:
        hit = _confirm(ctx, page, f"{cms.base}/wp-admin/", wp_login, follow=True)
    if hit is not None:
        _report_login(ctx, page, cms, hit, tech)


# -- Joomla --------------------------------------------------------------------------------


def _audit_joomla(ctx: CheckContext, page: Page, cms: Cms, level: int, tech: list[str]) -> None:
    path = "/administrator/manifests/files/joomla.xml"
    resp = _fetch(ctx, page, path)
    version = joomla_manifest_version(resp) if resp is not None else None
    if version:  # o manifesto vem com o pacote instalado: vale mais que qualquer banner
        cms.set_version(version, f"GET {path}: <version>{version}</version>", Confidence.FIRM)
        _report_file(ctx, page, path, f"manifesto legível, com a versão {version}", tech)
    if level >= 1:
        hit = _confirm(ctx, page, "/administrator/", joomla_admin, follow=True)
        if hit is not None:
            _report_login(ctx, page, cms, hit, tech)


# -- Drupal --------------------------------------------------------------------------------


def _audit_drupal(ctx: CheckContext, page: Page, cms: Cms, level: int, tech: list[str]) -> None:
    resp = _fetch(ctx, page, "/CHANGELOG.txt")
    version = drupal_changelog_version(resp) if resp is not None else None
    if version:
        _drupal_changelog(ctx, page, cms, version, tech)
    if level >= 1:
        hit = _confirm(ctx, page, "/user/login", drupal_login, follow=True)
        if hit is None:
            hit = _confirm(ctx, page, "/?q=user/login", drupal_login, follow=True)
        if hit is not None:
            _report_login(ctx, page, cms, hit, tech)


def _drupal_changelog(
    ctx: CheckContext, page: Page, cms: Cms, version: str, tech: list[str]
) -> None:
    major = version.split(".", 1)[0]
    source = f"CHANGELOG.txt: Drupal {version}"
    if int(major) <= _DRUPAL_LAST_EXACT_MAJOR:
        cms.set_version(version, source, Confidence.FIRM)
        shown = f"versão {version}"
    else:  # nas séries novas o arquivo não acompanha as correções
        if not cms.version:
            cms.set_version(major, source, Confidence.TENTATIVE)
        shown = f"série {major}"
    _report_file(ctx, page, "/CHANGELOG.txt", f"histórico legível, revela a {shown}", tech)


AUDITS: dict[str, Callable[[CheckContext, Page, Cms, int, list[str]], None]] = {
    "wordpress": _audit_wordpress,
    "joomla": _audit_joomla,
    "drupal": _audit_drupal,
}


# -- versão ----------------------------------------------------------------------------------


def _evaluate_version(ctx: CheckContext, page: Page, cms: Cms, tech: list[str]) -> None:
    shown = cms.version or cms.branch
    if not shown:
        ctx.log(f"{cms.label} em {page.origin}: versão não divulgada, sem avaliação de versão")
        return
    ended = _report_end_of_life(ctx, page, cms, shown, tech)
    if not cms.version:
        return  # só a série é conhecida: as faixas de CVE exigem a versão exata
    vulnerable = _report_cves(ctx, page, cms, cms.version, tech)
    if not ended and not vulnerable:
        _report_outdated(ctx, page, cms, cms.version, tech)


def _report_end_of_life(
    ctx: CheckContext, page: Page, cms: Cms, shown: str, tech: list[str]
) -> bool:
    row = kb_cms.end_of_life(cms.name, shown, kb_cms.today())
    if row is None:
        return False
    ctx.report(
        "web.cms.fim_de_suporte",
        asset=page.origin,
        title=f"{cms.label} {shown} não recebe mais correções de segurança",
        evidence=(
            f"{cms.label} {shown} ({cms.source}): a série {row['serie']} perdeu o suporte em "
            f"{row['data']} ({row['fonte']})"
        ),
        details={"versao": shown, "serie": row["serie"], "fim": row["data"], "fonte": row["fonte"]},
        confidence=cms.confidence,
        tech=tech,
    )
    return True


def _report_cves(ctx: CheckContext, page: Page, cms: Cms, version: str, tech: list[str]) -> bool:
    found = kb_cms.known_cves(cms.name, version)
    if not found:
        return False
    ids = sorted(cve["id"] for cve in found)
    kev = vulndb.any_kev(ids)
    note = " (catálogo CISA KEV: exploradas em ataques reais)" if kev else ""
    ctx.report(
        "web.cms.versao_vulneravel",
        asset=page.origin,
        title=f"{cms.label} {version} com falhas conhecidas ({', '.join(ids[:3])})",
        severity=Severity.CRITICAL if kev else None,
        evidence=f"{cms.label} {version} ({cms.source}) está na faixa de {', '.join(ids)}{note}",
        details={
            "versao": version,
            "falhas": [{"id": c["id"], "resumo": c["resumo"], "fonte": c["fonte"]} for c in found],
        },
        confidence=cms.confidence,
        cves=ids,
        kev=kev,
        tech=tech,
    )
    return True


def _report_outdated(
    ctx: CheckContext, page: Page, cms: Cms, version: str, tech: list[str]
) -> None:
    result = kb_cms.outdated(cms.name, version)
    if result is None:
        if not kb_cms.has_reference(cms.name, version):
            ctx.log(f"{cms.label} {version}: sem dados de referência para comparar a versão")
            return
        text = (
            f"{cms.label} {version} em dia com as versões oficiais conhecidas pelo EIGAN "
            f"(dados de {kb_cms.data_date()})"
        )
        ctx.passed("web.cms.versao", text, page.origin)
        return
    newest, behind = result
    reason = f"a última da série é {newest}"
    if not behind:
        reason = f"só a série mais recente ({newest}) é mantida oficialmente"
    ctx.report(
        "web.cms.desatualizado",
        asset=page.origin,
        title=f"{cms.label} {version} desatualizado",
        severity=Severity.MEDIUM if behind else Severity.LOW,
        evidence=f"{cms.label} {version} ({cms.source}): {reason} (dados de {kb_cms.data_date()})",
        details={"versao": version, "referencia": newest},
        confidence=cms.confidence,
        tech=tech,
    )
