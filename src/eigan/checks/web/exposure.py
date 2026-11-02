"""Arquivos e áreas sensíveis publicados por engano — sem nada intrusivo.

Para cada origem: caminhos conhecidos (repositório .git, .env, backups, páginas
de diagnóstico, painéis, documentação de API...) confirmados por ASSINATURA DE
CONTEÚDO, nunca só pelo código HTTP; listagem de diretório nas pastas dos
recursos da página; source maps dos scripts; introspecção do GraphQL (uma
consulta POST mínima, só leitura); robots.txt e security.txt.

Três travas contra falso positivo, nesta ordem: a assinatura do formato do
arquivo; a comparação com o "soft 404" do site (respostas HTML e assinaturas
fracas); e, em todo acerto, um caminho "isca" que não existe: se a isca também
passar na assinatura, o servidor responde aquilo para qualquer endereço.

Arquivos potencialmente grandes são lidos com ``Range`` e teto de bytes: o EIGAN
reconhece o formato pelo começo e fecha a conexão, sem baixar o conteúdo.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal
from urllib.parse import urljoin, urlsplit

from ...core import facts
from ...core.context import Cancelled, CheckContext
from ...core.http import Response
from ...core.models import Category, Confidence, Fact
from ...core.registry import check
from ...core.target import is_ip
from . import kb_exposure_files, kb_exposure_misc  # noqa: F401 — registram as entradas da base
from .common import (
    REDIRECTS,
    Page,
    claim,
    fetch_script,
    hints,
    host_of,
    is_soft404,
    load_page,
    page_doc,
    probe_url,
    profile_level,
    readable,
    run_parallel,
    safe_get,
    safe_location,
    same_origin,
    site_of,
    skip_reason,
    with_aliases,
)
from .exposure_catalog import (
    GRAPHQL_PATHS,
    LISTING_DIRS,
    SECURITY_TXT_PATHS,
    Probe,
    decoy_path,
    select,
)
from .signatures import Match
from .signatures_pages import (
    INTROSPECTION_QUERY,
    SecurityTxt,
    default_page,
    directory_listing,
    graphql_hint,
    graphql_introspection,
    robots_sensitive,
    security_txt,
    sourcemap,
)

EXPOSURE_FINDINGS = (
    "web.exposicao.repositorio",
    "web.exposicao.env",
    "web.exposicao.config",
    "web.exposicao.htpasswd",
    "web.exposicao.ds_store",
    "web.exposicao.backup",
    "web.exposicao.dump_sql",
    "web.exposicao.credenciais",
    "web.exposicao.logs",
    "web.exposicao.manifesto",
    "web.exposicao.docker",
    "web.exposicao.sourcemap",
    "web.exposicao.crossdomain",
    "web.exposicao.phpinfo",
    "web.exposicao.status",
    "web.exposicao.actuator",
    "web.exposicao.diagnostico",
    "web.exposicao.api_docs",
    "web.exposicao.graphql",
    "web.exposicao.listagem",
    "web.exposicao.pagina_padrao",
    "web.painel.exposto",
    "web.robots.sensivel",
    "web.securitytxt.ausente",
    "web.securitytxt.expirado",
    "web.securitytxt.invalido",
)
LISTING_BYTES = 262_144
SMALL_BYTES = 16_384
_MAP_COMMENT = re.compile(r"//[#@]\s*sourceMappingURL=([^\s'\"]+)")


@dataclass(frozen=True)
class Hit:
    probe: Probe
    path: str
    url: str
    status: int
    match: Match


class Coverage:
    """Conta as sondas que obtiveram uma resposta utilizável (e não bloqueio, limite ou falha)."""

    def __init__(self) -> None:
        self.usable = 0
        self._lock = threading.Lock()

    def note(self, resp: Response | None) -> None:
        if resp is not None and (resp.status < 400 or resp.status in (404, 410)):
            with self._lock:
                self.usable += 1

    def enough(self, total: int) -> bool:
        return total == 0 or self.usable * 2 >= total


@check(
    id="web.exposure",
    name="Arquivos e áreas sensíveis expostos",
    category=Category.WEB,
    consumes=facts.HTTP_SERVICE,
    description=(
        "Procura arquivos publicados por engano (.git, .env, backups, chaves, logs), páginas de "
        "diagnóstico, painéis administrativos, documentação de API, listagem de diretórios e "
        "source maps, confirmando cada um pelo conteúdo. Também lê robots.txt e security.txt."
    ),
    findings=EXPOSURE_FINDINGS,
    facts=(facts.TECH,),
    timeout=420.0,
    order=60,
)
def check_exposure(ctx: CheckContext, fact: Fact) -> None:
    url = str(fact.data["url"])
    page = load_page(ctx, url)
    if page is None:
        ctx.log(f"{url} não respondeu.")
        return
    reason = skip_reason(ctx, page)
    if reason:
        ctx.log(reason)
        return
    if not claim(ctx, f"web.exposure:{page.origin}"):
        return  # outra URL da mesma origem já foi auditada
    level = profile_level(ctx)
    tech = hints(ctx, page)
    probes = select(level, set(tech), page.host)
    coverage = Coverage()
    collected: list[Hit] = []
    try:
        run_parallel(ctx, probes, lambda probe: _collect(ctx, page, probe, coverage, collected))
    except Cancelled:
        _report_hits(ctx, page, list(collected), tech)  # o que já foi confirmado não se perde
        raise
    problems = _report_hits(ctx, page, list(collected), tech)
    problems += _check_home(ctx, page, tech)
    if level >= 1:
        problems += _check_listing(ctx, page, tech, level)
        problems += _check_sourcemaps(ctx, page, tech, level)
        problems += _check_graphql(ctx, page, tech)
    _check_robots(ctx, page, tech)
    _check_security_txt(ctx, page, tech)
    if problems:
        return
    if coverage.enough(len(probes)):
        ctx.passed(
            "web.exposicao",
            f"{len(probes)} caminhos sensíveis conferidos sem exposição",
            page.origin,
        )
    else:
        ctx.log(
            f"{page.origin}: só {coverage.usable} de {len(probes)} sondas tiveram resposta "
            "utilizável (bloqueio, limite de requisições ou falha de rede); área não avaliada."
        )


# -- sondas do catálogo ------------------------------------------------------------------


def _fetch(ctx: CheckContext, url: str, probe: Probe) -> Response | None:
    """GET com o ``Range`` e o teto da sonda; nunca levanta exceção por causa do endereço."""
    try:
        resp = ctx.http.get(url, headers=probe.headers, max_bytes=probe.max_bytes)
    except ValueError:  # UnicodeEncodeError no caminho ou "Port out of range"
        return None
    return readable(resp) if resp is not None else None


def _collect(
    ctx: CheckContext, page: Page, probe: Probe, coverage: Coverage, collected: list[Hit]
) -> None:
    """Uma sonda por vez; um erro inesperado numa sonda não derruba as outras."""
    try:
        hit = _try_probe(ctx, page, probe, coverage)
    except Cancelled:
        raise
    except Exception as exc:  # noqa: BLE001 — resposta hostil não pode abortar a auditoria
        ctx.log(f"sonda {probe.key} ignorada: {type(exc).__name__}")
        return
    if hit is not None:
        collected.append(hit)


def _try_probe(
    ctx: CheckContext, page: Page, probe: Probe, coverage: Coverage | None = None
) -> Hit | None:
    """Busca o caminho e confirma pela assinatura (roda nas threads de trabalho)."""
    path = probe.path_for(page.host)
    url = probe_url(page.origin, path)
    resp = _fetch(ctx, url, probe)
    if coverage is not None:
        coverage.note(resp)
    if resp is None or not probe.accepts(resp.status):
        return None
    match = probe.signature(resp)
    if match is None:
        return None
    if (probe.weak or resp.is_html) and is_soft404(ctx, page, path, resp):
        return None
    if _decoy_matches(ctx, page, probe, path):
        return None
    return Hit(probe, path, url, resp.status, match)


def _decoy_matches(ctx: CheckContext, page: Page, probe: Probe, path: str) -> bool:
    """Um caminho irmão que não existe também passa na assinatura? Então a prova não vale."""
    resp = _fetch(ctx, probe_url(page.origin, decoy_path(path)), probe)
    return resp is not None and probe.accepts(resp.status) and probe.signature(resp) is not None


def _report_hits(ctx: CheckContext, page: Page, hits: list[Hit], tech: list[str]) -> int:
    for hit in hits:
        probe, match = hit.probe, hit.match
        names = list(tech)
        if probe.reveals:
            name, kind = probe.reveals
            ctx.add_tech(page.host, name, kind=kind, evidence=f"{hit.path}: {match.evidence}")
            names = with_aliases([name, *names])
        ctx.report(
            match.finding or probe.finding,
            asset=page.origin,
            title=probe.title,
            severity=match.severity or probe.severity,
            evidence=f"GET {hit.url} -> HTTP {hit.status}: {match.evidence}",
            details={"caminho": hit.path, **match.details},
            confidence=match.confidence,
            discriminator=probe.key,
            tech=names,
        )
    return len(hits)


# -- página inicial e listagem de diretório ---------------------------------------------------


def _check_home(ctx: CheckContext, page: Page, tech: list[str]) -> int:
    """A própria página inicial é uma listagem de diretório ou a página padrão do servidor?"""
    home = page.final
    if not page.html or home.status != 200:
        return 0
    found = 0
    listing = directory_listing(home)
    if listing is not None:
        _report_listing(ctx, page, home.url, listing, tech)
        found += 1
    default = default_page(home)
    if default is not None:
        ctx.report(
            "web.exposicao.pagina_padrao",
            asset=page.origin,
            evidence=f"GET {home.url} -> {default.evidence}",
            details=default.details,
            confidence=Confidence.CONFIRMED,
            tech=tech,
        )
        found += 1
    return found


def listing_candidates(ctx: CheckContext, page: Page, level: int) -> list[str]:
    """Pastas dos recursos da própria página (as mais rasas primeiro) + comuns no completo."""
    doc = page_doc(ctx, page)
    found: list[str] = []
    for _element, url in doc.resources() if doc is not None else []:
        if not same_origin(url, page.origin):
            continue
        parts = urlsplit(url).path.split("/")[1:-1]
        for depth in range(1, len(parts) + 1):
            folder = "/" + "/".join(parts[:depth]) + "/"
            if folder not in found and "//" not in folder:
                found.append(folder)
    found.sort(key=lambda folder: folder.count("/"))
    chosen = found[: 4 if level == 1 else 10]
    if level >= 2:
        chosen += [d for d in LISTING_DIRS if d not in chosen]
    return chosen


def _try_listing(ctx: CheckContext, page: Page, path: str) -> tuple[str, Match] | None:
    url = probe_url(page.origin, path)
    resp = safe_get(ctx, url, LISTING_BYTES)
    if resp is None or resp.status != 200:
        return None
    match = directory_listing(resp)
    if match is None or is_soft404(ctx, page, path, resp):
        return None
    return url, match


def _check_listing(ctx: CheckContext, page: Page, tech: list[str], level: int) -> int:
    folders = listing_candidates(ctx, page, level)
    found = run_parallel(ctx, folders, lambda folder: _try_listing(ctx, page, folder))
    for url, match in found:
        _report_listing(ctx, page, url, match, tech)
    return len(found)


def _report_listing(ctx: CheckContext, page: Page, url: str, match: Match, tech: list[str]) -> None:
    folder = urlsplit(url).path or "/"
    ctx.report(
        "web.exposicao.listagem",
        asset=page.origin,
        severity=match.severity,
        evidence=f"GET {url} -> {match.evidence}",
        details={"pasta": folder, **match.details},
        confidence=Confidence.CONFIRMED,
        discriminator=folder,
        tech=tech,
    )


# -- source maps --------------------------------------------------------------------------


def _join(base: str, reference: str) -> str | None:
    try:
        return urljoin(base, reference.strip())
    except ValueError:  # ex.: "http://[::1" — o alvo pode mandar qualquer coisa
        return None


def map_url_of(script: Response, level: int) -> str | None:
    """Endereço do source map: cabeçalho, comentário no fim do script ou ``.map`` (completo)."""
    header = script.header("sourcemap") or script.header("x-sourcemap")
    if header:
        return _join(script.url, header)
    if not script.truncated:
        found = _MAP_COMMENT.findall(script.text[-4096:])
        if found:
            return None if found[-1].startswith("data:") else _join(script.url, found[-1])
    if level >= 2:
        return script.url.split("#", 1)[0].split("?", 1)[0] + ".map"
    return None


def _tail_map_url(ctx: CheckContext, script: Response) -> str | None:
    """Script grande demais para ler inteiro: pede só o final (``Range: bytes=-4096``)."""
    try:
        tail = ctx.http.get(script.url, headers={"Range": "bytes=-4096"}, max_bytes=8192)
    except ValueError:
        return None
    if tail is None or tail.status != 206:
        return None  # o servidor ignorou o Range: não há como ler o final sem baixar tudo
    found = _MAP_COMMENT.findall(readable(tail).text[-4096:])
    if not found or found[-1].startswith("data:"):
        return None
    return _join(script.url, found[-1])


def _try_sourcemap(
    ctx: CheckContext, page: Page, script_url: str, level: int
) -> tuple[str, Match] | None:
    script = fetch_script(ctx, script_url)
    map_url = map_url_of(script, level) if script is not None else None
    if map_url is None and script is not None and script.truncated:
        map_url = _tail_map_url(ctx, script)
    if map_url is None or not same_origin(map_url, page.origin):
        return None
    resp = safe_get(ctx, map_url, SMALL_BYTES)
    if resp is None or resp.status != 200:
        return None
    match = sourcemap(resp)
    return (map_url, match) if match is not None else None


def _check_sourcemaps(ctx: CheckContext, page: Page, tech: list[str], level: int) -> int:
    doc = page_doc(ctx, page)
    if doc is None:
        return 0
    scripts = [u for u in doc.script_urls() if same_origin(u, page.origin)]
    scripts = scripts[: 4 if level == 1 else 10]
    found = run_parallel(ctx, scripts, lambda u: _try_sourcemap(ctx, page, u, level))
    if not found:
        return 0
    ctx.report(
        "web.exposicao.sourcemap",
        asset=page.origin,
        evidence="\n".join(f"GET {url} -> {match.evidence}" for url, match in found[:3]),
        details={"mapas": [url for url, _ in found]},
        confidence=Confidence.CONFIRMED,
        tech=tech,
    )
    return 1


# -- GraphQL ----------------------------------------------------------------------------------


def _check_graphql(ctx: CheckContext, page: Page, tech: list[str]) -> int:
    """Consulta de introspecção mínima (só leitura) até achar um endpoint que fale GraphQL."""
    for path in GRAPHQL_PATHS:
        ctx.check_cancel()
        url = probe_url(page.origin, path)
        resp = ctx.http.post(
            url,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            body=INTROSPECTION_QUERY,
            max_bytes=SMALL_BYTES,
        )
        if resp is None:
            continue
        readable(resp)
        match = graphql_introspection(resp)
        if match is not None:
            _report_graphql(ctx, page, url, match, tech)
            return 1
        if graphql_hint(resp) is not None:
            ctx.passed("web.graphql", f"GraphQL em {url} não responde à introspecção", page.origin)
            return 0
    return 0


def _report_graphql(ctx: CheckContext, page: Page, url: str, match: Match, tech: list[str]) -> None:
    ctx.add_tech(page.host, "graphql", kind="service", evidence=f"{url}: {match.evidence}")
    ctx.report(
        "web.exposicao.graphql",
        asset=page.origin,
        evidence=f"POST {url} {{__schema{{queryType{{name}}}}}} -> {match.evidence}",
        details={"endpoint": url},
        confidence=Confidence.CONFIRMED,
        discriminator=urlsplit(url).path,
        tech=tech,
    )


# -- robots.txt e security.txt ---------------------------------------------------------------


def _check_robots(ctx: CheckContext, page: Page, tech: list[str]) -> None:
    resp = safe_get(ctx, probe_url(page.origin, "/robots.txt"), 65_536)
    if resp is None or resp.status != 200:
        return
    match = robots_sensitive(resp)
    if match is not None:
        ctx.report(
            "web.robots.sensivel",
            asset=page.origin,
            evidence=f"GET {resp.url}: {match.evidence}",
            details=match.details,
            confidence=Confidence.CONFIRMED,
            tech=tech,
        )


def _read_security_txt(
    ctx: CheckContext, page: Page, path: str
) -> SecurityTxt | str | Literal[False] | None:
    """O arquivo interpretado; o endereço, se ele é publicado em outro site.

    ``False`` = ausência confirmada (404/410 ou página que não é security.txt);
    ``None`` = não deu para saber (falha de rede, 403, 429, 5xx).
    """
    resp = safe_get(ctx, probe_url(page.origin, path), 32_768)
    if resp is not None and resp.status in REDIRECTS:
        target = safe_location(resp)
        if not target:
            return None
        if site_of(host_of(target)) != site_of(page.host):
            return target  # publicação centralizada da organização: não é lida aqui
        resp = safe_get(ctx, target, 32_768)
    if resp is None:
        return None
    parsed = security_txt(resp)
    if parsed is None and resp.status in (200, 404, 410):
        return False
    return parsed


def _check_security_txt(ctx: CheckContext, page: Page, tech: list[str]) -> None:
    """RFC 9116: valida o arquivo onde existir; só cobra a ausência no site principal em HTTPS."""
    absent = 0
    for path in SECURITY_TXT_PATHS:
        ctx.check_cancel()
        found = _read_security_txt(ctx, page, path)
        if found is False:
            absent += 1
            continue
        if isinstance(found, str):
            ctx.log(f"security.txt de {page.origin} é publicado em {found}")
            return
        if found is not None:
            _evaluate_security_txt(ctx, page, path, found, tech)
            return
    if absent < len(SECURITY_TXT_PATHS):
        ctx.log(f"{page.origin}: security.txt não avaliado (sem resposta definitiva).")
        return
    if page.https and (urlsplit(page.origin).port or 443) == 443 and not is_ip(page.host):
        ctx.report(
            "web.securitytxt.ausente",
            asset=page.origin,
            evidence="GET /.well-known/security.txt e /security.txt não devolveram um security.txt",
            confidence=Confidence.FIRM,
            tech=tech,
        )


def _evaluate_security_txt(
    ctx: CheckContext, page: Page, path: str, info: SecurityTxt, tech: list[str]
) -> None:
    if info.expires is not None and info.expires < datetime.now(UTC):
        ctx.report(
            "web.securitytxt.expirado",
            asset=page.origin,
            evidence=f"GET {path}: Expires: {info.expires_raw} (vencido)",
            confidence=Confidence.CONFIRMED,
            tech=tech,
        )
        return
    missing = [
        name
        for name, ok in (("Contact", info.contact), ("Expires", info.expires is not None))
        if not ok
    ]
    if missing:
        ctx.report(
            "web.securitytxt.invalido",
            asset=page.origin,
            evidence=f"GET {path}: faltam os campos {', '.join(missing)}",
            details={"faltando": missing},
            confidence=Confidence.CONFIRMED,
            tech=tech,
        )
        return
    ctx.passed(
        "web.securitytxt", "security.txt publicado com Contact e Expires válidos", page.origin
    )
