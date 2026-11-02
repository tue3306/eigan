"""Versões do protocolo: quais o servidor aceita, das obsoletas às modernas.

As versões antigas são testadas com um ClientHello montado à mão (``wire``): o OpenSSL 3
nem as oferece. O ``TLS_FALLBACK_SCSV`` nunca é enviado, porque com ele um servidor moderno
recusaria a versão antiga de propósito e a sonda daria falso negativo. O resultado é
compartilhado com a checagem de cifras por meio de ``support.version_map``.
"""

from __future__ import annotations

from ...core import facts, vulndb
from ...core.context import CheckContext
from ...core.models import Category, Confidence, Fact
from ...core.registry import STANDARD_UP, check
from . import kb_protocolos, suites, support
from .common import Endpoint, endpoint_of, io_timeout, tech_hint
from .kb_protocolos import LEGACY_FINDINGS, NO_TLS12, NO_TLS13
from .suites import SSL2, SSL3, TLS10, TLS11, TLS12, TLS13
from .support import Probe, VersionMap

#: versões que precisam ter sido recusadas de forma explícita para o ponto forte valer
#: (o SSLv2 fica de fora: muitos servidores atuais simplesmente não respondem a ele)
_MUST_BE_REFUSED = (SSL3, TLS10, TLS11)


def _cves(version: int, probe: Probe) -> list[str]:
    """CVEs de protocolo: o DROWN é do SSLv2 e o POODLE, do modo CBC no SSLv3."""
    if version == SSL2:
        return ["CVE-2016-0800"]
    if version == SSL3 and probe.suite is not None and suites.is_cbc(probe.suite):
        return ["CVE-2014-3566"]
    return []


def _report_legacy(ctx: CheckContext, endpoint: Endpoint, versions: VersionMap) -> None:
    for version in versions.legacy_accepted():
        probe = versions.results[version]
        name = suites.version_name(version)
        cves = _cves(version, probe)
        ctx.report(
            LEGACY_FINDINGS[version],
            asset=endpoint.asset,
            evidence=f"O servidor aceitou {name}: {probe.detail}.",
            details={
                "versao": name,
                "suite": suites.name(probe.suite) if probe.suite is not None else None,
            },
            confidence=Confidence.CONFIRMED,
            cves=cves,
            kev=vulndb.any_kev(cves),
            tech=tech_hint(ctx, endpoint.host),
        )


def _tls12_really_missing(ctx: CheckContext, endpoint: Endpoint, versions: VersionMap) -> bool:
    """Confirma com uma segunda sonda: uma conexão derrubada à toa não pode virar achado."""
    if not (versions.refused(TLS12) and versions.refused(TLS13)):
        return False
    if not versions.legacy_accepted():
        return False
    return support.raw_probe(endpoint, TLS12, suites.TLS12_PROBE, io_timeout(ctx)).refused


def _audit_modern(ctx: CheckContext, endpoint: Endpoint, versions: VersionMap) -> None:
    accepted_any = any(probe.accepted for probe in versions.results.values())
    if _tls12_really_missing(ctx, endpoint, versions):
        accepted = ", ".join(suites.version_name(v) for v in versions.legacy_accepted())
        probe = versions.results[TLS12]
        ctx.report(
            NO_TLS12,
            asset=endpoint.asset,
            evidence=f"Aceita só {accepted}. Na sonda de TLS 1.2: {probe.detail}.",
            details={"aceitas": accepted},
            confidence=Confidence.CONFIRMED,
            tech=tech_hint(ctx, endpoint.host),
        )
    if accepted_any and versions.refused(TLS13):
        ctx.report(
            NO_TLS13,
            asset=endpoint.asset,
            evidence=f"Na sonda de TLS 1.3: {versions.results[TLS13].detail}.",
            confidence=Confidence.CONFIRMED,
            tech=tech_hint(ctx, endpoint.host),
        )
    if versions.accepted(TLS13):
        ctx.passed("tls.protocolos.tls13", "TLS 1.3 disponível", endpoint.asset)


def _audit_only_modern(ctx: CheckContext, endpoint: Endpoint, versions: VersionMap) -> None:
    """Ponto forte só com TLS 1.2/1.3 aceitos e as versões antigas recusadas de fato."""
    modern = [v for v in (TLS13, TLS12) if versions.accepted(v)]
    if not modern or versions.legacy_accepted():
        return
    pending = [v for v in _MUST_BE_REFUSED if not versions.refused(v)]
    if pending:
        names = ", ".join(suites.version_name(v) for v in pending)
        ctx.log(f"{endpoint.asset}: sem resposta conclusiva para {names}.")
        return
    labels = " e ".join(suites.version_name(v) for v in sorted(modern))
    ctx.passed(
        "tls.protocolos.modernos",
        f"Só versões modernas aceitas ({labels}); SSLv3, TLS 1.0 e TLS 1.1 recusados",
        endpoint.asset,
    )


@check(
    id="tls.protocols",
    name="Versões do TLS",
    category=Category.TLS,
    consumes=facts.TLS_SERVICE,
    description=(
        "Descobre com handshakes comuns quais versões o servidor aceita: SSLv2, SSLv3, "
        "TLS 1.0 e 1.1 são obsoletas; TLS 1.2 e 1.3 são as recomendadas."
    ),
    findings=kb_protocolos.FINDINGS,
    profiles=STANDARD_UP,
    order=30,
)
def check_protocols(ctx: CheckContext, fact: Fact) -> None:
    endpoint = endpoint_of(fact)
    if endpoint is None:
        ctx.log(f"Serviço TLS com dados incompletos: {fact.key}.")
        return
    versions = support.version_map(ctx, endpoint)
    if not versions.reachable:
        ctx.log(f"{endpoint.asset}: não foi possível conectar para testar as versões do TLS.")
        return
    if not any(probe.accepted for probe in versions.results.values()):
        ctx.log(f"{endpoint.asset}: nenhuma versão do TLS foi aceita; o serviço pode não ser TLS.")
        return
    _report_legacy(ctx, endpoint, versions)
    _audit_modern(ctx, endpoint, versions)
    _audit_only_modern(ctx, endpoint, versions)
