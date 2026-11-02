"""Suítes de cifra: o servidor aceita alguma fraca? Oferece sigilo futuro?

Cada sonda é um ClientHello que oferece SÓ as suítes de uma família. Se o servidor escolher
uma, ela é registrada e retirada da lista, e a sonda se repete até ele recusar ou até o limite
do perfil. A troca de chaves é conferida do mesmo jeito: primeiro só com ECDHE/DHE; se
recusar, só com RSA. Nada além do ServerHello é lido e o handshake nunca é concluído.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ...core import facts, vulndb
from ...core.context import CheckContext
from ...core.models import Category, Confidence, Fact
from ...core.registry import STANDARD_UP, check
from . import kb_cifras, suites, support
from .common import Endpoint, endpoint_of, io_timeout, tech_hint
from .kb_cifras import BROKEN, INSECURE, NO_FORWARD_SECRECY, TRIPLE_DES
from .suites import TLS12, TLS13
from .support import Probe, VersionMap

#: por família e versão: quantas suítes aceitas basta nomear
_NAMED_STANDARD = 3
_NAMED_DEEP = 16
#: limite de conexões por auditoria de um serviço
_PROBES_STANDARD = 30
_PROBES_DEEP = 90
#: sondas seguidas sem resposta: o servidor (ou um firewall) parou de atender; melhor parar
_MAX_SILENT = 3

_WEAK_GROUPS: tuple[tuple[str, Callable[[], tuple[int, ...]]], ...] = (
    (INSECURE, suites.insecure_suites),
    (BROKEN, suites.broken_suites),
    (TRIPLE_DES, suites.triple_des_suites),
)


@dataclass
class _Budget:
    """Conta as conexões e interrompe quando o servidor para de responder."""

    left: int
    silent: int = 0
    closed: int = 0  # recusas sem alerta: só valem se uma sonda de controle ainda passar

    @property
    def exhausted(self) -> bool:
        return self.left <= 0 or self.silent >= _MAX_SILENT

    def note(self, probe: Probe) -> None:
        self.left -= 1
        self.silent = 0 if probe.accepted or probe.refused else self.silent + 1
        self.closed = self.closed + 1 if probe.closed else self.closed


@dataclass(frozen=True)
class _Session:
    """O que toda sonda de um serviço precisa."""

    ctx: CheckContext
    endpoint: Endpoint
    timeout: float
    budget: _Budget
    named: int

    def probe(self, version: int, offered: tuple[int, ...] | list[int]) -> Probe:
        self.ctx.check_cancel()
        probe = support.raw_probe(self.endpoint, version, offered, self.timeout)
        self.budget.note(probe)
        return probe


def _accepted_suites(
    session: _Session, version: int, offered: tuple[int, ...]
) -> tuple[list[int], bool]:
    """Suítes aceitas em ``version``, retirando cada uma até o servidor recusar.

    Devolve as suítes e se a resposta foi conclusiva (recusa explícita ou limite atingido).
    """
    remaining = list(offered)
    found: list[int] = []
    while remaining and len(found) < session.named:
        if session.budget.exhausted:
            return found, False
        probe = session.probe(version, remaining)
        if not probe.accepted or probe.suite is None:
            return found, probe.refused
        found.append(probe.suite)
        remaining.remove(probe.suite)
    return found, True


def _cves_of(codes: list[int]) -> list[str]:
    """CVEs que dependem da suíte aceita (RC4, SWEET32 e Logjam)."""
    families = {family for code in codes for family in suites.families(code)}
    cves: list[str] = []
    if "rc4" in families:
        cves += ["CVE-2013-2566", "CVE-2015-2808"]
    if "3des" in families:
        cves.append("CVE-2016-2183")
    if any(suites.is_dhe_export(code) for code in codes):
        cves.append("CVE-2015-4000")
    return cves


def _report_weak(session: _Session, finding: str, found: dict[int, list[int]]) -> None:
    named = {
        suites.version_name(version): [suites.name(code) for code in codes]
        for version, codes in found.items()
    }
    codes = [code for group in found.values() for code in group]
    families = sorted({family for code in codes for family in suites.families(code)})
    cves = _cves_of(codes)
    evidence = "; ".join(f"{version}: {', '.join(names)}" for version, names in named.items())
    session.ctx.report(
        finding,
        asset=session.endpoint.asset,
        evidence=f"O servidor aceitou: {evidence}.",
        details={
            "suites": named,
            "familias": [suites.FAMILY_LABEL[family] for family in families],
        },
        confidence=Confidence.CONFIRMED,
        cves=cves,
        kev=vulndb.any_kev(cves),
        tech=tech_hint(session.ctx, session.endpoint.host),
    )


def _control_ok(session: _Session, version: int) -> bool:
    """Depois de recusas sem alerta: o servidor ainda atende uma oferta normal?"""
    if not session.budget.closed:
        return True
    session.ctx.check_cancel()
    offered = suites.forward_secret_suites() + suites.rsa_suites()
    control = support.raw_probe(session.endpoint, version, offered, session.timeout)
    return control.accepted


def _audit_weak(session: _Session, classic: list[int]) -> None:
    all_clear = True
    reported = False
    for finding, offered in _WEAK_GROUPS:
        found: dict[int, list[int]] = {}
        for version in classic:
            if found and not session.ctx.settings.deep:
                break  # já está provado; o perfil completo lista também as versões seguintes
            codes, conclusive = _accepted_suites(session, version, offered())
            all_clear = all_clear and conclusive
            if codes:
                found[version] = codes
        if found:
            all_clear = False
            reported = True
            _report_weak(session, finding, found)
    if all_clear and not _control_ok(session, classic[0]):
        all_clear = False
    if all_clear:
        session.ctx.passed(
            "tls.cifras.fortes",
            "Nenhuma cifra NULL, anônima, EXPORT, RC4, DES, RC2, IDEA ou 3DES foi aceita",
            session.endpoint.asset,
        )
    elif not reported:
        session.ctx.log(
            f"{session.endpoint.asset}: a varredura de cifras fracas não foi conclusiva."
        )


def _audit_forward_secrecy(session: _Session, version: int, versions: VersionMap) -> None:
    """Sem ECDHE/DHE e com RSA aceito na versão clássica mais nova: não há sigilo futuro."""
    asset = session.endpoint.asset
    name = suites.version_name(version)
    if session.budget.exhausted:
        session.ctx.log(f"{asset}: limite de sondas atingido; troca de chaves não avaliada.")
        return
    ephemeral = session.probe(version, suites.forward_secret_suites())
    if ephemeral.accepted:
        session.ctx.passed("tls.cifras.sigilo_futuro", f"Sigilo futuro disponível em {name}", asset)
        return
    if not ephemeral.refused:
        session.ctx.log(f"{asset}: troca de chaves não avaliada ({ephemeral.detail}).")
        return
    rsa = session.probe(version, suites.rsa_suites())
    if not rsa.accepted or rsa.suite is None:
        session.ctx.log(f"{asset}: não aceitou ECDHE/DHE nem RSA em {name}; sem conclusão.")
        return
    # Confirma: uma recusa isolada (conexão derrubada, limite de taxa) não pode virar achado.
    if not session.probe(version, suites.forward_secret_suites()).refused:
        session.ctx.log(f"{asset}: respostas inconsistentes sobre ECDHE/DHE em {name}.")
        return
    extra = (
        " O TLS 1.3 tem sigilo futuro, mas os clientes em TLS 1.2 não."
        if versions.accepted(TLS13)
        else ""
    )
    session.ctx.report(
        NO_FORWARD_SECRECY,
        asset=asset,
        evidence=(
            f"Em {name}, o servidor recusou todas as suítes ECDHE e DHE ({ephemeral.detail}) e "
            f"aceitou {suites.name(rsa.suite)}.{extra}"
        ),
        details={"versao": name, "suite_rsa": suites.name(rsa.suite)},
        confidence=Confidence.CONFIRMED,
        tech=tech_hint(session.ctx, session.endpoint.host),
    )


@check(
    id="tls.ciphers",
    name="Suítes de cifra do TLS",
    category=Category.TLS,
    consumes=facts.TLS_SERVICE,
    description=(
        "Oferece só suítes fracas (NULL, anônimas, EXPORT, RC4, DES, 3DES) para ver se o "
        "servidor aceita e confere se a troca de chaves tem sigilo futuro."
    ),
    findings=kb_cifras.FINDINGS,
    profiles=STANDARD_UP,
    order=40,
)
def check_ciphers(ctx: CheckContext, fact: Fact) -> None:
    endpoint = endpoint_of(fact)
    if endpoint is None:
        ctx.log(f"Serviço TLS com dados incompletos: {fact.key}.")
        return
    versions = support.version_map(ctx, endpoint)
    if not versions.reachable:
        ctx.log(f"{endpoint.asset}: não foi possível conectar para testar as cifras.")
        return
    classic = versions.cipher_versions()
    if not classic:
        if versions.accepted(TLS13) and versions.refused(TLS12):
            text = "Só TLS 1.3: todas as suítes têm cifra moderna e sigilo futuro"
            ctx.passed("tls.cifras.fortes", text, endpoint.asset)
            ctx.passed("tls.cifras.sigilo_futuro", text, endpoint.asset)
        elif versions.accepted(TLS13):
            ctx.log(f"{endpoint.asset}: TLS 1.2 inconclusivo; cifras clássicas não avaliadas.")
        else:
            ctx.log(f"{endpoint.asset}: nenhuma versão aceita para testar as cifras.")
        return
    deep = ctx.settings.deep
    session = _Session(
        ctx,
        endpoint,
        io_timeout(ctx),
        _Budget(_PROBES_DEEP if deep else _PROBES_STANDARD),
        _NAMED_DEEP if deep else _NAMED_STANDARD,
    )
    _audit_weak(session, classic)
    _audit_forward_secrecy(session, classic[0], versions)
