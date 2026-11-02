"""SSH: protocolo, algoritmos do KEXINIT, Terrapin e regreSSHion.

Lê o banner e a lista de algoritmos que o servidor anuncia ANTES de qualquer
login (ver ``sshproto.py``) e compara com a política de algoritmos. Nenhuma
credencial é enviada e a troca de chaves não é iniciada: a conexão é encerrada
logo depois do KEXINIT. Versões muito antigas do OpenSSH são tratadas pela
checagem ``net.versions``, que recebe o mesmo banner pelo fato ``tech``.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

from ...core import facts, vulndb
from ...core.context import CheckContext
from ...core.models import Category, Confidence, Fact, Severity
from ...core.registry import check
from . import (
    kb_ssh,  # noqa: F401 — registra as entradas da base
    sshproto,
)
from .common import host_port, open_service, service_asset

CATEGORY_LABEL = {
    "kex": "troca de chaves",
    "hostkey": "chave do servidor",
    "cipher": "cifras",
    "mac": "integridade (MAC)",
}
TERRAPIN_CVE = "CVE-2023-48795"
REGRESSHION_CVE = "CVE-2024-6387"
REGRESSHION_CONFIDENCE = {
    sshproto.VULNERAVEL: Confidence.FIRM,
    sshproto.INDICIO: Confidence.TENTATIVE,
}


def _is_ssh(fact: Fact) -> bool:
    return fact.data.get("service") == "ssh"


@check(
    id="net.ssh",
    name="Segurança do SSH",
    category=Category.NETWORK,
    consumes=facts.SERVICE,
    when=_is_ssh,
    description=(
        "Lê o banner e os algoritmos que o servidor SSH anuncia antes do login e aponta protocolo "
        "SSH-1, algoritmos fracos ou obsoletos, a exposição ao Terrapin (CVE-2023-48795), versões "
        "afetadas pelo regreSSHion (CVE-2024-6387) e a falta de troca de chaves pós-quântica."
    ),
    findings=(
        "net.ssh.protocolo_v1",
        "net.ssh.algoritmos_fracos",
        "net.ssh.algoritmos_obsoletos",
        "net.ssh.terrapin",
        "net.ssh.regresshion",
        "net.ssh.sem_pos_quantico",
    ),
    order=30,
)
def check_ssh(ctx: CheckContext, fact: Fact) -> None:
    host, port = host_port(fact)
    conn = open_service(ctx, host, port, tls=bool(fact.data.get("tls")))
    if conn is None:
        ctx.log(f"SSH em {host}:{port} não aceitou a conexão para a leitura dos algoritmos.")
        return
    with conn:
        line, kex = sshproto.fetch(conn)
    banner = sshproto.parse_banner(line) if line else None
    if banner is None:
        ctx.log(f"{host}:{port} não enviou uma identificação SSH válida.")
        return
    asset = service_asset(host, port)
    tech = _techs(line)
    _check_protocol(ctx, asset, banner, tech)
    _check_regresshion(ctx, asset, banner, tech)
    if kex is None or not kex.get("kex"):
        ctx.log(f"{host}:{port}: não foi possível ler o KEXINIT do servidor SSH.")
        return
    _check_algorithms(ctx, asset, line, kex, tech)
    _check_terrapin(ctx, asset, line, kex, tech)
    _check_post_quantum(ctx, asset, line, kex, tech)


def _techs(banner: str) -> list[str]:
    lowered = banner.lower()
    tech = ["openssh"] if "openssh" in lowered else []
    if "for_windows" in lowered:
        tech.append("windows")
    elif re.search(r"ubuntu|debian|raspbian", lowered):
        tech.append("linux")
    elif re.search(r"freebsd|openbsd|netbsd", lowered):
        tech.append("bsd")
    return tech


def _cve_report(cve: str) -> tuple[list[str], bool, Severity | None]:
    """CVEs, marca do catálogo KEV e severidade: CVE no KEV sempre vira crítica."""
    cves = [cve]
    kev = vulndb.any_kev(cves)
    return cves, kev, Severity.CRITICAL if kev else None


def _check_protocol(
    ctx: CheckContext, asset: str, banner: sshproto.Banner, tech: list[str]
) -> None:
    version = banner.protocol
    if version.startswith("1"):
        detail = "aceita SSH-1 e SSH-2" if version == "1.99" else "fala apenas SSH-1"
        ctx.report(
            "net.ssh.protocolo_v1",
            asset=asset,
            evidence=f"Banner do servidor: {banner.raw} (protocolo {version}: {detail}).",
            details={"protocolo": version},
            confidence=Confidence.CONFIRMED,
            tech=tech,
        )
    elif version == "2.0":
        ctx.passed("net.ssh.protocolo", "Servidor SSH fala somente o protocolo SSH-2", asset)


def _check_regresshion(
    ctx: CheckContext, asset: str, banner: sshproto.Banner, tech: list[str]
) -> None:
    verdict = sshproto.regresshion(banner)
    if verdict is None:
        return  # não é OpenSSH: a falha é específica dele
    confidence = REGRESSHION_CONFIDENCE.get(verdict.status)
    if confidence is None:
        ctx.passed("net.ssh.regresshion", f"OpenSSH sem o regreSSHion: {verdict.reason}", asset)
        return
    cves, kev, severity = _cve_report(REGRESSHION_CVE)
    if severity is None and verdict.status == sshproto.INDICIO:
        severity = Severity.MEDIUM  # inconclusivo: pede conferência, não é exposição comprovada
    ctx.report(
        "net.ssh.regresshion",
        asset=asset,
        severity=severity,
        evidence=f"Banner: {banner.raw}\n{verdict.reason}.",
        details={"versao": verdict.version, "situacao": verdict.status, "motivo": verdict.reason},
        confidence=confidence,
        cves=cves,
        kev=kev,
        tech=tech,
    )


def _describe(found: Mapping[str, Mapping[str, str]]) -> str:
    lines = []
    for category, items in found.items():
        names = ", ".join(f"{name} ({reason})" for name, reason in items.items())
        lines.append(f"{CATEGORY_LABEL.get(category, category)}: {names}")
    return "\n".join(lines)


def _check_algorithms(
    ctx: CheckContext, asset: str, banner: str, kex: sshproto.KexInit, tech: list[str]
) -> None:
    result = sshproto.assess(kex)
    weak = result.level(sshproto.FRACO)
    legacy = result.level(sshproto.OBSOLETO)
    if weak:
        ctx.report(
            "net.ssh.algoritmos_fracos",
            asset=asset,
            severity=Severity.HIGH if result.critical else None,
            evidence=f"{banner}\nAlgoritmos fracos anunciados:\n{_describe(weak)}",
            details={"fracos": weak, "graves": [name for _, name in result.critical]},
            confidence=Confidence.CONFIRMED,
            tech=tech,
        )
    if legacy:
        ctx.report(
            "net.ssh.algoritmos_obsoletos",
            asset=asset,
            evidence=f"{banner}\nAlgoritmos obsoletos anunciados:\n{_describe(legacy)}",
            details={"obsoletos": legacy},
            confidence=Confidence.CONFIRMED,
            tech=tech,
        )
    if not weak and not legacy:
        ctx.passed("net.ssh.algoritmos", "SSH anuncia apenas algoritmos modernos", asset)


def _check_terrapin(
    ctx: CheckContext, asset: str, banner: str, kex: sshproto.KexInit, tech: list[str]
) -> None:
    vulnerable, reason = sshproto.terrapin(kex)
    if vulnerable:
        cves, is_kev, severity = _cve_report(TERRAPIN_CVE)
        ctx.report(
            "net.ssh.terrapin",
            asset=asset,
            severity=severity,
            evidence=(
                f"{banner}: {reason}. O EIGAN vê só o lado do servidor; a proteção completa "
                "também depende de o cliente suportar o strict KEX."
            ),
            details={"motivo": reason},
            confidence=Confidence.FIRM,
            cves=cves,
            kev=is_kev,
            tech=tech,
        )
    elif kex.strict_kex:
        ctx.passed("net.ssh.terrapin", "SSH com 'strict KEX' (protegido contra o Terrapin)", asset)
    else:
        ctx.passed("net.ssh.terrapin", "SSH sem as cifras afetadas pelo Terrapin", asset)


def _check_post_quantum(
    ctx: CheckContext, asset: str, banner: str, kex: sshproto.KexInit, tech: list[str]
) -> None:
    hybrid = kex.post_quantum
    if hybrid:
        ctx.passed(
            "net.ssh.pos_quantico",
            f"SSH oferece troca de chaves híbrida pós-quântica ({hybrid[0]})",
            asset,
        )
        return
    ctx.report(
        "net.ssh.sem_pos_quantico",
        asset=asset,
        evidence=f"{banner}: nenhuma troca de chaves híbrida pós-quântica (sntrup, mlkem) anunciada.",
        details={"kex": kex.get("kex")[:24]},
        confidence=Confidence.CONFIRMED,
        tech=tech,
    )
