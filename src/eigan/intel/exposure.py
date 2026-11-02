"""Exposição de cada achado: Internet, rede interna, máquina local, código ou logs."""

from __future__ import annotations

from ..core import netutil
from ..core.models import Exposure, ScanResult, TargetKind
from .correlation import asset_host

_BY_KIND = {
    TargetKind.LOCAL: Exposure.LOCAL,
    TargetKind.PROJECT: Exposure.CODE,
    TargetKind.LOGS: Exposure.LOGS,
}


def assign(result: ScanResult) -> None:
    """Define ``finding.exposure`` pelo tipo de alvo ou pelo endereço do ativo."""
    fixed = _BY_KIND.get(result.kind)
    cache: dict[str, Exposure] = {}
    for finding in result.findings:
        if fixed is not None:
            finding.exposure = fixed
            continue
        host = asset_host(finding.asset)
        if host not in cache:
            try:
                cache[host] = netutil.host_exposure(host) if host else Exposure.INTERNET
            except Exception:  # noqa: BLE001 — classificação nunca derruba a auditoria
                cache[host] = Exposure.INTERNET
        finding.exposure = cache[host]
