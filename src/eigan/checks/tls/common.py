"""Apoio comum às checagens de TLS: o serviço do fato, o ativo, prazos e exposição."""

from __future__ import annotations

from dataclasses import dataclass

from ...core import netutil
from ...core.context import CheckContext
from ...core.models import Exposure, Fact, Severity
from ...core.target import is_ip

#: tecnologias citadas nos exemplos de correção (casam com ``Fix.tech``)
FIX_TECHS = frozenset({"nginx", "apache", "iis", "tomcat", "express"})


@dataclass(frozen=True)
class Endpoint:
    """Um serviço TLS a auditar (vem do fato ``tls.service``)."""

    host: str
    port: int
    sni: str | None
    service: str = ""
    private_pki: bool = False

    @property
    def asset(self) -> str:
        return tls_asset(self.host, self.port)

    @property
    def key(self) -> str:
        """Chave dos fatos ``tls.service``/``tls.cert`` (``host:porta``)."""
        return f"{self.host}:{self.port}"

    @property
    def reference(self) -> str:
        """Nome que o cliente espera ver no certificado (SNI ou o próprio host)."""
        return self.sni or self.host.strip("[]")

    @property
    def by_ip(self) -> bool:
        return self.sni is None and is_ip(self.host)


def endpoint_of(fact: Fact) -> Endpoint | None:
    """Host, porta e SNI de um fato ``tls.service`` (None se o fato estiver incompleto)."""
    host = str(fact.data.get("host") or fact.key.rsplit(":", 1)[0]).strip()
    try:
        port = int(fact.data.get("port") or fact.key.rsplit(":", 1)[1])
    except (IndexError, TypeError, ValueError):
        return None
    if not host or not 0 < port < 65536:
        return None
    raw_sni = fact.data.get("sni")
    if raw_sni is None and "sni" not in fact.data:
        raw_sni = None if is_ip(host) else host
    sni = str(raw_sni).strip().rstrip(".") if raw_sni else None
    if sni and is_ip(sni):
        sni = None  # a RFC 6066 proíbe endereço IP no SNI
    return Endpoint(
        host=host.strip("[]"),
        port=port,
        sni=sni or None,
        service=str(fact.data.get("service") or ""),
        private_pki=bool(fact.data.get("private_pki")),
    )


def tls_asset(host: str, port: int) -> str:
    """Ativo no formato ``host:porta`` (IPv6 entre colchetes)."""
    netloc = f"[{host}]" if ":" in host else host
    return f"{netloc}:{port}"


def io_timeout(ctx: CheckContext) -> float:
    """Prazo de cada conexão/handshake: o tempo HTTP configurado, entre 2 e 6 segundos."""
    return max(2.0, min(float(ctx.settings.http_timeout), 6.0))


def exposure_of(host: str) -> Exposure:
    return netutil.host_exposure(host)


def severity_by_exposure(host: str, internet: Severity, other: Severity) -> Severity:
    """Mais grave na Internet, onde qualquer pessoa no caminho pode explorar."""
    return internet if exposure_of(host) is Exposure.INTERNET else other


def tech_hint(ctx: CheckContext, host: str) -> list[str]:
    """Tecnologias já vistas no host que têm exemplo de correção (escolhem o trecho mostrado)."""
    return [name for name in ctx.techs(host) if name in FIX_TECHS]


def plural(count: int, singular: str, many: str) -> str:
    return f"{count} {singular if count == 1 else many}"
