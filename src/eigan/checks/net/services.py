"""Identificação dos serviços nas portas abertas (``port.open`` → ``service``).

Para cada porta aberta, descobre o protocolo (banner, sondas, TLS e HTTP — ver
``identify.py``) e ensina ao motor:

* um fato ``service`` (``host:porta``) com serviço, produto, versão e banner —
  é ele que dispara as checagens específicas (SSH, bancos, RDP, SMB...);
* ``http.service`` quando a porta fala HTTP/HTTPS, para as checagens web;
* ``tls.service`` quando há TLS, para as checagens de certificado e protocolos;
* fatos ``tech`` (produto e versão) para a checagem de versões vulneráveis.
"""

from __future__ import annotations

import threading
from typing import Any

from ...core import facts
from ...core.context import CheckContext
from ...core.models import Category, Fact
from ...core.registry import check
from ...core.target import is_ip
from .banners import Identified
from .identify import identify, service_url

#: serviços que são "um site" (recebem as checagens web)
WEB_SERVICES = frozenset({"http", "https"})
#: produtos que são servidores web/aplicação (tipo ``server`` no inventário)
SERVER_PRODUCTS = frozenset({"apache", "nginx", "iis", "tomcat", "jetty", "lighttpd", "openresty"})
#: serviços cujo certificado costuma vir de uma CA privada (cluster, daemon)
PRIVATE_PKI = frozenset({"docker", "kubernetes", "kubelet", "etcd"})


@check(
    id="net.services",
    name="Identificação de serviços",
    category=Category.NETWORK,
    consumes=facts.PORT_OPEN,
    description=(
        "Descobre qual serviço responde em cada porta aberta (banner, handshake do protocolo, "
        "TLS e HTTP) e registra produto e versão para as próximas verificações."
    ),
    facts=(facts.SERVICE, facts.HTTP_SERVICE, facts.TLS_SERVICE, facts.TECH),
    order=15,
    timeout=120.0,
)
def check_services(ctx: CheckContext, fact: Fact) -> None:
    host = str(fact.data.get("host") or fact.key.rsplit(":", 1)[0])
    port = int(fact.data.get("port") or 0)
    if not host or not port:
        return
    found = identify(ctx, host, port)
    if fact.data.get("aceita_tudo") and not found.confirmed:
        # host que aceita conexão em qualquer porta: sem resposta do protocolo, nada se afirma
        ctx.log(f"{host}:{port}: nenhum protocolo respondeu (o host aceita qualquer conexão).")
        return
    register_service(ctx, host, port, found)


def register_service(ctx: CheckContext, host: str, port: int, found: Identified) -> Fact | None:
    """Transforma a identificação em fatos (serviço, HTTP, TLS e tecnologias)."""
    label = describe(found)
    how = "confirmado pelo protocolo" if found.confirmed else "suposto pela porta"
    service = ctx.add_fact(
        facts.SERVICE,
        f"{host}:{port}",
        f"Porta {port}/tcp de {host}: {label} ({how})",
        host=host,
        port=port,
        service=found.service,
        product=found.product,
        version=found.version,
        banner=found.banner,
        tls=found.tls,
        confirmed=found.confirmed,
        extra=dict(found.extra),
        label=f"{host}:{port} — {label}",
    )
    if found.service in WEB_SERVICES:
        url = service_url(host, port, found.tls)
        ctx.add_http_service(
            url, reason=f"A porta {port}/tcp de {host} fala {found.service.upper()}"
        )
    elif found.tls and found.confirmed:
        ctx.add_fact(
            facts.TLS_SERVICE,
            f"{host}:{port}",
            f"A porta {port}/tcp de {host} usa TLS ({found.service})",
            host=host,
            port=port,
            sni=None if is_ip(host) else host,
            service=found.service,
            private_pki=found.service in PRIVATE_PKI,
        )
    _register_techs(ctx, host, port, found)
    return service


def describe(found: Identified) -> str:
    """Texto curto: ``ssh (openssh 9.6p1)``, ``https``, ``mysql (mariadb 10.6.12)``."""
    parts = [found.product, found.version]
    detail = " ".join(p for p in parts if p)
    text = found.service + (f" ({detail})" if detail and detail != found.service else "")
    return text + (" sobre TLS" if found.tls and found.service not in ("https", "tls") else "")


def _register_techs(ctx: CheckContext, host: str, port: int, found: Identified) -> None:
    if found.product and found.confirmed:
        kind = "server" if found.product in SERVER_PRODUCTS else "service"
        add_tech(ctx, host, port, found.product, found.version, kind, found.banner or found.service)
    for tech in found.extra.get("techs", []) or []:
        if isinstance(tech, dict) and tech.get("name"):
            add_tech(
                ctx,
                host,
                port,
                str(tech["name"]),
                str(tech.get("version") or ""),
                str(tech.get("kind") or "server"),
                str(tech.get("evidence") or ""),
            )


_TECH_LOCK = threading.Lock()


def _tech_key(ctx: CheckContext, host: str, name: str, port: int) -> str:
    """Chave padrão ``host:produto``; outra porta com o mesmo produto ganha chave própria.

    Sem isso, uma instância antiga numa porta secundária seria descartada quando a
    primeira instância (mais nova) já estivesse registrada.
    """
    key = f"{host}:{name}"
    for fact in ctx.facts(facts.TECH):
        if fact.key == key and fact.data.get("port") not in (None, port):
            return f"{key}:{port}"
    return key


def add_tech(
    ctx: CheckContext, host: str, port: int, name: str, version: str, kind: str, evidence: str
) -> Fact | None:
    """Como ``ctx.add_tech``, mas guardando também a porta (o ativo dos achados de versão)."""
    clean = name.strip().lower()
    label = f"{clean} {version}" if version else clean
    data: dict[str, Any] = {
        "host": host,
        "name": clean,
        "version": version or None,
        "kind": kind,
        "evidence": evidence[:300],
        "port": port,
        "label": label,
    }
    summary = f"Tecnologia identificada em {host}:{port}: {label}"
    with _TECH_LOCK:
        key = _tech_key(ctx, host, clean, port)
        fact = ctx.add_fact(facts.TECH, key, summary, **data)
    if fact is not None and version and not fact.data.get("version"):
        fact.data["version"] = version
    return fact
