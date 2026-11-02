"""Contrato dos tipos de fato (o vocabulário do motor de regras).

Toda checagem que produz ou consome um fato usa estes nomes e formatos — é o que
permite encadear checagens escritas de forma independente.

=================  ======================  ==============================================
tipo               chave                   dados
=================  ======================  ==============================================
http.service       URL base                url, host, port, scheme
tls.service        host:porta              host, port, sni
dns.domain         domínio                 domain
dns.records        domínio                 a, aaaa, mx, ns, txt, caa, cname (listas)
host               host ou IP              host
network            faixa CIDR              network
port.open          host:porta/tcp          host, port
service            host:porta              host, port, service, product, version, banner, tls
tech               host:nome               host, name, version, kind, evidence
tls.cert           host:porta              subject, issuer, not_before, not_after, san, ...
local              plataforma              platform (windows | linux | darwin)
host.info          plataforma              os, version, build, hostname, ...
project            caminho                 path
code.manifest      caminho do arquivo      path, ecosystem, kind
code.inventory     caminho do projeto      files, languages, manifests
logs.source        caminho                 path
=================  ======================  ==============================================
"""

from __future__ import annotations

from urllib.parse import urlsplit

HTTP_SERVICE = "http.service"
TLS_SERVICE = "tls.service"
DNS_DOMAIN = "dns.domain"
DNS_RECORDS = "dns.records"
HOST = "host"
NETWORK = "network"
PORT_OPEN = "port.open"
SERVICE = "service"
TECH = "tech"
TLS_CERT = "tls.cert"
LOCAL = "local"
HOST_INFO = "host.info"
PROJECT = "project"
CODE_MANIFEST = "code.manifest"
CODE_INVENTORY = "code.inventory"
LOGS_SOURCE = "logs.source"

#: tipos de tecnologia aceitos em ``tech.kind``
TECH_KINDS = ("server", "language", "framework", "cms", "cdn", "waf", "js-lib", "os", "service")


def base_url(scheme: str, host: str, port: int | None) -> str:
    """URL base normalizada: ``https://host/`` (porta só se não for a padrão)."""
    scheme = scheme.lower()
    netloc = f"[{host}]" if ":" in host else host
    default = 443 if scheme == "https" else 80
    if port and port != default:
        netloc = f"{netloc}:{port}"
    return f"{scheme}://{netloc}/"


def origin_of(url: str) -> str:
    parts = urlsplit(url)
    return base_url(parts.scheme or "https", parts.hostname or "", parts.port)
