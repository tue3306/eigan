"""Resolvedor DNS aberto: o servidor faz consultas recursivas para qualquer um na Internet?

Uma única pergunta, a mesma de qualquer cliente DNS: o endereço IPv4 de
``example.com`` (domínio reservado para exemplos, RFC 2606), com o bit "recursão
desejada" (RD) ligado, por UDP e por TCP na porta 53. Resolvedor aberto = resposta
NOERROR com a flag RA (recursão disponível), sem AA (o servidor não é a autoridade
do nome) e com ao menos um endereço público na seção de resposta.

Só endereços da Internet são avaliados: na rede interna, responder recursão aos
clientes da organização é justamente o papel do resolvedor.

Redes que interceptam DNS (proxy transparente na saída) fariam QUALQUER endereço
parecer um resolvedor aberto. Antes de reportar, a mesma pergunta vai para um
endereço reservado para documentação (192.0.2.1, RFC 5737), que não existe na
Internet: se "ele" responder, quem respondeu foi um interceptador no caminho e
nada é afirmado.
"""

from __future__ import annotations

import ipaddress

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

from ...core import facts, netutil
from ...core.context import CheckContext
from ...core.models import Category, Confidence, Fact
from ...core.registry import check
from . import (
    common,
    kb_servicos,  # noqa: F401 — registra as entradas da base
)
from .common import io_timeout, service_asset

DNS_PORT = 53
#: nome que todo resolvedor recursivo consegue resolver (reservado pela IANA, RFC 2606)
PROBE_NAME = "example.com."
#: endereço de documentação (RFC 5737): ninguém responde nele, exceto um interceptador
CANARY_ADDRESS = "192.0.2.1"
#: espera pelo canário — normalmente ele não responde, então o tempo é curto
CANARY_TIMEOUT = 2.0


def ask(ip: str, port: int, *, tcp: bool, timeout: float) -> dns.message.Message | None:
    """Uma consulta recursiva (RD) pelo A de ``PROBE_NAME``. None sem resposta DNS válida."""
    query = dns.message.make_query(PROBE_NAME, dns.rdatatype.A)  # RD vem ligado por padrão
    try:
        if tcp:
            return dns.query.tcp(query, ip, timeout=timeout, port=port)
        return dns.query.udp(query, ip, timeout=timeout, port=port, ignore_unexpected=True)
    except (dns.exception.DNSException, OSError, EOFError, ValueError):
        return None


def recursion_answers(response: dns.message.Message | None) -> list[str]:
    """Endereços da resposta quando ela prova recursão aberta; vazio caso contrário."""
    if response is None or response.rcode() != dns.rcode.NOERROR:
        return []
    if not response.flags & dns.flags.RA or response.flags & dns.flags.AA:
        return []
    found: list[str] = []
    for rrset in response.answer:
        if rrset.rdtype != dns.rdatatype.A:
            continue
        for rdata in rrset:
            text = rdata.to_text()
            if _public(text) and text not in found:
                found.append(text)
    return found


def _public(address: str) -> bool:
    """Endereço roteável na Internet (descarta respostas falsas de portal cativo/sinkhole)."""
    try:
        return ipaddress.ip_address(address).is_global
    except ValueError:
        return False


def network_intercepts_dns(ctx: CheckContext) -> bool:
    """O caminho até a Internet responde DNS por qualquer endereço? (uma vez por auditoria)"""

    def probe() -> bool:
        response = ask(CANARY_ADDRESS, DNS_PORT, tcp=False, timeout=CANARY_TIMEOUT)
        return response is not None

    return ctx.memo("net.dns.interceptacao", probe)


def _internet_host(fact: Fact) -> bool:
    return common.on_internet(str(fact.data.get("host") or fact.key))


@check(
    id="net.dns",
    name="Resolvedor DNS aberto",
    category=Category.NETWORK,
    consumes=facts.HOST,
    when=_internet_host,
    description=(
        "Pergunta ao servidor, por UDP e TCP na porta 53, o endereço de example.com com recursão "
        "pedida e aponta resolvedores DNS que atendem qualquer endereço da Internet."
    ),
    findings=("net.dns.resolvedor_aberto",),
    order=20,
    timeout=60.0,
)
def check_open_resolver(ctx: CheckContext, fact: Fact) -> None:
    host = str(fact.data.get("host") or fact.key)
    ips = netutil.resolve(host)
    if not ips:
        return
    timeout = io_timeout(ctx)
    via: list[str] = []
    answers: list[str] = []
    for tcp in (False, True):
        ctx.check_cancel()
        found = recursion_answers(ask(ips[0], DNS_PORT, tcp=tcp, timeout=timeout))
        if found:
            via.append("TCP" if tcp else "UDP")
            answers = answers or found
    if not via:
        return
    ctx.check_cancel()
    if network_intercepts_dns(ctx):
        ctx.log(
            f"{host}: respondeu como resolvedor aberto, mas a rede deste computador intercepta "
            f"DNS (o endereço de teste {CANARY_ADDRESS} também respondeu); nada foi afirmado."
        )
        return
    ctx.report(
        "net.dns.resolvedor_aberto",
        asset=service_asset(host, DNS_PORT, "udp" if "UDP" in via else "tcp"),
        evidence=(
            f"Consulta recursiva por {PROBE_NAME.rstrip('.')} (A) respondida com recursão "
            f"disponível (RA) por {' e '.join(via)} na porta {DNS_PORT}: "
            f"{', '.join(answers[:4])} — {common.where(host)}."
        ),
        details={"protocolos": via},
        confidence=Confidence.FIRM,
        tech=["dns"],
    )
