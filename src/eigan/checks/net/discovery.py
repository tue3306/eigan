"""Descoberta de hosts ativos numa faixa de rede (CIDR) por conexão TCP.

Para cada endereço da faixa (até ``max_network_hosts``), tenta poucas portas
muito comuns. Um host que aceita a conexão ou a RECUSA (responde com RST) está
ativo — a recusa também prova que existe alguém naquele endereço. Hosts
encontrados viram fatos ``host``, que disparam a varredura de portas.
"""

from __future__ import annotations

import ipaddress
import itertools
import socket
import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor

from ...core import facts
from ...core.context import CheckContext
from ...core.models import Category, Fact
from ...core.registry import check
from .common import connect_timeout, port_gate
from .ports import DISCOVERY_PORTS

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def knock(ip: str, port: int, timeout: float) -> str | None:
    """``"aberta"``, ``"recusada"`` (o host respondeu com RST) ou None (sem resposta)."""
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except ConnectionRefusedError:
        return "recusada"
    except (OSError, ValueError):
        return None
    try:
        sock.close()
    except OSError:
        pass
    return "aberta"


#: a partir de tantos endereços testados e desta fração de recusas, o RST não prova nada
RESET_MIN_HOSTS = 8
RESET_RATIO = 0.9


def drop_reset_everywhere(
    ctx: CheckContext, found: dict[str, tuple[int, str]], tested: int
) -> dict[str, tuple[int, str]]:
    """Gateway/firewall que responde RST por toda a faixa: descarta os 'recusada'."""
    refused = [ip for ip, (_port, state) in found.items() if state == "recusada"]
    if tested < RESET_MIN_HOSTS or len(refused) < RESET_RATIO * tested:
        return found
    ctx.log(
        f"{len(refused)} de {tested} endereços recusaram a conexão: parece um firewall ou "
        "gateway que responde por toda a faixa. Só os hosts com porta aberta serão considerados."
    )
    return {ip: item for ip, item in found.items() if ip not in refused}


def addresses(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> Iterator[IPAddress]:
    """Endereços utilizáveis da faixa (sem rede/broadcast; /31, /32 e /128 inteiros)."""
    if network.num_addresses <= 2:
        return iter(network)
    return network.hosts()


@check(
    id="net.discovery",
    name="Descoberta de hosts na faixa",
    category=Category.NETWORK,
    consumes=facts.NETWORK,
    description=(
        "Procura endereços ativos na faixa informada, tentando conexão TCP nas portas "
        "22, 80, 443, 445, 3389 e 8080."
    ),
    facts=(facts.HOST,),
    order=5,
    timeout=900.0,
)
def check_discovery(ctx: CheckContext, fact: Fact) -> None:
    try:
        network = ipaddress.ip_network(str(fact.data.get("network") or fact.key), strict=False)
    except ValueError:
        ctx.log(f"Faixa de rede inválida: {fact.key}")
        return
    limit = max(1, int(ctx.settings.max_network_hosts))
    hosts = [str(ip) for ip in itertools.islice(addresses(network), limit)]
    if network.num_addresses > len(hosts) + 2:
        ctx.log(f"{network}: testando os primeiros {len(hosts)} endereços (limite configurado).")
    found = _sweep(ctx, hosts)
    found = drop_reset_everywhere(ctx, found, len(hosts))
    for ip in sorted(found, key=ipaddress.ip_address):
        port, state = found[ip]
        how = "respondeu" if state == "aberta" else "recusou a conexão (o host existe)"
        ctx.add_fact(facts.HOST, ip, f"{ip} {how} na porta {port}", host=ip)
    ctx.log(f"Descoberta em {network}: {len(found)} de {len(hosts)} endereço(s) ativo(s).")


def _sweep(ctx: CheckContext, hosts: list[str]) -> dict[str, tuple[int, str]]:
    """Testa as portas de descoberta em paralelo; para cada IP guarda a primeira resposta."""
    found: dict[str, tuple[int, str]] = {}
    lock = threading.Lock()
    gate = port_gate(ctx)
    timeout = connect_timeout(ctx)

    def task(ip: str, port: int) -> None:
        if ctx.cancelled:
            return
        with lock:
            if ip in found:
                return
        with gate:
            state = knock(ip, port, timeout)
        if state is not None:
            with lock:
                found.setdefault(ip, (port, state))

    pairs = [(ip, port) for port in DISCOVERY_PORTS for ip in hosts]
    workers = max(1, min(len(pairs), int(ctx.settings.port_workers)))
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="eigan-descoberta") as pool:
        for _ in pool.map(lambda pair: task(*pair), pairs):
            ctx.check_cancel()
    return found
