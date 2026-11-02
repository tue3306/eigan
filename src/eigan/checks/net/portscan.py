"""Varredura de portas TCP (conexão completa) com concorrência limitada.

As portas vêm do perfil (``top100``, ``top300``, ``todas`` ou lista explícita —
ver ``ports.py``). Cada porta aberta vira um fato ``port.open``, que dispara a
identificação do serviço. Só abre e fecha conexões: nada é enviado ao serviço.

Alguns firewalls, proxies e "tarpits" aceitam conexão em QUALQUER porta. Sem
cuidado, cada porta do catálogo viraria um "serviço aberto" falso. Quando quase
todas as portas testadas aceitam conexão, três portas altas sem serviço conhecido
servem de canário: se elas também aceitarem, o host é marcado como "aceita tudo"
e só os serviços confirmados pelo protocolo seguem adiante.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from ...core import facts, netutil
from ...core.context import CheckContext
from ...core.models import Category, Fact
from ...core.registry import check
from .common import connect_timeout, port_gate
from .ports import catalog, explicit_list_problems, ports_for, service_name

#: a suspeita de "aceita tudo" só vale com pelo menos tantas portas testadas...
ACCEPT_ALL_MIN_TESTED = 20
#: ...e quando esta fração delas (ou mais) aceitou conexão
ACCEPT_ALL_RATIO = 0.9
#: portas altas sem serviço conhecido (fora do catálogo): num host normal estão fechadas
CANARY_PORTS = (47321, 51873, 58219)
#: num host que aceita tudo, só as portas mais prioritárias do catálogo são identificadas
ACCEPT_ALL_KEEP = 40


def probe_port(ip: str, port: int, timeout: float) -> bool:
    """A porta aceita conexão TCP? (ponto único de rede, substituído nos testes)."""
    return netutil.port_open(ip, port, timeout)


@check(
    id="net.portscan",
    name="Varredura de portas TCP",
    category=Category.NETWORK,
    consumes=facts.HOST,
    description=(
        "Descobre as portas TCP abertas do servidor (perfil rápido: 100 portas; padrão: "
        "300; completo: lista inteira + 1-1024; ou a lista informada nas configurações)."
    ),
    facts=(facts.PORT_OPEN,),
    order=10,
    timeout=900.0,
)
def check_portscan(ctx: CheckContext, fact: Fact) -> None:
    host = str(fact.data.get("host") or fact.key)
    ips = netutil.resolve(host)
    if not ips:
        ctx.log(f"{host} não resolve para nenhum endereço; varredura de portas ignorada.")
        return
    if len(ips) > 1:
        ctx.log(
            f"{host} tem {len(ips)} endereços; a varredura de portas usa {ips[0]}. "
            "Serviços balanceados em outros endereços podem não aparecer."
        )
    profile = ctx.settings.ports_profile
    ports = ports_for(profile)
    note = explicit_list_problems(profile)
    if note:
        ctx.log(note)
    opened = scan(ctx, ips[0], ports)
    accept_all = accepts_everything(ctx, ips[0], len(ports), opened)
    if accept_all:
        kept = prioritize(opened)[:ACCEPT_ALL_KEEP]
        ctx.log(
            f"{host}: {len(opened)} de {len(ports)} portas aceitaram conexão, inclusive portas "
            "sem serviço nenhum — parece um firewall ou proxy que aceita qualquer conexão. "
            f"Só as {len(kept)} portas mais relevantes serão identificadas e apenas serviços "
            "confirmados pelo protocolo serão considerados."
        )
        opened = sorted(kept)
    for port in opened:
        name = service_name(port)
        label = f" ({name})" if name else ""
        ctx.add_fact(
            facts.PORT_OPEN,
            f"{host}:{port}/tcp",
            f"Porta {port}/tcp aberta em {host}{label}",
            host=host,
            port=port,
            hint=name,
            ip=ips[0],
            aceita_tudo=accept_all,
        )
    ctx.log(f"{host}: {len(opened)} porta(s) aberta(s) entre {len(ports)} testada(s) ({profile}).")


def scan(ctx: CheckContext, ip: str, ports: list[int]) -> list[int]:
    """Portas abertas de ``ip`` (conexão TCP completa), em ordem crescente."""
    if not ports:
        return []
    timeout = connect_timeout(ctx)
    gate = port_gate(ctx)

    def probe(port: int) -> int | None:
        if ctx.cancelled:
            return None
        with gate:
            return port if probe_port(ip, port, timeout) else None

    opened: list[int] = []
    workers = max(1, min(len(ports), int(ctx.settings.port_workers)))
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="eigan-portas") as pool:
        for result in pool.map(probe, ports):
            ctx.check_cancel()
            if result is not None:
                opened.append(result)
    return sorted(opened)


def accepts_everything(ctx: CheckContext, ip: str, tested: int, opened: list[int]) -> bool:
    """Quase tudo aberto E as portas-canário também abertas = o host aceita qualquer conexão."""
    if tested < ACCEPT_ALL_MIN_TESTED or len(opened) < ACCEPT_ALL_RATIO * tested:
        return False
    canaries = [port for port in CANARY_PORTS if port not in opened]
    if not canaries:
        return True
    reachable = set(scan(ctx, ip, canaries))
    return all(port in reachable for port in canaries)


def prioritize(ports: list[int]) -> list[int]:
    """Ordena pela prioridade do catálogo (portas fora dele vão para o fim)."""
    rank = {port: index for index, (port, _name) in enumerate(catalog())}
    return sorted(ports, key=lambda port: (rank.get(port, len(rank)), port))
