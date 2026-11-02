"""Parâmetros de segurança do kernel (sysctl), lidos de /proc/sys sem alterar nada.

Os parâmetros de rede são avaliados por interface, com a regra da documentação do kernel
(``ip-sysctl``), para não acusar o que o kernel não aplica. Exemplos: sem encaminhamento
de pacotes, a máquina nunca envia ICMP redirect, então ``send_redirects`` não é avaliado;
e ``accept_source_route`` só vale com ``all`` e a interface ligados ao mesmo tempo.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...core import facts
from ...core.context import CheckContext
from ...core.models import Category, Confidence, Fact, Severity
from ...core.registry import check
from . import comum, linux_kb_sistema  # noqa: F401
from . import linux_sistema as so
from .linux_sistema import SistemaLinux
from .sistema import AcessoNegado

IPV4 = "net/ipv4/conf"
IPV6 = "net/ipv6/conf"


@dataclass(frozen=True)
class _Regra:
    """Parâmetro que precisa estar em 1 ou mais."""

    chave: str
    achado: str
    aprovado: str


_REGRAS = (
    _Regra(
        "net.ipv4.tcp_syncookies",
        "host.linux.kernel.syncookies",
        "SYN cookies ativos contra inundação de conexões",
    ),
    _Regra(
        "kernel.kptr_restrict",
        "host.linux.kernel.ponteiros_expostos",
        "Endereços do kernel protegidos (kptr_restrict)",
    ),
    _Regra(
        "kernel.dmesg_restrict",
        "host.linux.kernel.dmesg_aberto",
        "Log do kernel restrito a usuários privilegiados (dmesg_restrict)",
    ),
)


def _valor(ctx: CheckContext, sis: SistemaLinux, chave: str) -> int | None:
    """Valor de um parâmetro; leitura negada fica no registro e vira "não verificado"."""
    try:
        return so.ler_sysctl(sis, chave)
    except AcessoNegado:
        comum.nao_verificado(ctx, chave.replace("/", "."))
        return None


def _interfaces(sis: SistemaLinux, pasta: str) -> list[str]:
    """Interfaces de rede; sem nenhuma, ``default`` representa as que vierem a ser criadas."""
    nomes = sis.listar(f"/proc/sys/{pasta}") or []
    reais = [nome for nome in nomes if nome not in ("all", "default", "lo")]
    return reais or (["default"] if "default" in nomes else [])


def _verificar_simples(ctx: CheckContext, sis: SistemaLinux) -> None:
    asset = comum.ativo(ctx)
    for regra in _REGRAS:
        valor = _valor(ctx, sis, regra.chave)
        if valor is None:
            continue
        if valor >= 1:
            ctx.passed(regra.achado, f"{regra.aprovado}: {regra.chave} = {valor}", asset)
        else:
            _reportar(ctx, sis, regra.achado, f"{regra.chave} = {valor}")


def _reportar(
    ctx: CheckContext,
    sis: SistemaLinux,
    achado: str,
    evidencia: str,
    *,
    severidade: Severity | None = None,
    detalhes: dict[str, object] | None = None,
) -> None:
    ctx.report(
        achado,
        asset=comum.ativo(ctx),
        severity=severidade,
        evidence=evidencia,
        details=detalhes or {},
        confidence=Confidence.CONFIRMED,
        tech=so.tecnologias(sis),
    )


def _verificar_aslr(ctx: CheckContext, sis: SistemaLinux) -> None:
    chave = "kernel.randomize_va_space"
    valor = _valor(ctx, sis, chave)
    if valor is None:
        return
    if valor >= 2:
        ctx.passed(
            "host.linux.kernel.aslr",
            f"Sorteio de endereços de memória (ASLR) completo: {chave} = {valor}",
            comum.ativo(ctx),
        )
        return
    # 1 ainda sorteia pilha e bibliotecas (só o heap fica de fora); 0 desliga tudo
    _reportar(
        ctx,
        sis,
        "host.linux.kernel.aslr",
        f"{chave} = {valor}",
        severidade=Severity.LOW if valor == 1 else None,
    )


def _verificar_links(ctx: CheckContext, sis: SistemaLinux) -> None:
    valores = {
        chave: _valor(ctx, sis, chave)
        for chave in ("fs.protected_symlinks", "fs.protected_hardlinks")
    }
    desligados = [chave for chave, valor in valores.items() if valor == 0]
    if desligados:
        _reportar(
            ctx,
            sis,
            "host.linux.kernel.links_desprotegidos",
            ", ".join(f"{chave} = 0" for chave in desligados),
            detalhes={"parametros": desligados},
        )
    elif all(valores.values()):
        ctx.passed(
            "host.linux.kernel.links_desprotegidos",
            "Proteção de links simbólicos e físicos ligada (fs.protected_*)",
            comum.ativo(ctx),
        )


def _aceitam_redirects_ipv4(ctx: CheckContext, sis: SistemaLinux) -> list[str] | None:
    """Regra do ip-sysctl: com encaminhamento, ``all`` E interface; sem, ``all`` OU interface."""
    todas = _valor(ctx, sis, f"{IPV4}/all/accept_redirects")
    if todas is None:
        return None
    aceitam: list[str] = []
    for nome in _interfaces(sis, IPV4):
        propria = _valor(ctx, sis, f"{IPV4}/{nome}/accept_redirects")
        if propria is None:
            continue
        encaminha = _valor(ctx, sis, f"{IPV4}/{nome}/forwarding")
        if (todas and propria) if encaminha else (todas or propria):
            aceitam.append(f"{nome} (all={todas}, interface={propria})")
    return aceitam


def _aceitam_redirects_ipv6(ctx: CheckContext, sis: SistemaLinux) -> list[str]:
    """Em IPv6 vale o valor da interface, e só quando ela não encaminha pacotes (ip-sysctl)."""
    aceitam: list[str] = []
    for nome in _interfaces(sis, IPV6):
        if _valor(ctx, sis, f"{IPV6}/{nome}/disable_ipv6"):
            continue
        if _valor(ctx, sis, f"{IPV6}/{nome}/accept_redirects") and not _valor(
            ctx, sis, f"{IPV6}/{nome}/forwarding"
        ):
            aceitam.append(nome)
    return aceitam


def _verificar_recebimento_redirects(ctx: CheckContext, sis: SistemaLinux) -> None:
    ipv4 = _aceitam_redirects_ipv4(ctx, sis)
    ipv6 = _aceitam_redirects_ipv6(ctx, sis)
    if ipv4 or ipv6:
        partes = []
        if ipv4:
            partes.append("IPv4: " + ", ".join(ipv4))
        if ipv6:
            partes.append("IPv6: " + ", ".join(ipv6))
        _reportar(
            ctx,
            sis,
            "host.linux.kernel.redirecionamentos_icmp",
            "Interfaces que aceitam redirects — " + "; ".join(partes),
            detalhes={"ipv4": ipv4 or [], "ipv6": ipv6},
        )
    elif ipv4 is not None:
        ctx.passed(
            "host.linux.kernel.redirecionamentos_icmp",
            "Kernel não aceita redirecionamentos ICMP",
            comum.ativo(ctx),
        )


def _verificar_envio_redirects(ctx: CheckContext, sis: SistemaLinux) -> None:
    """``send_redirects`` só tem efeito em quem encaminha pacotes ("Send redirects, if router")."""
    todas = _valor(ctx, sis, f"{IPV4}/all/send_redirects")
    if todas is None:
        return
    encaminham = [
        nome for nome in _interfaces(sis, IPV4) if _valor(ctx, sis, f"{IPV4}/{nome}/forwarding")
    ]
    enviam = [
        nome for nome in encaminham if todas or _valor(ctx, sis, f"{IPV4}/{nome}/send_redirects")
    ]
    if enviam:
        _reportar(
            ctx,
            sis,
            "host.linux.kernel.envio_redirecionamentos",
            f"Interfaces que encaminham pacotes e enviam redirects: {', '.join(enviam)} (all={todas})",
            detalhes={"interfaces": enviam},
        )
    elif encaminham:
        ctx.passed(
            "host.linux.kernel.envio_redirecionamentos",
            "A máquina encaminha pacotes, mas não envia redirecionamentos ICMP",
            comum.ativo(ctx),
        )
    else:
        ctx.log("send_redirects: a máquina não encaminha pacotes, então não envia redirects")


def _verificar_source_route(ctx: CheckContext, sis: SistemaLinux) -> None:
    """A interface só aceita com ``all`` também ligado ("must also be set to TRUE", ip-sysctl)."""
    todas = _valor(ctx, sis, f"{IPV4}/all/accept_source_route")
    if todas is None:
        return
    aceitam = (
        [
            nome
            for nome in _interfaces(sis, IPV4)
            if (_valor(ctx, sis, f"{IPV4}/{nome}/accept_source_route") or 0) > 0
        ]
        if todas > 0
        else []
    )
    if aceitam:
        _reportar(
            ctx,
            sis,
            "host.linux.kernel.source_route",
            f"accept_source_route ligado em all e em: {', '.join(aceitam)}",
            detalhes={"interfaces": aceitam},
        )
    else:
        ctx.passed(
            "host.linux.kernel.source_route",
            "Kernel recusa pacotes com rota definida pela origem (accept_source_route)",
            comum.ativo(ctx),
        )


def _verificar_kernel(ctx: CheckContext) -> None:
    sis = so.obter(ctx)
    if so.fora_de_escopo(ctx, sis, "Parâmetros do kernel", wsl=False):
        return
    _verificar_aslr(ctx, sis)
    _verificar_simples(ctx, sis)
    _verificar_links(ctx, sis)
    _verificar_recebimento_redirects(ctx, sis)
    _verificar_envio_redirects(ctx, sis)
    _verificar_source_route(ctx, sis)


@check(
    id="host.linux.kernel",
    name="Parâmetros de segurança do kernel (Linux)",
    category=Category.HOST,
    consumes=facts.LOCAL,
    description=(
        "Lê /proc/sys: ASLR, SYN cookies, kptr_restrict, dmesg_restrict, proteção de links e, por "
        "interface, ICMP redirects e roteamento pela origem."
    ),
    findings=(
        "host.linux.kernel.aslr",
        "host.linux.kernel.syncookies",
        "host.linux.kernel.ponteiros_expostos",
        "host.linux.kernel.dmesg_aberto",
        "host.linux.kernel.links_desprotegidos",
        "host.linux.kernel.redirecionamentos_icmp",
        "host.linux.kernel.envio_redirecionamentos",
        "host.linux.kernel.source_route",
    ),
    platforms=comum.LINUX,
)
def check_kernel(ctx: CheckContext, fact: Fact) -> None:
    comum.executar(ctx, "Parâmetros do kernel", _verificar_kernel)
