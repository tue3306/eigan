"""Hardening do Windows: compartilhamento, acesso remoto, nomes de rede e credenciais (só leitura).

Complementa ``windows.py``. Os valores vêm de ``windows_leitura`` e os caminhos exatos do
registro entram na evidência de cada achado.
"""

from __future__ import annotations

from ...core import facts
from ...core.context import CheckContext
from ...core.models import Category, Confidence, Fact, Severity
from ...core.registry import check
from . import comum
from . import windows_leitura as lw
from .comum import aprovar, nao_verificado, relatar_windows

COMPRIMENTO_MINIMO = 8
#: porta -> serviço; as de ``PORTAS_DO_WINDOWS`` existem em quase toda máquina
PORTAS_SENSIVEIS = {
    21: "FTP",
    23: "Telnet",
    135: "RPC",
    139: "NetBIOS",
    445: "SMB",
    1433: "SQL Server",
    1521: "Oracle",
    2375: "Docker (sem TLS)",
    3306: "MySQL/MariaDB",
    3389: "Área de Trabalho Remota",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM (HTTP)",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}
PORTAS_DO_WINDOWS = frozenset({135, 139, 445})


# -- SMB, RDP, LLMNR, NetBIOS, portas ----------------------------------------------------
def _verificar_smb1(ctx: CheckContext) -> None:
    estado = lw.estado_smb1_servidor()
    if estado.ligado:
        relatar_windows(
            ctx,
            "host.win.smb.v1_ligado",
            estado.evidencia,
            confianca=Confidence.FIRM if estado.firme else Confidence.TENTATIVE,
        )
    elif estado.ligado is False:
        aprovar(ctx, "host.win.smb.v1", "Servidor SMBv1 desativado")
    else:
        nao_verificado(ctx, "SMBv1", "o estado do servidor SMBv1 não pôde ser determinado")


def _verificar_assinatura_smb(ctx: CheckContext) -> None:
    for lado in ("servidor", "cliente"):
        assinatura = lw.assinatura_smb(lado)
        if assinatura.exigida is False:
            relatar_windows(
                ctx,
                "host.win.smb.assinatura_nao_exigida",
                assinatura.origem,
                discriminator=lado,
                lado=lado,
            )
        elif assinatura.exigida:
            aprovar(ctx, f"host.win.smb.assinatura.{lado}", f"Assinatura SMB exigida no {lado}")
        else:
            nao_verificado(ctx, f"Assinatura SMB ({lado})", "valor não encontrado")


def _verificar_rdp(ctx: CheckContext) -> None:
    rdp = lw.estado_rdp()
    if not rdp.ligado:
        aprovar(ctx, "host.win.rdp", "Área de Trabalho Remota desativada")
    elif rdp.nla.numero == 0:
        relatar_windows(ctx, "host.win.rdp.sem_nla", f"{rdp.conexoes}; {rdp.nla}")
    elif rdp.nla.numero == 1:
        aprovar(
            ctx,
            "host.win.rdp.nla",
            "Área de Trabalho Remota exige autenticação em nível de rede (NLA)",
        )
    else:
        nao_verificado(ctx, "NLA da Área de Trabalho Remota", "valor UserAuthentication ausente")


def _verificar_llmnr(ctx: CheckContext) -> None:
    ajuste = lw.ler(lw.DNS_CLIENTE, "EnableMulticast")
    if ajuste.numero == 0:
        aprovar(ctx, "host.win.llmnr", "LLMNR desativado por política")
    else:
        relatar_windows(ctx, "host.win.llmnr.ligado", str(ajuste))


def _verificar_netbios(ctx: CheckContext) -> None:
    adaptadores = lw.adaptadores_netbios()
    if adaptadores is None:
        nao_verificado(ctx, "NetBIOS", "as placas de rede não puderam ser listadas")
        return
    ligados = [(nome, opcao) for nome, opcao in adaptadores if opcao in (0, 1)]
    if not ligados:
        if adaptadores:
            aprovar(ctx, "host.win.netbios", "NetBIOS sobre TCP/IP desligado nas placas ativas")
        return
    explicito = any(opcao == 1 for _, opcao in ligados)
    relatar_windows(
        ctx,
        "host.win.netbios.ligado",
        "; ".join(f"{nome}: TcpipNetbiosOptions={opcao}" for nome, opcao in ligados),
        confianca=Confidence.FIRM if explicito else Confidence.TENTATIVE,
        placas=[nome for nome, _ in ligados],
    )


def _verificar_portas(ctx: CheckContext) -> None:
    portas = lw.portas_em_escuta()
    if portas is None:
        nao_verificado(ctx, "Portas em escuta", "o netstat não respondeu")
        return
    expostas = sorted(
        {(p.porta, p.pid) for p in portas if p.em_todas and p.porta in PORTAS_SENSIVEIS},
    )
    if not expostas:
        return
    texto = "; ".join(
        f"{PORTAS_SENSIVEIS[porta]} {porta}/tcp (PID {pid})" for porta, pid in expostas
    )
    so_windows = all(porta in PORTAS_DO_WINDOWS for porta, _ in expostas)
    relatar_windows(
        ctx,
        "host.win.portas.expostas",
        f"netstat -ano, escuta em 0.0.0.0/[::]: {texto}",
        severidade=Severity.INFO if so_windows else None,
        portas=[porta for porta, _ in expostas],
    )


@check(
    id="host.win.rede",
    name="Compartilhamento e acesso remoto (Windows)",
    category=Category.HOST,
    consumes=facts.LOCAL,
    description=(
        "Confere SMBv1 e assinatura SMB, Área de Trabalho Remota com NLA, LLMNR, NetBIOS e as portas "
        "de risco escutando em todas as interfaces."
    ),
    findings=(
        "host.win.smb.v1_ligado",
        "host.win.smb.assinatura_nao_exigida",
        "host.win.rdp.sem_nla",
        "host.win.llmnr.ligado",
        "host.win.netbios.ligado",
        "host.win.portas.expostas",
    ),
    platforms=comum.WINDOWS,
)
def check_rede(ctx: CheckContext, fact: Fact) -> None:
    comum.executar(ctx, "SMBv1", _verificar_smb1)
    comum.executar(ctx, "Assinatura SMB", _verificar_assinatura_smb)
    comum.executar(ctx, "Área de Trabalho Remota", _verificar_rdp)
    comum.executar(ctx, "LLMNR", _verificar_llmnr)
    comum.executar(ctx, "NetBIOS", _verificar_netbios)
    comum.executar(ctx, "Portas em escuta", _verificar_portas)


# -- credenciais e contas ----------------------------------------------------------------
def _verificar_wdigest(ctx: CheckContext) -> None:
    ajuste = lw.ler(lw.WDIGEST, "UseLogonCredential")
    if ajuste.numero == 1:
        relatar_windows(ctx, "host.win.wdigest.senha_em_memoria", str(ajuste))
    else:  # ausente = desligado nas versões atuais do Windows
        aprovar(ctx, "host.win.wdigest", "WDigest não guarda senhas em texto puro")


def _verificar_lsa(ctx: CheckContext) -> None:
    ajuste = lw.ler(lw.LSA, "RunAsPPL")
    if ajuste.numero in (1, 2):
        aprovar(ctx, "host.win.lsa", "LSASS roda como processo protegido (RunAsPPL)")
    elif ajuste.numero == 0:
        relatar_windows(ctx, "host.win.lsa.sem_protecao", str(ajuste))
    elif (no_log := lw.lsass_protegido_no_log()) is None:
        nao_verificado(ctx, "Proteção da LSA", "o log System não pôde ser consultado")
    elif no_log:
        aprovar(ctx, "host.win.lsa", "LSASS iniciado como processo protegido (evento WinInit 12)")
    else:
        relatar_windows(
            ctx,
            "host.win.lsa.sem_protecao",
            f"{ajuste}; nenhum evento WinInit 12 no log System",
            confianca=Confidence.TENTATIVE,  # o log pode ter sido reciclado
        )


def _verificar_ntlm(ctx: CheckContext) -> None:
    ajuste = lw.ler(lw.LSA, "LmCompatibilityLevel")
    nivel = ajuste.numero
    if nivel is None:
        return  # ausente = padrão atual (3 ou mais): nada a afirmar
    if nivel < 3:
        relatar_windows(ctx, "host.win.ntlm.nivel_fraco", str(ajuste), nivel=nivel)
    else:
        aprovar(ctx, "host.win.ntlm", f"LmCompatibilityLevel = {nivel} (envia só NTLMv2)")


def _verificar_convidado(ctx: CheckContext) -> None:
    conta = lw.conta_convidado()
    if conta is None:
        nao_verificado(ctx, "Conta de convidado", "a conta (SID -501) não foi listada")
    elif conta.ativa:
        relatar_windows(
            ctx,
            "host.win.conta.convidado_ativa",
            f"Win32_UserAccount SID -501 ({conta.nome}): Disabled=False",
        )
    else:
        aprovar(ctx, "host.win.conta.convidado", "Conta de convidado desativada")


def _verificar_senhas(ctx: CheckContext) -> None:
    politica = lw.politica_contas()
    if politica is None:
        nao_verificado(ctx, "Política de senhas", "a saída de 'net accounts' não foi reconhecida")
        return
    if politica.comprimento_minimo < COMPRIMENTO_MINIMO:
        relatar_windows(
            ctx,
            "host.win.senha.comprimento_curto",
            f"net accounts: comprimento mínimo da senha = {politica.comprimento_minimo}",
            confianca=Confidence.TENTATIVE,  # 'net accounts' mostra só a política local
            comprimento_minimo=politica.comprimento_minimo,
            observacao="Somente a política local foi lida; em máquinas de domínio vale a do domínio.",
        )
    else:
        aprovar(
            ctx,
            "host.win.senha.comprimento",
            f"Senha com no mínimo {politica.comprimento_minimo} caracteres",
        )
    if politica.limite_bloqueio == 0:
        relatar_windows(
            ctx,
            "host.win.senha.sem_bloqueio",
            "net accounts: limite de bloqueio = 0 (nunca bloqueia)",
        )
    else:
        aprovar(
            ctx,
            "host.win.senha.bloqueio",
            f"Conta bloqueada após {politica.limite_bloqueio} tentativas",
        )


@check(
    id="host.win.credenciais",
    name="Credenciais e contas (Windows)",
    category=Category.HOST,
    consumes=facts.LOCAL,
    description=(
        "Confere WDigest, proteção da LSA, nível de autenticação LM/NTLM, conta de convidado e a "
        "política local de senhas (comprimento mínimo e bloqueio)."
    ),
    findings=(
        "host.win.wdigest.senha_em_memoria",
        "host.win.lsa.sem_protecao",
        "host.win.ntlm.nivel_fraco",
        "host.win.conta.convidado_ativa",
        "host.win.senha.comprimento_curto",
        "host.win.senha.sem_bloqueio",
    ),
    platforms=comum.WINDOWS,
)
def check_credenciais(ctx: CheckContext, fact: Fact) -> None:
    comum.executar(ctx, "WDigest", _verificar_wdigest)
    comum.executar(ctx, "Proteção da LSA", _verificar_lsa)
    comum.executar(ctx, "Nível de autenticação NTLM", _verificar_ntlm)
    comum.executar(ctx, "Conta de convidado", _verificar_convidado)
    comum.executar(ctx, "Política de senhas", _verificar_senhas)
