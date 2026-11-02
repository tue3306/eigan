"""Hardening do Windows desta máquina: proteções, sistema e disco (só leitura).

Cada verificação lê uma configuração pelas funções de ``windows_leitura`` (que os testes
substituem) e reporta o valor exato do registro ou do comando na evidência. Leitura negada
por falta de privilégio vira "não verificado" no registro de atividade, nunca um achado.
As verificações de rede e de credenciais ficam em ``windows_rede.py``.
"""

from __future__ import annotations

from ...core import facts
from ...core.context import CheckContext
from ...core.models import Category, Confidence, Fact
from ...core.registry import check
from . import comum, kb_windows, kb_windows_sistema, sistema, windows_rede  # noqa: F401
from . import windows_leitura as lw
from .comum import aprovar, nao_verificado, relatar_windows

DIAS_ASSINATURAS = 7
DIAS_ATUALIZACAO = 60
_MODOS_PASSIVOS = ("passive", "sxs")


# -- firewall e antivírus ----------------------------------------------------------------
def _verificar_firewall(ctx: CheckContext) -> None:
    perfis = lw.perfis_firewall()
    desligados = [p for p in perfis if p.ligado is False]
    if any(p.ligado is None for p in perfis) and not desligados:
        nao_verificado(ctx, "Firewall do Windows", "estado de um perfil não pôde ser lido")
        return
    if desligados:
        terceiros = lw.produtos_de_terceiros("FirewallProduct")
        if terceiros:
            ctx.log(
                f"Firewall do Windows desligado, mas há firewall de terceiros ({', '.join(terceiros)}): não avaliado."
            )
            return
        relatar_windows(
            ctx,
            "host.win.firewall.desligado",
            "; ".join(p.origem for p in desligados),
            perfis_desligados=[p.nome for p in desligados],
            terceiros_consultados=terceiros is not None,
        )
    elif perfis:
        aprovar(
            ctx,
            "host.win.firewall",
            "Firewall do Windows ligado nos perfis Domínio, Privado e Público",
        )


def _outro_antivirus_ativo(estado: lw.EstadoDefender, terceiros: list[str] | None) -> bool:
    """Se outro antivírus assumiu a proteção (Defender em modo passivo ou produto de terceiros)."""
    passivo = any(modo in estado.modo.lower() for modo in _MODOS_PASSIVOS)
    return passivo or bool(terceiros)


def _verificar_defender(ctx: CheckContext) -> None:
    estado = lw.estado_defender()
    terceiros = lw.produtos_de_terceiros("AntiVirusProduct")
    if estado is None:
        if terceiros:
            ctx.log(
                f"Microsoft Defender sem resposta; antivírus de terceiros presente ({', '.join(terceiros)})."
            )
        else:
            nao_verificado(
                ctx,
                "Microsoft Defender",
                "o Defender não respondeu e a Central de Segurança não lista outro",
            )
        return
    resumo = (
        f"Get-MpComputerStatus: AMRunningMode={estado.modo or '?'}, AntivirusEnabled={estado.antivirus}, "
        f"RealTimeProtectionEnabled={estado.tempo_real}, assinaturas={estado.assinaturas_em or '?'}"
    )
    if _outro_antivirus_ativo(estado, terceiros):
        ctx.log(
            f"Antivírus de outro fabricante assumiu a proteção ({', '.join(terceiros or ['modo passivo'])})."
        )
        return
    if estado.antivirus is False or estado.servico is False:
        relatar_windows(
            ctx,
            "host.win.antivirus.ausente",
            resumo,
            confianca=Confidence.FIRM if terceiros is not None else Confidence.TENTATIVE,
            central_de_seguranca_consultada=terceiros is not None,
        )
        return
    if estado.tempo_real is False:
        relatar_windows(ctx, "host.win.defender.tempo_real_desligado", resumo)
    elif estado.tempo_real:
        aprovar(
            ctx,
            "host.win.defender.tempo_real",
            "Proteção em tempo real do Microsoft Defender ligada",
        )
    idade = estado.idade_assinaturas
    if idade is not None and idade > DIAS_ASSINATURAS:
        relatar_windows(
            ctx,
            "host.win.defender.assinaturas_antigas",
            f"{resumo}; idade das assinaturas: {idade} dias",
            idade_dias=idade,
        )
    elif idade is not None:
        aprovar(ctx, "host.win.defender.assinaturas", f"Assinaturas do Defender com {idade} dia(s)")


@check(
    id="host.win.protecao",
    name="Firewall e antivírus (Windows)",
    category=Category.HOST,
    consumes=facts.LOCAL,
    description=(
        "Lê o estado do Firewall do Windows em cada perfil e do Microsoft Defender (antivírus, proteção "
        "em tempo real e idade das assinaturas), respeitando antivírus de outro fabricante."
    ),
    findings=(
        "host.win.firewall.desligado",
        "host.win.antivirus.ausente",
        "host.win.defender.tempo_real_desligado",
        "host.win.defender.assinaturas_antigas",
    ),
    platforms=comum.WINDOWS,
)
def check_protecao(ctx: CheckContext, fact: Fact) -> None:
    comum.executar(ctx, "Firewall do Windows", _verificar_firewall)
    comum.executar(ctx, "Microsoft Defender", _verificar_defender)


# -- UAC ---------------------------------------------------------------------------------
def _verificar_uac(ctx: CheckContext) -> None:
    lua = lw.ler(lw.UAC, "EnableLUA")
    if lua.numero == 0:
        relatar_windows(ctx, "host.win.uac.desligado", str(lua))
        return
    consentimento = lw.ler(lw.UAC, "ConsentPromptBehaviorAdmin")
    if consentimento.numero == 0:
        relatar_windows(ctx, "host.win.uac.eleva_sem_perguntar", str(consentimento))
    elif lua.numero == 1:
        aprovar(ctx, "host.win.uac", "UAC ligado e pedindo confirmação para elevar administradores")


@check(
    id="host.win.uac",
    name="Controle de Conta de Usuário (Windows)",
    category=Category.HOST,
    consumes=facts.LOCAL,
    description="Confere EnableLUA e ConsentPromptBehaviorAdmin na política do UAC.",
    findings=("host.win.uac.desligado", "host.win.uac.eleva_sem_perguntar"),
    platforms=comum.WINDOWS,
)
def check_uac(ctx: CheckContext, fact: Fact) -> None:
    comum.executar(ctx, "UAC", _verificar_uac)


# -- sistema: atualizações, disco, inicialização, serviços -------------------------------
def _verificar_atualizacoes(ctx: CheckContext) -> None:
    if lw.servico_desativado("wuauserv"):
        relatar_windows(
            ctx,
            "host.win.atualizacoes.servico_desligado",
            str(lw.ler(rf"{lw.SERVICOS}\wuauserv", "Start")),
        )
    lista = lw.atualizacoes_instaladas()
    if not lista:
        nao_verificado(ctx, "Atualizações instaladas", "o Windows não listou atualizações com data")
        return
    recente = lista[0]
    dias = (sistema.hoje() - recente.data).days
    if dias > DIAS_ATUALIZACAO:
        relatar_windows(
            ctx,
            "host.win.atualizacoes.antigas",
            f"Get-HotFix: a mais recente é {recente.kb} de {recente.data.isoformat()} ({dias} dias)",
            confianca=Confidence.TENTATIVE,  # o Get-HotFix não lista todo tipo de atualização
            ultima_atualizacao=recente.data.isoformat(),
            dias=dias,
        )
    else:
        aprovar(
            ctx,
            "host.win.atualizacoes",
            f"Atualização mais recente há {dias} dia(s) ({recente.kb})",
        )


def _verificar_bitlocker(ctx: CheckContext) -> None:
    volume = lw.volume_do_sistema()
    if volume is None:
        nao_verificado(ctx, "BitLocker", "o volume do sistema não foi listado")
        return
    texto = (
        f"Win32_EncryptableVolume {volume.letra}: ProtectionStatus={volume.protecao}, "
        f"ConversionStatus={volume.conversao}"
    )
    if volume.protecao == 0 and volume.conversao in (0, None):
        relatar_windows(ctx, "host.win.bitlocker.desligado", texto, volume=volume.letra)
    elif volume.protecao == 1:
        aprovar(ctx, "host.win.bitlocker", f"BitLocker protegendo o disco {volume.letra}")


def _verificar_secure_boot(ctx: CheckContext) -> None:
    ajuste = lw.ler(lw.SECURE_BOOT, "UEFISecureBootEnabled")
    if ajuste.numero == 0:
        relatar_windows(ctx, "host.win.secureboot.desligado", str(ajuste))
    elif ajuste.numero == 1:
        aprovar(ctx, "host.win.secureboot", "Inicialização Segura (Secure Boot) ligada")
    else:  # chave ausente: BIOS legado, sem como afirmar
        nao_verificado(
            ctx, "Secure Boot", "a chave SecureBoot\\State não existe (BIOS legado ou sem suporte)"
        )


def _verificar_registro_remoto(ctx: CheckContext) -> None:
    servico = lw.estado_servico("RemoteRegistry")
    if servico is None:
        nao_verificado(ctx, "Registro Remoto", "o serviço não respondeu")
    elif servico.em_execucao:
        relatar_windows(
            ctx,
            "host.win.registro_remoto.ligado",
            f"Get-Service RemoteRegistry: Status=Running, StartType={servico.inicio}",
        )
    else:
        aprovar(ctx, "host.win.registro_remoto", "Serviço Registro Remoto parado")


def _verificar_powershell2(ctx: CheckContext) -> None:
    recursos = lw.recursos_opcionais("MicrosoftWindowsPowerShellV2%")
    if recursos is None:
        nao_verificado(ctx, "PowerShell 2.0", "a lista de recursos opcionais não respondeu")
        return
    ligados = {nome: estado for nome, estado in recursos.items() if estado == lw.RECURSO_LIGADO}
    if ligados:
        texto = "; ".join(
            f"Win32_OptionalFeature {n}: InstallState={e}" for n, e in sorted(ligados.items())
        )
        relatar_windows(ctx, "host.win.powershell2.presente", texto, recursos=sorted(ligados))
    else:
        aprovar(ctx, "host.win.powershell2", "Mecanismo do PowerShell 2.0 ausente ou desativado")


def _verificar_autorun(ctx: CheckContext) -> None:
    tipos = lw.ler(lw.EXPLORER, "NoDriveTypeAutoRun")
    sem_autorun = lw.ler(lw.EXPLORER, "NoAutorun")
    if tipos.numero == 255 or sem_autorun.numero == 1:
        aprovar(ctx, "host.win.autorun", "AutoRun desativado em todos os tipos de unidade")
        return
    if tipos.numero is None and sem_autorun.numero is None:
        # Ausentes = padrão do Windows desde o 7 (autorun.inf não roda em USB): sem achado.
        ctx.log("AutoRun: sem política definida (padrão do Windows); nada a reportar.")
        return
    relatar_windows(
        ctx,
        "host.win.autorun.ligado",
        f"{tipos}; {sem_autorun}",
    )


@check(
    id="host.win.sistema",
    name="Atualizações, disco e serviços (Windows)",
    category=Category.HOST,
    consumes=facts.LOCAL,
    description=(
        "Confere atualizações recentes e o serviço Windows Update, BitLocker no disco do sistema, "
        "Secure Boot, Registro Remoto, mecanismo do PowerShell 2.0 e AutoRun."
    ),
    findings=(
        "host.win.atualizacoes.antigas",
        "host.win.atualizacoes.servico_desligado",
        "host.win.bitlocker.desligado",
        "host.win.secureboot.desligado",
        "host.win.registro_remoto.ligado",
        "host.win.powershell2.presente",
        "host.win.autorun.ligado",
    ),
    platforms=comum.WINDOWS,
)
def check_sistema(ctx: CheckContext, fact: Fact) -> None:
    comum.executar(ctx, "Atualizações do Windows", _verificar_atualizacoes)
    comum.executar(ctx, "BitLocker", _verificar_bitlocker)
    comum.executar(ctx, "Secure Boot", _verificar_secure_boot)
    comum.executar(ctx, "Registro Remoto", _verificar_registro_remoto)
    comum.executar(ctx, "PowerShell 2.0", _verificar_powershell2)
    comum.executar(ctx, "AutoRun", _verificar_autorun)
