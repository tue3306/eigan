"""Checagens de hardening do Windows contra um Windows falso (rodam também em Linux)."""

from __future__ import annotations

from typing import Any

import pytest
from fakes_host_windows import WindowsFalso, net_accounts, netstat, rodar

from eigan.checks.host import sistema
from eigan.checks.host import windows_leitura as lw
from eigan.core.models import Confidence, Severity

PROTECAO = "host.win.protecao"
UAC = "host.win.uac"
SISTEMA = "host.win.sistema"
REDE = "host.win.rede"
CREDENCIAIS = "host.win.credenciais"


def resultado(sis: WindowsFalso, monkeypatch: pytest.MonkeyPatch, check_id: str) -> Any:
    return rodar(sis, monkeypatch, check_id)


@pytest.mark.parametrize("check_id", [PROTECAO, UAC, SISTEMA, REDE, CREDENCIAIS])
def test_windows_seguro_nao_gera_achados(monkeypatch: pytest.MonkeyPatch, check_id: str) -> None:
    saida = resultado(WindowsFalso(), monkeypatch, check_id)
    assert saida.ids() == set()
    assert saida.passed  # os controles aprovados viram pontos fortes


# -- firewall ------------------------------------------------------------------------------
def test_firewall_desligado_em_um_perfil(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.reg(rf"{lw.FIREWALL_LOCAL}\PublicProfile", "EnableFirewall", 0)
    saida = resultado(sis, monkeypatch, PROTECAO)
    achado = saida.by_id("host.win.firewall.desligado")[0]
    assert "PublicProfile" in achado.evidence and "EnableFirewall = 0" in achado.evidence


def test_politica_de_grupo_prevalece_sobre_o_local(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.reg(rf"{lw.FIREWALL_LOCAL}\PublicProfile", "EnableFirewall", 0)
    sis.reg(rf"{lw.FIREWALL_POLITICA}\PublicProfile", "EnableFirewall", 1)
    assert resultado(sis, monkeypatch, PROTECAO).ids() == set()


def test_firewall_de_terceiros_nao_acusa(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.reg(rf"{lw.FIREWALL_LOCAL}\StandardProfile", "EnableFirewall", 0)
    sis.ps["FirewallProduct"] = [{"displayName": "Acme Firewall"}]
    assert "host.win.firewall.desligado" not in resultado(sis, monkeypatch, PROTECAO).ids()


# -- Defender ------------------------------------------------------------------------------
def test_defender_tempo_real_desligado(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.ps["Get-MpComputerStatus"]["RealTimeProtectionEnabled"] = False
    assert resultado(sis, monkeypatch, PROTECAO).ids() == {"host.win.defender.tempo_real_desligado"}


def test_assinaturas_do_defender_antigas(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.ps["Get-MpComputerStatus"]["AssinaturasEm"] = "2026-10-20T08:00:00"
    saida = resultado(sis, monkeypatch, PROTECAO)
    assert saida.ids() == {"host.win.defender.assinaturas_antigas"}
    assert "12 dias" in saida.findings[0].evidence


def test_assinaturas_de_ontem_nao_acusam(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.ps["Get-MpComputerStatus"]["AssinaturasEm"] = "2026-10-26T08:00:00"  # 6 dias
    assert resultado(sis, monkeypatch, PROTECAO).ids() == set()


def test_antivirus_ausente_e_firme_quando_a_central_responde(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sis = WindowsFalso()
    sis.ps["Get-MpComputerStatus"].update(AntivirusEnabled=False, RealTimeProtectionEnabled=False)
    achado = resultado(sis, monkeypatch, PROTECAO).by_id("host.win.antivirus.ausente")[0]
    assert achado.confidence is Confidence.FIRM


def test_antivirus_ausente_e_indicio_sem_central_de_seguranca(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sis = WindowsFalso()
    sis.ps["Get-MpComputerStatus"].update(AntivirusEnabled=False)
    del sis.ps["AntiVirusProduct"]  # Windows Server: a Central de Segurança não existe
    achado = resultado(sis, monkeypatch, PROTECAO).by_id("host.win.antivirus.ausente")[0]
    assert achado.confidence is Confidence.TENTATIVE


@pytest.mark.parametrize("modo", ["Normal"])
def test_defender_desligado_com_outro_antivirus_nao_acusa(
    monkeypatch: pytest.MonkeyPatch, modo: str
) -> None:
    sis = WindowsFalso()
    sis.ps["Get-MpComputerStatus"].update(
        AntivirusEnabled=False, RealTimeProtectionEnabled=False, AMRunningMode=modo
    )
    sis.ps["AntiVirusProduct"] = [{"displayName": "Acme AV"}, {"displayName": "Windows Defender"}]
    assert resultado(sis, monkeypatch, PROTECAO).ids() == set()


def test_defender_em_modo_passivo_nao_acusa(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.ps["Get-MpComputerStatus"].update(
        AMRunningMode="Passive Mode", RealTimeProtectionEnabled=False
    )
    assert resultado(sis, monkeypatch, PROTECAO).ids() == set()


def test_defender_negado_vira_nao_verificado(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.ps["Get-MpComputerStatus"] = sistema.AcessoNegado("Get-MpComputerStatus")
    saida = resultado(sis, monkeypatch, PROTECAO)
    assert saida.ids() == set()
    assert any("Microsoft Defender" in log and "não verificado" in log for log in saida.logs)


# -- UAC -----------------------------------------------------------------------------------
def test_uac_desligado(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.reg(lw.UAC, "EnableLUA", 0)
    achado = resultado(sis, monkeypatch, UAC).by_id("host.win.uac.desligado")[0]
    assert "EnableLUA = 0" in achado.evidence


def test_uac_eleva_sem_perguntar(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.reg(lw.UAC, "ConsentPromptBehaviorAdmin", 0)
    assert resultado(sis, monkeypatch, UAC).ids() == {"host.win.uac.eleva_sem_perguntar"}


def test_uac_desligado_nao_repete_o_aviso_do_consentimento(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.reg(lw.UAC, "EnableLUA", 0)
    sis.reg(lw.UAC, "ConsentPromptBehaviorAdmin", 0)
    assert resultado(sis, monkeypatch, UAC).ids() == {"host.win.uac.desligado"}


# -- rede ----------------------------------------------------------------------------------
def test_smbv1_ligado_pelo_cmdlet_e_pelo_recurso(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.reg(lw.SMB_SERVIDOR, "SMB1", None)
    sis.ps["Get-SmbServerConfiguration"] = {"EnableSMB1Protocol": True}
    sis.ps["SMB1Protocol"] = [{"Name": "SMB1Protocol-Server", "InstallState": 1}]
    achado = resultado(sis, monkeypatch, REDE).by_id("host.win.smb.v1_ligado")[0]
    assert achado.confidence is Confidence.FIRM


def test_smbv1_so_pelo_registro_e_indicio(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.reg(lw.SMB_SERVIDOR, "SMB1", 1)
    del sis.ps["Get-SmbServerConfiguration"]
    achado = resultado(sis, monkeypatch, REDE).by_id("host.win.smb.v1_ligado")[0]
    assert achado.confidence is Confidence.TENTATIVE


def test_smbv1_sem_valor_e_recurso_ausente_nao_acusa(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.reg(lw.SMB_SERVIDOR, "SMB1", None)
    sis.ps["Get-SmbServerConfiguration"] = {"EnableSMB1Protocol": True}
    sis.ps["SMB1Protocol"] = [{"Name": "SMB1Protocol-Server", "InstallState": 2}]  # desabilitado
    assert "host.win.smb.v1_ligado" not in resultado(sis, monkeypatch, REDE).ids()


def test_assinatura_smb_nao_exigida_no_servidor(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.reg(lw.SMB_SERVIDOR, "RequireSecuritySignature", 0)
    saida = resultado(sis, monkeypatch, REDE)
    achados = saida.by_id("host.win.smb.assinatura_nao_exigida")
    assert len(achados) == 1 and "LanmanServer" in achados[0].evidence


def test_assinatura_smb_habilitada_mas_nao_exigida_ainda_acusa(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """EnableSecuritySignature é ignorado no SMB2: só RequireSecuritySignature conta."""
    sis = WindowsFalso()
    sis.reg(lw.SMB_SERVIDOR, "RequireSecuritySignature", 0)
    sis.reg(lw.SMB_SERVIDOR, "EnableSecuritySignature", 1)
    assert "host.win.smb.assinatura_nao_exigida" in resultado(sis, monkeypatch, REDE).ids()


def test_assinatura_smb_sem_registro_usa_o_cmdlet(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.reg(lw.SMB_CLIENTE, "RequireSecuritySignature", None)
    sis.ps["Get-SmbClientConfiguration"] = {"RequireSecuritySignature": False}
    achado = resultado(sis, monkeypatch, REDE).by_id("host.win.smb.assinatura_nao_exigida")[0]
    assert "Get-SmbClientConfiguration" in achado.evidence


def test_rdp_ligado_sem_nla(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.reg(lw.TS_LOCAL, "fDenyTSConnections", 0)
    sis.reg(lw.RDP_TCP, "UserAuthentication", 0)
    assert resultado(sis, monkeypatch, REDE).ids() == {"host.win.rdp.sem_nla"}


def test_rdp_desligado_sem_nla_nao_acusa(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.reg(lw.RDP_TCP, "UserAuthentication", 0)  # RDP continua desligado (fDenyTSConnections=1)
    assert resultado(sis, monkeypatch, REDE).ids() == set()


def test_rdp_com_nla_e_aprovado(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.reg(lw.TS_LOCAL, "fDenyTSConnections", 0)
    saida = resultado(sis, monkeypatch, REDE)
    assert saida.ids() == set()
    assert "host.win.rdp.nla" in {p.control for p in saida.passed}


@pytest.mark.parametrize("politica", [None, 1])
def test_llmnr_nao_desativado(monkeypatch: pytest.MonkeyPatch, politica: int | None) -> None:
    sis = WindowsFalso()
    sis.reg(lw.DNS_CLIENTE, "EnableMulticast", politica)
    assert resultado(sis, monkeypatch, REDE).ids() == {"host.win.llmnr.ligado"}


@pytest.mark.parametrize(("opcao", "confianca"), [(1, Confidence.FIRM), (0, Confidence.TENTATIVE)])
def test_netbios_ligado(monkeypatch: pytest.MonkeyPatch, opcao: int, confianca: Confidence) -> None:
    sis = WindowsFalso()
    sis.ps["Win32_NetworkAdapterConfiguration"] = [
        {"Description": "Ethernet", "TcpipNetbiosOptions": opcao}
    ]
    achado = resultado(sis, monkeypatch, REDE).by_id("host.win.netbios.ligado")[0]
    assert achado.confidence is confianca


def test_portas_de_banco_expostas(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.comandos["NETSTAT.EXE"] = sistema.Resultado(
        0, netstat("0.0.0.0:135 1868", "0.0.0.0:6379 900", "[::]:3306 901")
    )
    achado = resultado(sis, monkeypatch, REDE).by_id("host.win.portas.expostas")[0]
    assert achado.details["portas"] == [135, 3306, 6379]
    assert achado.severity is Severity.LOW


def test_so_portas_do_windows_sao_informativas(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.comandos["NETSTAT.EXE"] = sistema.Resultado(0, netstat("0.0.0.0:135 1868", "0.0.0.0:445 4"))
    achado = resultado(sis, monkeypatch, REDE).by_id("host.win.portas.expostas")[0]
    assert achado.severity is Severity.INFO


def test_porta_em_loopback_nao_conta(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.comandos["NETSTAT.EXE"] = sistema.Resultado(
        0, netstat("127.0.0.1:6379 900", "[::1]:3306 901")
    )
    assert "host.win.portas.expostas" not in resultado(sis, monkeypatch, REDE).ids()


# -- credenciais e contas ------------------------------------------------------------------
def test_wdigest_ligado(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.reg(lw.WDIGEST, "UseLogonCredential", 1)
    assert resultado(sis, monkeypatch, CREDENCIAIS).ids() == {"host.win.wdigest.senha_em_memoria"}


def test_lsa_sem_protecao_explicita(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.reg(lw.LSA, "RunAsPPL", 0)
    achado = resultado(sis, monkeypatch, CREDENCIAIS).by_id("host.win.lsa.sem_protecao")[0]
    assert achado.confidence is Confidence.FIRM


def test_lsa_sem_valor_e_sem_evento_e_indicio(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.reg(lw.LSA, "RunAsPPL", None)
    sis.ps["Get-WinEvent"] = []
    achado = resultado(sis, monkeypatch, CREDENCIAIS).by_id("host.win.lsa.sem_protecao")[0]
    assert achado.confidence is Confidence.TENTATIVE


def test_lsa_sem_valor_mas_com_evento_do_wininit_passa(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.reg(lw.LSA, "RunAsPPL", None)  # habilitação automática do Windows 11 22H2+
    assert resultado(sis, monkeypatch, CREDENCIAIS).ids() == set()


@pytest.mark.parametrize(
    ("nivel", "acusa"), [(0, True), (1, True), (2, True), (3, False), (5, False)]
)
def test_nivel_ntlm(monkeypatch: pytest.MonkeyPatch, nivel: int, acusa: bool) -> None:
    sis = WindowsFalso()
    sis.reg(lw.LSA, "LmCompatibilityLevel", nivel)
    assert ("host.win.ntlm.nivel_fraco" in resultado(sis, monkeypatch, CREDENCIAIS).ids()) is acusa


def test_nivel_ntlm_ausente_nao_acusa(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.reg(lw.LSA, "LmCompatibilityLevel", None)
    assert resultado(sis, monkeypatch, CREDENCIAIS).ids() == set()


def test_convidado_ativo(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.ps["Win32_UserAccount"] = [{"Name": "Guest", "Disabled": False}]
    assert resultado(sis, monkeypatch, CREDENCIAIS).ids() == {"host.win.conta.convidado_ativa"}


@pytest.mark.parametrize("idioma", ["en", "pt"])
def test_senha_curta_e_sem_bloqueio_em_qualquer_idioma(
    monkeypatch: pytest.MonkeyPatch, idioma: str
) -> None:
    sis = WindowsFalso()
    texto = net_accounts(minimo=0, bloqueio="Never" if idioma == "en" else "Nunca", idioma=idioma)
    sis.comandos["net.exe"] = sistema.Resultado(0, texto)
    assert resultado(sis, monkeypatch, CREDENCIAIS).ids() == {
        "host.win.senha.comprimento_curto",
        "host.win.senha.sem_bloqueio",
    }


def test_politica_de_senha_boa_e_aprovada(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.comandos["net.exe"] = sistema.Resultado(
        0, net_accounts(minimo=8, bloqueio="10", idioma="pt")
    )
    saida = resultado(sis, monkeypatch, CREDENCIAIS)
    assert saida.ids() == set()
    assert {"host.win.senha.comprimento", "host.win.senha.bloqueio"} <= {
        p.control for p in saida.passed
    }


def test_saida_irreconhecivel_do_net_accounts_nao_vira_achado(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sis = WindowsFalso()
    sis.comandos["net.exe"] = sistema.Resultado(0, "algo inesperado\n")
    assert resultado(sis, monkeypatch, CREDENCIAIS).ids() == set()


# -- sistema -------------------------------------------------------------------------------
def test_atualizacoes_antigas_sao_indicio(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.ps["Get-HotFix"] = [{"HotFixID": "KB1", "Data": "2026-07-01T00:00:00"}]
    achado = resultado(sis, monkeypatch, SISTEMA).by_id("host.win.atualizacoes.antigas")[0]
    assert achado.confidence is Confidence.TENTATIVE and "KB1" in achado.evidence


def test_atualizacao_de_59_dias_nao_acusa(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.ps["Get-HotFix"] = [{"HotFixID": "KB1", "Data": "2026-09-03T00:00:00"}]
    assert resultado(sis, monkeypatch, SISTEMA).ids() == set()


def test_data_no_futuro_e_ignorada(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.ps["Get-HotFix"] = [
        {"HotFixID": "KB9", "Data": "2027-01-05T00:00:00"},
        {"HotFixID": "KB1", "Data": "2026-10-25T00:00:00"},
    ]
    assert resultado(sis, monkeypatch, SISTEMA).ids() == set()


def test_windows_update_desativado(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.reg(rf"{lw.SERVICOS}\wuauserv", "Start", 4)
    assert resultado(sis, monkeypatch, SISTEMA).ids() == {"host.win.atualizacoes.servico_desligado"}


def test_bitlocker_desligado_e_negado_sem_admin(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.ps["Win32_EncryptableVolume"] = [
        {"DriveLetter": "C:", "ProtectionStatus": 0, "ConversionStatus": 0}
    ]
    assert resultado(sis, monkeypatch, SISTEMA).ids() == {"host.win.bitlocker.desligado"}


def test_bitlocker_negado_nao_e_achado(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.ps["Win32_EncryptableVolume"] = sistema.AcessoNegado("0x80041003")
    saida = resultado(sis, monkeypatch, SISTEMA)
    assert saida.ids() == set()
    assert any("BitLocker" in log and "não verificado" in log for log in saida.logs)


def test_bitlocker_criptografando_nao_acusa(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.ps["Win32_EncryptableVolume"] = [
        {"DriveLetter": "C:", "ProtectionStatus": 0, "ConversionStatus": 2}
    ]
    assert resultado(sis, monkeypatch, SISTEMA).ids() == set()


def test_secure_boot_desligado_e_chave_ausente(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.reg(lw.SECURE_BOOT, "UEFISecureBootEnabled", 0)
    assert resultado(sis, monkeypatch, SISTEMA).ids() == {"host.win.secureboot.desligado"}
    legado = WindowsFalso()
    legado.reg(lw.SECURE_BOOT, "UEFISecureBootEnabled", None)  # BIOS legado: sem como afirmar
    assert resultado(legado, monkeypatch, SISTEMA).ids() == set()


def test_registro_remoto_em_execucao(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.ps["Get-Service -Name RemoteRegistry"] = {
        "Name": "RemoteRegistry",
        "Status": "Running",
        "StartType": "Manual",
    }
    assert resultado(sis, monkeypatch, SISTEMA).ids() == {"host.win.registro_remoto.ligado"}


def test_powershell2_presente_e_ausente(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.ps["MicrosoftWindowsPowerShellV2"] = [
        {"Name": "MicrosoftWindowsPowerShellV2", "InstallState": 1},
        {"Name": "MicrosoftWindowsPowerShellV2Root", "InstallState": 1},
    ]
    assert resultado(sis, monkeypatch, SISTEMA).ids() == {"host.win.powershell2.presente"}
    desativado = WindowsFalso()
    desativado.ps["MicrosoftWindowsPowerShellV2"] = [
        {"Name": "MicrosoftWindowsPowerShellV2Root", "InstallState": 2}
    ]
    assert resultado(desativado, monkeypatch, SISTEMA).ids() == set()


def test_autorun_nao_desativado(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.reg(lw.EXPLORER, "NoDriveTypeAutoRun", 145)
    achado = resultado(sis, monkeypatch, SISTEMA).by_id("host.win.autorun.ligado")[0]
    assert achado.confidence is Confidence.FIRM
    ausente = WindowsFalso()
    ausente.reg(lw.EXPLORER, "NoDriveTypeAutoRun", None)
    assert "host.win.autorun.ligado" not in resultado(ausente, monkeypatch, SISTEMA).ids()


def test_leitura_negada_do_registro_nao_vira_achado(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.negados.add((lw.UAC, "EnableLUA"))
    saida = resultado(sis, monkeypatch, UAC)
    assert saida.ids() == set()
    assert any("não verificado" in log for log in saida.logs)


def test_interpretacao_do_netstat_ignora_o_idioma() -> None:
    texto = netstat("0.0.0.0:445 4", "[::]:3389 77")
    portas = lw.ler_netstat(texto)
    assert [(p.porta, p.pid, p.em_todas) for p in portas] == [(445, 4, True), (3389, 77, True)]


def test_assinatura_smb_dos_dois_lados_gera_dois_achados(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.reg(lw.SMB_SERVIDOR, "RequireSecuritySignature", 0)
    sis.reg(lw.SMB_CLIENTE, "RequireSecuritySignature", 0)
    achados = resultado(sis, monkeypatch, REDE).by_id("host.win.smb.assinatura_nao_exigida")
    assert {a.discriminator for a in achados} == {"servidor", "cliente"}


def test_lsa_sem_valor_e_log_ilegivel_nao_vira_achado(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.reg(lw.LSA, "RunAsPPL", None)
    monkeypatch.setattr(lw, "lsass_protegido_no_log", lambda: None)
    assert "host.win.lsa.sem_protecao" not in resultado(sis, monkeypatch, CREDENCIAIS).ids()


def test_lsa_sem_valor_e_sem_evento_e_tentativo(monkeypatch: pytest.MonkeyPatch) -> None:
    sis = WindowsFalso()
    sis.reg(lw.LSA, "RunAsPPL", None)
    monkeypatch.setattr(lw, "lsass_protegido_no_log", lambda: False)
    achado = resultado(sis, monkeypatch, CREDENCIAIS).by_id("host.win.lsa.sem_protecao")[0]
    assert achado.confidence is Confidence.TENTATIVE


def test_lsass_no_log_falha_da_consulta_e_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sistema, "powershell_lista", lambda *a, **k: None)
    assert lw.lsass_protegido_no_log() is None


def test_senha_curta_e_tentativa_pois_so_a_politica_local_foi_lida(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sis = WindowsFalso()
    sis.comandos["net.exe"] = sistema.Resultado(
        0, net_accounts(minimo=0, bloqueio="10", idioma="en")
    )
    achado = resultado(sis, monkeypatch, CREDENCIAIS).by_id("host.win.senha.comprimento_curto")[0]
    assert achado.confidence is Confidence.TENTATIVE
