"""Um Windows falso para testar as checagens de host sem tocar a máquina (roda em qualquer SO).

``WindowsFalso`` substitui as funções de ``eigan.checks.host.sistema`` (registro, PowerShell e
comandos). A base começa segura; cada teste estraga só o que quer avaliar.
"""

from __future__ import annotations

from datetime import date
from typing import Any

import pytest
from helpers import CheckOutcome, run_check

from eigan.checks.host import sistema
from eigan.checks.host import windows_leitura as lw
from eigan.core import facts
from eigan.core.models import Fact

HOJE = date(2026, 11, 1)
FATO_LOCAL = Fact(kind=facts.LOCAL, key="windows", data={"platform": "windows"})

NET_ACCOUNTS_EN = """Force user logoff how long after time expires?:       Never
Minimum password age (days):                          0
Maximum password age (days):                          42
Minimum password length:                              {minimo}
Length of password history maintained:                None
Lockout threshold:                                    {bloqueio}
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        WORKSTATION
The command completed successfully.
"""
NET_ACCOUNTS_PT = """Forcar logoff do usuario apos expirar o tempo?:      Nunca
Duracao minima da senha (dias):                       0
Duracao maxima da senha (dias):                       42
Comprimento minimo da senha:                          {minimo}
Tamanho do historico de senhas mantido:               Nenhum
Limite de bloqueio:                                   {bloqueio}
Duracao do bloqueio (minutos):                        30
Janela de observacao do bloqueio (minutos):           30
Funcao do computador:                                 WORKSTATION
O comando foi concluido com sucesso.
"""
CABECALHO_NETSTAT = """
Conexoes ativas

  Proto  Endereco local         Endereco Estrangeiro   Estado           PID
"""


def net_accounts(minimo: int = 12, bloqueio: str = "5", idioma: str = "en") -> str:
    modelo = NET_ACCOUNTS_EN if idioma == "en" else NET_ACCOUNTS_PT
    return modelo.format(minimo=minimo, bloqueio=bloqueio)


def netstat(*escutas: str) -> str:
    """Saída de ``netstat -ano`` com as escutas dadas (ex.: ``'0.0.0.0:3389 4321'``)."""
    linhas = [
        f"  TCP    {e.split()[0]:<22} 0.0.0.0:0              OUVINDO         {e.split()[1]}"
        for e in escutas
    ]
    return CABECALHO_NETSTAT + "\n".join(linhas) + "\n"


class WindowsFalso:
    """Registro, PowerShell e comandos de um Windows 11 sem problemas."""

    def __init__(self) -> None:
        self.registro: dict[tuple[str, str], Any] = {}
        self.negados: set[tuple[str, str]] = set()
        self.ps: dict[str, Any] = {}
        self.comandos: dict[str, sistema.Resultado | None] = {}
        self.admin = False
        self._base()

    # -- montagem ---------------------------------------------------------------------
    def reg(self, chave: str, nome: str, valor: Any) -> None:
        """Define (ou, com ``None``, remove) um valor do registro."""
        if valor is None:
            self.registro.pop((chave, nome), None)
        else:
            self.registro[(chave, nome)] = valor

    def _base(self) -> None:
        for _, _, local in lw.PERFIS_FIREWALL:
            self.reg(rf"{lw.FIREWALL_LOCAL}\{local}", "EnableFirewall", 1)
        self.reg(lw.SMB_SERVIDOR, "SMB1", 0)
        self.reg(lw.SMB_SERVIDOR, "RequireSecuritySignature", 1)
        self.reg(lw.SMB_CLIENTE, "RequireSecuritySignature", 1)
        self.reg(lw.TS_LOCAL, "fDenyTSConnections", 1)
        self.reg(lw.RDP_TCP, "UserAuthentication", 1)
        self.reg(lw.UAC, "EnableLUA", 1)
        self.reg(lw.UAC, "ConsentPromptBehaviorAdmin", 5)
        self.reg(lw.WDIGEST, "UseLogonCredential", 0)
        self.reg(lw.LSA, "RunAsPPL", 1)
        self.reg(lw.LSA, "LmCompatibilityLevel", 5)
        self.reg(lw.DNS_CLIENTE, "EnableMulticast", 0)
        self.reg(lw.EXPLORER, "NoDriveTypeAutoRun", 255)
        self.reg(lw.SECURE_BOOT, "UEFISecureBootEnabled", 1)
        self.ps = {
            "AntiVirusProduct": [],
            "FirewallProduct": [],
            "Get-MpComputerStatus": {
                "AMRunningMode": "Normal",
                "AMServiceEnabled": True,
                "AntivirusEnabled": True,
                "RealTimeProtectionEnabled": True,
                "AntivirusSignatureAge": 1,
                "AssinaturasEm": "2026-10-31T08:00:00",
            },
            "MicrosoftWindowsPowerShellV2": [],
            "Get-HotFix": [{"HotFixID": "KB5099999", "Data": "2026-10-20T00:00:00"}],
            "Win32_EncryptableVolume": [
                {"DriveLetter": "C:", "ProtectionStatus": 1, "ConversionStatus": 1}
            ],
            "Get-Service -Name RemoteRegistry": {
                "Name": "RemoteRegistry",
                "Status": "Stopped",
                "StartType": "Disabled",
            },
            "Win32_NetworkAdapterConfiguration": [
                {"Description": "Ethernet", "TcpipNetbiosOptions": 2}
            ],
            "Win32_UserAccount": [{"Name": "Convidado", "Disabled": True}],
            "Get-WinEvent": [{"Id": 12}],
            "Get-SmbServerConfiguration": {"EnableSMB1Protocol": False},
            "Get-SmbClientConfiguration": {"RequireSecuritySignature": True},
        }
        self.comandos = {
            "net.exe": sistema.Resultado(0, net_accounts()),
            "NETSTAT.EXE": sistema.Resultado(0, netstat("127.0.0.1:5432 700")),
        }

    # -- o que substitui o módulo sistema ----------------------------------------------
    def instalar(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sistema, "read_registry_value", self._ler_registro)
        monkeypatch.setattr(sistema, "powershell_json", self._powershell_json)
        monkeypatch.setattr(sistema, "powershell_lista", self._powershell_lista)
        monkeypatch.setattr(sistema, "run_command", self._comando)
        monkeypatch.setattr(sistema, "programa_windows", lambda nome: nome.rsplit("\\", 1)[-1])
        monkeypatch.setattr(sistema, "hoje", lambda: HOJE)
        monkeypatch.setattr(sistema, "is_admin", lambda: self.admin)

    def _ler_registro(self, caminho: str, nome: str) -> Any:
        if (caminho, nome) in self.negados:
            raise sistema.AcessoNegado(f"{caminho}\\{nome}")
        return self.registro.get((caminho, nome))

    def _resposta(self, script: str) -> Any:
        for trecho, resposta in self.ps.items():
            if trecho in script:
                if isinstance(resposta, Exception):
                    raise resposta
                return resposta
        return None

    def _powershell_json(self, script: str, tempo: float = 40.0) -> Any:
        return self._resposta(script)

    def _powershell_lista(self, script: str, tempo: float = 40.0) -> list[Any] | None:
        resposta = self._resposta(script)
        if resposta is None:
            return None
        return resposta if isinstance(resposta, list) else [resposta]

    def _comando(
        self, args: list[str], tempo: float = 30.0, codificacao: str = "utf-8", ambiente: Any = None
    ) -> Any:
        return self.comandos.get(args[0])


def rodar(sis: WindowsFalso, monkeypatch: pytest.MonkeyPatch, check_id: str) -> CheckOutcome:
    """Executa uma checagem de Windows contra o sistema falso (também em Linux)."""
    sis.instalar(monkeypatch)
    return run_check(check_id, FATO_LOCAL, target="local")
