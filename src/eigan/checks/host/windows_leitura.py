"""Leitura do estado do Windows: registro, PowerShell e comandos, em funções pequenas.

Só lê. Todo o acesso ao sistema passa por ``sistema`` (os testes o substituem com
``monkeypatch``); aqui ficam os caminhos exatos das configurações e a interpretação das
saídas, sempre independente do idioma: números, nomes de enumeração e a ORDEM das
linhas, nunca os rótulos traduzidos.

Convenção: ``None`` quer dizer "não deu para saber" e nunca vira achado. Leitura negada
pelo sistema sobe como :class:`~.sistema.AcessoNegado`, exceto onde há outra fonte para
tentar antes de desistir.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any

from . import sistema
from .comum import inteiro, verdadeiro
from .sistema import AcessoNegado

SERVICOS = r"HKLM\SYSTEM\CurrentControlSet\Services"
LSA = r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
WDIGEST = r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
UAC = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
EXPLORER = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
DNS_CLIENTE = r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
SECURE_BOOT = r"HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State"
SMB_SERVIDOR = rf"{SERVICOS}\LanmanServer\Parameters"
SMB_CLIENTE = rf"{SERVICOS}\LanmanWorkstation\Parameters"
FIREWALL_POLITICA = r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall"
FIREWALL_LOCAL = rf"{SERVICOS}\SharedAccess\Parameters\FirewallPolicy"
TS_POLITICA = r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
TS_LOCAL = r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server"
RDP_TCP = rf"{TS_LOCAL}\WinStations\RDP-Tcp"

#: (nome exibido, nome na política de grupo, nome na configuração local). O perfil Privado
#: se chama ``StandardProfile`` na configuração local.
PERFIS_FIREWALL = (
    ("Domínio", "DomainProfile", "DomainProfile"),
    ("Privado", "PrivateProfile", "StandardProfile"),
    ("Público", "PublicProfile", "PublicProfile"),
)
_PERFIL_POWERSHELL = {"Domain": "Domínio", "Private": "Privado", "Public": "Público"}
#: ``Start`` de um serviço no registro: 4 = desativado
SERVICO_DESATIVADO = 4
#: ``InstallState`` de ``Win32_OptionalFeature``
RECURSO_LIGADO = 1
_RECURSO_DESLIGADO = (2, 3)  # desabilitado ou ausente; 4 = desconhecido
#: ``AntivirusSignatureAge`` quando as assinaturas nunca foram atualizadas
_IDADE_NUNCA = 65535
_SEM_RESPOSTA = frozenset({"0.0.0.0", "::", "*"})  # noqa: S104  # nosec B104
_LINHA_NETSTAT = re.compile(r"^\s*TCP\s+(\S+):(\d+)\s+\S+:(\d+)\s+.*?(\d+)\s*$", re.I)
_NUMERO_FINAL = re.compile(r"(\d+)\s*$")


# -- registro ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Ajuste:
    """Um valor do registro e de onde ele veio (vai para a evidência do achado)."""

    chave: str
    nome: str
    valor: Any = None

    @property
    def numero(self) -> int | None:
        return None if self.valor is None else inteiro(self.valor)

    @property
    def caminho(self) -> str:
        return f"{self.chave}\\{self.nome}"

    def __str__(self) -> str:
        return f"{self.caminho} = {'(ausente)' if self.valor is None else self.valor}"


def ler(chave: str, nome: str) -> Ajuste:
    return Ajuste(chave, nome, sistema.read_registry_value(chave, nome))


def efetivo(politica: str, local: str, nome: str) -> Ajuste:
    """O valor que vale de fato: a política de grupo, quando definida, prevalece sobre o local."""
    ajuste = ler(politica, nome)
    return ajuste if ajuste.valor is not None else ler(local, nome)


def servico_desativado(nome: str) -> bool:
    return ler(rf"{SERVICOS}\{nome}", "Start").numero == SERVICO_DESATIVADO


def _sem_negar_json(script: str) -> Any:
    """``powershell_json`` para quando há outra fonte: leitura negada vale como "sem dado"."""
    try:
        return sistema.powershell_json(script)
    except AcessoNegado:
        return None


# -- firewall -----------------------------------------------------------------------------
@dataclass(frozen=True)
class PerfilFirewall:
    nome: str
    ligado: bool | None
    origem: str


def perfis_firewall() -> list[PerfilFirewall]:
    """Estado efetivo de cada perfil. O PowerShell só entra se o registro não responder."""
    perfis: list[PerfilFirewall] = []
    reserva: dict[str, bool | None] | None = None
    for nome, politica, local in PERFIS_FIREWALL:
        ajuste = _ajuste_firewall(politica, local)
        if ajuste is not None and ajuste.numero is not None:
            perfis.append(PerfilFirewall(nome, ajuste.numero != 0, str(ajuste)))
            continue
        if reserva is None:
            reserva = _firewall_powershell()
        origem = f"Get-NetFirewallProfile -PolicyStore ActiveStore ({nome}): {reserva.get(nome)}"
        perfis.append(PerfilFirewall(nome, reserva.get(nome), origem))
    return perfis


def _ajuste_firewall(politica: str, local: str) -> Ajuste | None:
    try:
        return efetivo(
            rf"{FIREWALL_POLITICA}\{politica}", rf"{FIREWALL_LOCAL}\{local}", "EnableFirewall"
        )
    except AcessoNegado:
        return None


def _firewall_powershell() -> dict[str, bool | None]:
    dados = sistema.powershell_lista(
        "Get-NetFirewallProfile -PolicyStore ActiveStore | "
        "Select-Object Name, @{n='Enabled';e={[string]$_.Enabled}}"
    )
    return {
        _PERFIL_POWERSHELL.get(str(item.get("Name")), str(item.get("Name"))): verdadeiro(
            item.get("Enabled")
        )
        for item in dados or []
        if isinstance(item, dict)
    }


def produtos_de_terceiros(classe: str) -> list[str] | None:
    """Produtos de outros fabricantes na Central de Segurança; None se ela não responder.

    A Central de Segurança (``root/SecurityCenter2``) só existe no Windows cliente. O
    ``classe`` é uma de ``AntiVirusProduct`` e ``FirewallProduct``.
    """
    try:
        dados = sistema.powershell_lista(
            f"Get-CimInstance -Namespace root/SecurityCenter2 -ClassName {classe} | Select-Object displayName"
        )
    except AcessoNegado:
        return None
    if dados is None:
        return None
    nomes = [str(item.get("displayName") or "") for item in dados if isinstance(item, dict)]
    return [nome for nome in nomes if nome and "defender" not in nome.lower()]


# -- Microsoft Defender -------------------------------------------------------------------
@dataclass(frozen=True)
class EstadoDefender:
    modo: str = ""
    servico: bool | None = None
    antivirus: bool | None = None
    tempo_real: bool | None = None
    idade_assinaturas: int | None = None
    assinaturas_em: str = ""


def estado_defender() -> EstadoDefender | None:
    """``Get-MpComputerStatus``; None se o Defender não responder (ex.: removido do servidor)."""
    dados = sistema.powershell_json(
        "Get-MpComputerStatus | Select-Object AMRunningMode, AMServiceEnabled, AntivirusEnabled, "
        "RealTimeProtectionEnabled, AntivirusSignatureAge, "
        "@{n='AssinaturasEm';e={if ($_.AntivirusSignatureLastUpdated) "
        "{ $_.AntivirusSignatureLastUpdated.ToString('s') } else { $null }}}"
    )
    if not isinstance(dados, dict):
        return None
    data = _data_iso(dados.get("AssinaturasEm"))
    idade = (sistema.hoje() - data).days if data else inteiro(dados.get("AntivirusSignatureAge"))
    return EstadoDefender(
        modo=str(dados.get("AMRunningMode") or ""),
        servico=_booleano(dados.get("AMServiceEnabled")),
        antivirus=_booleano(dados.get("AntivirusEnabled")),
        tempo_real=_booleano(dados.get("RealTimeProtectionEnabled")),
        idade_assinaturas=idade if idade is None or idade < _IDADE_NUNCA else None,
        assinaturas_em=data.isoformat() if data else "",
    )


def _booleano(valor: Any) -> bool | None:
    return None if valor is None else verdadeiro(valor)


def _data_iso(valor: Any) -> date | None:
    try:
        return datetime.fromisoformat(str(valor)).date() if valor else None
    except ValueError:
        return None


# -- SMB ------------------------------------------------------------------------------------
@dataclass(frozen=True)
class EstadoSmb1:
    ligado: bool | None
    evidencia: str
    firme: bool = True


def recursos_opcionais(padrao: str) -> dict[str, int] | None:
    """Estado dos recursos opcionais cujo nome casa com ``padrao`` (curinga ``%``).

    ``Win32_OptionalFeature`` não exige administrador. Dicionário vazio: o recurso nem existe
    nesta versão do Windows. None: a consulta falhou.
    """
    dados = sistema.powershell_lista(
        f"Get-CimInstance -ClassName Win32_OptionalFeature -Filter \"Name LIKE '{padrao}'\" | "
        "Select-Object Name, InstallState"
    )
    if dados is None:
        return None
    return {
        str(item.get("Name")): inteiro(item.get("InstallState")) or 0
        for item in dados
        if isinstance(item, dict)
    }


def estado_smb1_servidor() -> EstadoSmb1:
    """Se o servidor SMB aceita SMBv1, cruzando registro, cmdlet e recurso opcional.

    O valor ``SMB1`` ausente não prova nada (no Windows 11 o recurso nem vem instalado): só o
    ``0`` explícito encerra a análise. O recurso ``SMB1Protocol`` pai pode constar como ligado
    com o componente de servidor desligado, por isso vale ``SMB1Protocol-Server`` antes dele.
    """
    registro = ler(SMB_SERVIDOR, "SMB1")
    if registro.numero == 0:
        return EstadoSmb1(False, str(registro))
    config = _sem_negar_json("Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol")
    cmdlet = _booleano(config.get("EnableSMB1Protocol")) if isinstance(config, dict) else None
    origem = f"Get-SmbServerConfiguration: EnableSMB1Protocol={cmdlet}"
    if cmdlet is False:
        return EstadoSmb1(False, origem)
    recurso, texto_recurso = _recurso_smb1()
    evidencia = "; ".join(p for p in (origem if cmdlet else "", texto_recurso, str(registro)) if p)
    if recurso is False:
        return EstadoSmb1(False, evidencia)
    if cmdlet or recurso:
        return EstadoSmb1(True, evidencia)
    if registro.numero == 1:  # sem cmdlet e sem recurso: só o registro aponta, com menos certeza
        return EstadoSmb1(True, evidencia, firme=False)
    return EstadoSmb1(None, evidencia)


def _recurso_smb1() -> tuple[bool | None, str]:
    try:
        recursos = recursos_opcionais("SMB1Protocol%")
    except AcessoNegado:
        recursos = None
    if recursos is None:
        return None, ""
    nome = "SMB1Protocol-Server" if "SMB1Protocol-Server" in recursos else "SMB1Protocol"
    estado = recursos.get(nome)
    if estado is None:  # o recurso não existe nesta versão do Windows
        return False, "Win32_OptionalFeature: SMB1Protocol não existe nesta versão"
    texto = f"Win32_OptionalFeature {nome}: InstallState={estado}"
    if estado == RECURSO_LIGADO:
        return True, texto
    return (False, texto) if estado in _RECURSO_DESLIGADO else (None, texto)


@dataclass(frozen=True)
class AssinaturaSmb:
    lado: str  # servidor | cliente
    exigida: bool | None
    origem: str


def assinatura_smb(lado: str) -> AssinaturaSmb:
    """Se a assinatura é exigida. No SMB2+ só ``RequireSecuritySignature`` conta.

    ``EnableSecuritySignature`` é ignorado no SMB2 ou mais novo, então nem é lido. Sem o valor
    no registro, quem responde é o cmdlet: o padrão mudou no Windows 11 24H2/Server 2025.
    """
    chave, cmdlet = (
        (SMB_SERVIDOR, "Get-SmbServerConfiguration")
        if lado == "servidor"
        else (SMB_CLIENTE, "Get-SmbClientConfiguration")
    )
    ajuste = ler(chave, "RequireSecuritySignature")
    if ajuste.numero is not None:
        return AssinaturaSmb(lado, ajuste.numero != 0, str(ajuste))
    config = _sem_negar_json(f"{cmdlet} | Select-Object RequireSecuritySignature")
    exigida = (
        _booleano(config.get("RequireSecuritySignature")) if isinstance(config, dict) else None
    )
    return AssinaturaSmb(lado, exigida, f"{cmdlet}: RequireSecuritySignature={exigida}; {ajuste}")


# -- Área de Trabalho Remota --------------------------------------------------------------
@dataclass(frozen=True)
class EstadoRdp:
    ligado: bool
    conexoes: Ajuste
    nla: Ajuste


def estado_rdp() -> EstadoRdp:
    conexoes = efetivo(TS_POLITICA, TS_LOCAL, "fDenyTSConnections")
    nla = efetivo(TS_POLITICA, RDP_TCP, "UserAuthentication")
    ligado = conexoes.numero == 0 and not servico_desativado("TermService")
    return EstadoRdp(ligado, conexoes, nla)


# -- NetBIOS e portas -----------------------------------------------------------------------
def adaptadores_netbios() -> list[tuple[str, int]] | None:
    """(adaptador, ``TcpipNetbiosOptions``) de cada placa ativa: 0 = via DHCP, 1 = ligado, 2 = desligado."""
    dados = sistema.powershell_lista(
        "Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | "
        "Select-Object Description, TcpipNetbiosOptions"
    )
    if dados is None:
        return None
    adaptadores: list[tuple[str, int]] = []
    for item in dados:
        opcao = inteiro(item.get("TcpipNetbiosOptions")) if isinstance(item, dict) else None
        if opcao is not None:
            adaptadores.append((str(item.get("Description") or "?"), opcao))
    return adaptadores


@dataclass(frozen=True)
class PortaEmEscuta:
    endereco: str
    porta: int
    pid: int

    @property
    def em_todas(self) -> bool:
        """Se escuta em todas as interfaces de rede (``0.0.0.0`` ou ``[::]``)."""
        return self.endereco.strip("[]") in _SEM_RESPOSTA

    @property
    def local(self) -> bool:
        """Se só atende à própria máquina (``127.0.0.1``, ``[::1]``)."""
        endereco = self.endereco.strip("[]")
        return endereco == "::1" or endereco.startswith("127.")


def ler_netstat(saida: str) -> list[PortaEmEscuta]:
    """Portas TCP em escuta. O estado vem traduzido; quem marca a escuta é a porta remota 0."""
    portas: list[PortaEmEscuta] = []
    for linha in saida.splitlines():
        achado = _LINHA_NETSTAT.match(linha)
        if achado and achado.group(3) == "0":
            portas.append(
                PortaEmEscuta(achado.group(1), int(achado.group(2)), int(achado.group(4)))
            )
    return portas


def portas_em_escuta() -> list[PortaEmEscuta] | None:
    """``netstat -ano``; None se o comando falhou."""
    resultado = sistema.run_command(
        [sistema.programa_windows("NETSTAT.EXE"), "-ano"], tempo=30.0, codificacao="oem"
    )
    if resultado is None or resultado.codigo != 0:
        return None
    return ler_netstat(resultado.saida)


# -- contas -----------------------------------------------------------------------------------
@dataclass(frozen=True)
class PoliticaContas:
    comprimento_minimo: int
    limite_bloqueio: int


def ler_net_accounts(saida: str) -> PoliticaContas | None:
    """Interpreta ``net accounts`` pela ORDEM das linhas (os rótulos mudam com o idioma).

    Linhas: 0 logoff forçado, 1 idade mínima, 2 idade máxima, 3 comprimento mínimo, 4 histórico,
    5 limite de bloqueio, 6 duração, 7 janela, 8 função. Idade mínima e comprimento são sempre
    números: se não forem, a saída não é a esperada e nada é avaliado. O limite de bloqueio
    vem como número ou como uma palavra traduzida ("Never", "Nunca"), que significa 0.
    """
    linhas = [linha.strip() for linha in saida.splitlines() if linha.strip()]
    if len(linhas) < 8:
        return None
    idade_minima = _numero_final(linhas[1])
    comprimento = _numero_final(linhas[3])
    if idade_minima is None or comprimento is None:
        return None
    return PoliticaContas(comprimento, _numero_final(linhas[5]) or 0)


def _numero_final(linha: str) -> int | None:
    achado = _NUMERO_FINAL.search(linha)
    return int(achado.group(1)) if achado else None


def politica_contas() -> PoliticaContas | None:
    resultado = sistema.run_command(
        [sistema.programa_windows("net.exe"), "accounts"], tempo=30.0, codificacao="oem"
    )
    if resultado is None:
        return None
    if sistema.negado(resultado.erro):
        raise AcessoNegado("net accounts")
    return ler_net_accounts(resultado.saida) if resultado.codigo == 0 else None


@dataclass(frozen=True)
class ContaConvidado:
    nome: str
    ativa: bool


def conta_convidado() -> ContaConvidado | None:
    """A conta de convidado pelo SID (termina em -501): o nome muda com o idioma."""
    dados = sistema.powershell_lista(
        "Get-CimInstance -ClassName Win32_UserAccount -Filter \"LocalAccount=True AND SID LIKE '%-501'\" | "
        "Select-Object Name, Disabled"
    )
    for item in dados or []:
        desativada = _booleano(item.get("Disabled")) if isinstance(item, dict) else None
        if desativada is not None:
            return ContaConvidado(str(item.get("Name") or "?"), not desativada)
    return None


def lsass_protegido_no_log() -> bool | None:
    """Se o log System registra o LSASS iniciado como processo protegido (evento WinInit 12).

    É a verificação que a Microsoft indica, e vale para quem foi ligado sem valor no registro
    (habilitação automática do Windows 11 22H2+). Evento ausente não prova o contrário: o log
    pode ter sido reciclado.
    """
    try:
        dados = sistema.powershell_lista(
            "Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Wininit'; Id=12} "
            "-MaxEvents 1 -ErrorAction SilentlyContinue | Select-Object Id"
        )
    except AcessoNegado:
        return None
    if dados is None:
        return None  # falha ou tempo esgotado: não avaliado
    return bool(dados)


# -- atualizações -------------------------------------------------------------------------------
@dataclass(frozen=True)
class Atualizacao:
    kb: str
    data: date


def atualizacoes_instaladas() -> list[Atualizacao] | None:
    """``Get-HotFix`` com data legível, da mais nova para a mais antiga; None se falhou.

    Datas no futuro são descartadas: há instalações que gravam a data com dia e mês trocados.
    """
    dados = sistema.powershell_lista(
        "Get-HotFix | Select-Object HotFixID, "
        "@{n='Data';e={if ($_.InstalledOn) { $_.InstalledOn.ToString('s') } else { $null }}}",
        tempo=60.0,
    )
    if dados is None:
        return None
    hoje = sistema.hoje()
    lista: list[Atualizacao] = []
    for item in dados:
        data = _data_iso(item.get("Data")) if isinstance(item, dict) else None
        if data is not None and data <= hoje:
            lista.append(Atualizacao(str(item.get("HotFixID") or "?"), data))
    return sorted(lista, key=lambda a: a.data, reverse=True)


# -- disco e serviços ----------------------------------------------------------------------------
@dataclass(frozen=True)
class VolumeBitLocker:
    letra: str
    protecao: int | None  # 0 = desligada, 1 = ligada, 2 = desconhecida
    conversao: int | None


def volume_do_sistema() -> VolumeBitLocker | None:
    """BitLocker do disco do sistema. Sem administrador, o Windows nega (AcessoNegado).

    None: a classe não existe (BitLocker não instalado no servidor) ou o volume não é listado.
    """
    dados = sistema.powershell_lista(
        "Get-CimInstance -Namespace root/CIMV2/Security/MicrosoftVolumeEncryption "
        '-ClassName Win32_EncryptableVolume -Filter ("DriveLetter=\'" + $env:SystemDrive + "\'") | '
        "Select-Object DriveLetter, ProtectionStatus, ConversionStatus"
    )
    for item in dados or []:
        if isinstance(item, dict):
            return VolumeBitLocker(
                str(item.get("DriveLetter") or "?"),
                inteiro(item.get("ProtectionStatus")),
                inteiro(item.get("ConversionStatus")),
            )
    return None


@dataclass(frozen=True)
class EstadoServico:
    nome: str
    em_execucao: bool | None
    inicio: str = ""


def estado_servico(nome: str) -> EstadoServico | None:
    """``Get-Service``: ``Status`` e ``StartType`` são nomes de enumeração, iguais em todo idioma."""
    dados = sistema.powershell_json(
        f"Get-Service -Name {nome} | Select-Object Name, "
        "@{n='Status';e={[string]$_.Status}}, @{n='StartType';e={[string]$_.StartType}}"
    )
    if not isinstance(dados, dict):
        return None
    status = str(dados.get("Status") or "")
    return EstadoServico(
        nome, status == "Running" if status else None, str(dados.get("StartType") or "")
    )
