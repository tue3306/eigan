"""Eventos do Windows (Security e System): decide o que virou indício de ataque.

Cada evento chega como ``EventoWindows`` (vindo do XML ou do CSV). Os contadores só são lidos
no fim, com tudo ordenado, porque ``wevtutil`` e ``Get-WinEvent`` exportam do mais novo para
o mais antigo.
"""

from __future__ import annotations

import re
from collections import defaultdict

from ...core import redact
from ...core.context import CheckContext
from ...core.models import Confidence, Severity
from .agregacao import (
    CHAVE_DEMAIS,
    MAX_ACHADOS_POR_TIPO,
    Indicio,
    Relato,
    Tabela,
    contar_antes,
    eh_ip,
    ip_interno,
    limpar,
    pico_na_janela,
    principais,
    relatar,
)
from .windows import EventoWindows, resumo_campos

FORCA_BRUTA_MIN_FALHAS = 10
FORCA_BRUTA_JANELA_S = 600.0
FORCA_BRUTA_MIN_TOTAL = 30
FORCA_BRUTA_TOTAL_ALTO = 200
FORCA_BRUTA_MIN_USUARIOS = 3
SPRAY_MIN_USUARIOS = 5
SUCESSO_MIN_FALHAS = 5
SUCESSO_JANELA_S = 3_600.0
#: falhas concentradas antes do logon: 5 em 10 min ou 10 em 1 h
SUCESSO_JANELA_CURTA_S = 600.0
SUCESSO_MIN_FALHAS_LONGA = 10
MAX_SUCESSOS_POR_IP = 200
#: tipo de logon 10 = RemoteInteractive (Remote Desktop)
LOGON_RDP = "10"

#: SIDs conhecidos de grupos privilegiados (documentados pela Microsoft)
SIDS_PRIVILEGIADOS = frozenset({"S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-551"})
_FINAIS_SID_DOMINIO = ("-512", "-518", "-519")
_GRUPOS_PRIVILEGIADOS = frozenset(
    {
        "administrators",
        "administradores",
        "domain admins",
        "admins. do domínio",
        "admins. do dominio",
        "administradores do domínio",
        "administradores do dominio",
        "enterprise admins",
        "administradores de empresa",
        "administradores corporativos",
        "schema admins",
        "administradores de esquema",
        "backup operators",
        "operadores de backup",
        "account operators",
        "operadores de conta",
    }
)

_CAMINHO_SERVICO_SUSPEITO = re.compile(
    r"%comspec%|\bcmd(?:\.exe)?\s+/[ck]\b|powershell|pwsh|mshta|wscript|cscript|"
    r"\\temp\\|\\appdata\\|\\programdata\\(?!microsoft\\windows defender\\)|\\users\\public\\|\\windows\\debug\\|^\\\\|"
    r"\\\\[^\\]+\\(?:admin\$|c\$)|-enc(?:odedcommand)?\s",
    re.I,
)

_CAMINHO_SERVICO_FORTE = re.compile(
    r"%comspec%|\bcmd(?:\.exe)?\s+/[ck]\b|powershell|pwsh|mshta|wscript|cscript|^\\\\|"
    r"\\\\[^\\]+\\(?:admin\$|c\$)|-enc(?:odedcommand)?\s",
    re.I,
)

#: (categoria, rótulo, expressão, técnicas do ATT&CK)
_COMANDOS: tuple[tuple[str, str, re.Pattern[str], tuple[str, ...]], ...] = (
    (
        "powershell_codificado",
        "PowerShell com comando codificado (-EncodedCommand)",
        re.compile(
            r"\b(?:powershell|pwsh)(?:\.exe)?\b.*?\s[-/](?:e|ec|en|enc|enco|encod|encode|encoded|"
            r"encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)"
            r"\s+[\"']?[A-Za-z0-9+/=]{20,}",
            re.I,
        ),
        ("T1059.001", "T1027.010"),
    ),
    (
        "powershell_download",
        "PowerShell baixando e executando conteúdo da Internet",
        re.compile(
            r"\b(?:powershell|pwsh)(?:\.exe)?\b.*?(?:downloadstring|downloadfile|invoke-webrequest|"
            r"\biwr\b|net\.webclient).*?(?:\biex\b|invoke-expression|https?://)",
            re.I,
        ),
        ("T1059.001", "T1105"),
    ),
    (
        "certutil_download",
        "certutil usado para baixar arquivo (-urlcache)",
        re.compile(r"\bcertutil(?:\.exe)?\b.*?-urlcache\b", re.I),
        ("T1105",),
    ),
    (
        "mshta_remoto",
        "mshta executando script remoto ou embutido",
        re.compile(r"\bmshta(?:\.exe)?\b.*?(?:https?://|javascript:|vbscript:)", re.I),
        ("T1218.005",),
    ),
    (
        "rundll32_javascript",
        "rundll32 executando JavaScript",
        re.compile(r"\brundll32(?:\.exe)?\b.*?javascript:", re.I),
        ("T1218.011",),
    ),
    (
        "regsvr32_remoto",
        "regsvr32 carregando script remoto (/i:http)",
        re.compile(r"\bregsvr32(?:\.exe)?\b.*?/i:\s*https?://", re.I),
        ("T1218.010",),
    ),
)


def _hospedeiro(evento: EventoWindows) -> str:
    return limpar(evento.computador, 64)


def grupo_privilegiado(evento: EventoWindows) -> bool:
    """O grupo do evento 4728/4732/4756 dá poderes administrativos."""
    sid = evento.campo("TargetSid").upper()
    if (
        sid in SIDS_PRIVILEGIADOS
        or sid.startswith("S-1-5-21-")
        and sid.endswith(_FINAIS_SID_DOMINIO)
    ):
        return True
    return evento.campo("TargetUserName").strip().lower() in _GRUPOS_PRIVILEGIADOS


def servico_suspeito(caminho: str) -> bool:
    """Caminho do serviço com cara de dropper: shell, pasta gravável ou compartilhamento."""
    return _CAMINHO_SERVICO_SUSPEITO.search(caminho) is not None


def servico_forte(caminho: str) -> bool:
    """Caminho que só ferramenta de ataque usa: shell, compartilhamento administrativo ou -enc."""
    return _CAMINHO_SERVICO_FORTE.search(caminho) is not None


def classificar_comando(linha: str) -> tuple[str, str, tuple[str, ...]] | None:
    """Reconhece a linha de comando de um evento 4688 suspeito. ``None`` se for normal."""
    for categoria, rotulo, expressao, tecnicas in _COMANDOS:
        if expressao.search(linha) is not None:
            return categoria, rotulo, tecnicas
    return None


_SEGREDO_COMANDO = re.compile(
    r"(?P<pre>(?:"
    r"(?i:net1?(?:\.exe)?)\s+user\s+\S+\s+"  # net user conta SENHA
    r"|(?i:(?<!\S)-(?:p|pw|pass|password))(?:\s+|=|:)"  # -p senha, -pw senha, -password=senha
    r"|(?<!\S)-p(?=[^\s=:\-])"  # mysql -pSENHA
    r"|(?i:(?<!\S)/(?:p|rp|password))(?::|\s+)"  # schtasks /rp senha, /p:senha
    r"|://[^\s:@/]+:"  # http://usuario:SENHA@host
    r"|(?i:(?<!\S)-u)\s+[^\s:]+:"  # curl -u usuario:SENHA
    r"))(?P<segredo>[^\s\"'@]+)"
)


def mascarar_comando(linha: str) -> str:
    """Esconde senhas que aparecem em linhas de comando (``net user x senha``, ``-p senha``)."""
    return _SEGREDO_COMANDO.sub(
        lambda m: m.group("pre") + redact.mask(m.group("segredo"), 1), linha
    )


class AnalisadorWindows:
    """Acumula eventos de segurança do Windows; decide e reporta só no fim."""

    def __init__(self) -> None:
        self.eventos = 0
        self.fuso = "UTC"
        self.falhas = Tabela()
        self.sucessos_rdp: dict[str, list[tuple[float | None, str, str]]] = defaultdict(list)
        self.contas_criadas = Tabela()
        self.grupos = Tabela()
        self.limpezas = Tabela()
        self.servicos = Tabela()
        self.servicos_suspeitos: set[str] = set()
        self.servicos_fortes: set[str] = set()
        self.comandos: dict[str, Tabela] = {}
        self.rotulos: dict[str, tuple[str, tuple[str, ...]]] = {}

    # -- leitura -----------------------------------------------------------------
    def alimentar(self, evento: EventoWindows) -> None:
        self.eventos += 1
        if evento.id == 4625:
            self._falha(evento)
        elif evento.id == 4624:
            self._logon(evento)
        elif evento.id == 4720:
            self._conta(evento)
        elif evento.id in (4728, 4732, 4756):
            self._grupo(evento)
        elif evento.id in (1102, 104):
            self._limpeza(evento)
        elif evento.id in (4697, 7045):
            self._servico(evento)
        elif evento.id == 4688:
            self._processo(evento)

    def _origem(self, evento: EventoWindows) -> str:
        ip = evento.campo("IpAddress")
        if ip and eh_ip(ip):
            return ip
        estacao = evento.campo("WorkstationName")
        return f"estação {limpar(estacao, 40)}" if estacao else ""

    def _falha(self, evento: EventoWindows) -> None:
        origem = self._origem(evento)
        if not origem:
            return
        self.falhas.registrar(
            origem,
            evento.momento,
            resumo_campos(evento, ("TargetUserName", "IpAddress", "LogonType", "SubStatus")),
            usuario=limpar(evento.campo("TargetUserName"), 64),
            arquivo=evento.referencia.rsplit(":", 1)[0],
            guardar_tempo=True,
        )

    def _logon(self, evento: EventoWindows) -> None:
        ip = evento.campo("IpAddress")
        if evento.campo("LogonType") != LOGON_RDP or not eh_ip(ip):
            return
        lista = self.sucessos_rdp[ip]
        if len(lista) < MAX_SUCESSOS_POR_IP:
            amostra = resumo_campos(evento, ("TargetUserName", "IpAddress", "LogonType"))
            lista.append((evento.momento, limpar(evento.campo("TargetUserName"), 64), amostra))

    def _conta(self, evento: EventoWindows) -> None:
        nome = evento.campo("TargetUserName")
        if nome.endswith("$"):  # conta de máquina: criada ao ingressar no domínio
            return
        self.contas_criadas.registrar(
            nome or "(sem nome)",
            evento.momento,
            resumo_campos(evento, ("TargetUserName", "SubjectUserName")),
            usuario=limpar(evento.campo("SubjectUserName"), 64),
            extra=_hospedeiro(evento),
        )

    def _grupo(self, evento: EventoWindows) -> None:
        if not grupo_privilegiado(evento):
            return
        grupo = limpar(evento.campo("TargetUserName") or evento.campo("TargetSid"), 64)
        membro = evento.campo("MemberName") or evento.campo("MemberSid")
        self.grupos.registrar(
            f"{grupo}|{limpar(membro, 80)}",
            evento.momento,
            resumo_campos(evento, ("MemberName", "MemberSid", "TargetUserName", "SubjectUserName")),
            usuario=limpar(evento.campo("SubjectUserName"), 64),
            extra=_hospedeiro(evento),
        )

    def _limpeza(self, evento: EventoWindows) -> None:
        self.limpezas.registrar(
            _hospedeiro(evento) or "(máquina desconhecida)",
            evento.momento,
            resumo_campos(evento, ("SubjectUserName", "Channel")),
            usuario=limpar(evento.campo("SubjectUserName"), 64),
            extra=limpar(evento.campo("Channel"), 40),
        )

    def _servico(self, evento: EventoWindows) -> None:
        nome = limpar(evento.campo("ServiceName"), 80) or "(sem nome)"
        caminho = evento.campo("ImagePath") or evento.campo("ServiceFileName")
        if servico_suspeito(caminho):
            self.servicos_suspeitos.add(nome)
            if servico_forte(caminho):
                self.servicos_fortes.add(nome)
        self.servicos.registrar(
            nome,
            evento.momento,
            resumo_campos(
                evento, ("ServiceName", "ImagePath", "ServiceFileName", "SubjectUserName")
            ),
            usuario=limpar(evento.campo("SubjectUserName"), 64),
            arquivo=limpar(caminho, 160),
            extra=_hospedeiro(evento),
        )

    def _processo(self, evento: EventoWindows) -> None:
        linha = evento.campo("CommandLine")
        achado = classificar_comando(linha) if linha else None
        if achado is None:
            return
        categoria, rotulo, tecnicas = achado
        evento.campos["CommandLine"] = mascarar_comando(linha)
        self.rotulos[categoria] = (rotulo, tecnicas)
        tabela = self.comandos.setdefault(categoria, Tabela())
        tabela.registrar(
            _hospedeiro(evento) or "(máquina desconhecida)",
            evento.momento,
            resumo_campos(evento, ("SubjectUserName", "NewProcessName", "CommandLine")),
            usuario=limpar(evento.campo("SubjectUserName"), 64),
            arquivo=limpar(evento.campo("NewProcessName"), 160),
        )

    # -- decisão -----------------------------------------------------------------
    def relatar(self, ctx: CheckContext, ativo: str, parcial: bool) -> int:
        """Reporta tudo o que passou dos limites. Devolve quantos achados saíram."""
        antes = ctx.findings_reported
        self._forca_bruta(ctx, ativo)
        self._rdp_apos_falhas(ctx, ativo)
        self._contas(ctx, ativo)
        self._grupos(ctx, ativo)
        self._limpezas(ctx, ativo)
        self._servicos(ctx, ativo)
        self._comandos(ctx, ativo)
        if parcial:
            ctx.log("Eventos do Windows: resultado parcial, o limite de leitura foi atingido.")
        return ctx.findings_reported - antes

    def _eh_forca_bruta(self, indicio: Indicio) -> bool:
        # Total sem janela só vale com vários usuários ou ritmo mínimo: uma credencial antiga
        # falhando uma vez por hora numa estação não é ataque.
        if indicio.total >= FORCA_BRUTA_MIN_TOTAL and (
            len(indicio.usuarios) >= FORCA_BRUTA_MIN_USUARIOS
            or pico_na_janela(indicio.tempos, 3_600.0) >= FORCA_BRUTA_MIN_FALHAS
        ):
            return True
        return pico_na_janela(indicio.tempos, FORCA_BRUTA_JANELA_S) >= FORCA_BRUTA_MIN_FALHAS

    def _forca_bruta(self, ctx: CheckContext, ativo: str) -> None:
        candidatos = [
            (o, i) for o, i in sorted(self.falhas.itens.items()) if self._eh_forca_bruta(i)
        ]
        for origem, indicio in principais(candidatos):
            tecnicas = ["T1110.001"]
            if len(indicio.usuarios) >= SPRAY_MIN_USUARIOS:
                tecnicas.append("T1110.003")
            nome = "vários IPs" if origem == CHAVE_DEMAIS else origem
            relatar(
                ctx,
                Relato(
                    achado="logs.windows.forca_bruta",
                    ativo=ativo,
                    titulo=f"Força bruta contra contas do Windows a partir de {nome} ({indicio.total} falhas)",
                    resumo=(
                        f"{indicio.total} logons com falha (evento 4625) a partir de {nome}, "
                        f"contra {len(indicio.usuarios)} conta(s)."
                    ),
                    discriminador=origem,
                    tecnicas=tuple(tecnicas),
                    fuso=self.fuso,
                    severidade=Severity.HIGH if indicio.total >= FORCA_BRUTA_TOTAL_ALTO else None,
                    extras={"pico_em_10_min": pico_na_janela(indicio.tempos, FORCA_BRUTA_JANELA_S)},
                    tech=("windows",),
                ),
                indicio,
            )

    def _rdp_apos_falhas(self, ctx: CheckContext, ativo: str) -> None:
        relatados = 0
        for ip, sucessos in sorted(self.sucessos_rdp.items()):
            falhas = self.falhas.itens.get(ip)
            if falhas is None or falhas.total < SUCESSO_MIN_FALHAS:
                continue
            ordenadas = sorted(falhas.tempos)
            por_usuario: dict[str, tuple[Indicio, int]] = {}
            for momento, usuario, amostra in sucessos:
                antes = (
                    contar_antes(ordenadas, momento, SUCESSO_JANELA_S)
                    if momento is not None
                    else falhas.total
                )
                curta = (
                    contar_antes(ordenadas, momento, SUCESSO_JANELA_CURTA_S)
                    if momento is not None
                    else falhas.total
                )
                if curta < SUCESSO_MIN_FALHAS and antes < SUCESSO_MIN_FALHAS_LONGA:
                    continue
                indicio, maior = por_usuario.get(usuario, (Indicio(), 0))
                indicio.registrar(momento, amostra, ip=ip, usuario=usuario)
                por_usuario[usuario] = (indicio, max(maior, antes))
            for usuario, (indicio, antes) in sorted(por_usuario.items()):
                if relatados >= MAX_ACHADOS_POR_TIPO:
                    return
                relatados += 1
                # CRITICAL só quando quem entrou é uma das contas que falharam.
                interno = ip_interno(ip) or usuario not in falhas.usuarios
                indicio.amostras.extend(falhas.amostras[: 5 - len(indicio.amostras)])
                relatar(
                    ctx,
                    Relato(
                        achado="logs.windows.rdp_apos_falhas",
                        ativo=ativo,
                        titulo=f"Logon remoto (RDP) de {usuario} aceito depois de {antes} falhas vindas de {ip}",
                        resumo=(
                            f"O endereço {ip} errou a senha {antes} vezes na hora anterior e "
                            f"depois entrou como {usuario} por área de trabalho remota (evento 4624, "
                            "tipo 10). Trate a conta como comprometida até provar o contrário."
                        ),
                        discriminador=f"{ip}|{usuario}",
                        tecnicas=("T1110.001", "T1078", "T1021.001"),
                        fuso=self.fuso,
                        severidade=Severity.HIGH if interno else Severity.CRITICAL,
                        confianca=Confidence.TENTATIVE if interno else Confidence.FIRM,
                        extras={"falhas_antes": antes, "ip_interno": interno},
                        tech=("windows",),
                    ),
                    indicio,
                )

    def _contas(self, ctx: CheckContext, ativo: str) -> None:
        for nome, indicio in principais(sorted(self.contas_criadas.itens.items())):
            relatar(
                ctx,
                Relato(
                    achado="logs.windows.usuario_criado",
                    ativo=ativo,
                    titulo=f"Conta de usuário criada: {limpar(nome, 80)}",
                    resumo=(
                        f"O evento 4720 registrou a criação da conta {limpar(nome, 80)}. Confirme "
                        "que foi um chamado ou uma rotina de RH: contas criadas por atacantes "
                        "servem para voltar ao sistema depois."
                    ),
                    discriminador=nome,
                    tecnicas=("T1136.001", "T1136.002"),
                    fuso=self.fuso,
                    tech=("windows",),
                ),
                indicio,
            )

    def _grupos(self, ctx: CheckContext, ativo: str) -> None:
        for chave, indicio in principais(sorted(self.grupos.itens.items())):
            grupo, _, membro = chave.partition("|")
            relatar(
                ctx,
                Relato(
                    achado="logs.windows.grupo_privilegiado",
                    ativo=ativo,
                    titulo=f"Membro adicionado a grupo privilegiado: {membro or '?'} em {grupo}",
                    resumo=(
                        f"{membro or 'Um membro'} entrou no grupo {grupo} (eventos 4728, 4732 ou "
                        "4756). Isso concede poderes de administrador."
                    ),
                    discriminador=chave,
                    tecnicas=("T1098", "T1098.007"),
                    fuso=self.fuso,
                    tech=("windows",),
                ),
                indicio,
            )

    def _limpezas(self, ctx: CheckContext, ativo: str) -> None:
        for maquina, indicio in principais(sorted(self.limpezas.itens.items())):
            relatar(
                ctx,
                Relato(
                    achado="logs.windows.log_apagado",
                    ativo=ativo,
                    titulo=f"Log de eventos do Windows apagado em {maquina} ({indicio.total}x)",
                    resumo=(
                        "Os eventos 1102 (Security) e 104 (System e Application) mostram que um log foi limpo. Atacantes fazem isso "
                        "para apagar rastros; fora de uma manutenção planejada, é sinal de invasão."
                    ),
                    discriminador=maquina,
                    tecnicas=("T1685.005",),
                    fuso=self.fuso,
                    tech=("windows",),
                ),
                indicio,
            )

    def _servicos(self, ctx: CheckContext, ativo: str) -> None:
        escolhidos = principais(
            sorted(self.servicos.itens.items()), primeiro=self.servicos_suspeitos
        )
        for nome, indicio in escolhidos:
            suspeito = nome in self.servicos_suspeitos
            relatar(
                ctx,
                Relato(
                    achado="logs.windows.servico_instalado",
                    ativo=ativo,
                    titulo=f"Serviço instalado: {nome}"
                    + (" (caminho suspeito)" if suspeito else ""),
                    resumo=(
                        f"O serviço {nome} foi instalado (evento 4697 ou 7045)."
                        + (
                            " O executável fica em shell, pasta gravável ou compartilhamento "
                            "administrativo, padrão de ferramentas de ataque como PsExec."
                            if suspeito
                            else " Confirme se a instalação foi planejada."
                        )
                    ),
                    discriminador=nome,
                    tecnicas=("T1543.003", "T1569.002"),
                    fuso=self.fuso,
                    severidade=Severity.HIGH if suspeito else Severity.LOW,
                    confianca=(
                        Confidence.FIRM if nome in self.servicos_fortes else Confidence.TENTATIVE
                    ),
                    extras={"caminho_suspeito": suspeito},
                    tech=("windows",),
                ),
                indicio,
            )

    def _comandos(self, ctx: CheckContext, ativo: str) -> None:
        for categoria, tabela in sorted(self.comandos.items()):
            rotulo, tecnicas = self.rotulos[categoria]
            for maquina, indicio in principais(sorted(tabela.itens.items())):
                relatar(
                    ctx,
                    Relato(
                        achado="logs.windows.comando_suspeito",
                        ativo=ativo,
                        titulo=f"{rotulo} em {maquina} ({indicio.total}x)",
                        resumo=(
                            f"O evento 4688 registrou {rotulo.lower()} em {maquina}. É uma técnica "
                            "comum de malware, mas administradores também a usam: confira o contexto."
                        ),
                        discriminador=f"{categoria}|{maquina}",
                        tecnicas=tecnicas,
                        fuso=self.fuso,
                        confianca=Confidence.TENTATIVE,
                        extras={"categoria": categoria},
                        tech=("windows",),
                    ),
                    indicio,
                )
