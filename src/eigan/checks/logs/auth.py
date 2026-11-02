"""Logs de autenticação do Linux (``auth.log``, ``secure``, saída do ``journalctl``).

Os formatos reconhecidos vêm do código das próprias ferramentas: OpenSSH (``auth.c``), sudo
(``logging.c``) e shadow-utils (``useradd.c``, ``usermod.c``, ``gpasswd.c``). Só linhas emitidas
por esses programas contam: um site que registre a frase "Failed password" não vira alarme.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass

from ...core import redact
from ...core.context import CheckContext
from ...core.models import Confidence, Severity
from . import tempo
from .agregacao import (
    CHAVE_DEMAIS,
    MAX_ACHADOS_POR_TIPO,
    Indicio,
    Relato,
    Tabela,
    contar_antes,
    ip_interno,
    limpar,
    pico_na_janela,
    principais,
    relatar,
)

#: falhas do mesmo IP dentro da janela que caracterizam força bruta (padrão do fail2ban)
FORCA_BRUTA_MIN_FALHAS = 5
FORCA_BRUTA_JANELA_S = 600.0
#: total de falhas do mesmo IP que caracteriza força bruta lenta, sem olhar a janela
FORCA_BRUTA_MIN_TOTAL = 20
#: a partir deste total a força bruta sobe de severidade
FORCA_BRUTA_TOTAL_ALTO = 100
#: o total sem janela só vale com vários usuários ou com este ritmo (falhas em 1 hora)
FORCA_BRUTA_TOTAL_MIN_USUARIOS = 3
FORCA_BRUTA_TOTAL_MIN_POR_HORA = 10
#: nomes diferentes contra os quais um IP tentou entrar para indicar "password spraying"
SPRAY_MIN_USUARIOS = 5
#: login aceito é suspeito com este número de falhas do mesmo IP nesta janela antes dele
SUCESSO_MIN_FALHAS = 5
SUCESSO_JANELA_S = 3_600.0
#: falhas concentradas imediatamente antes do login: 5 em 10 min ou 10 em 1 h
SUCESSO_MIN_FALHAS_CURTA = 5
SUCESSO_JANELA_CURTA_S = 600.0
SUCESSO_MIN_FALHAS_LONGA = 10
#: nomes inexistentes tentados por um IP para indicar enumeração de usuários
INVALIDOS_MIN_USUARIOS = 5
#: IPs diferentes e total de falhas contra um usuário para indicar ataque distribuído
DISTRIBUIDA_MIN_IPS = 10
DISTRIBUIDA_MIN_FALHAS = 20
#: falhas de senha no sudo por usuário (errar a senha duas ou três vezes é normal)
SUDO_MIN_FALHAS = 5
#: negações do sudoers por usuário a partir das quais o achado deixa de ser só um indício
SUDO_NEGADO_FIRME = 3
#: logins bem-sucedidos guardados por IP
MAX_SUCESSOS_POR_IP = 200

#: grupos que dão poder de administrador (Ubuntu: sudo; RHEL: wheel; Ubuntu antigo: admin;
#: Docker: "the docker group grants root-level privileges")
GRUPOS_PRIVILEGIADOS = frozenset({"sudo", "wheel", "admin", "root", "docker"})
_SHELLS_SEM_LOGIN = ("nologin", "/false", "/sync", "/shutdown", "/halt")

_METODOS_SENHA = ("password", "keyboard-interactive")
_PROGRAMAS = ("sshd", "sudo", "useradd", "usermod", "gpasswd")

_CABECALHO = re.compile(
    r"^(?:<\d{1,3}>\d?\s*)?"
    r"(?:(?P<mes>[A-Z][a-z]{2})\s+(?P<dia>\d{1,2})\s+(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2})(?:\.\d+)?"
    r"|(?P<iso>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?))"
    r"\s+\S+\s+(?P<prog>[A-Za-z0-9_./-]+?)(?:\[\d+\])?:\s*(?P<msg>.*)$"
)
#: teto do peso de "message repeated N times" (linha forjada não pode fabricar volume nem memória)
PESO_MAX_REPETIDO = 1_000
_REPETIDO = re.compile(r"^message repeated (\d+) times: \[\s*(.*?)\]?\s*$")
# O usuário é guloso de propósito: quem escolhe o nome é o atacante e o nome pode conter
# " from 9.9.9.9 port 22". O endereço verdadeiro é sempre o último da linha.
_SSH_FALHA = re.compile(
    r"^Failed (?P<metodo>\S+) for (?P<invalido>invalid user )?(?P<usuario>.*) from (?P<ip>\S+) port \d+"
)
_SSH_ACEITO = re.compile(r"^Accepted (?P<metodo>\S+) for (?P<usuario>.*) from (?P<ip>\S+) port \d+")
_SSH_INVALIDO = re.compile(r"^Invalid user (?P<usuario>.*) from (?P<ip>[^\s\]]+)(?: port \d+)?")
_SUDO_LINHA = re.compile(r"^(?P<usuario>\S+) : (?P<texto>.*)$")
_SUDO_TENTATIVAS = re.compile(r"^(\d+) incorrect password attempts?\b")
_SUDO_NEGADO = re.compile(
    r"^(user NOT in sudoers|user NOT authorized on host|command not allowed)\b"
)
_SUDO_PAM = re.compile(r"^pam_\w+\(sudo(?:-i)?:auth\): authentication failure;.*?\buser=(\S+)")
_NOVO_USUARIO = re.compile(
    r"^new user: name=(?P<usuario>[^,]+), UID=(?P<uid>\d+), GID=\d+, home=(?P<home>[^,]*), shell=(?P<shell>[^,]*)"
)
_ADD_GRUPO = re.compile(r"^add '(?P<usuario>[^']+)' to group '(?P<grupo>[^']+)'")
_GPASSWD_ADD = re.compile(
    r"^user (?P<usuario>\S+) added by (?P<por>\S+) to group (?P<grupo>\S+?)(?: |$)"
)
_UID_ZERO = re.compile(r"^change user '(?P<usuario>[^']+)' UID from '\d+' to '0'")


@dataclass(frozen=True, slots=True)
class _Sucesso:
    momento: float | None
    usuario: str
    metodo: str
    amostra: str
    arquivo: str


def parece_senha(nome: str) -> bool:
    """Nome de usuário que parece uma senha digitada no campo errado (robôs e gente apressada)."""
    classes = sum(
        (
            any(c.islower() for c in nome),
            any(c.isupper() for c in nome),
            any(c.isdigit() for c in nome),
            any(not c.isalnum() for c in nome),
        )
    )
    return len(nome) > 20 or (len(nome) >= 8 and classes >= 3)


def proteger_nome(nome: str, amostra: str) -> tuple[str, str]:
    """Devolve o nome e a amostra, com o nome mascarado quando ele parece uma senha."""
    if not parece_senha(nome):
        return nome, amostra
    escondido = redact.mask(nome, keep=1)
    return escondido, amostra.replace(nome, escondido)


class AnalisadorAuth:
    """Acumula SSH, sudo e alterações de contas; decide e reporta só no fim."""

    def __init__(self) -> None:
        self.reconhecidas = 0
        self.falhas = Tabela()
        self.falhas_por_usuario = Tabela()
        self.invalidos = Tabela()
        self.sucessos: dict[str, list[_Sucesso]] = defaultdict(list)
        self.sudo_tentativas = Tabela()
        self.sudo_pam = Tabela()
        self.sudo_negado = Tabela()
        self.novos_usuarios = Tabela()
        self.grupos = Tabela()
        self.uid_zero = Tabela()
        self.fuso = "UTC"

    # -- leitura -----------------------------------------------------------------
    def alimentar(self, linha: str, arquivo: str, numero: int, referencia: float) -> bool:
        """Processa uma linha. ``True`` quando ela veio de um programa conhecido."""
        if not any(programa in linha for programa in _PROGRAMAS):
            return False
        cabecalho = _CABECALHO.match(linha)
        if cabecalho is None:
            return False
        programa = cabecalho.group("prog").rsplit("/", 1)[-1]
        if not programa.startswith(_PROGRAMAS):
            return False
        self.reconhecidas += 1
        momento = self._momento(cabecalho, referencia)
        amostra = f"{arquivo}:{numero}: {linha}"
        mensagem = cabecalho.group("msg").strip()
        if programa.startswith("sshd"):
            self._ssh(mensagem, momento, amostra, arquivo)
        elif programa == "sudo":
            self._sudo(mensagem, momento, amostra, arquivo)
        else:
            self._contas(programa, mensagem, momento, amostra, arquivo)
        return True

    def _momento(self, cabecalho: re.Match[str], referencia: float) -> float | None:
        if cabecalho.group("iso"):
            return tempo.de_iso(cabecalho.group("iso"))
        self.fuso = "horário do próprio log"
        return tempo.de_syslog(
            cabecalho.group("mes"),
            int(cabecalho.group("dia")),
            int(cabecalho.group("h")),
            int(cabecalho.group("m")),
            int(cabecalho.group("s")),
            referencia,
        )

    def _ssh(self, mensagem: str, momento: float | None, amostra: str, arquivo: str) -> None:
        peso = 1
        repetida = _REPETIDO.match(mensagem)
        if repetida is not None:
            peso = min(int(repetida.group(1)), PESO_MAX_REPETIDO)
            mensagem = repetida.group(2)
        if mensagem.startswith("Failed "):
            falha = _SSH_FALHA.match(mensagem)
            if falha is None or not falha.group("metodo").startswith(_METODOS_SENHA):
                return
            ip = falha.group("ip")
            usuario, amostra = proteger_nome(falha.group("usuario"), amostra)
            usuario = limpar(usuario, 64)
            dados = {"arquivo": arquivo, "peso": peso}
            self.falhas.registrar(
                ip, momento, amostra, usuario=usuario, guardar_tempo=True, **dados
            )
            self.falhas_por_usuario.registrar(usuario, momento, amostra, ip=ip, **dados)
        elif mensagem.startswith("Accepted "):
            aceito = _SSH_ACEITO.match(mensagem)
            if aceito is not None and len(self.sucessos[aceito.group("ip")]) < MAX_SUCESSOS_POR_IP:
                self.sucessos[aceito.group("ip")].append(
                    _Sucesso(
                        momento,
                        limpar(aceito.group("usuario"), 64),
                        aceito.group("metodo"),
                        amostra,
                        arquivo,
                    )
                )
        elif mensagem.startswith("Invalid user "):
            invalido = _SSH_INVALIDO.match(mensagem)
            if invalido is not None:
                nome, amostra = proteger_nome(invalido.group("usuario"), amostra)
                self.invalidos.registrar(
                    invalido.group("ip"),
                    momento,
                    amostra,
                    usuario=limpar(nome, 64),
                    arquivo=arquivo,
                    peso=peso,
                )

    def _sudo(self, mensagem: str, momento: float | None, amostra: str, arquivo: str) -> None:
        pam = _SUDO_PAM.match(mensagem)
        if pam is not None:
            self.sudo_pam.registrar(limpar(pam.group(1), 64), momento, amostra, arquivo=arquivo)
            return
        linha = _SUDO_LINHA.match(mensagem)
        if linha is None:
            return
        usuario, texto = limpar(linha.group("usuario"), 64), linha.group("texto")
        tentativas = _SUDO_TENTATIVAS.match(texto)
        if tentativas is not None:
            self.sudo_tentativas.registrar(
                usuario, momento, amostra, arquivo=arquivo, peso=int(tentativas.group(1))
            )
            return
        negado = _SUDO_NEGADO.match(texto)
        if negado is not None:
            self.sudo_negado.registrar(
                usuario, momento, amostra, arquivo=arquivo, extra=negado.group(1)
            )

    def _contas(
        self, programa: str, mensagem: str, momento: float | None, amostra: str, arquivo: str
    ) -> None:
        novo = _NOVO_USUARIO.match(mensagem)
        if novo is not None:
            self._novo_usuario(novo, momento, amostra, arquivo)
            return
        grupo = _ADD_GRUPO.match(mensagem) or _GPASSWD_ADD.match(mensagem)
        if grupo is not None:
            if grupo.group("grupo") in GRUPOS_PRIVILEGIADOS:
                usuario, nome = limpar(grupo.group("usuario"), 64), grupo.group("grupo")
                self.grupos.registrar(
                    f"{usuario}|{nome}", momento, amostra, usuario=usuario, arquivo=arquivo
                )
            return
        zero = _UID_ZERO.match(mensagem) if programa == "usermod" else None
        if zero is not None:
            usuario = limpar(zero.group("usuario"), 64)
            self.uid_zero.registrar(usuario, momento, amostra, usuario=usuario, arquivo=arquivo)

    def _novo_usuario(
        self, novo: re.Match[str], momento: float | None, amostra: str, arquivo: str
    ) -> None:
        uid = int(novo.group("uid"))
        # Pacotes criam contas de serviço o tempo todo: sem shell de login, não é alarme.
        if uid != 0 and novo.group("shell").strip().endswith(_SHELLS_SEM_LOGIN):
            return
        # Conta de sistema (UID < 1000) criada por pacote, com home fora de /home, é rotina.
        if 0 < uid < 1000 and not novo.group("home").strip().startswith("/home"):
            return
        usuario = limpar(novo.group("usuario"), 64)
        extra = "uid-zero" if uid == 0 else ""
        self.novos_usuarios.registrar(
            usuario, momento, amostra, usuario=usuario, arquivo=arquivo, extra=extra
        )

    # -- decisão -----------------------------------------------------------------
    def relatar(self, ctx: CheckContext, ativo: str, parcial: bool) -> int:
        """Reporta tudo o que passou dos limites. Devolve quantos achados saíram."""
        antes = ctx.findings_reported
        marcados = self._forca_bruta(ctx, ativo)
        self._sucesso_apos_falhas(ctx, ativo)
        self._invalidos(ctx, ativo, marcados)
        self._distribuida(ctx, ativo, marcados)
        self._sudo_relatos(ctx, ativo)
        self._contas_relatos(ctx, ativo)
        if parcial:
            ctx.log("Logs de autenticação: resultado parcial, o limite de leitura foi atingido.")
        return ctx.findings_reported - antes

    def _eh_forca_bruta(self, indicio: Indicio) -> bool:
        if indicio.total >= FORCA_BRUTA_MIN_TOTAL and (
            len(indicio.usuarios) >= FORCA_BRUTA_TOTAL_MIN_USUARIOS
            or pico_na_janela(indicio.tempos, 3_600.0) >= FORCA_BRUTA_TOTAL_MIN_POR_HORA
        ):
            return True
        return (
            indicio.total >= FORCA_BRUTA_MIN_FALHAS
            and pico_na_janela(indicio.tempos, FORCA_BRUTA_JANELA_S) >= FORCA_BRUTA_MIN_FALHAS
        )

    def _forca_bruta(self, ctx: CheckContext, ativo: str) -> set[str]:
        marcados = {ip for ip, item in self.falhas.itens.items() if self._eh_forca_bruta(item)}
        candidatos = [(ip, self.falhas.itens[ip]) for ip in sorted(marcados)]
        for ip, indicio in principais(candidatos):
            tecnicas = ["T1110.001", "T1021.004"]
            if len(indicio.usuarios) >= SPRAY_MIN_USUARIOS:
                tecnicas.insert(1, "T1110.003")
            origem = "vários IPs" if ip == CHAVE_DEMAIS else ip
            alto = indicio.total >= FORCA_BRUTA_TOTAL_ALTO
            relatar(
                ctx,
                Relato(
                    achado="logs.ssh.forca_bruta",
                    ativo=ativo,
                    titulo=f"Força bruta no SSH a partir de {origem} ({indicio.total} falhas)",
                    resumo=(
                        f"{indicio.total} falhas de senha no SSH a partir de {origem}, contra "
                        f"{len(indicio.usuarios)} usuário(s)."
                    ),
                    discriminador=ip,
                    tecnicas=tuple(tecnicas),
                    fuso=self.fuso,
                    severidade=Severity.HIGH if alto else None,
                    extras={"pico_em_10_min": pico_na_janela(indicio.tempos, FORCA_BRUTA_JANELA_S)},
                    tech=("openssh", "linux"),
                ),
                indicio,
            )
        return marcados

    def _sucesso_apos_falhas(self, ctx: CheckContext, ativo: str) -> None:
        relatados = 0
        for ip, sucessos in sorted(self.sucessos.items()):
            falhas = self.falhas.itens.get(ip)
            if falhas is None or falhas.total < SUCESSO_MIN_FALHAS:
                continue
            ordenadas = sorted(falhas.tempos)
            por_usuario: dict[str, tuple[Indicio, int, _Sucesso]] = {}
            for sucesso in sucessos:
                antes = (
                    contar_antes(ordenadas, sucesso.momento, SUCESSO_JANELA_S)
                    if sucesso.momento is not None
                    else falhas.total
                )
                curta = (
                    contar_antes(ordenadas, sucesso.momento, SUCESSO_JANELA_CURTA_S)
                    if sucesso.momento is not None
                    else falhas.total
                )
                if curta < SUCESSO_MIN_FALHAS_CURTA and antes < SUCESSO_MIN_FALHAS_LONGA:
                    continue
                indicio, maior, primeiro = por_usuario.get(sucesso.usuario, (Indicio(), 0, sucesso))
                indicio.registrar(
                    sucesso.momento,
                    sucesso.amostra,
                    ip=ip,
                    usuario=sucesso.usuario,
                    arquivo=sucesso.arquivo,
                )
                por_usuario[sucesso.usuario] = (indicio, max(maior, antes), primeiro)
            for usuario, (indicio, antes, primeiro) in sorted(por_usuario.items()):
                if relatados >= MAX_ACHADOS_POR_TIPO:
                    return
                relatados += 1
                self._relatar_sucesso(ctx, ativo, ip, usuario, indicio, antes, primeiro, falhas)

    def _relatar_sucesso(
        self,
        ctx: CheckContext,
        ativo: str,
        ip: str,
        usuario: str,
        indicio: Indicio,
        antes: int,
        sucesso: _Sucesso,
        falhas: Indicio,
    ) -> None:
        senha = sucesso.metodo.startswith(_METODOS_SENHA)
        interno = ip_interno(ip)
        # Só é conta comprometida com certeza quando quem entrou é um dos nomes que falharam.
        forte = senha and not interno and usuario in falhas.usuarios
        for amostra in falhas.amostras:
            if len(indicio.amostras) < 5:
                indicio.amostras.append(amostra)
        relatar(
            ctx,
            Relato(
                achado="logs.ssh.sucesso_apos_falhas",
                ativo=ativo,
                titulo=f"Login SSH aceito para {usuario} depois de {antes} falhas vindas de {ip}",
                resumo=(
                    f"O IP {ip} errou a senha {antes} vezes na hora anterior e entrou como "
                    f"{usuario} pelo método {limpar(sucesso.metodo, 40)}. Trate como conta "
                    "comprometida até provar o contrário."
                ),
                discriminador=f"{ip}|{usuario}",
                tecnicas=("T1110.001", "T1078", "T1021.004"),
                fuso=self.fuso,
                severidade=Severity.CRITICAL if forte else Severity.HIGH,
                confianca=Confidence.FIRM if forte else Confidence.TENTATIVE,
                extras={
                    "falhas_antes": antes,
                    "metodo": limpar(sucesso.metodo, 40),
                    "ip_interno": interno,
                },
                tech=("openssh", "linux"),
            ),
            indicio,
        )

    def _invalidos(self, ctx: CheckContext, ativo: str, marcados: set[str]) -> None:
        candidatos = [
            (ip, item)
            for ip, item in self.invalidos.itens.items()
            if ip not in marcados and len(item.usuarios) >= INVALIDOS_MIN_USUARIOS
        ]
        for ip, indicio in principais(candidatos):
            origem = "vários IPs" if ip == CHAVE_DEMAIS else ip
            relatar(
                ctx,
                Relato(
                    achado="logs.ssh.usuarios_invalidos",
                    ativo=ativo,
                    titulo=f"Tentativas no SSH com {len(indicio.usuarios)} usuários inexistentes a partir de {origem}",
                    resumo=(
                        f"{origem} tentou entrar com {len(indicio.usuarios)} nomes de usuário que "
                        "não existem no servidor: é um robô testando contas comuns."
                    ),
                    discriminador=ip,
                    tecnicas=("T1110", "T1021.004"),
                    fuso=self.fuso,
                    tech=("openssh", "linux"),
                ),
                indicio,
            )

    def _distribuida(self, ctx: CheckContext, ativo: str, marcados: set[str]) -> None:
        candidatos: list[tuple[str, Indicio]] = []
        for usuario, indicio in self.falhas_por_usuario.itens.items():
            soltos = [ip for ip in indicio.ips if ip not in marcados]
            if (
                len(soltos) >= DISTRIBUIDA_MIN_IPS
                and sum(indicio.ips[ip] for ip in soltos) >= DISTRIBUIDA_MIN_FALHAS
            ):
                candidatos.append((usuario, indicio))
        for usuario, indicio in principais(candidatos):
            relatar(
                ctx,
                Relato(
                    achado="logs.ssh.forca_bruta_distribuida",
                    ativo=ativo,
                    titulo=f"Força bruta distribuída no SSH contra {usuario} ({len(indicio.ips)} IPs)",
                    resumo=(
                        f"{indicio.total} falhas de senha para {usuario} vindas de "
                        f"{len(indicio.ips)} IPs, cada um abaixo do limite de bloqueio."
                    ),
                    discriminador=f"usuario:{usuario}",
                    tecnicas=("T1110.001", "T1021.004"),
                    fuso=self.fuso,
                    extras={"ips_distintos": len(indicio.ips)},
                    tech=("openssh", "linux"),
                ),
                indicio,
            )

    def _sudo_relatos(self, ctx: CheckContext, ativo: str) -> None:
        candidatos: list[tuple[str, Indicio]] = []
        for usuario in set(self.sudo_tentativas.itens) | set(self.sudo_pam.itens):
            tentativas = self.sudo_tentativas.itens.get(usuario, Indicio())
            pam = self.sudo_pam.itens.get(usuario, Indicio())
            maior = tentativas if tentativas.total >= pam.total else pam
            if maior.total >= SUDO_MIN_FALHAS:
                candidatos.append((usuario, maior))
        for usuario, indicio in principais(candidatos):
            relatar(
                ctx,
                Relato(
                    achado="logs.sudo.falhas",
                    ativo=ativo,
                    titulo=f"Falhas repetidas de senha no sudo: {usuario} ({indicio.total})",
                    resumo=f"{indicio.total} tentativas erradas de senha no sudo pelo usuário {usuario}.",
                    discriminador=usuario,
                    tecnicas=("T1548.003",),
                    fuso=self.fuso,
                    tech=("linux",),
                ),
                indicio,
            )
        for usuario, indicio in principais(self.sudo_negado.itens.items()):
            firme = indicio.total >= SUDO_NEGADO_FIRME
            relatar(
                ctx,
                Relato(
                    achado="logs.sudo.nao_autorizado",
                    ativo=ativo,
                    titulo=f"Sudo negado para {usuario} ({indicio.total} vezes)",
                    resumo=f"O sudo recusou {indicio.total} comando(s) de {usuario}, que não tem autorização.",
                    discriminador=usuario,
                    tecnicas=("T1548.003",),
                    fuso=self.fuso,
                    severidade=Severity.MEDIUM if firme else Severity.LOW,
                    confianca=Confidence.FIRM if firme else Confidence.TENTATIVE,
                    tech=("linux",),
                ),
                indicio,
            )

    def _contas_relatos(self, ctx: CheckContext, ativo: str) -> None:
        for usuario, indicio in principais(self.novos_usuarios.itens.items()):
            zero = indicio.extras["uid-zero"] > 0
            relatar(
                ctx,
                Relato(
                    achado="logs.linux.novo_usuario",
                    ativo=ativo,
                    titulo=(
                        f"Conta com UID 0 (root) criada: {usuario}"
                        if zero
                        else f"Conta de usuário criada: {usuario}"
                    ),
                    resumo=f"O useradd criou a conta {usuario}. Confirme quem pediu e por quê.",
                    discriminador=usuario,
                    tecnicas=("T1136.001",),
                    fuso=self.fuso,
                    severidade=Severity.CRITICAL if zero else None,
                    tech=("linux",),
                ),
                indicio,
            )
        for chave, indicio in principais(self.grupos.itens.items()):
            usuario, _, grupo = chave.partition("|")
            relatar(
                ctx,
                Relato(
                    achado="logs.linux.grupo_admin",
                    ativo=ativo,
                    titulo=(
                        f"{usuario} adicionado ao grupo {grupo}"
                        if grupo
                        else "Usuários adicionados a grupos de administradores"
                    ),
                    resumo=f"{usuario} entrou no grupo {grupo or 'privilegiado'}, que dá poder de root.",
                    discriminador=chave,
                    tecnicas=("T1098.007",),
                    fuso=self.fuso,
                    extras={"grupo": grupo},
                    tech=("linux",),
                ),
                indicio,
            )
        for usuario, indicio in principais(self.uid_zero.itens.items()):
            relatar(
                ctx,
                Relato(
                    achado="logs.linux.admin_uid_zero",
                    ativo=ativo,
                    titulo=f"UID da conta {usuario} alterado para 0 (root)",
                    resumo=f"O usermod trocou o UID de {usuario} para 0: a conta passou a ser root.",
                    discriminador=usuario,
                    tecnicas=("T1098",),
                    fuso=self.fuso,
                    tech=("linux",),
                ),
                indicio,
            )
