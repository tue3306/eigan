"""Contas, sudo e permissões de arquivos do Linux (só leitura).

Lê /etc/passwd, /etc/shadow (quando pode), as regras do sudo (quando pode) e as permissões
de pastas do PATH, programas SUID, arquivos do cron e o socket do Docker. O conteúdo das
senhas nunca sai daqui: só o nome da conta e o fato de o campo estar vazio.
"""

from __future__ import annotations

import re
import stat

from ...core import facts
from ...core.context import CheckContext
from ...core.models import Category, Confidence, Fact, Severity
from ...core.registry import check
from . import comum, linux_kb_acesso  # noqa: F401
from . import linux_analise as analise
from . import linux_sistema as so
from .linux_sistema import PASTAS_PROGRAMAS, SEM_PERMISSOES_POSIX, SistemaLinux
from .sistema import AcessoNegado, InfoArquivo

#: (arquivo, guarda senhas): os que guardam senhas também não podem ser lidos por todos
ARQUIVOS_DE_CONTAS = (
    ("/etc/passwd", False),
    ("/etc/group", False),
    ("/etc/shadow", True),
    ("/etc/gshadow", True),
)
#: programas que executam comandos ou mexem em arquivos: com SUID de root, dão root a qualquer um.
#: Lista própria do EIGAN; programas feitos para isso (su, sudo, passwd, mount...) ficam de fora.
SUID_ARRISCADOS = frozenset(
    {
        # shells
        "sh",
        "ash",
        "bash",
        "dash",
        "zsh",
        "ksh",
        "csh",
        "tcsh",
        "fish",
        "busybox",
        # interpretadores
        "awk",
        "gawk",
        "mawk",
        "nawk",
        "expect",
        "lua",
        "node",
        "nodejs",
        "perl",
        "php",
        "python",
        "ruby",
        "tclsh",
        # compiladores e depuradores
        "cc",
        "gcc",
        "make",
        "gdb",
        "strace",
        "ltrace",
        # editores e leitores de arquivo
        "ed",
        "emacs",
        "nano",
        "nvim",
        "vi",
        "vim",
        "vim.basic",
        "vim.tiny",
        "less",
        "more",
        "cat",
        # cópia e alteração de arquivos
        "chmod",
        "chown",
        "cp",
        "dd",
        "install",
        "mv",
        "rsync",
        "sed",
        "tar",
        "tee",
        "unzip",
        "zip",
        # executam outros programas
        "docker",
        "env",
        "find",
        "git",
        "ionice",
        "nice",
        "nohup",
        "taskset",
        "time",
        "timeout",
        "watch",
        "xargs",
        # rede
        "curl",
        "ftp",
        "nc",
        "ncat",
        "netcat",
        "nmap",
        "scp",
        "socat",
        "ssh",
        "tftp",
        "wget",
    }  # fmt: skip
)
_SUID_COM_VERSAO = re.compile(r"^(?:lua|node|perl|php|python|ruby|tclsh)[0-9][0-9.]*$")
CRON_ARQUIVOS = ("/etc/crontab", "/etc/anacrontab")
CRON_PASTAS = (
    "/etc/cron.d",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron",
    "/var/spool/cron/crontabs",
)
DOCKER_SOCKETS = ("/var/run/docker.sock", "/run/docker.sock")
_PATH_AMBIENTE = re.compile(r'^\s*PATH\s*=\s*"?([^"\n]+)"?', re.M)
_PATH_LOGIN = re.compile(r"^\s*ENV_(?:SU)?PATH\s+(?:PATH=)?(\S+)", re.M)
_TECH = ["linux"]


# -- contas ------------------------------------------------------------------------------
def _verificar_uid0(ctx: CheckContext) -> None:
    sis = so.obter(ctx)
    texto = sis.ler("/etc/passwd")
    if texto is None:
        comum.nao_verificado(ctx, "Contas com UID 0", "/etc/passwd não encontrado")
        return
    extras = [c for c in analise.contas_passwd(texto) if c.uid == 0 and c.nome != "root"]
    asset = comum.ativo(ctx)
    if not extras:
        ctx.passed("host.linux.contas.uid0", "Só a conta root tem UID 0", asset)
    for conta in extras:
        ctx.report(
            "host.linux.contas.uid0_extra",
            asset=asset,
            title=f"Outra conta com poderes de root: {conta.nome}",
            evidence=f"Conta {conta.nome} com UID 0 (/etc/passwd:{conta.linha})",
            details={"conta": conta.nome, "linha": conta.linha},
            confidence=Confidence.CONFIRMED,
            discriminator=conta.nome,
            tech=_TECH,
        )


def _verificar_senhas_vazias(ctx: CheckContext) -> None:
    """Campo de senha vazio; contas bloqueadas (``!``, ``*``) não entram. O hash nunca é exibido."""
    sis = so.obter(ctx)
    contas = analise.contas_passwd(sis.ler("/etc/passwd") or "")
    origem = {c.nome: "/etc/passwd" for c in contas if c.senha == ""}
    sem_login = {
        c.nome for c in contas if c.uid != 0 and c.shell.rsplit("/", 1)[-1] in ("nologin", "false")
    }
    try:
        shadow = sis.ler("/etc/shadow")
    except AcessoNegado:
        comum.nao_verificado(ctx, "Senhas vazias em /etc/shadow")
        shadow = None
    for nome, senha in analise.senhas_shadow(shadow or "").items():
        if senha == "":
            origem.setdefault(nome, "/etc/shadow")
    asset = comum.ativo(ctx)
    if not origem and shadow is not None:
        ctx.passed("host.linux.contas.senha_vazia", "Nenhuma conta com senha vazia", asset)
    for nome, arquivo in sorted(origem.items()):
        ctx.report(
            "host.linux.contas.senha_vazia",
            asset=asset,
            title=f"Conta sem senha: {nome}",
            severity=Severity.LOW if nome in sem_login else None,
            evidence=(
                f"Campo de senha vazio em {arquivo} (conta {nome})"
                + (", mas o shell dela não permite login interativo" if nome in sem_login else "")
            ),
            details={"conta": nome, "arquivo": arquivo, "sem_login_interativo": nome in sem_login},
            confidence=Confidence.CONFIRMED,
            discriminator=nome,
            tech=_TECH,
        )


def _verificar_arquivos_de_contas(ctx: CheckContext) -> None:
    sis = so.obter(ctx)
    asset = comum.ativo(ctx)
    problemas = 0
    for caminho, guarda_senhas in ARQUIVOS_DE_CONTAS:
        info = sis.estado(caminho)
        if info is None:
            continue
        if info.gravavel_por_todos:
            problemas += 1
            ctx.report(
                "host.linux.arquivos.passwd_gravavel",
                asset=asset,
                title=f"{caminho} pode ser alterado por qualquer usuário",
                evidence=f"{caminho} com modo {info.octal} (escrita para outros)",
                details={"arquivo": caminho, "modo": info.octal},
                confidence=Confidence.CONFIRMED,
                discriminator=caminho,
                tech=so.tecnologias(sis),
            )
        if guarda_senhas and info.legivel_por_todos:
            problemas += 1
            ctx.report(
                "host.linux.arquivos.shadow_legivel",
                asset=asset,
                title=f"{caminho} pode ser lido por qualquer usuário",
                evidence=f"{caminho} com modo {info.octal} (leitura para outros)",
                details={"arquivo": caminho, "modo": info.octal},
                confidence=Confidence.CONFIRMED,
                discriminator=caminho,
                tech=so.tecnologias(sis),
            )
    if not problemas and sis.estado("/etc/passwd") and sis.estado("/etc/shadow"):
        ctx.passed(
            "host.linux.arquivos.contas",
            "Arquivos de contas e senhas sem acesso indevido (/etc/passwd, /etc/shadow)",
            asset,
        )


@check(
    id="host.linux.contas",
    name="Contas e arquivos de senhas (Linux)",
    category=Category.HOST,
    consumes=facts.LOCAL,
    description=(
        "Procura outras contas com UID 0, contas sem senha (em /etc/shadow, quando pode ser lido) "
        "e permissões indevidas em /etc/passwd, /etc/group, /etc/shadow e /etc/gshadow."
    ),
    findings=(
        "host.linux.contas.uid0_extra",
        "host.linux.contas.senha_vazia",
        "host.linux.arquivos.shadow_legivel",
        "host.linux.arquivos.passwd_gravavel",
    ),
    platforms=comum.LINUX,
)
def check_contas(ctx: CheckContext, fact: Fact) -> None:
    comum.executar(ctx, "Contas com UID 0", _verificar_uid0)
    comum.executar(ctx, "Contas sem senha", _verificar_senhas_vazias)
    comum.executar(ctx, "Permissões dos arquivos de contas", _verificar_arquivos_de_contas)


# -- sudo --------------------------------------------------------------------------------
def _verificar_sudo(ctx: CheckContext) -> None:
    sis = so.obter(ctx)
    sudoers = analise.ler_sudoers(sis)
    if sudoers is None:
        ctx.log("Regras do sudo: /etc/sudoers não existe nesta máquina")
        return
    for caminho in sudoers.ilegiveis:
        comum.nao_verificado(ctx, f"Regras do sudo: {caminho}")
    regras = analise.regras_sem_senha(sudoers)
    asset = comum.ativo(ctx)
    if not regras and not sudoers.ilegiveis:
        ctx.passed("host.linux.sudo", "sudo não libera todos os comandos sem senha", asset)
    for regra in regras:
        ctx.report(
            "host.linux.sudo.nopasswd_total",
            asset=asset,
            title=f"sudo libera tudo sem senha para: {regra.usuarios}",
            severity=Severity.HIGH if regra.todos_usuarios else None,
            evidence=f"{regra.linha.origem}: {regra.linha.texto}",
            details={"usuarios": regra.usuarios, "origem": regra.linha.origem},
            confidence=Confidence.CONFIRMED,
            discriminator=regra.linha.origem,
            tech=_TECH,
        )


@check(
    id="host.linux.sudo",
    name="Regras do sudo (Linux)",
    category=Category.HOST,
    consumes=facts.LOCAL,
    description=(
        "Lê /etc/sudoers e as inclusões, quando podem ser lidos (normalmente exige root), e procura "
        "regras que liberam todos os comandos sem senha."
    ),
    findings=("host.linux.sudo.nopasswd_total",),
    platforms=comum.LINUX,
)
def check_sudo(ctx: CheckContext, fact: Fact) -> None:
    comum.executar(ctx, "Regras do sudo", _verificar_sudo)


# -- PATH --------------------------------------------------------------------------------
def _fontes_de_path(ctx: CheckContext, sis: SistemaLinux) -> list[tuple[str, str]]:
    """Listas de pastas (origem, valor): PATH do processo, arquivos do sistema e sudo."""
    fontes = [("PATH do processo da auditoria", sis.path_processo())]
    for arquivo, padrao in (("/etc/environment", _PATH_AMBIENTE), ("/etc/login.defs", _PATH_LOGIN)):
        try:
            fontes += [
                (arquivo, achado.group(1)) for achado in padrao.finditer(sis.ler(arquivo) or "")
            ]
        except AcessoNegado:
            comum.nao_verificado(ctx, f"PATH em {arquivo}")
    try:
        sudoers = analise.ler_sudoers(sis)
    except AcessoNegado:
        comum.nao_verificado(ctx, "secure_path do sudo")
        sudoers = None
    if sudoers is not None and sudoers.secure_path:
        fontes.append(("secure_path do sudo", sudoers.secure_path))
    return fontes


def _pasta_gravavel(ctx: CheckContext, sis: SistemaLinux, pasta: str) -> InfoArquivo | None:
    """Permissões da pasta, se qualquer usuário pode gravar nela; negado vira "não verificado"."""
    try:
        info = sis.estado(pasta)
    except AcessoNegado:
        comum.nao_verificado(ctx, f"Pasta do PATH: {pasta}")
        return None
    return info if info is not None and info.diretorio and info.gravavel_por_todos else None


def _verificar_path(ctx: CheckContext) -> None:
    sis = so.obter(ctx)
    tabela = so.montagens(sis)
    origens: dict[str, list[str]] = {}
    modos: dict[str, str] = {}
    for origem, valor in _fontes_de_path(ctx, sis):
        ctx.check_cancel()
        for pasta in valor.split(":"):
            # relativo depende da pasta atual; sem permissões POSIX (WSL /mnt/c), o modo não diz nada
            if not pasta.startswith("/") or tabela.tipo(pasta) in SEM_PERMISSOES_POSIX:
                continue
            real = sis.real(pasta)
            if real not in modos and tabela.tipo(real) not in SEM_PERMISSOES_POSIX:
                info = _pasta_gravavel(ctx, sis, pasta)
                if info is None:
                    continue
                modos[real] = info.octal
            if real in modos and origem not in origens.setdefault(real, []):
                origens[real].append(origem)
    asset = comum.ativo(ctx)
    if not modos:
        ctx.passed(
            "host.linux.path", "Nenhuma pasta do PATH é gravável por qualquer usuário", asset
        )
    for real, modo in sorted(modos.items()):
        ctx.report(
            "host.linux.path.pasta_gravavel",
            asset=asset,
            title=f"Pasta do PATH gravável por qualquer usuário: {real}",
            evidence=f"{real} com modo {modo}, presente em: {'; '.join(origens[real])}",
            details={"pasta": real, "modo": modo, "origens": origens[real]},
            confidence=Confidence.CONFIRMED,
            discriminator=real,
            tech=_TECH,
        )


# -- SUID --------------------------------------------------------------------------------
def _suid_de_root(info: InfoArquivo | None) -> bool:
    """Arquivo comum executável, com SUID e dono root."""
    return (
        info is not None
        and info.suid
        and info.uid == 0
        and stat.S_ISREG(info.modo)
        and bool(info.modo & 0o111)
    )


def _programas_arriscados(ctx: CheckContext, sis: SistemaLinux) -> dict[str, InfoArquivo]:
    encontrados: dict[str, InfoArquivo] = {}
    for pasta in PASTAS_PROGRAMAS:
        ctx.check_cancel()
        try:
            nomes = sis.listar(pasta) or []
        except AcessoNegado:
            comum.nao_verificado(ctx, f"Programas SUID em {pasta}")
            continue
        for nome in nomes:
            if nome not in SUID_ARRISCADOS and not _SUID_COM_VERSAO.match(nome):
                continue
            caminho = f"{pasta}/{nome}"
            try:
                info = sis.estado(caminho)
            except AcessoNegado:
                continue
            if _suid_de_root(info) and info is not None:
                encontrados.setdefault(sis.real(caminho), info)
    return encontrados


def _verificar_suid(ctx: CheckContext) -> None:
    sis = so.obter(ctx)
    encontrados = _programas_arriscados(ctx, sis)
    asset = comum.ativo(ctx)
    if not encontrados:
        ctx.passed(
            "host.linux.suid",
            "Nenhum shell, interpretador ou utilitário arriscado com SUID de root nas pastas padrão",
            asset,
        )
    for caminho, info in sorted(encontrados.items()):
        ctx.report(
            "host.linux.suid.binario_arriscado",
            asset=asset,
            title=f"Bit SUID em programa arriscado: {caminho}",
            evidence=f"{caminho} com modo {info.octal} e dono root",
            details={"programa": caminho, "modo": info.octal},
            confidence=Confidence.CONFIRMED,
            discriminator=caminho,
            tech=_TECH,
        )


# -- cron --------------------------------------------------------------------------------
def _candidatos_cron(ctx: CheckContext, sis: SistemaLinux) -> list[str]:
    caminhos = list(CRON_ARQUIVOS)
    for pasta in CRON_PASTAS:
        caminhos.append(pasta)
        try:
            caminhos += [f"{pasta}/{nome}" for nome in sis.listar(pasta) or []]
        except AcessoNegado:
            comum.nao_verificado(ctx, f"Arquivos do cron em {pasta}")
    return caminhos


def _verificar_cron(ctx: CheckContext) -> None:
    sis = so.obter(ctx)
    gravaveis: dict[str, str] = {}
    avaliados = 0
    for caminho in _candidatos_cron(ctx, sis):
        ctx.check_cancel()
        try:
            info = sis.estado(caminho)
        except AcessoNegado:
            comum.nao_verificado(ctx, f"Arquivo do cron: {caminho}")
            continue
        if info is None:
            continue
        avaliados += 1
        if info.gravavel_por_todos:
            gravaveis[caminho] = info.octal
    asset = comum.ativo(ctx)
    if gravaveis:
        ctx.report(
            "host.linux.cron.gravavel",
            asset=asset,
            evidence="\n".join(
                f"{c} com modo {m} (escrita para outros)" for c, m in gravaveis.items()
            ),
            details={"arquivos": gravaveis},
            confidence=Confidence.CONFIRMED,
            tech=_TECH,
        )
    elif avaliados:
        ctx.passed(
            "host.linux.cron",
            "Arquivos e pastas do cron sem escrita para qualquer usuário",
            asset,
        )


# -- socket do Docker -------------------------------------------------------------------
def _verificar_docker(ctx: CheckContext) -> None:
    sis = so.obter(ctx)
    asset = comum.ativo(ctx)
    vistos: set[str] = set()
    for caminho in DOCKER_SOCKETS:
        info = sis.estado(caminho)
        if info is None or not stat.S_ISSOCK(info.modo) or sis.real(caminho) in vistos:
            continue
        vistos.add(sis.real(caminho))
        if info.gravavel_por_todos:
            ctx.report(
                "host.linux.docker.socket_gravavel",
                asset=asset,
                evidence=f"{caminho} com modo {info.octal} (escrita para outros)",
                details={"socket": caminho, "modo": info.octal},
                confidence=Confidence.CONFIRMED,
                discriminator=sis.real(caminho),
                tech=_TECH,
            )
        else:
            ctx.passed(
                "host.linux.docker.socket",
                f"Socket do Docker sem escrita para qualquer usuário ({caminho}, modo {info.octal})",
                asset,
            )


@check(
    id="host.linux.permissoes",
    name="Permissões perigosas de arquivos (Linux)",
    category=Category.HOST,
    consumes=facts.LOCAL,
    description=(
        "Confere pastas do PATH graváveis por todos, bit SUID em programas arriscados nas pastas "
        "padrão, arquivos do cron com escrita para todos e o socket do Docker."
    ),
    findings=(
        "host.linux.path.pasta_gravavel",
        "host.linux.suid.binario_arriscado",
        "host.linux.cron.gravavel",
        "host.linux.docker.socket_gravavel",
    ),
    platforms=comum.LINUX,
)
def check_permissoes(ctx: CheckContext, fact: Fact) -> None:
    comum.executar(ctx, "Pastas do PATH", _verificar_path)
    comum.executar(ctx, "Programas com SUID", _verificar_suid)
    comum.executar(ctx, "Arquivos do cron", _verificar_cron)
    comum.executar(ctx, "Socket do Docker", _verificar_docker)
