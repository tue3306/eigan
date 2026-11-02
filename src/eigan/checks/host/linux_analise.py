"""Interpretação de arquivos e saídas de comandos do Linux (funções puras, sem I/O).

Ficam aqui os "leitores" usados pelas checagens de Linux: contas (/etc/passwd,
/etc/shadow), regras do sudo, sockets em escuta (/proc/net/tcp), regras de firewall
(nftables, iptables, ufw) e saídas dos gerenciadores de pacotes. A exceção é
:func:`ler_sudoers`, que segue as inclusões do sudo pelo :class:`SistemaLinux`.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field

from .linux_sistema import SistemaLinux
from .sistema import AcessoNegado

# -- contas ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Conta:
    nome: str
    senha: str  # campo de senha do /etc/passwd ("x" = está no /etc/shadow)
    uid: int | None
    linha: int
    shell: str = ""


def contas_passwd(texto: str) -> list[Conta]:
    """Contas do /etc/passwd (ignora comentários e entradas NIS ``+``/``-``)."""
    contas: list[Conta] = []
    for numero, linha in enumerate(texto.splitlines(), start=1):
        if not linha.strip() or linha.startswith(("#", "+", "-")):
            continue
        campos = linha.split(":")
        if len(campos) < 4 or not campos[0]:
            continue
        uid = int(campos[2]) if campos[2].strip().isdigit() else None
        contas.append(
            Conta(campos[0], campos[1], uid, numero, campos[6].strip() if len(campos) > 6 else "")
        )
    return contas


def senhas_shadow(texto: str) -> dict[str, str]:
    """Nome da conta -> campo de senha do /etc/shadow (o hash nunca sai daqui)."""
    senhas: dict[str, str] = {}
    for linha in texto.splitlines():
        if not linha.strip() or linha.startswith(("#", "+", "-")):
            continue
        campos = linha.split(":")
        if len(campos) >= 2 and campos[0]:
            senhas[campos[0]] = campos[1]
    return senhas


# -- sudo ------------------------------------------------------------------------------

SUDOERS = "/etc/sudoers"
_PROFUNDIDADE_SUDO = 8
_DIRETIVA = re.compile(r"^[#@](include|includedir)\s+(.+?)\s*$")
_COMENTARIO = re.compile(r"#(?!\d).*$")  # "#1000" é um UID, não comentário
_ALIAS = re.compile(r"^(?:User|Runas|Host|Cmnd|Cmd)_Alias\b")
_DEFAULTS = re.compile(r"^Defaults(?:([:>@!])(\S+))?\s+(.*)$")
_SEM_AUTENTICAR = re.compile(r"(?:^|[\s,])!\s*authenticate\b")
_REGRA = re.compile(r"^((?:[^\s,=]+\s*,\s*)*[^\s,=]+)\s+([^=]+?)\s*=\s*(.+)$")
_TAG = re.compile(r"^(?:([A-Z_]+):|[A-Z_]+=\S+)\s*")
_SECURE_PATH = re.compile(r"\bsecure_path\s*=\s*\"?([^\"\s]+)\"?")


@dataclass(frozen=True)
class LinhaSudo:
    arquivo: str
    numero: int
    texto: str

    @property
    def origem(self) -> str:
        return f"{self.arquivo}:{self.numero}"


@dataclass
class Sudoers:
    linhas: list[LinhaSudo] = field(default_factory=list)
    arquivos: list[str] = field(default_factory=list)
    ilegiveis: list[str] = field(default_factory=list)

    @property
    def secure_path(self) -> str | None:
        for linha in self.linhas:
            if linha.texto.startswith("Defaults"):
                achado = _SECURE_PATH.search(linha.texto)
                if achado:
                    return achado.group(1)
        return None


@dataclass(frozen=True)
class RegraSemSenha:
    linha: LinhaSudo
    usuarios: str
    todos_usuarios: bool  # vale para qualquer usuário (ALL)


def ler_sudoers(sis: SistemaLinux) -> Sudoers | None:
    """/etc/sudoers e inclusões; None se não existe. Levanta AcessoNegado se ilegível."""
    if sis.ler(SUDOERS) is None:
        return None
    sudoers = Sudoers()
    _ler_arquivo_sudo(sis, SUDOERS, sudoers, 0)
    return sudoers


def _ler_arquivo_sudo(sis: SistemaLinux, caminho: str, sudoers: Sudoers, nivel: int) -> None:
    texto = sis.ler(caminho)
    if texto is None:
        return
    sudoers.arquivos.append(caminho)
    for numero, logica in _linhas_logicas(texto):
        diretiva = _DIRETIVA.match(logica)
        if diretiva:
            if nivel < _PROFUNDIDADE_SUDO:
                alvo = diretiva.group(2).strip('"')
                _incluir_sudo(sis, caminho, diretiva.group(1), alvo, sudoers, nivel)
            continue
        limpo = _COMENTARIO.sub("", logica).strip()
        if limpo:
            sudoers.linhas.append(LinhaSudo(caminho, numero, limpo))


def _incluir_sudo(
    sis: SistemaLinux, origem: str, tipo: str, alvo: str, sudoers: Sudoers, nivel: int
) -> None:
    if "%" in alvo:  # "%h" (nome da máquina) não é expandido aqui
        return
    if not alvo.startswith("/"):
        alvo = posixpath.join(posixpath.dirname(origem), alvo)
    try:
        if tipo == "include":
            _ler_arquivo_sudo(sis, alvo, sudoers, nivel + 1)
            return
        # o sudo pula nomes terminados em "~" ou que contêm "." (sudoers(5))
        nomes = [n for n in sis.listar(alvo) or [] if not n.endswith("~") and "." not in n]
        for nome in nomes:
            try:
                _ler_arquivo_sudo(sis, f"{alvo}/{nome}", sudoers, nivel + 1)
            except AcessoNegado:
                sudoers.ilegiveis.append(f"{alvo}/{nome}")
    except AcessoNegado:
        sudoers.ilegiveis.append(alvo)


def _linhas_logicas(texto: str) -> list[tuple[int, str]]:
    """Junta linhas terminadas em barra invertida (continuação do sudoers)."""
    linhas: list[tuple[int, str]] = []
    acumulado, inicio = "", 0
    for numero, linha in enumerate(texto.splitlines(), start=1):
        if not acumulado:
            inicio = numero
        if linha.rstrip().endswith("\\"):
            acumulado += linha.rstrip()[:-1] + " "
            continue
        linhas.append((inicio, (acumulado + linha).strip()))
        acumulado = ""
    if acumulado:
        linhas.append((inicio, acumulado.strip()))
    return linhas


def regras_sem_senha(sudoers: Sudoers) -> list[RegraSemSenha]:
    """Regras que dão TODOS os comandos sem pedir senha (``NOPASSWD: ALL`` ou ``!authenticate``)."""
    regras: list[RegraSemSenha] = []
    for linha in sudoers.linhas:
        texto = linha.texto
        if texto.startswith("Defaults"):
            padrao = _DEFAULTS.match(texto)
            if padrao and _SEM_AUTENTICAR.search(padrao.group(3)):
                escopo, alvo = padrao.group(1), padrao.group(2)
                if escopo in ("@", "!"):
                    continue  # vale só para um host ou um comando: não libera "tudo"
                if escopo == ">" and not _runas_root(alvo):
                    continue  # só vale para quem roda como outro usuário
                usuarios = alvo if escopo == ":" else "ALL"
                regras.append(RegraSemSenha(linha, usuarios, _todos(usuarios)))
            continue
        if _ALIAS.match(texto):
            continue
        regra = _REGRA.match(texto)
        if regra and regra.group(1).strip() != "root" and _nopasswd_todos_comandos(regra.group(3)):
            regras.append(RegraSemSenha(linha, regra.group(1), _todos(regra.group(1))))
    return regras


def _todos(usuarios: str) -> bool:
    return "ALL" in [u.strip() for u in usuarios.split(",")]


def _runas_root(usuarios: str) -> bool:
    """A lista ``(usuários[:grupos])`` do sudoers inclui o root? Lista vazia = root (padrão)."""
    parte = usuarios.split(":", 1)[0].replace(";", ",")
    lista = [u.strip().lstrip("!") for u in parte.split(",")]
    return not parte.strip() or "ALL" in lista or "root" in lista


def _nopasswd_todos_comandos(comandos: str) -> bool:
    """O NOPASSWD vale para os comandos seguintes da lista até um PASSWD (sudoers(5)).

    Uma regra pode ter vários trechos ``host = comandos`` separados por `` : ``. Só conta
    quando o comando roda como root: ``(www-data) NOPASSWD: ALL`` não dá poder de root.
    """
    protegido = re.sub(
        r"\(([^)]*)\)",
        lambda m: f"@RUNAS[{m.group(1).replace(',', ';').replace(':', '%')}]@ ",
        comandos,
    )
    for numero, trecho in enumerate(re.split(r"\s:\s", protegido)):
        lista = trecho.split("=", 1)[1] if numero and "=" in trecho else trecho
        if _sem_senha_na_lista(lista):
            return True
    return False


_RUNAS = re.compile(r"^@RUNAS\[([^\]]*)\]@\s*")


def _sem_senha_na_lista(comandos: str) -> bool:
    sem_senha, root = False, True
    for item in comandos.split(","):
        resto = item.strip()
        while True:
            runas = _RUNAS.match(resto)
            if runas:
                root = _runas_root(runas.group(1).split("%", 1)[0])
                resto = resto[runas.end() :]
                continue
            tag = _TAG.match(resto)
            if tag is None:
                break
            if tag.group(1) == "NOPASSWD":
                sem_senha = True
            elif tag.group(1) == "PASSWD":
                sem_senha = False
            resto = resto[tag.end() :]
        if sem_senha and root and resto.strip() == "ALL":
            return True
    return False


# -- rede --------------------------------------------------------------------------------

_TCP_LISTEN = "0A"  # TCP_LISTEN = 10 (include/net/tcp_states.h)


def tem_sockets(texto: str) -> bool:
    """O conteúdo parece um /proc/net/tcp[6] de verdade (ao menos uma linha de socket legível)?"""
    for linha in texto.splitlines()[1:]:
        campos = linha.split()
        if len(campos) >= 4 and ":" in campos[1] and re.fullmatch(r"[0-9A-Fa-f]{2}", campos[3]):
            return True
    return False


def portas_em_todas_interfaces(texto: str) -> set[int]:
    """Portas TCP em escuta no endereço "qualquer" (0.0.0.0 ou ::) de /proc/net/tcp[6]."""
    portas: set[int] = set()
    for linha in texto.splitlines()[1:]:
        campos = linha.split()
        if len(campos) < 4 or campos[3].upper() != _TCP_LISTEN:
            continue
        endereco, _, porta = campos[1].rpartition(":")
        if endereco and set(endereco) == {"0"}:
            try:
                portas.add(int(porta, 16))
            except ValueError:
                continue
    return portas


# -- firewall ---------------------------------------------------------------------------


#: tabelas/cadeias de ajudantes (fail2ban, Tailscale, Kubernetes, Docker): não são a política do host
_AUXILIARES = ("f2b-", "fail2ban-", "ts-", "kube-", "docker", "cni-", "libvirt")
_VEREDITO_BLOQUEIO = re.compile(r"\b(drop|reject)\b")
_SALTO_NFT = re.compile(r"\b(?:jump|goto)\s+(\S+)")


def _auxiliar(nome: str) -> bool:
    return nome.lower().startswith(_AUXILIARES)


def nft_filtra_entrada(ruleset: str) -> bool:
    """Alguma cadeia ``hook input`` do nftables bloqueia de verdade (política drop ou regra drop/reject)?

    Tabelas de ajudantes (fail2ban, Tailscale...) e política accept com regras só de accept
    não contam: o host continuaria aceitando tudo o que não foi banido.
    """
    cadeias: dict[tuple[str, str], list[str]] = {}
    tabela, atual = "", None
    for bruta in ruleset.splitlines():
        texto = bruta.strip()
        if texto.startswith("table ") and texto.endswith("{"):
            tabela = texto.split()[-2]
        elif texto.startswith("chain ") and texto.endswith("{"):
            atual = (tabela, texto.split()[1])
            cadeias[atual] = []
        elif texto == "}":
            atual = None
        elif atual is not None and texto:
            cadeias[atual].append(texto)

    def bloqueia(chave: tuple[str, str], visitadas: set[tuple[str, str]]) -> bool:
        visitadas.add(chave)
        for linha in cadeias.get(chave, []):
            if linha.startswith("type "):
                continue
            if _VEREDITO_BLOQUEIO.search(linha):
                return True
            salto = _SALTO_NFT.search(linha)
            if salto:
                destino = (chave[0], salto.group(1))
                if destino not in visitadas and bloqueia(destino, visitadas):
                    return True
        return False

    for chave, linhas in cadeias.items():
        if _auxiliar(chave[0]):
            continue
        if not any("hook input" in linha for linha in linhas):
            continue
        if any("policy drop" in linha for linha in linhas) or bloqueia(chave, set()):
            return True
    return False


def iptables_filtra_entrada(saida: str) -> bool:
    """``iptables -S`` ou ``iptables-save``: INPUT com política DROP ou com alguma regra que bloqueia.

    Saltos para cadeias de ajudantes (``f2b-*``, ``ts-input``, ``KUBE-*``) e regras só de ACCEPT
    não contam como firewall.
    """
    cadeias: dict[str, list[list[str]]] = {}
    for linha in saida.splitlines():
        partes = linha.split()
        if partes[:3] == ["-P", "INPUT", "DROP"] or partes[:2] == [":INPUT", "DROP"]:
            return True
        if len(partes) >= 2 and partes[0] == "-A":
            cadeias.setdefault(partes[1], []).append(partes)

    def bloqueia(cadeia: str, visitadas: set[str]) -> bool:
        visitadas.add(cadeia)
        for partes in cadeias.get(cadeia, []):
            if "-j" not in partes[:-1]:
                continue
            alvo = partes[partes.index("-j") + 1]
            if alvo in ("DROP", "REJECT"):
                return True
            if alvo not in visitadas and not _auxiliar(alvo) and bloqueia(alvo, visitadas):
                return True
        return False

    return bloqueia("INPUT", set())


def ufw_habilitado(conf: str) -> bool | None:
    """``ENABLED=yes|no`` do /etc/ufw/ufw.conf (o ufw carrega as regras no boot)."""
    for linha in conf.splitlines():
        chave, sep, valor = linha.strip().partition("=")
        if sep and chave.strip() == "ENABLED":
            return valor.strip().strip('"').strip("'").lower() == "yes"
    return None


# -- pacotes ---------------------------------------------------------------------------


def apt_check(saida: str) -> tuple[int, int] | None:
    """``apt-check`` (update-notifier) escreve "atualizações;de segurança" na saída de erro."""
    achado = re.search(r"^\s*(\d+);(\d+)\s*$", saida, re.M)
    return (int(achado.group(1)), int(achado.group(2))) if achado else None


def apt_simulacao(saida: str) -> tuple[list[str], list[str]]:
    """``apt-get -s dist-upgrade``: (pacotes atualizáveis, os que vêm de repositório -security)."""
    todos: list[str] = []
    seguranca: list[str] = []
    for linha in saida.splitlines():
        partes = linha.split()
        if len(partes) < 2 or partes[0] != "Inst":
            continue
        todos.append(partes[1])
        if "-security" in linha.lower():
            seguranca.append(partes[1])
    return todos, seguranca


def apt_config(saida: str, chave: str) -> str | None:
    """Valor de ``chave`` na saída do ``apt-config dump`` (nomes não diferenciam maiúsculas)."""
    achado = re.search(rf'^{re.escape(chave)}\s+"([^"]*)";', saida, re.M | re.I)
    return achado.group(1) if achado else None


def dnf_pacotes(saida: str) -> list[str]:
    """Pacotes listados por ``dnf check-update`` (linhas ``nome.arq versão repositório``)."""
    pacotes: list[str] = []
    for linha in saida.splitlines():
        if linha.strip().lower().startswith("obsoleting packages"):
            break  # a seção de "obsoletos" não lista atualizações
        partes = linha.split()
        if len(partes) == 3 and "." in partes[0] and not partes[0].endswith(":"):
            pacotes.append(partes[0])
    return pacotes
