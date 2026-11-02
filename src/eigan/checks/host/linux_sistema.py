"""Acesso de SÓ LEITURA a um Linux a partir de uma raiz (``/`` na máquina real).

Todas as checagens de Linux leem o sistema por meio de :class:`SistemaLinux`. A
raiz de arquivos e o executor de comandos são injetáveis: os testes montam um Linux
falso numa pasta temporária (em qualquer sistema operacional) e respondem aos
comandos sem executar nada — basta trocar :data:`criar`.

Regras: nada é alterado; comandos só com lista de argumentos, programa procurado nas
pastas padrão do sistema (nunca no PATH de quem executa), tempo limite e idioma fixo
(``LC_ALL=C``, para a saída ser sempre a mesma) — e apenas quando a raiz é a própria
máquina. Leitura negada pelo sistema vira :class:`~.sistema.AcessoNegado`, que a
checagem registra como "não verificado".
"""

from __future__ import annotations

import fnmatch
import os
import posixpath
import re
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from ...core.context import CheckContext
from . import sistema
from .sistema import AcessoNegado, InfoArquivo, Resultado

#: pastas padrão de programas (não confiamos no PATH do processo)
PASTAS_PROGRAMAS = ("/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin")
LIMITE_LEITURA = 4_000_000
AMBIENTE_C = {"LC_ALL": "C", "LANG": "C"}
#: sistemas de arquivos sem permissões POSIX de verdade (ex.: unidades do Windows no WSL)
SEM_PERMISSOES_POSIX = frozenset(
    {"9p", "drvfs", "vfat", "msdos", "exfat", "ntfs", "ntfs3", "fuseblk", "cifs", "smb3", "smbfs"}
)
_CURINGA = re.compile(r"[*?\[]")
_OCTAL = re.compile(r"\\([0-7]{3})")


class SistemaLinux:
    """Um Linux visto a partir de ``raiz``. Na máquina real, ``raiz`` é ``/``."""

    def __init__(self, raiz: str | Path = "/") -> None:
        self.raiz = Path(raiz)
        #: comandos só fazem sentido quando a raiz é o próprio sistema em execução
        self.local = str(raiz) == "/"

    # -- arquivos ------------------------------------------------------------------------
    def caminho(self, alvo: str) -> Path:
        """Onde fica, dentro da raiz, o caminho absoluto ``alvo`` do Linux auditado."""
        partes = [parte for parte in posixpath.normpath("/" + alvo).split("/") if parte]
        return self.raiz.joinpath(*partes)

    def ler(self, alvo: str, limite: int = LIMITE_LEITURA) -> str | None:
        """Conteúdo de um arquivo de texto; None se não existe."""
        destino = self.caminho(alvo)
        try:
            if destino.is_dir():
                return None
            with destino.open("rb") as arquivo:
                dados = arquivo.read(limite)
        except (FileNotFoundError, NotADirectoryError, IsADirectoryError):
            return None
        except PermissionError as exc:
            raise AcessoNegado(alvo) from exc
        except OSError:
            return None
        return dados.decode("utf-8", errors="replace")

    def listar(self, alvo: str) -> list[str] | None:
        """Nomes dentro de uma pasta (ordenados); None se a pasta não existe."""
        try:
            return sorted(os.listdir(self.caminho(alvo)))
        except (FileNotFoundError, NotADirectoryError):
            return None
        except PermissionError as exc:
            raise AcessoNegado(alvo) from exc
        except OSError:
            return None

    def estado(self, alvo: str) -> InfoArquivo | None:
        """Permissões e dono (segue links simbólicos); None se não existe."""
        try:
            info = os.stat(self.caminho(alvo))
        except (FileNotFoundError, NotADirectoryError):
            return None
        except PermissionError as exc:
            raise AcessoNegado(alvo) from exc
        except OSError:
            return None
        return InfoArquivo(info.st_mode, info.st_uid, info.st_gid)

    def idade_dias(self, alvo: str) -> float | None:
        """Dias desde a última modificação do arquivo; None se não existe ou não dá para ler."""
        try:
            return (time.time() - os.stat(self.caminho(alvo)).st_mtime) / 86400
        except OSError:
            return None

    def existe(self, alvo: str) -> bool:
        return os.path.lexists(self.caminho(alvo))

    def real(self, alvo: str) -> str:
        """Caminho canônico no Linux auditado (links resolvidos): não conta um arquivo duas vezes."""
        relativo = os.path.relpath(
            os.path.realpath(self.caminho(alvo)), os.path.realpath(self.raiz)
        )
        return "/" if relativo == "." else "/" + relativo.replace(os.sep, "/")

    def expandir(self, padrao: str) -> list[str]:
        """Caminhos que casam com ``padrao`` (curingas do glob em qualquer parte), em ordem léxica.

        Como no glob(3), ``*`` não casa com nomes ocultos (iniciados por ponto).
        """
        atuais = ["/"]
        for parte in [p for p in posixpath.normpath("/" + padrao).split("/") if p]:
            proximos: list[str] = []
            for base in atuais:
                if not _CURINGA.search(parte):
                    proximos.append(posixpath.join(base, parte))
                    continue
                for nome in self.listar(base) or []:
                    oculto = nome.startswith(".") and not parte.startswith(".")
                    if not oculto and fnmatch.fnmatchcase(nome, parte):
                        proximos.append(posixpath.join(base, nome))
            atuais = proximos
        return sorted(item for item in atuais if self.existe(item))

    # -- programas e comandos -----------------------------------------------------------
    def programa(self, nome: str) -> str | None:
        """Caminho de um programa (absoluto ou nas pastas padrão); None se não está instalado."""
        if nome.startswith("/"):
            return nome if self.caminho(nome).is_file() else None
        for pasta in PASTAS_PROGRAMAS:
            alvo = f"{pasta}/{nome}"
            if self.caminho(alvo).is_file():
                return alvo
        return None

    def comando(self, nome: str, *args: str, tempo: float = 30.0) -> Resultado | None:
        """Executa ``nome args...`` (só leitura). None se o programa não existe ou falhou ao rodar."""
        if not self.local:
            return None
        executavel = self.programa(nome)
        if executavel is None:
            return None
        return sistema.run_command([executavel, *args], tempo=tempo, ambiente=AMBIENTE_C)

    # -- processo ------------------------------------------------------------------------
    def root(self) -> bool:
        """Se a auditoria roda como root (UID efetivo 0)."""
        if sys.platform == "win32":
            return False
        return os.geteuid() == 0

    def path_processo(self) -> str:
        """PATH do processo que executa a auditoria."""
        return os.environ.get("PATH", "")


#: fábrica do sistema auditado — os testes trocam por um Linux falso
criar: Callable[[], SistemaLinux] = SistemaLinux


def obter(ctx: CheckContext) -> SistemaLinux:
    """O sistema auditado (um por auditoria)."""
    return ctx.memo("host.linux:sistema", lambda: criar())


def fora_de_escopo(ctx: CheckContext, sis: SistemaLinux, item: str, *, wsl: bool = True) -> bool:
    """Container (e WSL, se ``wsl``): quem controla isso é o host, então não há o que avaliar aqui."""
    if em_conteiner(sis):
        ctx.log(f"{item}: não se aplica dentro de um container (é controlado pelo host)")
        return True
    if wsl and em_wsl(sis):
        ctx.log(f"{item}: não se aplica ao WSL (kernel e rede são gerenciados pelo Windows)")
        return True
    return False


# -- utilidades sobre o sistema ----------------------------------------------------------
def ler_sysctl(sis: SistemaLinux, chave: str) -> int | None:
    """Valor inteiro de um parâmetro do kernel (``kernel.randomize_va_space``) em /proc/sys.

    Também aceita o caminho com barras, necessário quando o nome da interface tem ponto
    (``net/ipv4/conf/eth0.100/forwarding``). None quando o parâmetro não existe ou não é
    numérico. Leitura negada levanta :class:`AcessoNegado`.
    """
    caminho = chave if "/" in chave else chave.replace(".", "/")
    texto = sis.ler("/proc/sys/" + caminho, limite=256)
    if texto is None:
        return None
    try:
        return int(texto.split()[0])
    except (IndexError, ValueError):
        return None


def os_release(sis: SistemaLinux) -> dict[str, str]:
    """Campos de /etc/os-release (ou /usr/lib/os-release)."""
    for caminho in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            texto = sis.ler(caminho, limite=64_000)
        except AcessoNegado:
            texto = None
        if not texto:
            continue
        campos: dict[str, str] = {}
        for linha in texto.splitlines():
            chave, sep, valor = linha.strip().partition("=")
            if sep and chave and not chave.startswith("#"):
                campos[chave] = valor.strip().strip('"').strip("'")
        return campos
    return {}


def familia(sis: SistemaLinux) -> str:
    """``debian`` (Debian, Ubuntu e derivados), ``rhel`` (RHEL, Fedora, CentOS, Alma, Rocky) ou ``""``."""
    campos = os_release(sis)
    ids = {campos.get("ID", "").lower(), *campos.get("ID_LIKE", "").lower().split()}
    if ids & {"debian", "ubuntu"}:
        return "debian"
    if ids & {"rhel", "fedora", "centos"}:
        return "rhel"
    return ""


def tecnologias(sis: SistemaLinux, *extras: str) -> list[str]:
    """Tecnologias do achado (escolhem o exemplo de correção): ``linux`` + família da distribuição."""
    nomes = ["linux", *extras]
    distro = familia(sis)
    if distro:
        nomes.append(distro)
    return nomes


def em_conteiner(sis: SistemaLinux) -> bool:
    """Roda dentro de um container (Docker, Podman, systemd-nspawn): kernel e rede são do host."""
    if any(sis.existe(marca) for marca in ("/.dockerenv", "/run/.containerenv")):
        return True
    if not sis.existe("/run/systemd/container"):
        return False
    try:
        tipo = (sis.ler("/run/systemd/container", limite=64) or "").strip().lower()
    except AcessoNegado:
        return True
    return tipo != "wsl"  # o WSL com systemd escreve "wsl" ali: é tratado por em_wsl


def em_wsl(sis: SistemaLinux) -> bool:
    """É uma distribuição dentro do WSL (o kernel da Microsoft se identifica no ``osrelease``)."""
    try:
        return "microsoft" in (sis.ler("/proc/sys/kernel/osrelease", limite=256) or "").lower()
    except AcessoNegado:
        return False


def servico_ativo(sis: SistemaLinux, unidade: str) -> bool | None:
    """``systemctl is-active``: True/False; None se o systemctl não respondeu."""
    resultado = sis.comando("systemctl", "is-active", unidade, tempo=15.0)
    if resultado is None:
        return None
    estado = (resultado.saida.strip().splitlines() or [""])[0].strip()
    if estado == "active":
        return True
    if estado in ("inactive", "failed", "unknown", "dead", "deactivating"):
        return False
    return None


def unidade_desligada(sis: SistemaLinux, unidade: str) -> bool | None:
    """``systemctl is-enabled``: True se ``disabled``/``masked``; None se não deu para saber."""
    resultado = sis.comando("systemctl", "is-enabled", unidade, tempo=15.0)
    if resultado is None:
        return None
    estado = (resultado.saida.strip().splitlines() or [""])[0].strip()
    if estado in ("disabled", "masked", "masked-runtime"):
        return True
    if estado in (
        "enabled",
        "enabled-runtime",
        "static",
        "indirect",
        "generated",
        "alias",
        "linked",
    ):
        return False
    return None


@dataclass(frozen=True)
class Montagem:
    ponto: str
    tipo: str


@dataclass
class TabelaMontagens:
    """Pontos de montagem (``/proc/self/mounts``) para saber o sistema de arquivos de um caminho."""

    itens: list[Montagem] = field(default_factory=list)

    def tipo(self, alvo: str) -> str:
        melhor = Montagem("", "")
        for item in self.itens:
            base = item.ponto.rstrip("/") + "/"
            if (alvo == item.ponto or alvo.startswith(base) or item.ponto == "/") and len(
                item.ponto
            ) >= len(melhor.ponto):
                melhor = item
        return melhor.tipo


def montagens(sis: SistemaLinux) -> TabelaMontagens:
    try:
        texto = sis.ler("/proc/self/mounts") or sis.ler("/proc/mounts") or ""
    except AcessoNegado:
        texto = ""
    tabela = TabelaMontagens()
    for linha in texto.splitlines():
        campos = linha.split()
        if len(campos) >= 3:
            ponto = _OCTAL.sub(lambda m: chr(int(m.group(1), 8)), campos[1])
            tabela.itens.append(Montagem(ponto, campos[2]))
    return tabela
