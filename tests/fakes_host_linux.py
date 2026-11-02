"""Um Linux falso para testar as checagens em qualquer sistema operacional.

Os arquivos ficam em uma pasta temporária (a "raiz"), as permissões POSIX vêm de uma tabela
(o Windows não as guarda) e os comandos são respostas programadas: nada é executado.
"""

from __future__ import annotations

import stat
from pathlib import Path

import pytest
from helpers import CheckOutcome, run_check

from eigan.checks.host import linux_sistema
from eigan.checks.host.linux_sistema import SistemaLinux
from eigan.checks.host.sistema import AcessoNegado, InfoArquivo, Resultado
from eigan.core.models import Fact

FATO_LOCAL = Fact("local", "linux", {"platform": "linux"})

UBUNTU = 'NAME="Ubuntu"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID="24.04"\n'
RHEL = 'NAME="Rocky Linux"\nID="rocky"\nID_LIKE="rhel centos fedora"\nVERSION_ID="9.4"\n'
#: /proc/net/tcp: endereço:porta em hexadecimal; estado 0A = em escuta, 01 = conexão estabelecida
CABECALHO_TCP = (
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid\n"
)
ROOT_E_USUARIO = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "ana:x:1000:1000:Ana:/home/ana:/bin/bash\n"
)
SHADOW_OK = (
    "root:*:19000:0:99999:7:::\ndaemon:*:19000:0:99999:7:::\nana:$y$j9T$resumo:19000:0:99999:7:::\n"
)
SYSCTL_SEGURO = {
    "kernel/randomize_va_space": "2",
    "kernel/kptr_restrict": "1",
    "kernel/dmesg_restrict": "1",
    "fs/protected_symlinks": "1",
    "fs/protected_hardlinks": "1",
    "net/ipv4/tcp_syncookies": "1",
    "net/ipv4/conf/all/accept_redirects": "0",
    "net/ipv4/conf/all/send_redirects": "1",
    "net/ipv4/conf/all/accept_source_route": "0",
    "net/ipv4/conf/default/accept_redirects": "0",
    "net/ipv4/conf/default/send_redirects": "1",
    "net/ipv4/conf/default/accept_source_route": "0",
    "net/ipv4/conf/default/forwarding": "0",
    "net/ipv4/conf/lo/accept_redirects": "1",
    "net/ipv4/conf/eth0/accept_redirects": "0",
    "net/ipv4/conf/eth0/send_redirects": "1",
    "net/ipv4/conf/eth0/accept_source_route": "0",
    "net/ipv4/conf/eth0/forwarding": "0",
    "net/ipv6/conf/all/accept_redirects": "0",
    "net/ipv6/conf/default/accept_redirects": "0",
    "net/ipv6/conf/eth0/accept_redirects": "0",
    "net/ipv6/conf/eth0/forwarding": "0",
    "net/ipv6/conf/eth0/disable_ipv6": "0",
}


def linha_tcp(endereco: str, porta: int, estado: str = "0A") -> str:
    return f"   0: {endereco}:{porta:04X} {'0' * len(endereco)}:0000 {estado} 00000000:00000000 00:00000000 00000000 0\n"


class LinuxFalso(SistemaLinux):
    """:class:`SistemaLinux` com permissões, recusas e comandos programados pelo teste."""

    def __init__(self, raiz: Path, *, root: bool = False, path: str = "/usr/bin:/bin") -> None:
        super().__init__(raiz)
        self.eh_root = root
        self.path = path
        self.modos: dict[str, InfoArquivo] = {}
        self.negados: set[str] = set()
        self.reais: dict[str, str] = {}
        self.respostas: dict[tuple[str, ...], Resultado] = {}
        self.executados: list[tuple[str, ...]] = []

    # -- montagem do cenário ---------------------------------------------------------------
    def arquivo(self, alvo: str, texto: str = "", modo: int | None = None, uid: int = 0) -> None:
        destino = self.caminho(alvo)
        destino.parent.mkdir(parents=True, exist_ok=True)
        destino.write_text(texto, encoding="utf-8", newline="\n")
        if modo is not None:
            self.modos[alvo] = InfoArquivo(stat.S_IFREG | modo, uid, 0)

    def pasta(self, alvo: str, modo: int | None = None, uid: int = 0) -> None:
        self.caminho(alvo).mkdir(parents=True, exist_ok=True)
        if modo is not None:
            self.modos[alvo] = InfoArquivo(stat.S_IFDIR | modo, uid, 0)

    def socket(self, alvo: str, modo: int) -> None:
        self.arquivo(alvo)
        self.modos[alvo] = InfoArquivo(stat.S_IFSOCK | modo, 0, 0)

    def programa_instalado(self, *nomes: str, pasta: str = "/usr/bin") -> None:
        for nome in nomes:
            self.arquivo(f"{pasta}/{nome}")

    def responder(self, *comando: str, codigo: int = 0, saida: str = "", erro: str = "") -> None:
        self.respostas[comando] = Resultado(codigo, saida, erro)

    def servicos(self, **estados: str) -> None:
        """Estado das unidades: ``servicos(ufw="active", nftables="inactive")``."""
        for unidade, estado in estados.items():
            self.responder("systemctl", "is-active", unidade.replace("_", "-"), saida=f"{estado}\n")

    def sysctl(self, **valores: str) -> None:
        """``sysctl(kernel__kptr_restrict="0")``: ``__`` separa as pastas de /proc/sys."""
        for chave, valor in valores.items():
            self.arquivo("/proc/sys/" + chave.replace("__", "/"), f"{valor}\n")

    # -- o que as checagens usam -----------------------------------------------------------
    def _negado(self, alvo: str) -> bool:
        return any(alvo == n or alvo.startswith(n.rstrip("/") + "/") for n in self.negados)

    def ler(self, alvo: str, limite: int = linux_sistema.LIMITE_LEITURA) -> str | None:
        if self._negado(alvo):
            raise AcessoNegado(alvo)
        return super().ler(alvo, limite)

    def listar(self, alvo: str) -> list[str] | None:
        if self._negado(alvo):
            raise AcessoNegado(alvo)
        return super().listar(alvo)

    def estado(self, alvo: str) -> InfoArquivo | None:
        if alvo in self.modos:
            return self.modos[alvo]
        destino = self.caminho(alvo)
        if not destino.exists():
            return None
        return InfoArquivo(stat.S_IFDIR | 0o755 if destino.is_dir() else stat.S_IFREG | 0o644)

    def real(self, alvo: str) -> str:
        return self.reais.get(alvo, super().real(alvo))

    def comando(self, nome: str, *args: str, tempo: float = 30.0) -> Resultado | None:
        self.executados.append((nome, *args))
        return self.respostas.get((nome, *args))

    def root(self) -> bool:
        return self.eh_root

    def path_processo(self) -> str:
        return self.path


def rodar(sis: LinuxFalso, monkeypatch: pytest.MonkeyPatch, check_id: str) -> CheckOutcome:
    """Executa uma checagem de Linux contra o sistema falso (também em Windows)."""
    monkeypatch.setattr(linux_sistema, "criar", lambda: sis)
    return run_check(check_id, FATO_LOCAL, target="local")


def base_segura(raiz: Path, *, root: bool = False, path: str = "/usr/bin:/bin") -> LinuxFalso:
    """Um Ubuntu sem nenhum problema: cada teste estraga só o que quer avaliar."""
    sis = LinuxFalso(raiz, root=root, path=path)
    sis.arquivo("/etc/os-release", UBUNTU)
    sis.arquivo("/proc/sys/kernel/osrelease", "6.8.0-40-generic\n")
    sis.arquivo("/etc/passwd", ROOT_E_USUARIO, 0o644)
    sis.arquivo("/etc/group", "root:x:0:\n", 0o644)
    sis.arquivo("/etc/shadow", SHADOW_OK, 0o640)
    sis.arquivo("/etc/gshadow", "root:*::\n", 0o640)
    sis.arquivo("/etc/sudoers", "root ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n", 0o440)
    sis.pasta("/usr/bin")
    sis.pasta("/bin")
    sis.pasta("/sys/module")
    sis.arquivo("/sys/module/apparmor/parameters/enabled", "Y\n")
    for chave, valor in SYSCTL_SEGURO.items():
        sis.arquivo(f"/proc/sys/{chave}", f"{valor}\n")
    sis.arquivo("/proc/net/tcp", CABECALHO_TCP + linha_tcp("0100007F", 5432))
    sis.arquivo("/proc/net/tcp6", CABECALHO_TCP)
    sis.arquivo("/proc/self/mounts", "/dev/sda1 / ext4 rw 0 0\n")
    return sis
