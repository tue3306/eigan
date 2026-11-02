"""Acesso de SÓ LEITURA ao sistema operacional: registro, arquivos e comandos.

Toda checagem de host passa por estas funções pequenas — e só por elas. Os testes
as substituem com ``monkeypatch`` para simular Windows e Linux em qualquer
plataforma, sem tocar a máquina real.

Regras: comandos sempre com lista de argumentos (nunca ``shell=True``), caminho
absoluto do executável, tempo limite, sem janela no Windows e tolerância a
programa ausente. Leitura negada pelo sistema vira :class:`AcessoNegado`, que a
checagem registra como "não verificado: requer administrador/root".
"""

from __future__ import annotations

import fnmatch
import json
import os
import platform
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any

NAO_VERIFICADO = "não verificado: requer administrador/root"
#: pastas padrão de programas no Linux (não confiamos no PATH de quem executa)
PASTAS_PROGRAMAS = ("/usr/sbin", "/usr/bin", "/sbin", "/bin", "/usr/local/sbin", "/usr/local/bin")

#: recusa por privilégio, em qualquer idioma: códigos Win32/WMI (0x80070005, 0x80041003) e
#: as categorias do PowerShell (PermissionDenied, UnauthorizedAccess)
_NEGADO = re.compile(
    r"access (is )?denied|acesso negado|0x80070005|0x80041003|PermissionDenied|UnauthorizedAccess",
    re.I,
)


class AcessoNegado(Exception):
    """O sistema negou a leitura (falta de privilégio)."""


def negado(texto: str) -> bool:
    """Se uma mensagem ou código de erro indica falta de privilégio (independe do idioma)."""
    return bool(_NEGADO.search(texto or ""))


@dataclass(frozen=True)
class Resultado:
    """Saída de um comando."""

    codigo: int
    saida: str
    erro: str = ""


@dataclass(frozen=True)
class InfoArquivo:
    """Permissões e dono de um arquivo ou pasta (``os.stat``)."""

    modo: int
    uid: int = 0
    gid: int = 0

    @property
    def diretorio(self) -> bool:
        return stat.S_ISDIR(self.modo)

    @property
    def gravavel_por_todos(self) -> bool:
        return bool(self.modo & stat.S_IWOTH)

    @property
    def legivel_por_todos(self) -> bool:
        return bool(self.modo & stat.S_IROTH)

    @property
    def suid(self) -> bool:
        return bool(self.modo & stat.S_ISUID)

    @property
    def octal(self) -> str:
        return oct(stat.S_IMODE(self.modo))[2:].zfill(4)


# -- privilégio e identificação ----------------------------------------------------
def is_admin() -> bool:
    """Administrador elevado (Windows) ou root (Linux)."""
    if sys.platform == "win32":
        import ctypes

        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False
    return os.geteuid() == 0


def info_plataforma() -> dict[str, str]:
    """Nome da máquina, arquitetura e versão do kernel."""
    dados = platform.uname()
    return {"hostname": dados.node, "arch": dados.machine, "kernel": dados.release}


def hoje() -> date:
    """Data de hoje (UTC). Os testes substituem esta função para fixar o calendário."""
    return datetime.now(UTC).date()


# -- Windows -------------------------------------------------------------------------
def read_registry_value(caminho: str, nome: str) -> Any:
    """Valor ``nome`` da chave ``HKLM\\...`` (ou ``HKCU\\...``); None se não existe."""
    if sys.platform != "win32":
        return None
    import winreg

    raiz, _, subchave = caminho.partition("\\")
    colmeias = {
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
    }
    colmeia = colmeias.get(raiz.upper())
    if colmeia is None:
        raise ValueError(f"colmeia desconhecida: {raiz}")
    try:
        with winreg.OpenKey(
            colmeia, subchave, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        ) as chave:
            valor, _tipo = winreg.QueryValueEx(chave, nome)
    except FileNotFoundError:
        return None
    except PermissionError as exc:
        raise AcessoNegado(f"{caminho}\\{nome}") from exc
    except OSError:
        return None
    return valor


def programa_windows(nome: str) -> str:
    """Caminho absoluto de um programa do sistema (``System32``; ``Sysnative`` em Python 32 bits)."""
    raiz = os.environ.get("SystemRoot") or os.environ.get("windir") or r"C:\Windows"
    for pasta in ("Sysnative", "System32"):
        caminho = os.path.join(raiz, pasta, nome)
        if os.path.exists(caminho):
            return caminho
    return os.path.join(raiz, "System32", nome)


def run_powershell(script: str, tempo: float = 40.0) -> Resultado | None:
    """Executa um script curto no Windows PowerShell 5.1 (sem perfil, sem interação)."""
    executavel = programa_windows(os.path.join("WindowsPowerShell", "v1.0", "powershell.exe"))
    prefixo = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; $ProgressPreference='SilentlyContinue'; "
    args = [executavel, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", prefixo + script]
    return run_command(args, tempo=tempo)


def powershell_json(script: str, tempo: float = 40.0) -> Any:
    """Resultado de ``script | ConvertTo-Json`` já convertido; None se falhou ou veio vazio.

    Levanta :class:`AcessoNegado` quando o PowerShell recusa por falta de privilégio.
    """
    return _ler_json(run_powershell(f"{script} | ConvertTo-Json -Depth 3 -Compress", tempo=tempo))


def powershell_lista(script: str, tempo: float = 40.0) -> list[Any] | None:
    """Resultado de ``script`` sempre como lista; None se o comando falhou.

    Ao contrário de :func:`powershell_json`, separa "nenhum resultado" (``[]``, ex.: o recurso
    não existe nesta versão) de falha (None, nunca vira achado). Por isso qualquer erro do
    script interrompe a execução em vez de produzir uma lista vazia enganosa.
    """
    comando = (
        f"$ErrorActionPreference='Stop'; ConvertTo-Json -Depth 3 -Compress -InputObject @({script})"
    )
    resultado = run_powershell(comando, tempo=tempo)
    dados = _ler_json(resultado)
    if resultado is None or resultado.codigo != 0 or not isinstance(dados, list):
        return None
    return dados


def _ler_json(resultado: Resultado | None) -> Any:
    if resultado is None:
        return None
    if _NEGADO.search(resultado.erro):
        raise AcessoNegado(resultado.erro.strip().splitlines()[0][:200])
    texto = resultado.saida.strip()
    if not texto:
        return None
    try:
        return json.loads(texto)
    except ValueError:
        return None


# -- comandos (Windows e Linux) ---------------------------------------------------------
def run_command(
    args: list[str],
    tempo: float = 30.0,
    codificacao: str = "utf-8",
    ambiente: dict[str, str] | None = None,
) -> Resultado | None:
    """Executa ``args`` (sem shell). None se o programa não existe ou estourou o tempo."""
    flags = 0
    if sys.platform == "win32":
        flags = subprocess.CREATE_NO_WINDOW
    env = _ambiente_filho(ambiente)
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=tempo,
            check=False,
            env=env,
            creationflags=flags,
        )
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None
    return Resultado(
        proc.returncode, _texto(proc.stdout, codificacao), _texto(proc.stderr, codificacao)
    )


def _ambiente_filho(ambiente: dict[str, str] | None) -> dict[str, str] | None:
    """Ambiente do processo filho. No Linux, desfaz o LD_LIBRARY_PATH do PyInstaller.

    O bootloader do PyInstaller antepõe a pasta de extração ao LD_LIBRARY_PATH (e guarda o
    original em ``LD_LIBRARY_PATH_ORIG``); sem restaurar, ferramentas do sistema carregariam
    as bibliotecas embutidas e falhariam.
    """
    env: dict[str, str] | None = None
    if sys.platform != "win32":
        for var in ("LD_LIBRARY_PATH", "LD_PRELOAD"):
            original = os.environ.get(f"{var}_ORIG")
            if original is not None:
                env = env if env is not None else dict(os.environ)
                if original:
                    env[var] = original
                else:
                    env.pop(var, None)
    if ambiente:
        env = env if env is not None else dict(os.environ)
        env.update(ambiente)
    return env


def _texto(dados: bytes, codificacao: str) -> str:
    try:
        return dados.decode(codificacao, errors="replace")
    except LookupError:  # ex.: codec "oem" só existe no Windows
        return dados.decode("utf-8", errors="replace")


# -- arquivos (Linux) --------------------------------------------------------------------
def read_text_file(caminho: str, limite: int = 2_000_000) -> str | None:
    """Conteúdo de um arquivo de texto; None se não existe."""
    try:
        with open(caminho, "rb") as arquivo:
            dados = arquivo.read(limite)
    except (FileNotFoundError, NotADirectoryError, IsADirectoryError):
        return None
    except PermissionError as exc:
        raise AcessoNegado(caminho) from exc
    except OSError:
        return None
    return dados.decode("utf-8", errors="replace")


def list_dir(caminho: str) -> list[str] | None:
    """Nomes dentro de uma pasta (ordenados); None se a pasta não existe."""
    try:
        return sorted(os.listdir(caminho))
    except (FileNotFoundError, NotADirectoryError):
        return None
    except PermissionError as exc:
        raise AcessoNegado(caminho) from exc
    except OSError:
        return None


def stat_path(caminho: str) -> InfoArquivo | None:
    """Permissões de um caminho (segue links); None se não existe."""
    try:
        info = os.stat(caminho)
    except (FileNotFoundError, NotADirectoryError):
        return None
    except PermissionError as exc:
        raise AcessoNegado(caminho) from exc
    except OSError:
        return None
    return InfoArquivo(info.st_mode, info.st_uid, info.st_gid)


def exists(caminho: str) -> bool:
    return os.path.lexists(caminho)


def find_program(nome: str, pastas: tuple[str, ...] = PASTAS_PROGRAMAS) -> str | None:
    """Caminho de um programa nas pastas padrão do sistema (não usa o PATH)."""
    for pasta in pastas:
        caminho = f"{pasta}/{nome}"
        if os.path.isfile(caminho):
            return caminho
    return None


def environ_path() -> str:
    """PATH do processo que executa a auditoria."""
    return os.environ.get("PATH", "")


# -- utilidades sem acesso ao sistema ------------------------------------------------------
def expandir(padrao: str) -> list[str]:
    """Arquivos que casam com ``padrao`` (curinga só no último componente), em ordem."""
    if not any(c in padrao for c in "*?["):
        return [padrao]
    pasta, _, nome = padrao.rpartition("/")
    nomes = list_dir(pasta or "/") or []
    return [f"{pasta}/{item}" for item in nomes if fnmatch.fnmatchcase(item, nome)]
