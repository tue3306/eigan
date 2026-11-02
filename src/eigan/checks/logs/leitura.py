"""Leitura dos logs em fluxo: arquivo ou pasta, ``.gz``, UTF-8 e UTF-16, com limites.

Nada aqui carrega o arquivo inteiro na memória. Log de servidor pode ter gigabytes e vem
de fora: um ``.gz`` malicioso pode descompactar para terabytes numa linha só. Por isso há
limite de linhas (``settings.max_log_lines``), de caracteres por linha, de caracteres no
total, de tempo e de profundidade de pasta, e o botão Cancelar é respeitado.
"""

from __future__ import annotations

import bz2
import codecs
import gzip
import io
import lzma
import os
import re
import time
import zlib
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, TextIO, cast

from ...core.settings import Settings

#: profundidade máxima de subpastas percorridas
MAX_PROFUNDIDADE = 8
#: linha maior que isto é cortada (o resto é descartado sem ir para a memória)
MAX_CHARS_LINHA = 65_536
#: orçamento total de caracteres: ``max_log_lines`` vezes esta média
CHARS_POR_LINHA = 4_096
#: de quantas em quantas linhas conferir o cancelamento e o relógio
INTERVALO_CONTROLE = 2_048
#: amostra lida do início do arquivo para reconhecer codificação e formato
TAMANHO_AMOSTRA = 65_536
#: tamanho do bloco ao ler arquivos sem quebra de linha (XML exportado)
BLOCO_CHARS = 65_536

GZIP_ASSINATURA = b"\x1f\x8b"
EVTX_ASSINATURA = b"ElfFile\x00"
BZIP2_ASSINATURA = b"BZh"
XZ_ASSINATURA = b"\xfd7zXZ\x00"
ZSTD_ASSINATURA = b"\x28\xb5\x2f\xfd"
#: fração de bytes NUL (de uma amostra) acima da qual o arquivo é tratado como binário
NUL_MAX_FRACAO = 0.30
ERROS_LEITURA = (OSError, EOFError, zlib.error, lzma.LZMAError)

_SUFIXOS_LOG = {
    ".log",
    ".txt",
    ".csv",
    ".xml",
    ".gz",
    ".bz2",
    ".xz",
    ".zst",
    ".evtx",
    ".out",
    ".old",
    ".audit",
}
_ROTACIONADO = re.compile(r"\.\d{1,4}$|[-_.]\d{8}$")
_BINARIOS_CONHECIDOS = {"wtmp", "btmp", "utmp", "lastlog", "faillog", "tallylog"}


class ArquivoBinario(Exception):
    """O arquivo não é texto (ex.: ``wtmp`` ou banco do journald): não dá para analisar."""


class CompressaoNaoSuportada(ArquivoBinario):
    """Arquivo compactado em formato que a biblioteca padrão não lê (ex.: ``.zst``)."""


@dataclass
class Orcamento:
    """Limites de leitura compartilhados por todos os arquivos da fonte."""

    max_linhas: int
    max_chars: int
    prazo: float
    cancelamento: Callable[[], None]
    linhas: int = 0
    chars: int = 0
    motivo: str = ""

    @classmethod
    def novo(
        cls, settings: Settings, cancelamento: Callable[[], None], tempo_s: float
    ) -> Orcamento:
        return cls(
            max_linhas=max(1, settings.max_log_lines),
            max_chars=max(1, settings.max_log_lines) * CHARS_POR_LINHA,
            prazo=time.monotonic() + tempo_s,
            cancelamento=cancelamento,
        )

    @property
    def esgotado(self) -> bool:
        return bool(self.motivo)

    def consumir(self, chars: int) -> bool:
        """Conta um registro. ``False`` quando já não se deve processá-lo."""
        if self.motivo:
            return False
        if self.linhas >= self.max_linhas:
            self.motivo = "linhas"
            return False
        self.linhas += 1
        self.chars += chars
        if time.monotonic() > self.prazo:
            self.motivo = "tempo"
            return False
        if self.chars > self.max_chars:
            self.motivo = "tamanho"
            return False
        if self.linhas % INTERVALO_CONTROLE == 0:
            self.cancelamento()
            if time.monotonic() > self.prazo:
                self.motivo = "tempo"
                return False
        return True


@dataclass(frozen=True)
class ArquivoLog:
    """Um arquivo a ler: ``rotulo`` é o nome curto usado nas amostras."""

    caminho: Path
    rotulo: str


@dataclass
class Descoberta:
    """Resultado de percorrer a fonte: o que ler e o que ficou de fora."""

    arquivos: list[ArquivoLog] = field(default_factory=list)
    problemas: list[str] = field(default_factory=list)
    limite_atingido: bool = False


def parece_log(nome: str) -> bool:
    """Decide pelo nome se um arquivo de uma pasta merece ser aberto."""
    minusculo = nome.lower()
    if minusculo in _BINARIOS_CONHECIDOS or minusculo.endswith(".journal"):
        return False
    sufixo = Path(minusculo).suffix
    return not sufixo or sufixo in _SUFIXOS_LOG or _ROTACIONADO.search(minusculo) is not None


def descobrir(origem: Path, settings: Settings) -> Descoberta:
    """Lista os arquivos da fonte, em ordem estável, sem seguir atalhos da pasta."""
    resultado = Descoberta()
    if origem.is_file():
        resultado.arquivos.append(ArquivoLog(origem, origem.name))
        return resultado
    if not origem.is_dir():
        resultado.problemas.append(f"{origem}: caminho não encontrado ou sem permissão")
        return resultado
    ignoradas = {nome.strip() for nome in settings.skip_dirs.split(",") if nome.strip()}
    pendentes: list[tuple[Path, int]] = [(origem, 0)]
    while pendentes:
        pasta, profundidade = pendentes.pop()
        try:
            with os.scandir(pasta) as itens:
                entradas = sorted(itens, key=lambda item: item.name)
        except OSError as erro:
            resultado.problemas.append(f"{pasta}: {_motivo(erro)}")
            continue
        for entrada in entradas:
            try:
                if entrada.is_dir(follow_symlinks=False):
                    if entrada.name not in ignoradas and profundidade < MAX_PROFUNDIDADE:
                        pendentes.append((Path(entrada.path), profundidade + 1))
                elif entrada.is_file(follow_symlinks=False) and parece_log(entrada.name):
                    if len(resultado.arquivos) >= settings.max_files:
                        resultado.limite_atingido = True
                        return resultado
                    caminho = Path(entrada.path)
                    rotulo = caminho.relative_to(origem).as_posix()
                    resultado.arquivos.append(ArquivoLog(caminho, rotulo))
            except OSError as erro:
                resultado.problemas.append(f"{entrada.path}: {_motivo(erro)}")
    resultado.arquivos.sort(key=lambda arquivo: arquivo.rotulo)
    return resultado


def _motivo(erro: OSError) -> str:
    if isinstance(erro, PermissionError):
        return "sem permissão de leitura"
    return erro.strerror or type(erro).__name__


def _utf8_ou_cp1252(inicio: bytes) -> str:
    """UTF-8 quando a amostra decodifica; senão cp1252 (``Export-Csv`` do PowerShell 5.1)."""
    try:
        codecs.getincrementaldecoder("utf-8")().decode(inicio, final=False)
    except UnicodeDecodeError:
        return "cp1252"
    return "utf-8"


def detectar_codificacao(inicio: bytes) -> str:
    """Escolhe o codec pelo BOM ou pelo padrão de zeros; texto binário levanta exceção."""
    if inicio.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    if inicio.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf-16"
    if b"\x00" not in inicio:
        return _utf8_ou_cp1252(inicio)
    amostra = inicio[: 4096 - (len(inicio[:4096]) % 2)]
    pares = amostra[0::2].count(0)
    impares = amostra[1::2].count(0)
    metade = len(amostra) // 2 or 1
    if impares / metade > 0.4 and pares / metade < 0.05:
        return "utf-16-le"
    if pares / metade > 0.4 and impares / metade < 0.05:
        return "utf-16-be"
    if inicio.count(0) / len(inicio) <= NUL_MAX_FRACAO:
        # Poucos zeros: bloco de NUL de queda de energia no meio de um log de texto.
        return _utf8_ou_cp1252(inicio)
    raise ArquivoBinario


@dataclass
class TextoAberto:
    """Arquivo aberto como texto: ``amostra`` é o começo já decodificado."""

    fluxo: TextIO
    amostra: str
    compactado: bool


def _descompactar(bruto: BinaryIO, assinatura: bytes) -> io.BufferedReader:
    if assinatura.startswith(BZIP2_ASSINATURA):
        leitor: io.BufferedIOBase = bz2.BZ2File(bruto, mode="rb")
    elif assinatura.startswith(XZ_ASSINATURA):
        leitor = lzma.LZMAFile(bruto, mode="rb")
    else:
        leitor = gzip.GzipFile(fileobj=bruto, mode="rb")
    return io.BufferedReader(cast(io.RawIOBase, leitor), buffer_size=TAMANHO_AMOSTRA)


@contextmanager
def abrir_texto(caminho: Path) -> Iterator[TextoAberto]:
    """Abre o arquivo como texto, descompactando pela assinatura, não pela extensão.

    Levanta ``ArquivoBinario`` quando não é texto. Erros de disco ou de ``.gz`` corrompido
    ficam para quem lê: fazem parte de ``ERROS_LEITURA``.
    """
    with open(caminho, "rb", buffering=TAMANHO_AMOSTRA) as aberto:
        bruto = cast(io.BufferedReader, aberto)
        assinatura = bruto.peek(8)[:8]
        if assinatura.startswith(EVTX_ASSINATURA):
            raise ArquivoBinario
        if assinatura.startswith(ZSTD_ASSINATURA):
            raise CompressaoNaoSuportada
        compactado = assinatura.startswith((GZIP_ASSINATURA, BZIP2_ASSINATURA, XZ_ASSINATURA))
        binario: io.BufferedReader = _descompactar(bruto, assinatura) if compactado else bruto
        inicio = binario.peek(TAMANHO_AMOSTRA)[:TAMANHO_AMOSTRA]
        codec = detectar_codificacao(inicio)
        if codec.startswith("utf-16"):
            inicio = inicio[: len(inicio) - (len(inicio) % 2)]
        amostra = inicio.decode(codec, errors="replace").replace("\r\n", "\n")
        fluxo = io.TextIOWrapper(binario, encoding=codec, errors="replace", newline=None)
        try:
            yield TextoAberto(fluxo, amostra, compactado)
        finally:
            fluxo.detach()


def ler_linhas(fluxo: TextIO, orcamento: Orcamento) -> Iterator[str]:
    """Gera as linhas sem o fim de linha, respeitando o orçamento e cortando as gigantes."""
    while True:
        linha = fluxo.readline(MAX_CHARS_LINHA)
        if not linha:
            return
        consumidos = len(linha)
        if consumidos >= MAX_CHARS_LINHA and not linha.endswith("\n"):
            while True:
                resto = fluxo.readline(MAX_CHARS_LINHA)
                consumidos += len(resto)
                if not resto or resto.endswith("\n") or consumidos > orcamento.max_chars:
                    break
        if not orcamento.consumir(consumidos):
            return
        if "\x00" in linha:
            linha = linha.replace("\x00", "")
        yield linha.rstrip("\r\n")


def data_referencia(caminho: Path) -> float:
    """Data do arquivo: de onde vem o ano das linhas de syslog que não o trazem."""
    try:
        return caminho.stat().st_mtime
    except OSError:
        return time.time()
