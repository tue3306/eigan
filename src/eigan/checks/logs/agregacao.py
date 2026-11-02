"""Contadores de indícios: quantos, quando, de onde, quem, e como virar um achado.

Um indício é o que os analisadores acumulam por chave (um IP, um usuário): total, primeira e
última ocorrência, até cinco linhas de amostra e os horários, guardados em ``array`` para que
milhões de eventos não pesem na memória. A ordem das linhas não importa, porque rotação de
log e ``Get-WinEvent`` entregam do mais novo para o mais antigo: as janelas de tempo só são
calculadas no fim, com tudo ordenado.
"""

from __future__ import annotations

import ipaddress
import re
from array import array
from bisect import bisect_left, bisect_right
from collections import Counter
from collections.abc import Collection, Iterable, Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from ...core import redact
from ...core.context import CheckContext
from ...core.models import Confidence, Severity
from . import mitre, tempo

#: linhas de amostra por achado
MAX_AMOSTRAS = 5
#: tamanho máximo de uma linha de amostra
MAX_CHARS_AMOSTRA = 400
#: valores distintos (IPs, usuários...) contados por indício
MAX_DISTINTOS = 2_000
#: chaves distintas por tabela (protege a memória contra logs forjados)
MAX_CHAVES = 200_000
#: achados por tipo; o que passar disto entra em um achado único de "demais"
MAX_ACHADOS_POR_TIPO = 20
#: valores listados na evidência e nos detalhes
MAX_LISTADOS = 20
#: chave do achado que reúne o que passou do limite por tipo
CHAVE_DEMAIS = "demais"

_CONTROLE = re.compile(r"[\x00-\x1f\x7f-\x9f]+")


def limpar(valor: str, limite: int = 120) -> str:
    """Tira caracteres de controle e encurta: usuário e URL de log vêm do atacante."""
    texto = _CONTROLE.sub(" ", valor).strip()
    return texto if len(texto) <= limite else f"{texto[:limite]}…"


@lru_cache(maxsize=4_096)
def ip_interno(valor: str) -> bool:
    """Endereço privado ou local. Texto que não é IP (nome de máquina) conta como externo."""
    try:
        endereco = ipaddress.ip_address(valor.split("%", 1)[0])
    except ValueError:
        return False
    return endereco.is_private or endereco.is_loopback or endereco.is_link_local


def eh_ip(valor: str) -> bool:
    """O texto é um endereço IPv4 ou IPv6 válido."""
    try:
        ipaddress.ip_address(valor.split("%", 1)[0])
    except ValueError:
        return False
    return True


def _somar(contador: Counter[str], chave: str, peso: int) -> None:
    if chave and (chave in contador or len(contador) < MAX_DISTINTOS):
        contador[chave] += peso


@dataclass(slots=True)
class Indicio:
    """Acúmulo de ocorrências de uma mesma chave."""

    total: int = 0
    primeiro: float | None = None
    ultimo: float | None = None
    amostras: list[str] = field(default_factory=list)
    ips: Counter[str] = field(default_factory=Counter)
    usuarios: Counter[str] = field(default_factory=Counter)
    arquivos: Counter[str] = field(default_factory=Counter)
    extras: Counter[str] = field(default_factory=Counter)
    tempos: array[float] = field(default_factory=lambda: array("d"))

    def registrar(
        self,
        momento: float | None,
        amostra: str = "",
        *,
        ip: str = "",
        usuario: str = "",
        arquivo: str = "",
        extra: str = "",
        peso: int = 1,
        guardar_tempo: bool = False,
    ) -> None:
        self.total += peso
        if momento is not None:
            if self.primeiro is None or momento < self.primeiro:
                self.primeiro = momento
            if self.ultimo is None or momento > self.ultimo:
                self.ultimo = momento
            if guardar_tempo:
                self.tempos.extend([momento] * peso)
        if amostra and len(self.amostras) < MAX_AMOSTRAS:
            self.amostras.append(limpar(amostra, MAX_CHARS_AMOSTRA))
        _somar(self.ips, ip, peso)
        _somar(self.usuarios, usuario, peso)
        _somar(self.arquivos, arquivo, peso)
        _somar(self.extras, extra, peso)

    def fundir(self, outro: Indicio) -> None:
        """Soma outro indício a este (usado no achado de "demais")."""
        self.total += outro.total
        for momento in (outro.primeiro, outro.ultimo):
            if momento is not None:
                self.primeiro = min(momento, self.primeiro or momento)
                self.ultimo = max(momento, self.ultimo or momento)
        for amostra in outro.amostras:
            if len(self.amostras) < MAX_AMOSTRAS:
                self.amostras.append(amostra)
        for nome in ("ips", "usuarios", "arquivos", "extras"):
            destino: Counter[str] = getattr(self, nome)
            for chave, peso in getattr(outro, nome).items():
                _somar(destino, chave, peso)


class Tabela:
    """Indícios por chave, com limite de chaves distintas."""

    def __init__(self) -> None:
        self.itens: dict[str, Indicio] = {}
        self.descartados = 0

    def obter(self, chave: str) -> Indicio | None:
        """Indício da chave (criado na primeira vez); ``None`` se a tabela lotou."""
        atual = self.itens.get(chave)
        if atual is None:
            if len(self.itens) >= MAX_CHAVES:
                self.descartados += 1
                return None
            atual = self.itens[chave] = Indicio()
        return atual

    def registrar(self, chave: str, momento: float | None, amostra: str = "", **dados: Any) -> None:
        indicio = self.obter(chave)
        if indicio is not None:
            indicio.registrar(momento, amostra, **dados)


def pico_na_janela(tempos: Sequence[float], janela: float) -> int:
    """Maior número de ocorrências dentro de qualquer janela de ``janela`` segundos."""
    ordenados = sorted(tempos)
    inicio = 0
    melhor = 0
    for fim, momento in enumerate(ordenados):
        while momento - ordenados[inicio] > janela:
            inicio += 1
        melhor = max(melhor, fim - inicio + 1)
    return melhor


def contar_antes(ordenados: Sequence[float], momento: float, janela: float) -> int:
    """Quantas ocorrências (lista ordenada) aconteceram até ``janela`` s antes de ``momento``."""
    return bisect_right(ordenados, momento) - bisect_left(ordenados, momento - janela)


def principais(
    itens: Iterable[tuple[str, Indicio]],
    limite: int = MAX_ACHADOS_POR_TIPO,
    primeiro: Collection[str] = (),
) -> list[tuple[str, Indicio]]:
    """Mantém as chaves com mais ocorrências (e as de ``primeiro``) e funde as demais em uma só."""
    ordenados = sorted(itens, key=lambda par: (par[0] not in primeiro, -par[1].total, par[0]))
    if len(ordenados) <= limite:
        return ordenados
    demais = Indicio()
    for _, indicio in ordenados[limite:]:
        demais.fundir(indicio)
    return [*ordenados[:limite], (CHAVE_DEMAIS, demais)]


def _topo(contador: Counter[str]) -> list[str]:
    return [limpar(chave) for chave, _ in contador.most_common(MAX_LISTADOS)]


def _topo_com_total(contador: Counter[str]) -> list[dict[str, Any]]:
    return [{"valor": limpar(chave), "total": n} for chave, n in contador.most_common(MAX_LISTADOS)]


@dataclass(frozen=True)
class Relato:
    """O que ``relatar`` precisa além do indício."""

    achado: str
    ativo: str
    titulo: str
    resumo: str
    discriminador: str
    tecnicas: tuple[str, ...]
    fuso: str = "UTC"
    severidade: Severity | None = None
    confianca: Confidence = Confidence.FIRM
    extras: dict[str, Any] = field(default_factory=dict)
    tech: tuple[str, ...] = ()
    cves: tuple[str, ...] = ()


def relatar(ctx: CheckContext, relato: Relato, indicio: Indicio) -> None:
    """Transforma um indício em achado: contagens, período, origem e amostras mascaradas."""
    amostras = [redact.redact(linha) for linha in indicio.amostras]
    periodo = ""
    if indicio.primeiro is not None:
        periodo = (
            f"Período ({relato.fuso}): {tempo.formatar(indicio.primeiro)} "
            f"a {tempo.formatar(indicio.ultimo)}"
        )
    linhas = [
        limpar(relato.resumo, 500),
        f"Ocorrências: {indicio.total}",
        periodo,
        _linha_lista("IPs de origem", indicio.ips),
        _linha_lista("Usuários", indicio.usuarios),
        f"MITRE ATT&CK: {mitre.texto(relato.tecnicas)}",
    ]
    if amostras:
        linhas += ["Amostras:", *amostras]
    detalhes: dict[str, Any] = {
        "total": indicio.total,
        "primeiro": tempo.formatar(indicio.primeiro),
        "ultimo": tempo.formatar(indicio.ultimo),
        "fuso": relato.fuso,
        "ips": _topo_com_total(indicio.ips),
        "usuarios": [
            {"valor": redact.redact(item["valor"]), "total": item["total"]}
            for item in _topo_com_total(indicio.usuarios)
        ],
        "arquivos": _topo_com_total(indicio.arquivos),
        "mitre": mitre.detalhes(relato.tecnicas),
        "amostras": amostras,
    }
    detalhes.update(relato.extras)
    ctx.report(
        relato.achado,
        asset=relato.ativo,
        title=limpar(redact.redact(relato.titulo), 160),
        severity=relato.severidade,
        evidence="\n".join(linha for linha in linhas if linha),
        details=detalhes,
        confidence=relato.confianca,
        cves=list(relato.cves),
        discriminator=relato.discriminador,
        tech=list(relato.tech),
    )


def _linha_lista(rotulo: str, contador: Counter[str]) -> str:
    if not contador:
        return ""
    texto = ", ".join(redact.redact(valor) for valor in _topo(contador))
    if len(contador) > MAX_LISTADOS:
        texto += f" (e mais {len(contador) - MAX_LISTADOS})"
    return f"{rotulo}: {texto}"
