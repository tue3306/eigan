"""Leitura de eventos do Windows exportados: XML do ``wevtutil`` e CSV.

O XML é lido com expressões regulares sobre cada bloco ``<Event>``, e não com um analisador
XML, de propósito. O ``wevtutil qe`` gera vários documentos colados, sem elemento raiz; o
Visualizador de Eventos gera um único documento, às vezes em uma linha só; e o arquivo pode
vir de uma máquina comprometida (sem análise de XML não há expansão de entidades nem XXE).

O CSV do Visualizador traz os campos só na mensagem traduzida para o idioma do Windows. Os
rótulos conhecidos estão em inglês e português; em outros idiomas prefira exportar em XML.
"""

from __future__ import annotations

import csv
import html
import re
import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass
from typing import TextIO

from . import tempo
from .agregacao import eh_ip, limpar
from .leitura import BLOCO_CHARS, Orcamento, ler_linhas

#: evento maior que isto é descartado (só protege a memória; eventos reais têm poucos KiB)
MAX_CHARS_EVENTO = 1_048_576
#: eventos cuja mensagem o CSV sabe interpretar
EVENTOS_LOGON = frozenset({4624, 4625})
EVENTOS_GRUPO = frozenset({4728, 4732, 4756})

_EVENTO_INICIO = re.compile(r"<Event[\s>]")
_FIM_EVENTO = "</Event>"
_ID = re.compile(r"<EventID(?:\s[^>]*)?>\s*(\d+)\s*</EventID>")
_TEMPO = re.compile(r"<TimeCreated\s[^>]*?SystemTime=['\"]([^'\"]+)['\"]")
_PROVEDOR = re.compile(r"<Provider\s[^>]*?Name=['\"]([^'\"]+)['\"]")
_COMPUTADOR = re.compile(r"<Computer>([^<]*)</Computer>")
_DADO = re.compile(r"<Data\s+Name=['\"]([^'\"]+)['\"]\s*>([^<]*)</Data>")
_DADO_USUARIO = re.compile(r"<(Subject\w+|Channel)>([^<]*)</\1>")

_COLUNAS = {
    "id": ("eventid", "id", "identificacaodoevento", "iddoevento", "codigodoevento", "instanceid"),
    "tempo": (
        "dateandtime",
        "timecreated",
        "timegenerated",
        "dataehora",
        "datahora",
        "date",
        "data",
        "timewritten",
    ),
    "fonte": ("source", "providername", "fonte", "origem"),
    "mensagem": ("message", "mensagem", "description", "descricao"),
    "computador": ("machinename", "computer", "computername", "computador"),
}
_ROTULOS_CONTA = {"accountname", "nomedaconta", "nomedeconta"}
_ROTULOS_SID = {"securityid", "iddeseguranca", "identificacaodeseguranca"}
_ROTULOS_LOGON = {"logontype", "tipodelogon"}
_ROTULOS_GRUPO = {"groupname", "nomedogrupo"}
_ROTULOS_SERVICO = {"servicename", "nomedoservico"}
_ROTULOS_ARQUIVO_SERVICO = {"servicefilename", "nomedoarquivodoservico", "nomedearquivodoservico"}
_ROTULOS_COMANDO = {"processcommandline", "linhadecomandodoprocesso", "linhadecomandodeprocesso"}
_ROTULOS_PROCESSO = {"newprocessname", "nomedonovoprocesso"}


@dataclass(slots=True)
class EventoWindows:
    """Um evento: ``campos`` usa os nomes do XML, mesmo quando veio de um CSV."""

    id: int
    momento: float | None
    provedor: str
    computador: str
    campos: dict[str, str]
    referencia: str

    def campo(self, nome: str) -> str:
        """Valor de um campo. ``-``, usado pelo Windows para vazio, vira texto vazio."""
        valor = self.campos.get(nome, "").strip()
        return "" if valor == "-" else valor


# -- XML -----------------------------------------------------------------------------


def blocos_xml(fluxo: TextIO, orcamento: Orcamento) -> Iterator[str]:
    """Separa os blocos ``<Event>...</Event>`` lendo o arquivo aos poucos."""
    resto = ""
    while not orcamento.esgotado:
        leitura = fluxo.read(BLOCO_CHARS)
        if not leitura:
            return
        texto = resto + leitura
        posicao = 0
        while True:
            inicio = _EVENTO_INICIO.search(texto, posicao)
            if inicio is None:
                resto = texto[-16:]
                break
            fim = texto.find(_FIM_EVENTO, inicio.start())
            if fim < 0:
                resto = texto[inicio.start() :]
                if len(resto) > MAX_CHARS_EVENTO:
                    resto = ""
                break
            posicao = fim + len(_FIM_EVENTO)
            bloco = texto[inicio.start() : posicao]
            if not orcamento.consumir(len(bloco)):
                return
            yield bloco


def interpretar_bloco(bloco: str, referencia: str) -> EventoWindows | None:
    """Extrai o que interessa de um bloco ``<Event>``. ``None`` se não for evento do Windows."""
    identificador = _ID.search(bloco)
    if identificador is None:
        return None
    campos = {nome: html.unescape(valor) for nome, valor in _DADO.findall(bloco)}
    usuario = bloco.find("<UserData")
    if usuario >= 0:
        for nome, valor in _DADO_USUARIO.findall(bloco, usuario):
            campos.setdefault(nome, html.unescape(valor))
    momento = _TEMPO.search(bloco)
    provedor = _PROVEDOR.search(bloco)
    computador = _COMPUTADOR.search(bloco)
    return EventoWindows(
        id=int(identificador.group(1)) & 0xFFFF,
        momento=tempo.de_iso(momento.group(1)) if momento else None,
        provedor=provedor.group(1) if provedor else "",
        computador=computador.group(1).strip() if computador else "",
        campos=campos,
        referencia=referencia,
    )


# -- CSV -----------------------------------------------------------------------------


def _norma(texto: str) -> str:
    """Rótulo sem acento, espaço nem pontuação: ``Nome da Conta:`` vira ``nomedaconta``."""
    decomposto = unicodedata.normalize("NFKD", texto)
    return "".join(c for c in decomposto if c.isalnum() and c.isascii()).lower()


def _mapear_colunas(cabecalho: list[str]) -> dict[str, int]:
    mapa: dict[str, int] = {}
    normalizados = [_norma(coluna) for coluna in cabecalho]
    for papel, nomes in _COLUNAS.items():
        for nome in nomes:
            if nome in normalizados:
                mapa[papel] = normalizados.index(nome)
                break
    return mapa


def _delimitador(linha: str) -> str:
    return max((",", ";", "\t"), key=linha.count)


def _cabecalho_da_amostra(amostra: str) -> str:
    for linha in amostra.split("\n"):
        texto = linha.strip("﻿ \r")
        if texto and not texto.startswith("#"):
            return texto
    return ""


def eh_csv_windows(amostra: str) -> bool:
    """Reconhece o cabeçalho de uma exportação de eventos do Windows."""
    cabecalho = _cabecalho_da_amostra(amostra)
    if not cabecalho:
        return False
    try:
        colunas = next(csv.reader([cabecalho], delimiter=_delimitador(cabecalho)))
    except (csv.Error, StopIteration):
        return False
    mapa = _mapear_colunas(colunas)
    if not ("id" in mapa and "tempo" in mapa and ("fonte" in mapa or "mensagem" in mapa)):
        return False
    # Uma coluna chamada só "id" é de qualquer aplicação; exportação do Windows diz "Event ID".
    return _norma(colunas[mapa["id"]]) != "id"


def _pares(mensagem: str) -> list[tuple[str, str]]:
    pares: list[tuple[str, str]] = []
    for linha in mensagem.splitlines():
        rotulo, separador, valor = linha.partition(":")
        if separador:
            pares.append((_norma(rotulo), valor.strip()))
    return pares


def _valores(pares: list[tuple[str, str]], rotulos: set[str]) -> list[str]:
    return [valor for rotulo, valor in pares if rotulo in rotulos]


def _posicao(valores: list[str], indice: int) -> str:
    return valores[indice] if indice < len(valores) else ""


def _primeiro(pares: list[tuple[str, str]], rotulos: set[str]) -> str:
    return _posicao(_valores(pares, rotulos), 0)


def campos_da_mensagem(evento: int, mensagem: str) -> dict[str, str]:
    """Traduz a mensagem do evento para os nomes de campo do XML.

    As contas aparecem sempre na mesma ordem no modelo de cada evento: primeiro quem fez a
    ação (``Subject``), depois o alvo. O IP é localizado pelo valor, o que independe do idioma.
    """
    pares = _pares(mensagem)
    contas = _valores(pares, _ROTULOS_CONTA)
    campos = {"SubjectUserName": _posicao(contas, 0)}
    if evento in EVENTOS_LOGON:
        campos["TargetUserName"] = _posicao(contas, 1)
        campos["LogonType"] = _primeiro(pares, _ROTULOS_LOGON)
        campos["IpAddress"] = next((v for _, v in pares if eh_ip(v)), "")
        campos["Status"] = _primeiro(pares, {"status"})
        campos["SubStatus"] = _primeiro(pares, {"substatus"})
    elif evento == 4720:
        campos["TargetUserName"] = _posicao(contas, 1)
    elif evento in EVENTOS_GRUPO:
        sids = _valores(pares, _ROTULOS_SID)
        campos["MemberSid"] = _posicao(sids, 1)
        campos["MemberName"] = _posicao(contas, 1)
        campos["TargetSid"] = _posicao(sids, 2)
        campos["TargetUserName"] = _primeiro(pares, _ROTULOS_GRUPO) or _posicao(contas, 2)
    elif evento in (4697, 7045):
        campos["ServiceName"] = _primeiro(pares, _ROTULOS_SERVICO)
        campos["ImagePath"] = _primeiro(pares, _ROTULOS_ARQUIVO_SERVICO)
    elif evento == 4688:
        campos["CommandLine"] = _primeiro(pares, _ROTULOS_COMANDO)
        campos["NewProcessName"] = _primeiro(pares, _ROTULOS_PROCESSO)
    return campos


def _sem_comentarios(linhas: Iterator[str]) -> Iterator[str]:
    """Pula o ``#TYPE ...`` do Windows PowerShell e as linhas em branco antes do cabeçalho."""
    no_inicio = True
    for linha in linhas:
        if no_inicio and (not linha.strip() or linha.startswith("#")):
            continue
        no_inicio = False
        yield linha + "\n"


def eventos_csv(
    fluxo: TextIO, amostra: str, orcamento: Orcamento, rotulo: str
) -> Iterator[EventoWindows]:
    """Gera os eventos de um CSV. Levanta ``csv.Error`` se a estrutura estiver quebrada."""
    cabecalho_texto = _cabecalho_da_amostra(amostra)
    leitor = csv.reader(
        _sem_comentarios(ler_linhas(fluxo, orcamento)), delimiter=_delimitador(cabecalho_texto)
    )
    cabecalho = next(leitor, None)
    if cabecalho is None:
        return
    colunas = _mapear_colunas(cabecalho)
    dia_antes = tempo.dia_primeiro(amostra)
    for numero, linha in enumerate(leitor, 2):
        evento = _evento_da_linha(linha, cabecalho, colunas, dia_antes, f"{rotulo}:{numero}")
        if evento is not None:
            yield evento


def _evento_da_linha(
    linha: list[str],
    cabecalho: list[str],
    colunas: dict[str, int],
    dia_antes: bool,
    referencia: str,
) -> EventoWindows | None:
    def coluna(papel: str) -> str:
        indice = colunas.get(papel)
        return linha[indice] if indice is not None and indice < len(linha) else ""

    identificador = coluna("id").strip()
    if not identificador.isdigit():
        return None
    numero = int(identificador) & 0xFFFF
    mensagem = coluna("mensagem")
    if not mensagem and len(linha) > len(cabecalho):
        # O Visualizador de Eventos grava a mensagem em uma sexta coluna sem título.
        mensagem = linha[len(cabecalho)]
    return EventoWindows(
        id=numero,
        momento=tempo.de_numerica(coluna("tempo"), dia_antes=dia_antes),
        provedor=coluna("fonte").strip(),
        computador=coluna("computador").strip(),
        campos=campos_da_mensagem(numero, mensagem),
        referencia=referencia,
    )


def resumo_campos(evento: EventoWindows, nomes: tuple[str, ...]) -> str:
    """Linha de amostra de um evento: data, número e os campos que importam."""
    partes = [f"{nome}={evento.campo(nome)}" for nome in nomes if evento.campo(nome)]
    prefixo = f"{evento.referencia}: {tempo.formatar(evento.momento)} evento {evento.id}"
    return limpar(f"{prefixo} {' '.join(partes)}", 400)
