"""Leitura de registros DMARC (RFC 7489): versão, política, subdomínios, pct e relatórios.

Só interpreta texto; a decisão do que reportar fica em ``correio.py``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ...core.context import CheckContext
from . import resolver
from .nomes import dentro_de, normalizar

POLITICAS = ("none", "quarantine", "reject")
#: no máximo estes destinos externos de relatório são conferidos (uma consulta cada)
MAX_DESTINOS = 3

_CANDIDATO = re.compile(r"^\s*v\s*=\s*dmarc1\s*(?:;|$)", re.I)
_VERSAO_EXATA = re.compile(r"^\s*[vV]\s*=\s*DMARC1\s*(?:;|$)")


@dataclass
class Dmarc:
    registro: str
    tags: dict[str, str] = field(default_factory=dict)

    @property
    def versao_exata(self) -> bool:
        """``v=DMARC1`` precisa ser exatamente assim e vir primeiro (RFC 7489, 6.3)."""
        return bool(_VERSAO_EXATA.match(self.registro))

    @property
    def politica(self) -> str | None:
        valor = self.tags.get("p", "").lower()
        return valor if valor in POLITICAS else None

    @property
    def sp_invalido(self) -> bool:
        return "sp" in self.tags and self.tags["sp"].lower() not in POLITICAS

    @property
    def subdominios(self) -> str | None:
        """Política dos subdomínios: ``sp`` ou, sem ele, a mesma de ``p`` (RFC 7489, 6.3)."""
        if "sp" in self.tags and not self.sp_invalido:
            return self.tags["sp"].lower()
        return self.politica

    @property
    def pct(self) -> int:
        """Percentual em que a política vale; valor ausente ou inválido = 100."""
        texto = self.tags.get("pct", "").strip()
        if not (texto.isascii() and texto.isdigit()) or not 0 <= int(texto) <= 100:
            return 100
        return int(texto)

    @property
    def rua(self) -> list[str]:
        """URIs de relatório agregado válidos (``mailto:`` com endereço, ``https:``)."""
        uris: list[str] = []
        for bruto in self.tags.get("rua", "").split(","):
            uri = bruto.strip().split("!", 1)[0]  # "!10m" é o limite de tamanho
            esquema, sep, resto = uri.partition(":")
            if not sep or not resto:
                continue
            if esquema.lower() == "mailto" and "@" in resto:
                uris.append(uri)
            elif esquema.lower() == "https":
                uris.append(uri)
        return uris


def candidatos(resposta: resolver.Resposta) -> list[str]:
    """Registros que pretendem ser DMARC (começam com v=DMARC1, sem diferenciar maiúsculas)."""
    return [texto.strip() for texto in resposta.registros if _CANDIDATO.match(texto)]


def analisar(registro: str) -> Dmarc:
    tags: dict[str, str] = {}
    for parte in registro.split(";"):
        chave, sep, valor = parte.partition("=")
        if sep:
            tags.setdefault(chave.strip().lower(), valor.strip())
    return Dmarc(registro=registro, tags=tags)


def host_externo(uri: str, org: str) -> str | None:
    """Domínio de um ``mailto:`` do rua quando fica fora do domínio da política."""
    if not uri.lower().startswith("mailto:"):
        return None
    host = normalizar(uri.split("?", 1)[0].rsplit("@", 1)[-1])
    return host if host and not dentro_de(host, org) else None


def relatorios_bloqueados(ctx: CheckContext, dmarc: Dmarc, org: str) -> list[str] | None:
    """Destinos externos que NÃO autorizam receber relatórios de ``org`` (RFC 7489, 7.1).

    O destino externo precisa publicar ``<org>._report._dmarc.<destino>`` com
    ``v=DMARC1``; sem isso, quem recebe e-mail não envia o relatório para lá.
    Devolve a lista só quando TODOS os destinos estão nessa situação; None se
    algum destino funciona (interno, https ou externo autorizado) ou se o DNS
    não respondeu de forma conclusiva.
    """
    if not dmarc.rua:
        return None
    externos: list[str] = []
    for uri in dmarc.rua:
        host = host_externo(uri, org)
        if host is None:
            return None  # destino interno ou https: os relatórios chegam
        if host not in externos:
            externos.append(host)
    if len(externos) > MAX_DESTINOS:
        return None
    for host in externos:
        resposta = resolver.txt(ctx, f"{org}._report._dmarc.{host}")
        if resposta.status == resolver.ERRO:
            return None
        if any(_CANDIDATO.match(texto) for texto in resposta.registros):
            return None
    return externos
