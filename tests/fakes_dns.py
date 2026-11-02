"""Zona DNS de mentira: o resolvedor das checagens responde a partir de um dicionário.

Nenhum teste de DNS toca a rede. ``ZonaFalsa.instalar`` troca ``resolver.query`` e
``resolver.axfr`` e, por garantia, reprova qualquer resolução de nome fora de
127.0.0.1 (a fixture ``serve`` continua funcionando).
"""

from __future__ import annotations

import socket
import threading
from typing import Any

import dns.message
import dns.rcode
import dns.rrset
import pytest
from helpers import CheckOutcome, run_check

from eigan.checks.dns import resolver
from eigan.checks.dns.resolver import ERRO, NXDOMAIN, OK, VAZIO, Resposta, Transferencia
from eigan.core.models import Fact
from eigan.core.settings import Settings

#: valor especial: "o DNS não respondeu" para esse tipo de registro (ou nome inteiro)
FALHA = "falha"
_LOCAIS = {"127.0.0.1", "::1", "localhost", ""}


class ZonaFalsa:
    """``{nome: {tipo: [registros] | FALHA}}``; nome fora do dicionário = NXDOMAIN."""

    def __init__(
        self,
        registros: dict[str, Any] | None = None,
        *,
        transferencias: dict[str, Transferencia] | None = None,
        sem_rede: bool = False,
    ) -> None:
        self.registros = {nome.lower(): dados for nome, dados in (registros or {}).items()}
        self.transferencias = transferencias or {}
        self.sem_rede = sem_rede
        self.consultas: list[tuple[str, str]] = []
        self.flags_cd: list[tuple[str, str]] = []
        self.axfrs: list[tuple[str, str]] = []

    def query(
        self, nome: str, tipo: str, tempo: float = 3.0, sem_validacao: bool = False
    ) -> Resposta:
        self.consultas.append((nome, tipo))
        if sem_validacao:
            self.flags_cd.append((nome, tipo))
        if self.sem_rede:
            return Resposta(ERRO, erro="tempo esgotado")
        dados = self.registros.get(nome.lower())
        if dados is None:
            return Resposta(NXDOMAIN)
        if dados == FALHA or dados.get(tipo) == FALHA:
            return Resposta(ERRO, erro="tempo esgotado")
        valores = dados.get(tipo)
        return Resposta(OK, tuple(valores)) if valores else Resposta(VAZIO)

    def axfr(self, servidor: str, zona: str, tempo: float = 4.0) -> Transferencia:
        self.axfrs.append((servidor, zona))
        return self.transferencias.get(servidor, Transferencia(False, erro="REFUSED"))

    def instalar(self, monkeypatch: pytest.MonkeyPatch) -> ZonaFalsa:
        monkeypatch.setattr(resolver, "query", self.query)
        monkeypatch.setattr(resolver, "axfr", self.axfr)
        bloquear_rede(monkeypatch)
        return self


def bloquear_rede(monkeypatch: pytest.MonkeyPatch) -> None:
    """Qualquer tentativa de resolver um nome de verdade reprova o teste."""
    original = socket.getaddrinfo

    def so_local(host: Any, *args: Any, **kwargs: Any) -> Any:
        if str(host) not in _LOCAIS:
            raise AssertionError(f"teste tentou resolver um nome de verdade: {host}")
        return original(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", so_local)


def fato_dominio(dominio: str) -> Fact:
    return Fact("dns.domain", dominio, {"domain": dominio, "label": dominio})


def rodar(check_id: str, dominio: str = "exemplo.com.br") -> CheckOutcome:
    """Roda a checagem com um contexto novo (o cache de DNS vale por auditoria)."""
    return run_check(
        check_id,
        fato_dominio(dominio),
        target="https://exemplo.com.br/",
        settings=Settings(http_timeout=5.0),
    )


class ServidorAxfr:
    """Servidor TCP local que responde a um pedido AXFR como um servidor DNS responderia.

    ``modo``: ``entrega`` (zona inteira), ``recusa`` (REFUSED), ``so_soa`` (zona vazia),
    ``mudo`` (aceita e não responde), ``fecha`` (derruba a conexão) e ``sem_fim`` (nomes
    sem o SOA final, para provar que a leitura para na amostra).
    """

    def __init__(self, modo: str, zona: str = "exemplo.com.br", mensagens: int = 3) -> None:
        self.modo = modo
        self.zona = zona
        self.mensagens = mensagens
        self.socket = socket.create_server(("127.0.0.1", 0))
        self.porta = int(self.socket.getsockname()[1])
        self._aberto = threading.Event()
        self._thread = threading.Thread(target=self._atender, daemon=True)
        self._thread.start()

    def _soa(self) -> dns.rrset.RRset:
        return dns.rrset.from_text(
            f"{self.zona}.", 300, "IN", "SOA", f"ns1.{self.zona}. admin.{self.zona}. 1 2 3 4 5"
        )

    def _registro(self, rotulo: str) -> dns.rrset.RRset:
        return dns.rrset.from_text(f"{rotulo}.{self.zona}.", 300, "IN", "A", "192.0.2.10")

    def _atender(self) -> None:
        try:
            conexao, _ = self.socket.accept()
        except OSError:
            return
        with conexao:
            tamanho = int.from_bytes(self._ler(conexao, 2), "big")
            pedido = dns.message.from_wire(self._ler(conexao, tamanho))
            if self.modo == "mudo":
                self._aberto.wait(5.0)
            elif self.modo == "recusa":
                resposta = dns.message.make_response(pedido)
                resposta.set_rcode(dns.rcode.REFUSED)
                self._enviar(conexao, resposta)
            elif self.modo != "fecha":
                self._enviar_zona(conexao, pedido)

    def _enviar_zona(self, conexao: socket.socket, pedido: dns.message.Message) -> None:
        if self.modo == "so_soa":
            lotes = [[self._soa(), self._soa()]]
        elif self.modo == "sem_fim":
            lotes = [[self._soa()]] + [
                [self._registro(f"h{n}-{i}") for i in range(50)] for n in range(self.mensagens)
            ]
        else:
            lotes = [
                [self._soa(), self._registro("www")],
                [self._registro("vpn"), self._registro("homologacao")],
                [self._soa()],
            ]
        try:
            for lote in lotes:
                resposta = dns.message.make_response(pedido)
                resposta.answer = list(lote)
                self._enviar(conexao, resposta)
        except OSError:
            pass  # o cliente parou de ler na amostra: é o esperado

    @staticmethod
    def _ler(conexao: socket.socket, total: int) -> bytes:
        dados = b""
        while len(dados) < total:
            pedaco = conexao.recv(total - len(dados))
            if not pedaco:
                break
            dados += pedaco
        return dados

    @staticmethod
    def _enviar(conexao: socket.socket, resposta: dns.message.Message) -> None:
        dados = resposta.to_wire(max_size=65535)
        conexao.sendall(len(dados).to_bytes(2, "big") + dados)

    def fechar(self) -> None:
        self._aberto.set()
        self.socket.close()
        self._thread.join(timeout=5.0)
