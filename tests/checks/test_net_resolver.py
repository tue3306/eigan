"""Resolvedor DNS aberto (``net.dns``): UDP e TCP, com servidores DNS falsos em 127.0.0.1."""

from __future__ import annotations

import socket
import struct
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager

import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset
import pytest
from fakes_net import fast_settings
from helpers import CheckOutcome, run_check

from eigan.checks.net import common, resolver
from eigan.core.context import CheckContext, ScanContext
from eigan.core.models import Confidence, Exposure, Fact, Severity
from eigan.core.registry import get_check
from eigan.core.target import parse_target

Answer = Callable[[dns.message.Message], dns.message.Message | None]
PUBLIC_IP = "93.184.216.34"


def answer_with(
    *addresses: str,
    ra: bool = True,
    aa: bool = False,
    rcode: dns.rcode.Rcode = dns.rcode.NOERROR,
) -> Answer:
    def build(query: dns.message.Message) -> dns.message.Message:
        response = dns.message.make_response(query)
        if ra:
            response.flags |= dns.flags.RA
        if aa:
            response.flags |= dns.flags.AA
        response.set_rcode(rcode)
        if addresses:
            name = query.question[0].name
            response.answer.append(dns.rrset.from_text(name, 60, "IN", "A", *addresses))
        return response

    return build


def _bind_pair() -> tuple[socket.socket, socket.socket]:
    """TCP e UDP na mesma porta efêmera; tenta de novo se o UDP já estiver ocupado."""
    for _ in range(50):
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            tcp.bind(("127.0.0.1", 0))
            udp.bind(("127.0.0.1", tcp.getsockname()[1]))
        except OSError:
            tcp.close()
            udp.close()
            continue
        return tcp, udp
    raise OSError("sem porta TCP+UDP livre")


class FakeDns:
    """Escuta TCP e UDP na MESMA porta; ``None`` num protocolo = fica mudo nele."""

    def __init__(self, udp: Answer | None, tcp: Answer | None) -> None:
        self.udp_answer = udp
        self.tcp_answer = tcp
        self.queries: list[dns.message.Message] = []
        self._stop = threading.Event()
        self._tcp, self._udp = _bind_pair()
        self.port: int = self._tcp.getsockname()[1]
        self._tcp.listen(8)
        self._tcp.settimeout(0.05)
        self._udp.settimeout(0.05)
        self._threads = [
            threading.Thread(target=self._serve_udp, daemon=True),
            threading.Thread(target=self._serve_tcp, daemon=True),
        ]
        for thread in self._threads:
            thread.start()

    def _serve_udp(self) -> None:
        while not self._stop.is_set():
            try:
                data, peer = self._udp.recvfrom(4096)
            except TimeoutError:
                continue
            except OSError:
                # no Windows, um ICMP de porta fechada aparece aqui como ConnectionResetError
                if self._stop.is_set():
                    return
                continue
            query = dns.message.from_wire(data)
            self.queries.append(query)
            response = self.udp_answer(query) if self.udp_answer else None
            if response is not None:
                self._udp.sendto(response.to_wire(), peer)

    def _serve_tcp(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _peer = self._tcp.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with conn:
                conn.settimeout(2.0)
                self._answer_tcp(conn)

    def _answer_tcp(self, conn: socket.socket) -> None:
        try:
            header = conn.recv(2)
            if len(header) < 2:
                return
            size = struct.unpack(">H", header)[0]
            data = b""
            while len(data) < size:
                chunk = conn.recv(size - len(data))
                if not chunk:
                    return
                data += chunk
            query = dns.message.from_wire(data)
            self.queries.append(query)
            response = self.tcp_answer(query) if self.tcp_answer else None
            if response is not None:
                wire = response.to_wire()
                conn.sendall(struct.pack(">H", len(wire)) + wire)
        except OSError:
            return

    def stop(self) -> None:
        self._stop.set()
        for thread in self._threads:
            thread.join(timeout=2)
        self._udp.close()
        self._tcp.close()


@contextmanager
def fake_dns(udp: Answer | None, tcp: Answer | None) -> Iterator[FakeDns]:
    server = FakeDns(udp, tcp)
    try:
        yield server
    finally:
        server.stop()


def host_fact(host: str = "127.0.0.1") -> Fact:
    return Fact("host", host, {"host": host, "label": host})


@pytest.fixture
def internet(monkeypatch: pytest.MonkeyPatch) -> None:
    """O alvo "está" na Internet e a rede deste computador não intercepta DNS."""
    monkeypatch.setattr(common, "exposure_of", lambda _host: Exposure.INTERNET)
    monkeypatch.setattr(resolver, "network_intercepts_dns", lambda _ctx: False)


def run_dns(monkeypatch: pytest.MonkeyPatch, server: FakeDns) -> CheckOutcome:
    monkeypatch.setattr(resolver, "DNS_PORT", server.port)
    return run_check("net.dns", host_fact(), settings=fast_settings())


# -- achado ---------------------------------------------------------------------------------------


@pytest.mark.usefixtures("internet")
def test_resolvedor_aberto_por_udp_e_tcp(monkeypatch: pytest.MonkeyPatch) -> None:
    with fake_dns(answer_with(PUBLIC_IP), answer_with(PUBLIC_IP)) as server:
        out = run_dns(monkeypatch, server)
    [finding] = out.by_id("net.dns.resolvedor_aberto")
    assert finding.severity is Severity.MEDIUM
    assert finding.confidence is Confidence.FIRM
    assert finding.asset == f"127.0.0.1:{server.port}/udp"
    assert "UDP e TCP" in finding.evidence
    assert PUBLIC_IP in finding.evidence
    assert finding.details["protocolos"] == ["UDP", "TCP"]
    # a pergunta é a de um cliente comum: A de example.com com recursão desejada
    [udp_query, tcp_query] = server.queries
    for query in (udp_query, tcp_query):
        assert query.flags & dns.flags.RD
        assert query.question[0].rdtype == dns.rdatatype.A
        assert query.question[0].name.to_text() == "example.com."


@pytest.mark.usefixtures("internet")
def test_resolvedor_aberto_so_por_tcp(monkeypatch: pytest.MonkeyPatch) -> None:
    with fake_dns(None, answer_with(PUBLIC_IP)) as server:
        out = run_dns(monkeypatch, server)
    [finding] = out.by_id("net.dns.resolvedor_aberto")
    assert finding.asset == f"127.0.0.1:{server.port}/tcp"
    assert finding.details["protocolos"] == ["TCP"]


@pytest.mark.usefixtures("internet")
def test_resolvedor_aberto_so_por_udp(monkeypatch: pytest.MonkeyPatch) -> None:
    with fake_dns(answer_with(PUBLIC_IP), None) as server:
        out = run_dns(monkeypatch, server)
    [finding] = out.by_id("net.dns.resolvedor_aberto")
    assert finding.asset == f"127.0.0.1:{server.port}/udp"
    assert finding.details["protocolos"] == ["UDP"]


# -- falso positivo --------------------------------------------------------------------------------


@pytest.mark.usefixtures("internet")
@pytest.mark.parametrize(
    "answer",
    [
        pytest.param(answer_with(PUBLIC_IP, ra=False), id="sem-flag-RA"),
        pytest.param(answer_with(PUBLIC_IP, aa=True), id="servidor-autoritativo"),
        pytest.param(answer_with(rcode=dns.rcode.REFUSED), id="recursao-recusada"),
        pytest.param(answer_with(rcode=dns.rcode.SERVFAIL), id="falha-do-servidor"),
        pytest.param(answer_with(), id="resposta-vazia"),
        pytest.param(answer_with("10.0.0.1"), id="endereco-privado"),
        pytest.param(answer_with("127.0.0.1"), id="sinkhole-local"),
    ],
)
def test_resposta_que_nao_prova_recursao(monkeypatch: pytest.MonkeyPatch, answer: Answer) -> None:
    with fake_dns(answer, answer) as server:
        out = run_dns(monkeypatch, server)
    assert not out.findings


@pytest.mark.usefixtures("internet")
def test_resposta_com_cname_sem_endereco_nao_conta(monkeypatch: pytest.MonkeyPatch) -> None:
    def cname(query: dns.message.Message) -> dns.message.Message:
        response = dns.message.make_response(query)
        response.flags |= dns.flags.RA
        response.answer.append(
            dns.rrset.from_text(query.question[0].name, 60, "IN", "CNAME", "outro.example.")
        )
        return response

    with fake_dns(cname, cname) as server:
        out = run_dns(monkeypatch, server)
    assert not out.findings


@pytest.mark.usefixtures("internet")
def test_servidor_que_nao_e_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    with fake_dns(None, None) as server:
        out = run_dns(monkeypatch, server)
    assert not out.findings


def test_rede_que_intercepta_dns_nao_acusa_ninguem(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(common, "exposure_of", lambda _host: Exposure.INTERNET)
    monkeypatch.setattr(resolver, "network_intercepts_dns", lambda _ctx: True)
    with fake_dns(answer_with(PUBLIC_IP), None) as server:
        out = run_dns(monkeypatch, server)
    assert not out.findings
    assert any("intercepta" in line for line in out.logs)


def test_host_que_nao_resolve(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(common, "exposure_of", lambda _host: Exposure.INTERNET)
    monkeypatch.setattr(resolver.netutil, "resolve", lambda _host: ())
    monkeypatch.setattr(resolver, "ask", lambda *_a, **_k: pytest.fail("não deveria consultar"))
    out = run_check("net.dns", host_fact("nao-existe.invalid"), settings=fast_settings())
    assert not out.findings


@pytest.mark.parametrize(
    ("exposure", "applies"),
    [(Exposure.INTERNET, True), (Exposure.INTERNAL, False), (Exposure.LOCAL, False)],
)
def test_so_avalia_enderecos_da_internet(
    monkeypatch: pytest.MonkeyPatch, exposure: Exposure, applies: bool
) -> None:
    monkeypatch.setattr(common, "exposure_of", lambda _host: exposure)
    item = get_check("net.dns")
    assert item is not None
    assert item.applies(host_fact("192.0.2.10"), "padrao", "linux") is applies


# -- apoios ---------------------------------------------------------------------------------------


def test_consulta_sem_resposta_devolve_none(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_args: object, **_kwargs: object) -> dns.message.Message:
        raise OSError("sem rota")

    monkeypatch.setattr(resolver.dns.query, "udp", boom)
    monkeypatch.setattr(resolver.dns.query, "tcp", boom)
    assert resolver.ask("192.0.2.1", 53, tcp=False, timeout=0.1) is None
    assert resolver.ask("192.0.2.1", 53, tcp=True, timeout=0.1) is None


def test_lixo_na_resposta_udp_nao_quebra() -> None:
    silent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    silent.bind(("127.0.0.1", 0))
    silent.settimeout(1.0)
    port = silent.getsockname()[1]
    result: list[dns.message.Message | None] = []
    client = threading.Thread(
        target=lambda: result.append(resolver.ask("127.0.0.1", port, tcp=False, timeout=0.5))
    )
    client.start()
    try:
        _data, peer = silent.recvfrom(4096)
        silent.sendto(b"isto nao e dns", peer)
        client.join(timeout=3)
    finally:
        silent.close()
    assert result == [None]


def test_respostas_de_recursao_filtram_tipo_e_repetidos() -> None:
    query = dns.message.make_query(resolver.PROBE_NAME, dns.rdatatype.A)
    response = answer_with(PUBLIC_IP, "8.8.8.8", PUBLIC_IP)(query)
    assert response is not None
    assert resolver.recursion_answers(response) == [PUBLIC_IP, "8.8.8.8"]
    assert resolver.recursion_answers(None) == []


def test_canario_memorizado_por_auditoria(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def fake_ask(ip: str, _port: int, *, tcp: bool, timeout: float) -> None:
        calls.append(ip)
        assert tcp is False
        assert timeout == resolver.CANARY_TIMEOUT

    monkeypatch.setattr(resolver, "ask", fake_ask)
    item = get_check("net.dns")
    assert item is not None
    fact = host_fact()
    scan = ScanContext(parse_target("https://127.0.0.1/"), fast_settings())
    ctx = CheckContext(scan, item, fact)
    assert resolver.network_intercepts_dns(ctx) is False
    assert resolver.network_intercepts_dns(ctx) is False
    assert calls == [resolver.CANARY_ADDRESS]
    assert resolver.CANARY_ADDRESS == "192.0.2.1"  # reservado para documentação (RFC 5737)


def test_canario_que_responde_prova_interceptacao(monkeypatch: pytest.MonkeyPatch) -> None:
    query = dns.message.make_query(resolver.PROBE_NAME, dns.rdatatype.A)
    monkeypatch.setattr(resolver, "ask", lambda *_a, **_k: dns.message.make_response(query))
    item = get_check("net.dns")
    assert item is not None
    fact = host_fact()
    scan = ScanContext(parse_target("https://127.0.0.1/"), fast_settings())
    assert resolver.network_intercepts_dns(CheckContext(scan, item, fact)) is True
