"""Descoberta de hosts numa faixa de rede (``net.discovery``)."""

from __future__ import annotations

import ipaddress
import socket
import threading

import pytest
from fakes_net import fake_tcp, fast_settings
from helpers import run_check

from eigan.checks.net import discovery
from eigan.core.context import Cancelled, CheckContext, ScanContext
from eigan.core.models import Fact
from eigan.core.registry import get_check
from eigan.core.target import parse_target, seed_facts


def network_fact(network: str) -> Fact:
    return Fact("network", network, {"network": network, "label": network})


# -- endereços da faixa -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("network", "expected"),
    [
        ("192.168.0.0/30", ["192.168.0.1", "192.168.0.2"]),  # sem rede nem broadcast
        ("192.168.0.0/31", ["192.168.0.0", "192.168.0.1"]),  # enlace ponto a ponto: ambos valem
        ("192.168.0.7/32", ["192.168.0.7"]),
        ("2001:db8::/126", ["2001:db8::1", "2001:db8::2", "2001:db8::3"]),
    ],
)
def test_enderecos_utilizaveis(network: str, expected: list[str]) -> None:
    parsed = ipaddress.ip_network(network)
    assert [str(ip) for ip in discovery.addresses(parsed)] == expected


# -- batida nas portas ------------------------------------------------------------------------


def test_batida_em_porta_aberta() -> None:
    with fake_tcp() as server:
        assert discovery.knock("127.0.0.1", server.port, 1.0) == "aberta"


def test_batida_em_porta_fechada_e_recusa() -> None:
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    # no Windows a recusa chega depois de novas tentativas do SYN (cerca de 2 s)
    assert discovery.knock("127.0.0.1", port, 5.0) == "recusada"


def test_batida_com_erro_de_rede_e_sem_resposta(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object, **_kwargs: object) -> socket.socket:
        raise TimeoutError("sem resposta")

    monkeypatch.setattr(discovery.socket, "create_connection", fail)
    assert discovery.knock("192.0.2.1", 80, 0.1) is None


# -- checagem ---------------------------------------------------------------------------------


def test_hosts_que_responderam_viram_fatos(monkeypatch: pytest.MonkeyPatch) -> None:
    answers = {("10.0.0.1", 22): "aberta", ("10.0.0.2", 445): "recusada"}
    monkeypatch.setattr(discovery, "knock", lambda ip, port, _t: answers.get((ip, port)))
    out = run_check("net.discovery", network_fact("10.0.0.0/29"), settings=fast_settings())
    assert out.fact_keys("host") == {"10.0.0.1", "10.0.0.2"}
    by_key = {f.key: f for f in out.facts}
    assert by_key["10.0.0.1"].data["host"] == "10.0.0.1"
    assert "respondeu na porta 22" in by_key["10.0.0.1"].reason
    assert "recusou" in by_key["10.0.0.2"].reason
    assert "porta 445" in by_key["10.0.0.2"].reason
    assert any("2 de 6 endereço(s)" in line for line in out.logs)
    assert not out.findings


def test_faixa_sem_ninguem_nao_gera_fatos(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(discovery, "knock", lambda _ip, _port, _t: None)
    out = run_check("net.discovery", network_fact("10.0.0.0/30"), settings=fast_settings())
    assert not out.facts


def test_todas_as_portas_de_descoberta_sao_tentadas(monkeypatch: pytest.MonkeyPatch) -> None:
    tried: list[int] = []
    lock = threading.Lock()

    def fake(_ip: str, port: int, _timeout: float) -> None:
        with lock:
            tried.append(port)

    monkeypatch.setattr(discovery, "knock", fake)
    run_check("net.discovery", network_fact("10.0.0.1/32"), settings=fast_settings())
    assert sorted(tried) == sorted(discovery.DISCOVERY_PORTS)


def test_limite_de_hosts_da_configuracao(monkeypatch: pytest.MonkeyPatch) -> None:
    tested: set[str] = set()
    lock = threading.Lock()

    def fake(ip: str, _port: int, _timeout: float) -> str:
        with lock:
            tested.add(ip)
        return "aberta"

    monkeypatch.setattr(discovery, "knock", fake)
    settings = fast_settings(max_network_hosts=3)
    out = run_check("net.discovery", network_fact("10.0.0.0/24"), settings=settings)
    assert tested == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}
    assert len(out.fact_keys("host")) == 3
    assert any("primeiros 3 endereços" in line for line in out.logs)


def test_servidor_local_real_e_descoberto(monkeypatch: pytest.MonkeyPatch) -> None:
    with fake_tcp() as server:
        monkeypatch.setattr(discovery, "DISCOVERY_PORTS", (server.port,))
        out = run_check("net.discovery", network_fact("127.0.0.1/32"), settings=fast_settings())
    assert out.fact_keys("host") == {"127.0.0.1"}


def test_faixa_invalida_so_registra(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(discovery, "knock", lambda *_a: pytest.fail("não deveria conectar"))
    out = run_check("net.discovery", network_fact("nao-e-faixa"), settings=fast_settings())
    assert not out.facts
    assert any("inválida" in line for line in out.logs)


def test_cancelamento_nao_conecta(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(discovery, "knock", lambda ip, _p, _t: calls.append(ip))
    scan = ScanContext(parse_target("10.0.0.0/30"), fast_settings())
    scan.cancel.set()
    item = get_check("net.discovery")
    assert item is not None
    fact = network_fact("10.0.0.0/30")
    with pytest.raises(Cancelled):
        item.func(CheckContext(scan, item, fact), fact)
    assert not calls


def test_alvo_cidr_dispara_a_descoberta() -> None:
    [seed] = seed_facts(parse_target("192.168.10.0/28"))
    assert (seed.kind, seed.key) == ("network", "192.168.10.0/28")
    item = get_check("net.discovery")
    assert item is not None
    assert item.consumes == seed.kind
    assert item.applies(seed, "padrao", "linux")


def test_gateway_que_responde_rst_na_faixa_inteira_e_descartado() -> None:
    ctx_logs: list[str] = []

    class Ctx:
        def log(self, text: str) -> None:
            ctx_logs.append(text)

    found = {f"10.0.0.{i}": (22, "recusada") for i in range(1, 11)}
    kept = discovery.drop_reset_everywhere(Ctx(), found, 10)  # type: ignore[arg-type]
    assert kept == {}
    assert ctx_logs


def test_recusa_isolada_continua_sendo_host_ativo() -> None:
    class Ctx:
        def log(self, text: str) -> None:
            raise AssertionError(text)

    found = {"10.0.0.1": (22, "recusada"), "10.0.0.2": (80, "aberta")}
    assert discovery.drop_reset_everywhere(Ctx(), found, 10) == found  # type: ignore[arg-type]
