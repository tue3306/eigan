"""Catálogo de portas, perfis de varredura e a checagem ``net.portscan``."""

from __future__ import annotations

import threading
import time

import pytest
from fakes_net import fake_tcp, fast_settings
from helpers import run_check

from eigan.checks.net import portscan
from eigan.checks.net.ports import (
    DISCOVERY_PORTS,
    MAX_EXPLICIT_PORTS,
    catalog,
    parse_port_list,
    ports_for,
    service_name,
)
from eigan.core.context import Cancelled, CheckContext, ScanContext
from eigan.core.models import Fact
from eigan.core.registry import get_check
from eigan.core.settings import Settings
from eigan.core.target import parse_target
from eigan.data import load_json


def host_fact(host: str = "127.0.0.1") -> Fact:
    return Fact("host", host, {"host": host, "label": host})


# -- catálogo ------------------------------------------------------------------------------


def test_catalogo_registra_origem_e_licenca() -> None:
    raw = load_json("net_ports.json")
    assert raw["fonte"]
    assert raw["licenca"]
    assert raw["referencia"].startswith("https://")
    assert raw["atualizado"]


def test_catalogo_tem_as_portas_de_auditoria() -> None:
    items = catalog()
    assert len(items) >= 300
    numbers = [port for port, _ in items]
    assert len(numbers) == len(set(numbers))
    assert all(0 < port < 65536 for port in numbers)
    assert all(name for _port, name in items)
    top100 = set(numbers[:100])
    must_have = {21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 1521, 2375, 3306, 3389}
    must_have |= {5432, 5900, 6379, 6443, 8009, 9200, 10250, 11211, 27017, 2379}
    assert must_have <= top100


def test_nome_do_servico_pela_porta() -> None:
    assert service_name(3389) == "rdp"
    assert service_name(445) == "smb"
    assert service_name(22) == "ssh"
    assert service_name(47999) == ""


def test_portas_de_descoberta_sao_as_combinadas() -> None:
    assert DISCOVERY_PORTS == (22, 80, 443, 445, 3389, 8080)


# -- perfis --------------------------------------------------------------------------------


def test_perfis_de_portas() -> None:
    ordered = [port for port, _ in catalog()]
    assert ports_for("top100") == ordered[:100]
    assert ports_for("TOP300") == ordered[:300]
    todas = ports_for("todas")
    assert set(range(1, 1025)) <= set(todas)
    assert set(ordered) <= set(todas)
    assert len(todas) == len(set(todas))


def test_lista_explicita_de_portas() -> None:
    assert ports_for("22,80,443") == [22, 80, 443]
    assert ports_for(" 8000-8002 ; 9000 ") == [8000, 8001, 8002, 9000]


def test_lista_invalida_cai_no_padrao() -> None:
    assert ports_for("nada") == [port for port, _ in catalog()][:300]
    assert ports_for("") == [port for port, _ in catalog()][:300]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("22", [22]),
        ("22,22,80", [22, 80]),
        ("10-8", [8, 9, 10]),
        ("abc,443", [443]),
        ("0,70000,65535", [65535]),
        ("1 2;3", [1, 2, 3]),
        ("", []),
    ],
)
def test_interpretacao_de_lista(text: str, expected: list[int]) -> None:
    assert parse_port_list(text) == expected


def test_lista_gigante_e_limitada() -> None:
    assert len(parse_port_list("1-65535")) == MAX_EXPLICIT_PORTS


@pytest.mark.parametrize(
    ("profile", "ports", "expected"),
    [
        ("rapido", "auto", "top100"),
        ("padrao", "auto", "top300"),
        ("completo", "auto", "todas"),
        ("rapido", "22,80", "22,80"),
    ],
)
def test_configuracao_escolhe_o_perfil(profile: str, ports: str, expected: str) -> None:
    assert Settings(profile=profile, ports=ports).ports_profile == expected


# -- varredura ------------------------------------------------------------------------------


def test_porta_aberta_real_vira_fato() -> None:
    with fake_tcp() as server:
        out = run_check("net.portscan", host_fact(), settings=fast_settings(ports=str(server.port)))
    assert out.fact_keys("port.open") == {f"127.0.0.1:{server.port}/tcp"}
    [fact] = [f for f in out.facts if f.kind == "port.open"]
    assert fact.data["host"] == "127.0.0.1"
    assert fact.data["port"] == server.port
    assert fact.data["aceita_tudo"] is False
    assert any("1 porta(s) aberta(s)" in line for line in out.logs)


def test_varredura_usa_o_nome_do_host_e_o_primeiro_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []

    def fake_probe(ip: str, port: int, _timeout: float) -> bool:
        seen.append(ip)
        return port == 8443

    monkeypatch.setattr(portscan, "probe_port", fake_probe)
    monkeypatch.setattr(portscan.netutil, "resolve", lambda _host: ("192.0.2.10", "192.0.2.11"))
    fact = host_fact("servidor.exemplo")
    out = run_check("net.portscan", fact, settings=fast_settings(ports="8443,8444"))
    assert set(seen) == {"192.0.2.10"}
    [opened] = [f for f in out.facts if f.kind == "port.open"]
    assert opened.key == "servidor.exemplo:8443/tcp"
    assert opened.data["hint"] == "https-alt"
    assert "https-alt" in opened.reason


def test_host_que_nao_resolve_nao_gera_fatos(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(portscan.netutil, "resolve", lambda _host: ())
    out = run_check("net.portscan", host_fact("nao-existe.invalid"), settings=fast_settings())
    assert not out.facts
    assert any("não resolve" in line for line in out.logs)


def test_perfil_rapido_testa_100_portas(monkeypatch: pytest.MonkeyPatch) -> None:
    tested: list[int] = []
    lock = threading.Lock()

    def fake_probe(_ip: str, port: int, _timeout: float) -> bool:
        with lock:
            tested.append(port)
        return False

    monkeypatch.setattr(portscan, "probe_port", fake_probe)
    out = run_check("net.portscan", host_fact(), settings=fast_settings(profile="rapido"))
    assert sorted(tested) == sorted(ports_for("top100"))
    assert not out.fact_keys("port.open")


def test_concorrencia_limitada_por_port_workers(monkeypatch: pytest.MonkeyPatch) -> None:
    active = {"now": 0, "peak": 0}
    lock = threading.Lock()

    def fake_probe(_ip: str, _port: int, _timeout: float) -> bool:
        with lock:
            active["now"] += 1
            active["peak"] = max(active["peak"], active["now"])
        time.sleep(0.01)
        with lock:
            active["now"] -= 1
        return False

    monkeypatch.setattr(portscan, "probe_port", fake_probe)
    run_check(
        "net.portscan", host_fact(), settings=fast_settings(ports="1000-1040", port_workers=3)
    )
    assert 1 <= active["peak"] <= 3


def test_cancelamento_interrompe_a_varredura(monkeypatch: pytest.MonkeyPatch) -> None:
    probes: list[int] = []
    monkeypatch.setattr(portscan, "probe_port", lambda _i, p, _t: probes.append(p) or False)
    scan = ScanContext(parse_target("https://127.0.0.1/"), fast_settings(ports="1-500"))
    scan.cancel.set()
    item = get_check("net.portscan")
    assert item is not None
    fact = host_fact()
    with pytest.raises(Cancelled):
        item.func(CheckContext(scan, item, fact), fact)
    assert not probes


# -- host que aceita conexão em qualquer porta -----------------------------------------------


def test_host_que_aceita_tudo_nao_vira_dezenas_de_servicos(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(portscan, "probe_port", lambda _ip, _port, _timeout: True)
    out = run_check("net.portscan", host_fact(), settings=fast_settings(ports="top100"))
    opened = [f for f in out.facts if f.kind == "port.open"]
    assert len(opened) == portscan.ACCEPT_ALL_KEEP
    assert all(f.data["aceita_tudo"] is True for f in opened)
    assert {f.data["port"] for f in opened} == set(ports_for("top100")[: portscan.ACCEPT_ALL_KEEP])
    assert any("aceita qualquer conexão" in line for line in out.logs)


def test_muitas_portas_abertas_sem_canario_e_host_normal(monkeypatch: pytest.MonkeyPatch) -> None:
    canaries = set(portscan.CANARY_PORTS)
    monkeypatch.setattr(portscan, "probe_port", lambda _ip, port, _timeout: port not in canaries)
    out = run_check("net.portscan", host_fact(), settings=fast_settings(ports="top100"))
    opened = [f for f in out.facts if f.kind == "port.open"]
    assert len(opened) == 100
    assert not any(f.data["aceita_tudo"] for f in opened)


def test_canario_so_entra_com_quase_tudo_aberto(monkeypatch: pytest.MonkeyPatch) -> None:
    tested: list[int] = []

    def fake_probe(_ip: str, port: int, _timeout: float) -> bool:
        tested.append(port)
        return port in (80, 443)

    monkeypatch.setattr(portscan, "probe_port", fake_probe)
    run_check("net.portscan", host_fact(), settings=fast_settings(ports="top100"))
    assert not set(portscan.CANARY_PORTS) & set(tested)


def test_poucas_portas_testadas_nao_ativam_a_suspeita(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(portscan, "probe_port", lambda _ip, _port, _timeout: True)
    out = run_check("net.portscan", host_fact(), settings=fast_settings(ports="22,80,443"))
    opened = [f for f in out.facts if f.kind == "port.open"]
    assert len(opened) == 3
    assert not any(f.data["aceita_tudo"] for f in opened)


def test_prioridade_segue_o_catalogo() -> None:
    first, second = catalog()[0][0], catalog()[1][0]
    assert portscan.prioritize([47999, second, first]) == [first, second, 47999]


def test_canarios_estao_fora_do_catalogo() -> None:
    known: set[int] = {port for port, _ in catalog()}
    assert not set(portscan.CANARY_PORTS) & known


def test_lista_explicita_invalida_gera_aviso() -> None:
    from eigan.checks.net.ports import explicit_list_problems

    assert explicit_list_problems("top300") == ""
    assert explicit_list_problems("22,80") == ""
    assert "inválida" in explicit_list_problems("99999")
    assert "inválida" in explicit_list_problems("top-100")
    assert "70000" in explicit_list_problems("22,70000")


def test_lista_completa_nao_e_cortada() -> None:
    assert max(parse_port_list("1-65535")) == 65535
