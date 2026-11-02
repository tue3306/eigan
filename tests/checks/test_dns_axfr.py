"""Transferência de zona (AXFR): a checagem e o cliente real contra um servidor local."""

from __future__ import annotations

import time
from collections.abc import Iterator
from typing import Any

import dns.query
import pytest
from fakes_dns import FALHA, ServidorAxfr, ZonaFalsa, fato_dominio, rodar
from helpers import run_check

from eigan.checks.dns import resolver
from eigan.checks.dns.resolver import Transferencia
from eigan.checks.dns.zona import MAX_SERVIDORES_AXFR
from eigan.core.context import ScanContext
from eigan.core.models import Confidence, Severity
from eigan.core.registry import get_check
from eigan.core.settings import Settings
from eigan.core.target import parse_target

ORG = "exemplo.com.br"
ENTREGOU = Transferencia(True, ("@", "homologacao", "vpn", "www"), 7)
RECUSOU = Transferencia(False, erro="REFUSED")
SEM_RESPOSTA = Transferencia(False, erro="tempo esgotado", respondeu=False)


def _base(**extra: Any) -> dict[str, Any]:
    return {
        ORG: {"NS": ["ns1.exemplo.com.br", "ns2.exemplo.com.br"]},
        f"ns1.{ORG}": {"A": ["192.0.2.1"], "AAAA": ["2001:db8::1"]},
        f"ns2.{ORG}": {"A": ["192.0.2.2"]},
        **extra,
    }


def test_checagem_e_ativa_e_tem_tempo_limite() -> None:
    item = get_check("dns.axfr")
    assert item is not None
    assert item.active is True and item.timeout > 0


def test_servidor_que_entrega_a_zona(monkeypatch: pytest.MonkeyPatch) -> None:
    ZonaFalsa(_base(), transferencias={"192.0.2.2": ENTREGOU}).instalar(monkeypatch)
    saida = rodar("dns.axfr", ORG)
    [achado] = saida.by_id("dns.axfr.permitido")
    assert achado.severity == Severity.HIGH and achado.confidence == Confidence.CONFIRMED
    assert achado.asset == ORG and achado.discriminator == "ns2.exemplo.com.br"
    assert f"vpn.{ORG}" in achado.evidence and f"www.{ORG}" in achado.evidence
    assert achado.details == {"servidor": "ns2.exemplo.com.br", "ip": "192.0.2.2", "nomes": 4}
    assert saida.passed == []  # o outro servidor recusou, mas a zona vazou


def test_todos_os_servidores_que_entregam_viram_achados(monkeypatch: pytest.MonkeyPatch) -> None:
    ZonaFalsa(_base(), transferencias={"192.0.2.1": ENTREGOU, "192.0.2.2": ENTREGOU}).instalar(
        monkeypatch
    )
    assert len(rodar("dns.axfr", ORG).by_id("dns.axfr.permitido")) == 2


def test_amostra_longa_e_resumida(monkeypatch: pytest.MonkeyPatch) -> None:
    muitos = Transferencia(True, tuple(f"h{n}" for n in range(30)), 30)
    ZonaFalsa(_base(), transferencias={"192.0.2.2": muitos}).instalar(monkeypatch)
    [achado] = rodar("dns.axfr", ORG).by_id("dns.axfr.permitido")
    assert "30 nomes" in achado.evidence and "..." in achado.evidence


def test_todos_recusam_vira_ponto_forte(monkeypatch: pytest.MonkeyPatch) -> None:
    zona = ZonaFalsa(_base()).instalar(monkeypatch)
    saida = rodar("dns.axfr", ORG)
    assert saida.findings == []
    assert [p.control for p in saida.passed] == ["dns.axfr"]
    assert {servidor for servidor, _ in zona.axfrs} == {"192.0.2.1", "2001:db8::1", "192.0.2.2"}
    assert {nome for _, nome in zona.axfrs} == {ORG}


def test_sem_resposta_nao_afirma_nada(monkeypatch: pytest.MonkeyPatch) -> None:
    ZonaFalsa(
        _base(),
        transferencias={
            "192.0.2.1": SEM_RESPOSTA,
            "2001:db8::1": SEM_RESPOSTA,
            "192.0.2.2": SEM_RESPOSTA,
        },
    ).instalar(monkeypatch)
    saida = rodar("dns.axfr", ORG)
    assert saida.findings == [] and saida.passed == []
    assert sum("não verificado" in linha for linha in saida.logs) == 2


def test_recusa_parcial_nao_vira_ponto_forte(monkeypatch: pytest.MonkeyPatch) -> None:
    ZonaFalsa(_base(), transferencias={"192.0.2.2": SEM_RESPOSTA}).instalar(monkeypatch)
    saida = rodar("dns.axfr", ORG)
    assert saida.findings == [] and saida.passed == []


def test_segundo_ip_do_servidor_tambem_e_testado(monkeypatch: pytest.MonkeyPatch) -> None:
    ZonaFalsa(
        _base(), transferencias={"192.0.2.1": SEM_RESPOSTA, "2001:db8::1": ENTREGOU}
    ).instalar(monkeypatch)
    [achado] = rodar("dns.axfr", ORG).by_id("dns.axfr.permitido")
    assert achado.details["ip"] == "2001:db8::1"


def test_servidor_sem_endereco_nao_e_recusa(monkeypatch: pytest.MonkeyPatch) -> None:
    ZonaFalsa({ORG: {"NS": ["ns1.outro.exemplo.net"]}}).instalar(monkeypatch)
    saida = rodar("dns.axfr", ORG)
    assert saida.findings == [] and saida.passed == []
    assert any("ns1.outro.exemplo.net" in linha for linha in saida.logs)


def test_limite_de_servidores(monkeypatch: pytest.MonkeyPatch) -> None:
    total = MAX_SERVIDORES_AXFR + 3
    registros: dict[str, Any] = {ORG: {"NS": [f"ns{n}.{ORG}" for n in range(total)]}}
    registros.update({f"ns{n}.{ORG}": {"A": [f"192.0.2.{n + 1}"]} for n in range(total)})
    zona = ZonaFalsa(registros).instalar(monkeypatch)
    saida = rodar("dns.axfr", ORG)
    assert len(zona.axfrs) == MAX_SERVIDORES_AXFR
    assert saida.findings == []


def test_subdominio_delegado_tem_zona_propria(monkeypatch: pytest.MonkeyPatch) -> None:
    sub = f"sub.{ORG}"
    registros = _base(
        **{
            sub: {"NS": [f"ns.{sub}"]},
            f"ns.{sub}": {"A": ["192.0.2.9"]},
        }
    )
    zona = ZonaFalsa(registros, transferencias={"192.0.2.9": ENTREGOU}).instalar(monkeypatch)
    [achado] = rodar("dns.axfr", sub).by_id("dns.axfr.permitido")
    assert achado.asset == sub
    assert {nome for _, nome in zona.axfrs} == {ORG, sub}


def test_subdominio_sem_delegacao_usa_a_zona_do_dominio(monkeypatch: pytest.MonkeyPatch) -> None:
    zona = ZonaFalsa(_base(**{f"www.{ORG}": {"A": ["192.0.2.80"]}})).instalar(monkeypatch)
    rodar("dns.axfr", f"www.{ORG}")
    assert {nome for _, nome in zona.axfrs} == {ORG}


def test_sem_servidores_ns(monkeypatch: pytest.MonkeyPatch) -> None:
    zona = ZonaFalsa({ORG: {"A": ["192.0.2.1"]}}).instalar(monkeypatch)
    saida = rodar("dns.axfr", ORG)
    assert saida.findings == [] and zona.axfrs == []
    assert any("sem servidores NS" in linha for linha in saida.logs)


def test_dns_fora_do_ar_nao_vira_achado(monkeypatch: pytest.MonkeyPatch) -> None:
    zona = ZonaFalsa({ORG: {"NS": FALHA}}).instalar(monkeypatch)
    saida = rodar("dns.axfr", ORG)
    assert saida.findings == [] and saida.passed == [] and zona.axfrs == []


def test_plataforma_compartilhada_nao_e_testada(monkeypatch: pytest.MonkeyPatch) -> None:
    zona = ZonaFalsa({"meusite.github.io": {"NS": ["ns1.exemplo.net"]}}).instalar(monkeypatch)
    assert rodar("dns.axfr", "meusite.github.io").findings == []
    assert zona.axfrs == [] and zona.consultas == []


def test_cada_zona_uma_vez_por_auditoria(monkeypatch: pytest.MonkeyPatch) -> None:
    zona = ZonaFalsa(_base()).instalar(monkeypatch)
    scan = ScanContext(parse_target("https://exemplo.com.br/"), Settings())
    run_check("dns.axfr", fato_dominio(ORG), scan=scan)
    pedidos = len(zona.axfrs)
    run_check("dns.axfr", fato_dominio(f"www.{ORG}"), scan=scan)
    assert len(zona.axfrs) == pedidos


# -- cliente real (dnspython) contra um servidor local -----------------------------------
@pytest.fixture
def servidores() -> Iterator[list[ServidorAxfr]]:
    criados: list[ServidorAxfr] = []
    yield criados
    for servidor in criados:
        servidor.fechar()


def _na_porta(monkeypatch: pytest.MonkeyPatch, porta: int) -> None:
    """``resolver.axfr`` sempre usa a porta 53; aqui o cliente real vai para a porta local."""
    original = dns.query.xfr

    def xfr(where: str, zone: str, **kwargs: Any) -> Any:
        return original(where, zone, port=porta, **kwargs)

    monkeypatch.setattr(dns.query, "xfr", xfr)


def _pedir(
    monkeypatch: pytest.MonkeyPatch,
    servidores: list[ServidorAxfr],
    modo: str,
    tempo: float = 3.0,
    **opcoes: Any,
) -> Transferencia:
    servidor = ServidorAxfr(modo, **opcoes)
    servidores.append(servidor)
    _na_porta(monkeypatch, servidor.porta)
    return resolver.axfr("127.0.0.1", ORG, tempo=tempo)


def test_cliente_recebe_a_zona(
    monkeypatch: pytest.MonkeyPatch, servidores: list[ServidorAxfr]
) -> None:
    resultado = _pedir(monkeypatch, servidores, "entrega")
    assert resultado.permitida and resultado.respondeu
    assert set(resultado.nomes) == {"@", "www", "vpn", "homologacao"}
    assert resultado.registros == 3  # os SOA de abertura e fechamento não contam


def test_cliente_entende_a_recusa(
    monkeypatch: pytest.MonkeyPatch, servidores: list[ServidorAxfr]
) -> None:
    resultado = _pedir(monkeypatch, servidores, "recusa")
    assert not resultado.permitida and resultado.respondeu


def test_zona_so_com_soa_nao_prova_nada(
    monkeypatch: pytest.MonkeyPatch, servidores: list[ServidorAxfr]
) -> None:
    resultado = _pedir(monkeypatch, servidores, "so_soa")
    assert not resultado.permitida and "não trouxe registros" in resultado.erro


def test_conexao_derrubada_nao_e_achado(
    monkeypatch: pytest.MonkeyPatch, servidores: list[ServidorAxfr]
) -> None:
    resultado = _pedir(monkeypatch, servidores, "fecha")
    assert not resultado.permitida and resultado.respondeu


def test_servidor_mudo_respeita_o_tempo_limite(
    monkeypatch: pytest.MonkeyPatch, servidores: list[ServidorAxfr]
) -> None:
    inicio = time.monotonic()
    resultado = _pedir(monkeypatch, servidores, "mudo", tempo=0.3)
    assert not resultado.permitida and not resultado.respondeu
    assert time.monotonic() - inicio < 3.0


def test_leitura_para_na_amostra(
    monkeypatch: pytest.MonkeyPatch, servidores: list[ServidorAxfr]
) -> None:
    resultado = _pedir(monkeypatch, servidores, "sem_fim", mensagens=50)
    assert resultado.permitida
    assert resolver.LIMITE_NOMES_AXFR <= len(resultado.nomes) < 2500


def test_porta_fechada_nao_e_achado(monkeypatch: pytest.MonkeyPatch) -> None:
    _na_porta(monkeypatch, 1)
    assert not resolver.axfr("127.0.0.1", ORG, tempo=5.0).permitida


def test_nome_invalido_nao_levanta(monkeypatch: pytest.MonkeyPatch) -> None:
    resultado = resolver.axfr("nao-e-um-ip", ORG, tempo=0.5)
    assert not resultado.permitida
