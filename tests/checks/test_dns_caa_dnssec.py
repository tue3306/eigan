"""CAA (RFC 8659) e DNSSEC: presença de DS/DNSKEY e coerência entre os dois."""

from __future__ import annotations

import base64
from typing import Any

import dns.dnssec
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import pytest
from fakes_dns import FALHA, ZonaFalsa, fato_dominio, rodar
from helpers import CheckOutcome, run_check

from eigan.checks.dns import zona as modulo_zona
from eigan.checks.dns.zona import ds_sem_chave, restringe_emissao, tag_da_chave, tag_do_ds
from eigan.core.context import ScanContext
from eigan.core.models import Confidence, Severity
from eigan.core.settings import Settings
from eigan.core.target import parse_target

ORG = "exemplo.com.br"


# -- CAA -------------------------------------------------------------------------------
def _caa(
    monkeypatch: pytest.MonkeyPatch, registros: dict[str, Any], dominio: str = ORG
) -> CheckOutcome:
    ZonaFalsa(registros).instalar(monkeypatch)
    return rodar("dns.caa", dominio)


def test_sem_caa_em_nenhum_nivel(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _caa(
        monkeypatch,
        {ORG: {"A": ["192.0.2.1"]}, "com.br": {"NS": ["a.dns.br"]}, "br": {"NS": ["a.dns.br"]}},
    )
    [achado] = saida.by_id("dns.caa.ausente")
    assert achado.severity == Severity.LOW and achado.confidence == Confidence.CONFIRMED
    assert achado.asset == ORG
    assert "com.br" in achado.evidence


def test_caa_na_raiz_do_dominio_vira_ponto_forte(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _caa(monkeypatch, {ORG: {"CAA": ['0 issue "letsencrypt.org"']}})
    assert saida.findings == []
    [ponto] = saida.passed
    assert ponto.control == "dns.caa" and "letsencrypt.org" in ponto.text


def test_caa_e_procurado_subindo_a_arvore(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _caa(
        monkeypatch,
        {"a.www.exemplo.com.br": {"A": ["192.0.2.1"]}, ORG: {"CAA": ['0 issue "pki.goog"']}},
        "a.www.exemplo.com.br",
    )
    assert saida.findings == []
    assert saida.passed[0].asset == ORG


def test_caa_mais_proximo_do_nome_e_o_que_vale(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _caa(
        monkeypatch,
        {
            f"www.{ORG}": {"CAA": ['0 iodef "mailto:a@exemplo.com.br"']},
            ORG: {"CAA": ['0 issue "letsencrypt.org"']},
        },
        f"www.{ORG}",
    )
    # RFC 8659, 3: a busca para no primeiro conjunto encontrado, mesmo que ele não restrinja nada
    assert "dns.caa.ausente" in saida.ids()


def test_caa_no_tld_tambem_vale(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _caa(monkeypatch, {ORG: {"A": ["192.0.2.1"]}, "br": {"CAA": ['0 issue "ca.exemplo"']}})
    assert saida.findings == []


@pytest.mark.parametrize(
    "registros",
    [
        ['0 iodef "mailto:seguranca@exemplo.com.br"'],
        ['0 issuewild "letsencrypt.org"'],
        ['0 contactemail "seguranca@exemplo.com.br"'],
    ],
)
def test_caa_que_nao_restringe_certificados_comuns(
    monkeypatch: pytest.MonkeyPatch, registros: list[str]
) -> None:
    saida = _caa(monkeypatch, {ORG: {"CAA": registros}})
    [achado] = saida.by_id("dns.caa.ausente")
    assert "issue" in achado.title and achado.details["caa"] == registros
    assert saida.passed == []


@pytest.mark.parametrize(
    "registros",
    [
        ['0 issue ";"'],  # ninguém pode emitir: é a restrição máxima
        ['128 issue "letsencrypt.org"'],
        ['0 ISSUE "letsencrypt.org"'],
        ['0 iodef "mailto:a@b.exemplo"', '0 issue "letsencrypt.org"'],
    ],
)
def test_caa_que_restringe(monkeypatch: pytest.MonkeyPatch, registros: list[str]) -> None:
    saida = _caa(monkeypatch, {ORG: {"CAA": registros}})
    assert saida.findings == [] and saida.passed


def test_restringe_emissao_ignora_lixo() -> None:
    assert not restringe_emissao(("",))
    assert not restringe_emissao(("issue",))


def test_caa_sem_resposta_nao_vira_achado(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _caa(monkeypatch, {ORG: {"CAA": FALHA}})
    assert saida.findings == []
    assert any("não verificado" in linha for linha in saida.logs)


def test_caa_de_dominio_inexistente(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _caa(monkeypatch, {})
    assert saida.findings == []
    assert any("não existe" in linha for linha in saida.logs)


def test_caa_sob_plataforma_nao_e_cobrado(monkeypatch: pytest.MonkeyPatch) -> None:
    zona = ZonaFalsa({"meusite.github.io": {"A": ["192.0.2.1"]}}).instalar(monkeypatch)
    saida = rodar("dns.caa", "meusite.github.io")
    assert saida.findings == [] and zona.consultas == []


def test_cadeia_ate_raiz() -> None:
    assert modulo_zona.cadeia_ate_raiz("a.exemplo.com") == ["a.exemplo.com", "exemplo.com", "com"]


# -- key tag -----------------------------------------------------------------------------
# RFC 4034, seção 5.4: exemplo oficial de DNSKEY (key id 60485) e do DS correspondente
DNSKEY_RFC = (
    "256 3 5 AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZ"
    "DRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9Xzc"
    "nOf+EPbtG9DMBmADjFDc2w/rljwvFw=="
)
DS_RFC = "60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118"


def _chave(semente: int, algoritmo: int = 13) -> str:
    bruta = base64.b64encode(bytes((semente + i) % 256 for i in range(64))).decode("ascii")
    return f"257 3 {algoritmo} {bruta}"


def _ds_de(chave: str) -> str:
    return f"{tag_da_chave(chave)} 13 2 " + "AB" * 32


def test_key_tag_do_exemplo_da_rfc() -> None:
    assert tag_da_chave(DNSKEY_RFC) == 60485
    assert tag_do_ds(DS_RFC) == 60485


@pytest.mark.parametrize("semente", [0, 7, 99, 200, 255])
def test_key_tag_igual_ao_do_dnspython(semente: int) -> None:
    chave = _chave(semente)
    rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY, chave)
    assert tag_da_chave(chave) == dns.dnssec.key_id(rdata)


@pytest.mark.parametrize(
    "registro",
    [
        "",
        "257",
        "x y z w",
        "257 3 13 ***",
        f"257 3 1 {base64.b64encode(b'abc').decode()}",
        "70000 3 13 QUJD",
    ],
)
def test_key_tag_de_registro_ilegivel(registro: str) -> None:
    assert tag_da_chave(registro) is None


def test_ds_sem_chave() -> None:
    chave = _chave(1)
    assert not ds_sem_chave((_ds_de(chave),), (chave,))
    assert ds_sem_chave((_ds_de(_chave(2)),), (chave,))
    assert not ds_sem_chave((_ds_de(_chave(2)), _ds_de(chave)), (chave, _chave(3)))
    assert not ds_sem_chave(("texto-estranho",), (chave,))  # não dá para ler: nada a afirmar
    assert not ds_sem_chave((_ds_de(chave),), ("257 3 1 QUJD",))


# -- DNSSEC ------------------------------------------------------------------------------
def _dnssec(
    monkeypatch: pytest.MonkeyPatch, dados: dict[str, Any]
) -> tuple[CheckOutcome, ZonaFalsa]:
    zona = ZonaFalsa({ORG: dados}).instalar(monkeypatch)
    return rodar("dns.dnssec", ORG), zona


def test_sem_dnssec(monkeypatch: pytest.MonkeyPatch) -> None:
    saida, _ = _dnssec(monkeypatch, {"A": ["192.0.2.1"]})
    [achado] = saida.by_id("dns.dnssec.ausente")
    assert achado.severity == Severity.LOW and achado.confidence == Confidence.CONFIRMED
    assert saida.passed == []


def test_dnssec_completo_vira_ponto_forte(monkeypatch: pytest.MonkeyPatch) -> None:
    chave = _chave(5)
    saida, zona = _dnssec(monkeypatch, {"DS": [_ds_de(chave)], "DNSKEY": [chave, _chave(6)]})
    assert saida.findings == []
    assert [p.control for p in saida.passed] == ["dns.dnssec"]
    # as duas consultas ligam o CD: um resolvedor que valida esconderia a cadeia quebrada
    assert set(zona.flags_cd) == {(ORG, "DS"), (ORG, "DNSKEY")}


def test_chaves_sem_ds(monkeypatch: pytest.MonkeyPatch) -> None:
    saida, _ = _dnssec(monkeypatch, {"DNSKEY": [_chave(5)]})
    [achado] = saida.by_id("dns.dnssec.incompleto")
    assert achado.severity == Severity.LOW
    assert saida.passed == []


def test_ds_sem_nenhuma_chave_e_cadeia_quebrada(monkeypatch: pytest.MonkeyPatch) -> None:
    saida, _ = _dnssec(monkeypatch, {"DS": [_ds_de(_chave(5))]})
    [achado] = saida.by_id("dns.dnssec.quebrado")
    assert achado.severity == Severity.HIGH and "nenhuma chave" in achado.evidence
    assert saida.passed == []


def test_ds_de_outra_chave_e_cadeia_quebrada(monkeypatch: pytest.MonkeyPatch) -> None:
    saida, _ = _dnssec(monkeypatch, {"DS": [_ds_de(_chave(5))], "DNSKEY": [_chave(6)]})
    [achado] = saida.by_id("dns.dnssec.quebrado")
    assert "corresponde" in achado.evidence and achado.details["dnskey"] == 1


def test_ds_antigo_junto_do_atual_nao_e_quebra(monkeypatch: pytest.MonkeyPatch) -> None:
    chave = _chave(5)
    saida, _ = _dnssec(monkeypatch, {"DS": [_ds_de(_chave(9)), _ds_de(chave)], "DNSKEY": [chave]})
    assert saida.findings == [] and saida.passed


@pytest.mark.parametrize(
    "dados", [{"DS": FALHA}, {"DNSKEY": FALHA}, {"DS": FALHA, "DNSKEY": FALHA}]
)
def test_dnssec_sem_resposta_nao_vira_achado(
    monkeypatch: pytest.MonkeyPatch, dados: dict[str, Any]
) -> None:
    saida, _ = _dnssec(monkeypatch, dados)
    assert saida.findings == [] and saida.passed == []
    assert any("não verificado" in linha for linha in saida.logs)


def test_dnssec_de_dominio_inexistente(monkeypatch: pytest.MonkeyPatch) -> None:
    ZonaFalsa().instalar(monkeypatch)
    saida = rodar("dns.dnssec", ORG)
    assert saida.findings == []
    assert any("não existe" in linha for linha in saida.logs)


def test_dnssec_avalia_o_dominio_organizacional_uma_vez(monkeypatch: pytest.MonkeyPatch) -> None:
    zona = ZonaFalsa({ORG: {"A": ["192.0.2.1"]}}).instalar(monkeypatch)
    scan = ScanContext(parse_target("https://exemplo.com.br/"), Settings())
    run_check("dns.dnssec", fato_dominio(f"www.{ORG}"), scan=scan)
    run_check("dns.dnssec", fato_dominio(ORG), scan=scan)
    assert zona.consultas.count((ORG, "DS")) == 1
    assert (f"www.{ORG}", "DS") not in zona.consultas
    assert [f.check_id for f in scan.findings.values()] == ["dns.dnssec.ausente"]


def test_dnssec_sob_plataforma_nao_e_cobrado(monkeypatch: pytest.MonkeyPatch) -> None:
    zona = ZonaFalsa({"meusite.github.io": {"A": ["192.0.2.1"]}}).instalar(monkeypatch)
    assert rodar("dns.dnssec", "meusite.github.io").findings == []
    assert zona.consultas == []
