"""DMARC (RFC 7489), DKIM nos seletores comuns e domínios que não usam e-mail."""

from __future__ import annotations

from typing import Any

import pytest
from fakes_dns import FALHA, ZonaFalsa, fato_dominio, rodar
from helpers import CheckOutcome, run_check

from eigan.checks.dns import correio, dmarc
from eigan.core.context import ScanContext
from eigan.core.models import Confidence, Severity
from eigan.core.settings import Settings
from eigan.core.target import parse_target

ORG = "exemplo.com.br"
BASE = {ORG: {"TXT": ["v=spf1 include:_spf.exemplo.net -all"], "MX": ["10 mx1.exemplo.com.br"]}}
SPF_INCLUIDO = {"_spf.exemplo.net": {"TXT": ["v=spf1 ip4:192.0.2.1 -all"]}}


def _email(monkeypatch: pytest.MonkeyPatch, registro: Any = None, **extra: Any) -> CheckOutcome:
    registros: dict[str, Any] = {**BASE, **SPF_INCLUIDO, **extra}
    if registro is not None:
        registros[f"_dmarc.{ORG}"] = {"TXT": registro} if isinstance(registro, list) else registro
    ZonaFalsa(registros).instalar(monkeypatch)
    return rodar("dns.email", ORG)


def _dmarc_ids(saida: CheckOutcome) -> set[str]:
    return {i for i in saida.ids() if "dmarc" in i}


# -- existência -----------------------------------------------------------------------
def test_sem_registro_dmarc(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(monkeypatch)
    [achado] = saida.by_id("dns.email.dmarc_ausente")
    assert achado.severity == Severity.MEDIUM and achado.asset == ORG


def test_txt_que_nao_e_dmarc_nao_conta(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(monkeypatch, ["verificacao=abc"])
    assert _dmarc_ids(saida) == {"dns.email.dmarc_ausente"}
    assert "verificacao=abc" in saida.by_id("dns.email.dmarc_ausente")[0].evidence


def test_versao_precisa_ser_a_primeira_tag(monkeypatch: pytest.MonkeyPatch) -> None:
    # RFC 7489, 6.3: registro em que v= não vem primeiro é descartado
    saida = _email(monkeypatch, ["p=reject; v=DMARC1"])
    assert _dmarc_ids(saida) == {"dns.email.dmarc_ausente"}


# -- política -------------------------------------------------------------------------
@pytest.mark.parametrize("politica", ["quarantine", "reject", "REJECT"])
def test_politica_aplicada_vira_ponto_forte(monkeypatch: pytest.MonkeyPatch, politica: str) -> None:
    saida = _email(monkeypatch, [f"v=DMARC1; p={politica}; rua=mailto:dmarc@{ORG}"])
    assert _dmarc_ids(saida) == set()
    assert any(p.control == "dns.email.dmarc" for p in saida.passed)


def test_p_none_e_so_monitoramento(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(monkeypatch, [f"v=DMARC1; p=none; rua=mailto:dmarc@{ORG}"])
    assert _dmarc_ids(saida) == {"dns.email.dmarc_monitoramento"}
    assert saida.by_id("dns.email.dmarc_monitoramento")[0].severity == Severity.LOW
    assert not any(p.control == "dns.email.dmarc" for p in saida.passed)


def test_subdominios_em_none_sao_achado_a_parte(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(monkeypatch, [f"v=DMARC1; p=reject; sp=none; rua=mailto:dmarc@{ORG}"])
    [achado] = saida.by_id("dns.email.dmarc_monitoramento")
    assert achado.discriminator == "sp"
    assert not any(p.control == "dns.email.dmarc" for p in saida.passed)


def test_sp_ausente_herda_o_p(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(monkeypatch, [f"v=DMARC1; p=quarantine; rua=mailto:dmarc@{ORG}"])
    assert "dns.email.dmarc_monitoramento" not in saida.ids()
    assert dmarc.analisar("v=DMARC1; p=quarantine").subdominios == "quarantine"
    assert dmarc.analisar("v=DMARC1; p=reject; sp=quarantine").subdominios == "quarantine"


@pytest.mark.parametrize("pct", ["0", "50", "99"])
def test_pct_menor_que_100(monkeypatch: pytest.MonkeyPatch, pct: str) -> None:
    saida = _email(monkeypatch, [f"v=DMARC1; p=reject; pct={pct}; rua=mailto:dmarc@{ORG}"])
    [achado] = saida.by_id("dns.email.dmarc_parcial")
    assert achado.details["pct"] == int(pct) and achado.severity == Severity.LOW
    assert not any(p.control == "dns.email.dmarc" for p in saida.passed)


@pytest.mark.parametrize("pct", ["100", "abc", "150"])
def test_pct_100_ou_invalido_vale_100(monkeypatch: pytest.MonkeyPatch, pct: str) -> None:
    saida = _email(monkeypatch, [f"v=DMARC1; p=reject; pct={pct}; rua=mailto:dmarc@{ORG}"])
    assert "dns.email.dmarc_parcial" not in saida.ids()


def test_pct_nao_importa_com_p_none(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(monkeypatch, [f"v=DMARC1; p=none; pct=10; rua=mailto:dmarc@{ORG}"])
    assert _dmarc_ids(saida) == {"dns.email.dmarc_monitoramento"}


# -- registros inválidos ---------------------------------------------------------------
def test_dois_registros_dmarc(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(monkeypatch, ["v=DMARC1; p=reject", "v=DMARC1; p=none"])
    assert _dmarc_ids(saida) == {"dns.email.dmarc_invalido"}
    assert saida.by_id("dns.email.dmarc_invalido")[0].confidence == Confidence.CONFIRMED


def test_versao_em_minusculas_e_descartada(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(monkeypatch, ["v=dmarc1; p=reject"])
    [achado] = saida.by_id("dns.email.dmarc_invalido")
    assert achado.confidence == Confidence.FIRM and "v=DMARC1" in achado.evidence


def test_espacos_em_torno_das_tags_sao_validos(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(monkeypatch, [f"v = DMARC1 ; p = reject ; rua = mailto:dmarc@{ORG}"])
    assert _dmarc_ids(saida) == set()


def test_sem_p_com_rua_vale_como_none(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(monkeypatch, [f"v=DMARC1; rua=mailto:dmarc@{ORG}"])
    assert "vale como p=none" in saida.by_id("dns.email.dmarc_invalido")[0].evidence


def test_sem_p_e_sem_rua_e_ignorado(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(monkeypatch, ["v=DMARC1"])
    assert "ignorado" in saida.by_id("dns.email.dmarc_invalido")[0].evidence


def test_p_ou_sp_com_valor_errado(monkeypatch: pytest.MonkeyPatch) -> None:
    assert "dns.email.dmarc_invalido" in _email(monkeypatch, ["v=DMARC1; p=rejeitar"]).ids()
    saida = _email(monkeypatch, ["v=DMARC1; p=reject; sp=talvez"])
    assert "sp= inválido" in saida.by_id("dns.email.dmarc_invalido")[0].evidence


# -- relatórios ------------------------------------------------------------------------
def test_sem_rua_e_so_informativo_e_a_politica_vale(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(monkeypatch, ["v=DMARC1; p=reject"])
    assert _dmarc_ids(saida) == {"dns.email.dmarc_sem_relatorio"}
    assert saida.by_id("dns.email.dmarc_sem_relatorio")[0].severity == Severity.INFO
    assert any(p.control == "dns.email.dmarc" for p in saida.passed)


def test_rua_invalido_conta_como_sem_rua(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(monkeypatch, [f"v=DMARC1; p=reject; rua=dmarc@{ORG}"])
    assert "dns.email.dmarc_sem_relatorio" in saida.ids()


def test_destino_externo_sem_autorizacao(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(monkeypatch, ["v=DMARC1; p=reject; rua=mailto:dmarc@relatorios.exemplo.net"])
    [achado] = saida.by_id("dns.email.dmarc_sem_relatorio")
    assert achado.discriminator == "externo"
    assert achado.details["registros_esperados"] == [f"{ORG}._report._dmarc.relatorios.exemplo.net"]


def test_destino_externo_autorizado(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(
        monkeypatch,
        ["v=DMARC1; p=reject; rua=mailto:dmarc@relatorios.exemplo.net"],
        **{f"{ORG}._report._dmarc.relatorios.exemplo.net": {"TXT": ["v=DMARC1"]}},
    )
    assert _dmarc_ids(saida) == set()


def test_um_destino_que_funciona_basta(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(
        monkeypatch, [f"v=DMARC1; p=reject; rua=mailto:a@fora.exemplo.net,mailto:b@{ORG}"]
    )
    assert _dmarc_ids(saida) == set()


def test_autorizacao_sem_resposta_nao_vira_achado(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(
        monkeypatch,
        ["v=DMARC1; p=reject; rua=mailto:dmarc@relatorios.exemplo.net"],
        **{f"{ORG}._report._dmarc.relatorios.exemplo.net": FALHA},
    )
    assert _dmarc_ids(saida) == set()


def test_leitura_do_rua() -> None:
    lido = dmarc.analisar(
        "v=DMARC1; p=none; rua=mailto:a@x.com!10m, https://r.exemplo.net/d, ftp://x, b"
    )
    assert lido.rua == ["mailto:a@x.com", "https://r.exemplo.net/d"]


# -- DKIM ------------------------------------------------------------------------------
CHAVE = "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"


def test_dkim_encontrado_vira_ponto_forte(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(monkeypatch, **{f"selector1._domainkey.{ORG}": {"TXT": [CHAVE]}})
    assert "dns.email.dkim_nao_encontrado" not in saida.ids()
    assert any(p.control == "dns.email.dkim" and "selector1" in p.text for p in saida.passed)


def test_dkim_ausente_e_so_indicio(monkeypatch: pytest.MonkeyPatch) -> None:
    [achado] = _email(monkeypatch).by_id("dns.email.dkim_nao_encontrado")
    assert achado.severity == Severity.INFO and achado.confidence == Confidence.TENTATIVE
    assert "selector1" in achado.evidence


def test_chave_dkim_revogada_nao_conta(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(monkeypatch, **{f"google._domainkey.{ORG}": {"TXT": ["v=DKIM1; p="]}})
    assert "dns.email.dkim_nao_encontrado" in saida.ids()


def test_dkim_para_de_tentar_quando_o_dns_falha(monkeypatch: pytest.MonkeyPatch) -> None:
    falhas = {f"{seletor}._domainkey.{ORG}": FALHA for seletor in correio.SELETORES_DKIM}
    saida = _email(monkeypatch, **falhas)
    assert "dns.email.dkim_nao_encontrado" not in saida.ids()
    assert any("DKIM de" in linha for linha in saida.logs)


# -- domínio que não usa e-mail --------------------------------------------------------
def _estacionado(
    monkeypatch: pytest.MonkeyPatch, raiz: dict[str, Any], registro: Any = None
) -> CheckOutcome:
    registros: dict[str, Any] = {ORG: raiz}
    if registro is not None:
        registros[f"_dmarc.{ORG}"] = {"TXT": registro} if isinstance(registro, list) else registro
    ZonaFalsa(registros).instalar(monkeypatch)
    return rodar("dns.email", ORG)


def test_dominio_sem_mx_e_sem_protecao(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _estacionado(monkeypatch, {"A": ["192.0.2.1"]})
    assert saida.ids() == {"dns.email.estacionado"}  # em vez de cobrar SPF e DMARC separados
    [achado] = saida.by_id("dns.email.estacionado")
    assert achado.severity == Severity.MEDIUM
    assert len(achado.details["faltando"]) == 2


def test_dominio_sem_mx_protegido_vira_ponto_forte(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _estacionado(monkeypatch, {"TXT": ["v=spf1 -all"]}, ["v=DMARC1; p=reject"])
    assert saida.findings == []
    assert any(p.control == "dns.email.estacionado" for p in saida.passed)


def test_mx_nulo_conta_como_nao_receber_email(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _estacionado(
        monkeypatch, {"TXT": ["v=spf1 -all"], "MX": ["0 ."]}, ["v=DMARC1; p=reject"]
    )
    assert saida.findings == [] and any(p.control == "dns.email.estacionado" for p in saida.passed)


@pytest.mark.parametrize(
    ("txt", "registro", "faltas"),
    [
        (["v=spf1 -all"], ["v=DMARC1; p=none"], 1),
        (["v=spf1 -all"], ["v=DMARC1; p=reject; sp=none"], 1),
        (["v=spf1 -all"], ["v=DMARC1; p=reject; pct=50"], 1),
        (["v=spf1 ~all"], ["v=DMARC1; p=reject"], 1),
        (["v=spf1 ?all"], ["v=DMARC1; p=reject"], 1),
        (["v=spf1 -all", "v=spf1 ~all"], ["v=DMARC1; p=reject"], 1),
    ],
)
def test_protecao_parcial_do_dominio_sem_mx(
    monkeypatch: pytest.MonkeyPatch, txt: list[str], registro: list[str], faltas: int
) -> None:
    saida = _estacionado(monkeypatch, {"TXT": txt}, registro)
    assert saida.ids() == {"dns.email.estacionado"}
    assert len(saida.by_id("dns.email.estacionado")[0].details["faltando"]) == faltas


def test_sem_mx_mas_com_remetentes_segue_o_caminho_normal(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _estacionado(
        monkeypatch, {"TXT": ["v=spf1 ip4:192.0.2.1 -all"]}, ["v=DMARC1; p=reject"]
    )
    assert "dns.email.estacionado" not in saida.ids()
    assert any(p.control == "dns.email.spf" for p in saida.passed)


def test_sem_mx_com_mais_all_e_permissivo(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _estacionado(monkeypatch, {"TXT": ["v=spf1 +all"]}, ["v=DMARC1; p=reject"])
    assert "dns.email.spf_permissivo" in saida.ids() and "dns.email.estacionado" not in saida.ids()


def test_estacionado_com_dmarc_sem_resposta_nao_afirma_nada_sobre_dmarc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    saida = _estacionado(monkeypatch, {"TXT": ["v=spf1 -all"]}, FALHA)
    assert saida.findings == [] and saida.passed == []
    assert any("DMARC de" in linha for linha in saida.logs)


def test_mx_sem_resposta_nao_vira_estacionado(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _estacionado(monkeypatch, {"TXT": ["v=spf1 -all"], "MX": FALHA}, ["v=DMARC1; p=reject"])
    assert "dns.email.estacionado" not in saida.ids()


# -- abrangência --------------------------------------------------------------------
def test_avalia_o_dominio_organizacional(monkeypatch: pytest.MonkeyPatch) -> None:
    zona = ZonaFalsa({**BASE, **SPF_INCLUIDO}).instalar(monkeypatch)
    saida = rodar("dns.email", "www.exemplo.com.br")
    assert saida.by_id("dns.email.dmarc_ausente")[0].asset == ORG
    assert (f"_dmarc.{ORG}", "TXT") in zona.consultas
    assert ("_dmarc.www.exemplo.com.br", "TXT") not in zona.consultas


def test_avalia_uma_vez_por_auditoria(monkeypatch: pytest.MonkeyPatch) -> None:
    zona = ZonaFalsa({**BASE, **SPF_INCLUIDO}).instalar(monkeypatch)
    scan = ScanContext(parse_target("https://exemplo.com.br/"), Settings())
    run_check("dns.email", fato_dominio(ORG), scan=scan)
    consultas = len(zona.consultas)
    run_check("dns.email", fato_dominio(f"www.{ORG}"), scan=scan)
    assert len(zona.consultas) == consultas


def test_nome_sob_plataforma_compartilhada_nao_e_cobrado(monkeypatch: pytest.MonkeyPatch) -> None:
    zona = ZonaFalsa({"meusite.github.io": {"A": ["192.0.2.1"]}}).instalar(monkeypatch)
    saida = rodar("dns.email", "meusite.github.io")
    assert saida.findings == [] and zona.consultas == []
    assert any("plataforma" in linha for linha in saida.logs)


def test_dominio_inexistente_nao_gera_achado(monkeypatch: pytest.MonkeyPatch) -> None:
    ZonaFalsa().instalar(monkeypatch)
    saida = rodar("dns.email", ORG)
    assert saida.findings == []
    assert any("NXDOMAIN" in linha for linha in saida.logs)


def test_dmarc_sem_resposta_e_nao_verificado(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(monkeypatch, FALHA)
    assert _dmarc_ids(saida) == set()
    assert any("DMARC de" in linha and "não verificado" in linha for linha in saida.logs)
