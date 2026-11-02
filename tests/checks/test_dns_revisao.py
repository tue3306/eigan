"""Regressões da revisão: entradas hostis, falsos positivos e escopo do AXFR."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import pytest
from fakes_dns import FALHA, ZonaFalsa, fato_dominio, rodar
from helpers import LocalServer, Route, run_check

from eigan.checks.dns import dmarc, resolver, spf, takeover, transporte, zona
from eigan.core.context import ScanContext
from eigan.core.models import Confidence
from eigan.core.settings import Settings
from eigan.core.target import parse_target

ORG = "exemplo.com.br"
WWW = f"www.{ORG}"
RUA = f"rua=mailto:dmarc@{ORG}"


# -- entradas hostis: dígitos que não são ASCII -------------------------------------------
def test_pct_com_digito_nao_ascii_nao_quebra() -> None:
    assert dmarc.analisar("v=DMARC1; p=reject; pct=²").pct == 100


def test_mx_com_preferencia_nao_ascii_nao_quebra() -> None:
    resposta = resolver.Resposta("ok", ("²  mx.exemplo.com",))
    assert resolver.hosts_mx(resposta) == ["mx.exemplo.com"]


def test_ds_com_tag_nao_ascii_nao_quebra() -> None:
    assert zona.tag_do_ds("² 13 2 aa") is None
    assert zona.ds_sem_chave(("² 13 2 aa",), ()) in (True, False)


def test_max_age_nao_ascii_vira_problema_da_politica() -> None:
    avaliacao = transporte.Avaliacao()
    campos = {"version": ["STSv1"], "mode": ["enforce"], "max_age": ["²"], "mx": ["mx.exemplo.com"]}
    transporte._validar_campos(campos, ["mx.exemplo.com"], avaliacao)
    assert any("max_age" in p for p in avaliacao.problemas)


def test_email_com_dmarc_hostil_continua_avaliando(monkeypatch: pytest.MonkeyPatch) -> None:
    ZonaFalsa(
        {
            ORG: {"TXT": ["v=spf1 -all"], "MX": ["10 mx.exemplo.com.br"]},
            f"_dmarc.{ORG}": {"TXT": [f"v=DMARC1; p=reject; pct=²; {RUA}"]},
        }
    ).instalar(monkeypatch)
    assert "dns.email.dmarc_parcial" not in rodar("dns.email", ORG).ids()


# -- DMARC: URI com cabeçalhos (RFC 6068) -------------------------------------------------
def test_rua_com_query_usa_so_o_host() -> None:
    assert dmarc.host_externo("mailto:x@terceiro.com?subject=rel", ORG) == "terceiro.com"


# -- SPF -----------------------------------------------------------------------------------
@pytest.mark.parametrize("registro", ["v=spf1 a/0 -all", "v=spf1 mx/0 -all", "v=spf1 a:h.x/0 -all"])
def test_a_e_mx_com_prefixo_zero_sao_faixa_ampla(registro: str) -> None:
    assert spf.analisar(registro).redes_amplas


@pytest.mark.parametrize("registro", ["v=spf1 a -all", "v=spf1 mx/24 -all", "v=spf1 a//0 -all"])
def test_a_e_mx_normais_nao_sao_faixa_ampla(registro: str) -> None:
    assert spf.analisar(registro).redes_amplas == []


def test_include_sem_resposta_nao_da_ponto_forte(monkeypatch: pytest.MonkeyPatch) -> None:
    ZonaFalsa(
        {
            ORG: {"TXT": ["v=spf1 include:x.exemplo.net -all"], "MX": ["10 mx.exemplo.com.br"]},
            "x.exemplo.net": FALHA,
        }
    ).instalar(monkeypatch)
    saida = rodar("dns.email", ORG)
    assert not any(p.control == "dns.email.spf" for p in saida.passed)


# -- domínio estacionado -------------------------------------------------------------------
def test_dominio_sem_mx_mas_com_dkim_nao_e_estacionado(monkeypatch: pytest.MonkeyPatch) -> None:
    ZonaFalsa(
        {
            ORG: {"A": ["192.0.2.1"]},
            f"selector1._domainkey.{ORG}": {"TXT": ["v=DKIM1; p=MIGfMA0GCSqGSIb3DQEB"]},
        }
    ).instalar(monkeypatch)
    assert "dns.email.estacionado" not in rodar("dns.email", ORG).ids()


def test_estacionado_nao_afirma_que_nao_recebe_email(monkeypatch: pytest.MonkeyPatch) -> None:
    ZonaFalsa({ORG: {"A": ["192.0.2.1"]}}).instalar(monkeypatch)
    [achado] = rodar("dns.email", ORG).by_id("dns.email.estacionado")
    assert "não publica MX" in achado.evidence


# -- CAA: uma vez por organização ----------------------------------------------------------
def test_caa_ausente_nao_repete_evidencia_por_subdominio(monkeypatch: pytest.MonkeyPatch) -> None:
    ZonaFalsa({ORG: {"A": ["192.0.2.1"]}, f"a.{ORG}": {"A": ["192.0.2.2"]}}).instalar(monkeypatch)
    scan = ScanContext(parse_target("https://exemplo.com.br/"), Settings())
    run_check("dns.caa", fato_dominio(f"a.{ORG}"), scan=scan)
    run_check("dns.caa", fato_dominio(f"b.{ORG}"), scan=scan)
    [achado] = scan.findings.values()
    assert achado.evidence.count("Nenhum registro CAA") == 1


# -- AXFR: só endereços do escopo ----------------------------------------------------------
@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "::1",
        "10.0.0.5",
        "192.168.1.1",
        "172.16.0.1",
        "fe80::1",
        "fd00::1",
        "169.254.169.254",
        "100.64.0.1",
        "x",
    ],
)
def test_enderecos_locais_ficam_fora_do_escopo(ip: str) -> None:
    assert zona.ip_fora_do_escopo(ip)


@pytest.mark.parametrize("ip", ["192.0.2.1", "8.8.8.8", "2001:db8::1"])
def test_enderecos_publicos_ficam_no_escopo(ip: str) -> None:
    assert not zona.ip_fora_do_escopo(ip)


def test_axfr_nao_conecta_em_ns_local_ou_privado(monkeypatch: pytest.MonkeyPatch) -> None:
    falsa = ZonaFalsa(
        {
            ORG: {"NS": [f"ns1.{ORG}", f"ns2.{ORG}"]},
            f"ns1.{ORG}": {"A": ["127.0.0.1"]},
            f"ns2.{ORG}": {"A": ["10.0.0.5"], "AAAA": ["fe80::1"]},
        }
    ).instalar(monkeypatch)
    saida = rodar("dns.axfr", ORG)
    assert falsa.axfrs == [] and saida.findings == []


def test_axfr_respeita_o_orcamento_de_tempo(monkeypatch: pytest.MonkeyPatch) -> None:
    falsa = ZonaFalsa(
        {
            ORG: {"NS": [f"ns1.{ORG}", f"ns2.{ORG}"]},
            f"ns1.{ORG}": {"A": ["192.0.2.1"]},
            f"ns2.{ORG}": {"A": ["192.0.2.2"]},
        }
    ).instalar(monkeypatch)
    monkeypatch.setattr(zona, "ORCAMENTO_AXFR", -1.0)
    saida = rodar("dns.axfr", ORG)
    assert falsa.axfrs == [] and saida.passed == []


# -- takeover ------------------------------------------------------------------------------
def _pagina(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer], destino: str, rota: Route
) -> Any:
    srv = serve({"/": rota}, default=rota)
    monkeypatch.setattr(takeover, "urls_para", lambda nome: [srv.url])
    ZonaFalsa({WWW: {"CNAME": [destino]}, destino: {"A": ["192.0.2.1"]}}).instalar(monkeypatch)
    return rodar("dns.takeover", ORG)


def test_site_ativo_que_cita_a_frase_em_script_nao_e_takeover(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer]
) -> None:
    corpo = "<html><script>var m={nf:'page not found'}</script><p>Olá</p></html>"
    saida = _pagina(monkeypatch, serve, "stats.uptimerobot.com", Route(200, corpo))
    assert saida.findings == []


def test_site_ativo_grande_que_cita_a_frase_nao_e_takeover(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer]
) -> None:
    corpo = "<html><p>Repository not found</p>" + "x" * 30_000 + "</html>"
    saida = _pagina(monkeypatch, serve, "foo.bitbucket.io", Route(200, corpo))
    assert saida.findings == []


def test_pagina_curta_com_status_200_e_so_tentativa(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer]
) -> None:
    saida = _pagina(monkeypatch, serve, "blog.ghost.io", Route(200, "<h1>Site unavailable.</h1>"))
    [achado] = saida.by_id("dns.takeover.possivel")
    assert achado.confidence == Confidence.TENTATIVE


def test_pagina_de_erro_confirma(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer]
) -> None:
    saida = _pagina(monkeypatch, serve, "blog.ghost.io", Route(404, "<h1>Site unavailable.</h1>"))
    [achado] = saida.by_id("dns.takeover.possivel")
    assert achado.confidence == Confidence.CONFIRMED


@pytest.mark.parametrize("rotulo", ["Ngrok", "WordPress.com"])
def test_assinatura_regex_nao_trava_com_pagina_hostil(rotulo: str) -> None:
    servico = next(s for s in takeover.servicos() if s["servico"] == rotulo)
    inicio = time.monotonic()
    assert takeover.trecho_assinatura(servico, ("Tunnel " * 40_000)[:262_144]) is None
    assert time.monotonic() - inicio < 2.0


@pytest.mark.parametrize("destino", ["app.eastus.azurecontainer.io", "meuacr-abc123.azurecr.io"])
def test_nome_com_hash_do_azure_nao_e_takeover(
    monkeypatch: pytest.MonkeyPatch, destino: str
) -> None:
    dono = ".".join(destino.split(".")[-2:])
    ZonaFalsa({WWW: {"CNAME": [destino]}, dono: {"SOA": ["ns. admin. 1 2 3 4 5"]}}).instalar(
        monkeypatch
    )
    assert rodar("dns.takeover", ORG).ids() == {"dns.cname.orfao"}
