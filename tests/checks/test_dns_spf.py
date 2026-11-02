"""SPF (RFC 7208): existência, política final, duplicidade, sintaxe e limites de consultas."""

from __future__ import annotations

from typing import Any

import pytest
from fakes_dns import FALHA, ZonaFalsa, rodar
from helpers import CheckOutcome

from eigan.checks.dns import spf
from eigan.core.models import Confidence, Severity

ORG = "exemplo.com.br"
DMARC_OK = {"TXT": ["v=DMARC1; p=reject; rua=mailto:dmarc@exemplo.com.br"]}
MX_OK = ["10 mx1.exemplo.com.br"]


def _email(monkeypatch: pytest.MonkeyPatch, txt: Any, **extra: Any) -> CheckOutcome:
    registros: dict[str, Any] = {
        ORG: {"TXT": txt, "MX": MX_OK},
        f"_dmarc.{ORG}": DMARC_OK,
        **extra,
    }
    ZonaFalsa(registros).instalar(monkeypatch)
    return rodar("dns.email", ORG)


def _spf_ids(saida: CheckOutcome) -> set[str]:
    return {i for i in saida.ids() if ".spf" in i}


# -- existência e política final -------------------------------------------------------
def test_sem_spf_com_mx(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(monkeypatch, ["google-site-verification=abc"])
    [achado] = saida.by_id("dns.email.spf_ausente")
    assert achado.severity == Severity.MEDIUM
    assert achado.confidence == Confidence.CONFIRMED
    assert achado.asset == ORG


def test_spf_restritivo_vira_ponto_forte(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(monkeypatch, ["v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 -all"])
    assert _spf_ids(saida) == set()
    assert any(p.control == "dns.email.spf" for p in saida.passed)


@pytest.mark.parametrize(
    ("registro", "esperado", "severidade"),
    [
        ("v=spf1 +all", "dns.email.spf_permissivo", Severity.HIGH),
        ("v=spf1 all", "dns.email.spf_permissivo", Severity.HIGH),
        ("V=SPF1 ip4:192.0.2.1 +ALL", "dns.email.spf_permissivo", Severity.HIGH),
        ("v=spf1 ip4:192.0.2.1 ?all", "dns.email.spf_neutro", Severity.MEDIUM),
        ("v=spf1 ip4:192.0.2.1", "dns.email.spf_neutro", Severity.MEDIUM),
        ("v=spf1", "dns.email.spf_neutro", Severity.MEDIUM),
        ("v=spf1 ip4:192.0.2.1 ~all", "dns.email.spf_softfail", Severity.INFO),
    ],
)
def test_politica_do_all(
    monkeypatch: pytest.MonkeyPatch, registro: str, esperado: str, severidade: Severity
) -> None:
    saida = _email(monkeypatch, [registro])
    assert _spf_ids(saida) == {esperado}
    assert saida.by_id(esperado)[0].severity == severidade
    assert not any(p.control == "dns.email.spf" for p in saida.passed)


def test_mecanismos_depois_do_all_sao_ignorados(monkeypatch: pytest.MonkeyPatch) -> None:
    # RFC 7208, 5.1: include depois do -all não conta consulta nem é seguido
    saida = _email(monkeypatch, ["v=spf1 -all include:nao-existe.exemplo.net"])
    assert _spf_ids(saida) == set()


def test_redirect_segue_a_politica_final(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(
        monkeypatch,
        ["v=spf1 redirect=_spf.exemplo.net"],
        **{"_spf.exemplo.net": {"TXT": ["v=spf1 ip4:192.0.2.1 ~all"]}},
    )
    assert _spf_ids(saida) == {"dns.email.spf_softfail"}


def test_redirect_e_ignorado_quando_ha_all(monkeypatch: pytest.MonkeyPatch) -> None:
    # RFC 7208, 6.1: com "all" no registro, o redirect não vale (nem é consultado)
    zona = ZonaFalsa(
        {
            ORG: {"TXT": ["v=spf1 -all redirect=_spf.exemplo.net"], "MX": MX_OK},
            f"_dmarc.{ORG}": DMARC_OK,
        }
    ).instalar(monkeypatch)
    saida = rodar("dns.email", ORG)
    assert _spf_ids(saida) == set()
    assert ("_spf.exemplo.net", "TXT") not in zona.consultas


def test_redirect_para_dominio_sem_spf_e_permerror(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(
        monkeypatch,
        ["v=spf1 redirect=_spf.exemplo.net"],
        **{"_spf.exemplo.net": {"TXT": ["outra coisa"]}},
    )
    assert "dns.email.spf_invalido" in saida.ids()
    assert not any(p.control == "dns.email.spf" for p in saida.passed)


# -- duplicidade --------------------------------------------------------------------
def test_dois_registros_spf_sao_permerror(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(monkeypatch, ["v=spf1 -all", "v=spf1 include:_spf.google.com ~all"])
    assert _spf_ids(saida) == {"dns.email.spf_multiplo"}
    assert len(saida.by_id("dns.email.spf_multiplo")[0].details["registros"]) == 2


def test_outros_txt_nao_contam_como_spf(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(
        monkeypatch, ["v=spf1 -all", "v=spf10 nao-e-spf", "spf2.0/pra -all", "MS=ms12345678"]
    )
    assert _spf_ids(saida) == set()


# -- sintaxe -------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("registro", "trecho"),
    [
        ("v=spf1 inlcude:_spf.google.com -all", "mecanismo desconhecido"),
        ("v=spf1 ip4:300.1.1.1 -all", "ip4 inválido"),
        ("v=spf1 ip6:zzzz -all", "ip6 inválido"),
        ("v=spf1 ip4 -all", "exige um endereço"),
        ("v=spf1 include -all", "exige um domínio"),
        ("v=spf1 include:exemplo.net/24 -all", "mal formado"),
        ("v=spf1 a:1.2.3.4 -all", "endereço IP"),
        ("v=spf1 a/99 -all", "CIDR inválido"),
        ("v=spf1 ptr/24 -all", "não aceita /CIDR"),
        ("v=spf1 all:exemplo.net", "não aceita valor"),
        ("v=spf1 redirect=a.exemplo.net redirect=b.exemplo.net -all", "mais de uma vez"),
    ],
)
def test_erros_de_sintaxe_viram_achado(
    monkeypatch: pytest.MonkeyPatch, registro: str, trecho: str
) -> None:
    saida = _email(monkeypatch, [registro], **{"a.exemplo.net": {"TXT": ["v=spf1 -all"]}})
    [achado] = saida.by_id("dns.email.spf_invalido")
    assert trecho in achado.evidence
    assert not any(p.control == "dns.email.spf" for p in saida.passed)


@pytest.mark.parametrize(
    "registro",
    [
        "v=spf1 a mx -all",
        "v=spf1 a/24 mx/24//64 -all",
        "v=spf1 a:servidor.exemplo.com.br/24 -all",
        "v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::1 -all",
        "v=spf1 exists:%{i}._spf.exemplo.com.br -all",
        "v=spf1 -include:%{d}.exemplo.net -all",
        "v=spf1 foo=bar -all",  # modificador desconhecido é ignorado (RFC 7208, 6)
        "v=spf1 exp=explica.exemplo.com.br -all",
    ],
)
def test_sintaxe_valida_nao_vira_achado(monkeypatch: pytest.MonkeyPatch, registro: str) -> None:
    saida = _email(
        monkeypatch,
        [registro],
        **{
            "servidor.exemplo.com.br": {"A": ["192.0.2.1"]},
            "mx1.exemplo.com.br": {"A": ["192.0.2.2"]},
        },
    )
    assert "dns.email.spf_invalido" not in saida.ids()


def test_include_de_dominio_sem_spf_e_permerror(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(
        monkeypatch,
        ["v=spf1 include:semspf.exemplo.net -all"],
        **{"semspf.exemplo.net": {"TXT": ["outra coisa"]}},
    )
    [achado] = saida.by_id("dns.email.spf_invalido")
    assert "semspf.exemplo.net" in achado.evidence and "permerror" in achado.evidence


def test_include_com_dois_spf_ou_erro_de_sintaxe(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(
        monkeypatch,
        ["v=spf1 include:dois.exemplo.net include:ruim.exemplo.net -all"],
        **{
            "dois.exemplo.net": {"TXT": ["v=spf1 -all", "v=spf1 ~all"]},
            "ruim.exemplo.net": {"TXT": ["v=spf1 nada-disso -all"]},
        },
    )
    problemas = saida.by_id("dns.email.spf_invalido")[0].details["problemas"]
    assert any("dois.exemplo.net publica 2 registros" in p for p in problemas)
    assert any("ruim.exemplo.net" in p and "desconhecido" in p for p in problemas)


def test_laco_de_includes_e_detectado(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(
        monkeypatch,
        ["v=spf1 include:a.exemplo.net -all"],
        **{"a.exemplo.net": {"TXT": [f"v=spf1 include:{ORG} -all"]}},
    )
    assert "laço" in saida.by_id("dns.email.spf_invalido")[0].evidence


# -- limite de 10 consultas -----------------------------------------------------------
def _includes(total: int) -> dict[str, Any]:
    return {f"i{n}.exemplo.net": {"TXT": ["v=spf1 ip4:192.0.2.1 ~all"]} for n in range(total)}


def _registro_com(total: int) -> str:
    return "v=spf1 " + " ".join(f"include:i{n}.exemplo.net" for n in range(total)) + " -all"


def test_dez_consultas_e_o_limite(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(monkeypatch, [_registro_com(10)], **_includes(10))
    assert "dns.email.spf_consultas" not in saida.ids()
    assert any(p.control == "dns.email.spf" for p in saida.passed)


def test_onze_consultas_estouram(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(monkeypatch, [_registro_com(11)], **_includes(11))
    [achado] = saida.by_id("dns.email.spf_consultas")
    assert achado.details["consultas"] == 11
    assert achado.severity == Severity.MEDIUM
    assert not any(p.control == "dns.email.spf" for p in saida.passed)


def test_consultas_somam_a_recursao_e_todos_os_tipos(monkeypatch: pytest.MonkeyPatch) -> None:
    # raiz: a, mx, ptr, exists, include (5) + redirect (1) = 6
    # nivel1: include + a + mx (3) = 9; nivel2: 2 a = 11; ip4/ip6/all não contam
    raiz = "v=spf1 ip4:192.0.2.1 a mx ptr exists:%{i}.exemplo.net include:nivel1.exemplo.net redirect=fim.exemplo.net"
    saida = _email(
        monkeypatch,
        [raiz],
        **{
            ORG: {"TXT": [raiz], "MX": MX_OK, "A": ["192.0.2.1"]},
            "nivel1.exemplo.net": {
                "TXT": ["v=spf1 include:nivel2.exemplo.net a mx ip6:2001:db8::1 -all"],
                "A": ["192.0.2.1"],
                "MX": ["10 mx.exemplo.net"],
            },
            "nivel2.exemplo.net": {
                "TXT": ["v=spf1 a a:mx.exemplo.net -all"],
                "A": ["192.0.2.1"],
            },
            "mx.exemplo.net": {"A": ["192.0.2.3"]},
            "fim.exemplo.net": {"TXT": ["v=spf1 -all"]},
        },
    )
    assert saida.by_id("dns.email.spf_consultas")[0].details["consultas"] == 11


def test_contagem_para_no_teto(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(monkeypatch, [_registro_com(60)], **_includes(60))
    [achado] = saida.by_id("dns.email.spf_consultas")
    assert achado.details["consultas"] == spf.TETO_CONTAGEM
    assert "ou mais" in achado.evidence


def test_include_sem_resposta_nao_vira_achado(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(
        monkeypatch,
        ["v=spf1 include:lento.exemplo.net -all"],
        **{"lento.exemplo.net": FALHA},
    )
    assert _spf_ids(saida) == set()
    assert any("incompleta" in linha for linha in saida.logs)


# -- consultas vazias e MX grande ------------------------------------------------------
def test_mais_de_duas_consultas_vazias(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(monkeypatch, ["v=spf1 a:v1.exemplo.net a:v2.exemplo.net mx:v3.exemplo.net -all"])
    achados = saida.by_id("dns.email.spf_consultas")
    assert [a.discriminator for a in achados] == ["vazias"]
    assert len(achados[0].details["vazias"]) == 3
    assert achados[0].confidence == Confidence.FIRM


def test_duas_consultas_vazias_sao_toleradas(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(monkeypatch, ["v=spf1 a:v1.exemplo.net a:v2.exemplo.net -all"])
    assert "dns.email.spf_consultas" not in saida.ids()


def test_nome_com_so_aaaa_nao_e_consulta_vazia(monkeypatch: pytest.MonkeyPatch) -> None:
    so_v6 = {"AAAA": ["2001:db8::1"]}
    saida = _email(
        monkeypatch,
        ["v=spf1 a:v1.exemplo.net a:v2.exemplo.net a:v3.exemplo.net -all"],
        **{"v1.exemplo.net": so_v6, "v2.exemplo.net": so_v6, "v3.exemplo.net": so_v6},
    )
    assert "dns.email.spf_consultas" not in saida.ids()


def test_mecanismo_mx_com_mais_de_dez_servidores(monkeypatch: pytest.MonkeyPatch) -> None:
    muitos = [f"10 mx{n}.exemplo.net" for n in range(11)]
    saida = _email(
        monkeypatch, ["v=spf1 mx:grande.exemplo.net -all"], **{"grande.exemplo.net": {"MX": muitos}}
    )
    assert [a.discriminator for a in saida.by_id("dns.email.spf_consultas")] == ["mx"]


# -- aprovação ampla por outros caminhos ---------------------------------------------
@pytest.mark.parametrize(
    "registro",
    ["v=spf1 ip4:0.0.0.0/0 -all", "v=spf1 +ip4:128.0.0.0/1 -all", "v=spf1 ip6:::/0 -all"],
)
def test_faixa_gigantesca_equivale_a_mais_all(
    monkeypatch: pytest.MonkeyPatch, registro: str
) -> None:
    saida = _email(monkeypatch, [registro])
    [achado] = saida.by_id("dns.email.spf_permissivo")
    assert achado.discriminator == "faixa"
    assert achado.severity == Severity.HIGH
    assert not any(p.control == "dns.email.spf" for p in saida.passed)


@pytest.mark.parametrize(
    "registro",
    [
        "v=spf1 ip4:10.0.0.0/8 ip4:192.0.2.0/24 -all",
        "v=spf1 -ip4:0.0.0.0/0 -all",
        "v=spf1 ip6:2001:db8::/32 -all",
    ],
)
def test_faixas_normais_nao_viram_achado(monkeypatch: pytest.MonkeyPatch, registro: str) -> None:
    assert "dns.email.spf_permissivo" not in _email(monkeypatch, [registro]).ids()


def test_include_que_termina_em_mais_all(monkeypatch: pytest.MonkeyPatch) -> None:
    saida = _email(
        monkeypatch,
        ["v=spf1 include:aberto.exemplo.net -all"],
        **{"aberto.exemplo.net": {"TXT": ["v=spf1 +all"]}},
    )
    [achado] = saida.by_id("dns.email.spf_permissivo")
    assert achado.discriminator == "include"
    assert "aberto.exemplo.net" in achado.evidence


def test_menos_include_nao_aprova_ninguem(monkeypatch: pytest.MonkeyPatch) -> None:
    # "-include": o pass do registro incluído vira fail do remetente
    saida = _email(
        monkeypatch,
        ["v=spf1 -include:aberto.exemplo.net -all"],
        **{"aberto.exemplo.net": {"TXT": ["v=spf1 +all"]}},
    )
    assert "dns.email.spf_permissivo" not in saida.ids()


# -- leitura do registro ---------------------------------------------------------------
def test_analisar_separa_termos_e_qualificadores() -> None:
    lido = spf.analisar(
        "v=spf1 ~a:x.exemplo.net/24 ?mx -ptr +ip4:192.0.2.1/32 redirect=r.exemplo.net"
    )
    assert [(t.qualificador, t.nome, t.valor) for t in lido.termos] == [
        ("~", "a", "x.exemplo.net"),
        ("?", "mx", ""),
        ("-", "ptr", ""),
        ("+", "ip4", "192.0.2.1/32"),
    ]
    assert lido.redirect == "r.exemplo.net" and lido.redirect_vale


def test_eh_spf_exige_o_fim_da_versao() -> None:
    assert spf.eh_spf("v=spf1") and spf.eh_spf("v=spf1 -all") and spf.eh_spf("V=SPF1 -all")
    assert not spf.eh_spf("v=spf10") and not spf.eh_spf("x v=spf1")


def test_autoriza_alguem() -> None:
    assert not spf.analisar("v=spf1 -all").autoriza_alguem
    assert not spf.analisar("v=spf1 ?all").autoriza_alguem
    assert spf.analisar("v=spf1 ip4:192.0.2.1 -all").autoriza_alguem
    assert spf.analisar("v=spf1 redirect=r.exemplo.net").autoriza_alguem
    assert not spf.analisar("v=spf1 -all ip4:192.0.2.1").autoriza_alguem  # depois do all é ignorado


# -- sem rede: nunca achado --------------------------------------------------------------
def test_sem_resposta_do_dns_nao_gera_achado(monkeypatch: pytest.MonkeyPatch) -> None:
    ZonaFalsa(sem_rede=True).instalar(monkeypatch)
    saida = rodar("dns.email", ORG)
    assert saida.findings == []
    assert any("não verificado" in linha for linha in saida.logs)


def test_txt_sem_resposta_mas_mx_ok_nao_diz_que_falta_spf(monkeypatch: pytest.MonkeyPatch) -> None:
    ZonaFalsa({ORG: {"TXT": FALHA, "MX": MX_OK}, f"_dmarc.{ORG}": DMARC_OK}).instalar(monkeypatch)
    saida = rodar("dns.email", ORG)
    assert _spf_ids(saida) == set()
    assert any("SPF de" in linha and "não verificado" in linha for linha in saida.logs)
