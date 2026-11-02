"""Inventário de registros (dns.records), nomes e o resolvedor tolerante."""

from __future__ import annotations

from types import SimpleNamespace

import dns.exception
import dns.resolver
import pytest
from fakes_dns import FALHA, ZonaFalsa, rodar

from eigan.checks.dns import nomes, resolver
from eigan.checks.dns.nomes import (
    dentro_de,
    dominio_organizacional,
    dominio_registravel,
    normalizar,
    plataforma,
    sufixo_publico,
    tld_existe,
)
from eigan.data import load_json


# -- nomes ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("nome", "org"),
    [
        ("www.exemplo.com.br", "exemplo.com.br"),
        ("exemplo.com.br", "exemplo.com.br"),
        ("a.b.c.exemplo.com.br", "exemplo.com.br"),
        ("loja.exemplo.gov.br", "exemplo.gov.br"),
        ("www.example.co.uk", "example.co.uk"),
        ("api.example.com.au", "example.com.au"),
        ("www.example.com", "example.com"),
        ("meusite.github.io", "meusite.github.io"),  # sufixo privado: cada cliente é um domínio
        ("WWW.Exemplo.COM.BR.", "exemplo.com.br"),
        ("com.br", "com.br"),  # o próprio sufixo fica como está
        ("www.foo.nome-inventado", "foo.nome-inventado"),  # sem regra: vale o último rótulo
    ],
)
def test_dominio_organizacional(nome: str, org: str) -> None:
    assert dominio_organizacional(nome) == org


def test_regras_de_curinga_e_de_excecao_da_lista() -> None:
    # *.ck com a exceção !www.ck (exemplo clássico da Public Suffix List)
    assert sufixo_publico("foo.bar.ck") == "bar.ck"
    assert dominio_organizacional("a.foo.bar.ck") == "foo.bar.ck"
    assert sufixo_publico("www.ck") == "ck"
    assert dominio_organizacional("sub.www.ck") == "www.ck"


def test_dominio_registravel_ignora_a_secao_de_plataformas() -> None:
    assert dominio_registravel("cliente.github.io") == "github.io"
    assert dominio_registravel("www.exemplo.com.br") == "exemplo.com.br"
    assert dominio_registravel("com.br") is None


def test_plataforma_compartilhada() -> None:
    assert plataforma("meusite.github.io") == "github.io"
    assert plataforma("github.io") is None  # o domínio do próprio provedor é auditado
    assert plataforma("exemplo.com.br") is None


def test_tld_existe() -> None:
    assert tld_existe("foo.com.br")
    assert tld_existe("foo.ck")  # a lista só traz o curinga *.ck
    assert not tld_existe("servidor.corp.local")


def test_normalizar_e_dentro_de() -> None:
    assert normalizar("Café.COM.br.") == "xn--caf-dma.com.br"
    assert dentro_de("a.exemplo.com.br", "exemplo.com.br")
    assert dentro_de("exemplo.com.br", "exemplo.com.br")
    assert not dentro_de("naoexemplo.com.br", "exemplo.com.br")


def test_dados_da_lista_trazem_origem_e_licenca() -> None:
    dados = load_json("dns_sufixos.json")
    assert dados["url"].startswith("https://publicsuffix.org/")
    assert "MPL-2.0" in dados["licenca"]
    assert dados["atualizado"]
    assert "com.br" in dados["icann"] and "github.io" in dados["privado"]


# -- inventário ----------------------------------------------------------------------
def test_inventario_reune_os_registros(monkeypatch: pytest.MonkeyPatch) -> None:
    ZonaFalsa(
        {
            "www.exemplo.com.br": {
                "A": ["192.0.2.10"],
                "AAAA": ["2001:db8::10"],
                "MX": ["10 mx1.exemplo.com.br"],
                "NS": ["ns1.exemplo.com.br", "ns2.exemplo.com.br"],
                "TXT": ["v=spf1 -all", "token=abcdefghijklmnop"],
                "CAA": ['0 issue "letsencrypt.org"'],
                "CNAME": ["alvo.exemplo.com.br"],
                "SOA": ["ns1.exemplo.com.br. admin.exemplo.com.br. 1 2 3 4 5"],
            },
        }
    ).instalar(monkeypatch)
    saida = rodar("dns.records", "www.exemplo.com.br")
    assert saida.findings == []
    [fato] = [f for f in saida.facts if f.kind == "dns.records"]
    assert fato.key == "www.exemplo.com.br"
    assert fato.data["domain"] == "www.exemplo.com.br"
    assert fato.data["org"] == "exemplo.com.br"
    assert fato.data["a"] == ["192.0.2.10"]
    assert fato.data["aaaa"] == ["2001:db8::10"]
    assert fato.data["mx"] == ["10 mx1.exemplo.com.br"]
    assert fato.data["ns"] == ["ns1.exemplo.com.br", "ns2.exemplo.com.br"]
    assert fato.data["caa"] == ['0 issue "letsencrypt.org"']
    assert fato.data["cname"] == ["alvo.exemplo.com.br"]
    assert len(fato.data["soa"]) == 1
    assert "v=spf1 -all" in fato.data["txt"]
    assert not any("abcdefghijklmnop" in texto for texto in fato.data["txt"])  # segredo mascarado


def test_dominio_sem_alguns_registros_ainda_gera_inventario(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ZonaFalsa({"exemplo.com.br": {"A": ["192.0.2.1"], "TXT": FALHA}}).instalar(monkeypatch)
    saida = rodar("dns.records")
    [fato] = [f for f in saida.facts if f.kind == "dns.records"]
    assert fato.data["a"] == ["192.0.2.1"]
    assert fato.data["txt"] == [] and fato.data["mx"] == []


def test_nxdomain_nao_gera_inventario_nem_achado(monkeypatch: pytest.MonkeyPatch) -> None:
    ZonaFalsa().instalar(monkeypatch)
    saida = rodar("dns.records")
    assert saida.facts == [] and saida.findings == []
    assert any("não existe" in linha for linha in saida.logs)


def test_sem_rede_registra_nao_verificado(monkeypatch: pytest.MonkeyPatch) -> None:
    ZonaFalsa(sem_rede=True).instalar(monkeypatch)
    saida = rodar("dns.records")
    assert saida.facts == [] and saida.findings == []
    assert any("não respondeu" in linha for linha in saida.logs)


def test_mesma_consulta_nao_se_repete_na_auditoria(monkeypatch: pytest.MonkeyPatch) -> None:
    from fakes_dns import fato_dominio
    from helpers import run_check

    from eigan.core.context import ScanContext
    from eigan.core.settings import Settings
    from eigan.core.target import parse_target

    zona = ZonaFalsa({"exemplo.com.br": {"A": ["192.0.2.1"]}}).instalar(monkeypatch)
    scan = ScanContext(parse_target("https://exemplo.com.br/"), Settings())
    run_check("dns.records", fato_dominio("exemplo.com.br"), scan=scan)
    primeira = len(zona.consultas)
    run_check("dns.records", fato_dominio("exemplo.com.br"), scan=scan)
    assert len(zona.consultas) == primeira


# -- resolvedor real, com o dnspython simulado -----------------------------------------
class _Rdata(SimpleNamespace):
    def __str__(self) -> str:
        return str(self.__dict__.get("texto", ""))


def _resolvedor_que(acao: object) -> SimpleNamespace:
    def resolve(*_args: object, **_kwargs: object) -> object:
        if isinstance(acao, BaseException):
            raise acao
        return acao

    return SimpleNamespace(resolve=resolve)


def _com_resolvedor(monkeypatch: pytest.MonkeyPatch, acao: object) -> None:
    monkeypatch.setattr(resolver, "_resolvedor", lambda sem_validacao=False: _resolvedor_que(acao))


@pytest.mark.parametrize(
    ("excecao", "status"),
    [
        (dns.resolver.NXDOMAIN(), resolver.NXDOMAIN),
        (dns.resolver.NoAnswer(), resolver.VAZIO),
        (dns.exception.Timeout(), resolver.ERRO),
        (dns.resolver.NoNameservers(), resolver.ERRO),
        (dns.resolver.NoResolverConfiguration(), resolver.ERRO),
        (OSError("sem rota"), resolver.ERRO),
        (UnicodeError("nome inválido"), resolver.ERRO),
    ],
)
def test_query_nunca_levanta(
    monkeypatch: pytest.MonkeyPatch, excecao: Exception, status: str
) -> None:
    _com_resolvedor(monkeypatch, excecao)
    assert resolver.query("exemplo.com.br", "TXT").status == status


def test_query_sem_configuracao_de_dns_vira_erro(monkeypatch: pytest.MonkeyPatch) -> None:
    def sem_config(sem_validacao: bool = False) -> object:
        raise dns.resolver.NoResolverConfiguration("sem /etc/resolv.conf")

    monkeypatch.setattr(resolver, "_resolvedor", sem_config)
    resposta = resolver.query("exemplo.com.br", "A")
    assert resposta.status == resolver.ERRO and "resolvedor indisponível" in resposta.erro


def test_query_formata_cada_tipo_de_registro(monkeypatch: pytest.MonkeyPatch) -> None:
    alvo = SimpleNamespace(to_text=lambda omit_final_dot=True: "mx.exemplo.com.br")
    casos = [
        ("A", _Rdata(address="192.0.2.1"), "192.0.2.1"),
        ("MX", _Rdata(preference=10, exchange=alvo), "10 mx.exemplo.com.br"),
        ("NS", _Rdata(target=alvo), "mx.exemplo.com.br"),
        (
            "TXT",
            _Rdata(strings=(b"v=spf1 ", b"-all")),
            "v=spf1 -all",
        ),  # partes se juntam sem espaço
        (
            "CAA",
            _Rdata(flags=0, tag=b"issue", value=b"letsencrypt.org"),
            '0 issue "letsencrypt.org"',
        ),
        ("SOA", _Rdata(texto="ns1. admin. 1 2 3 4 5"), "ns1. admin. 1 2 3 4 5"),
    ]
    for tipo, rdata, esperado in casos:
        _com_resolvedor(monkeypatch, SimpleNamespace(rrset=[rdata]))
        assert resolver.query("exemplo.com.br", tipo).registros == (esperado,)
    _com_resolvedor(monkeypatch, SimpleNamespace(rrset=None))
    assert resolver.query("exemplo.com.br", "MX").status == resolver.VAZIO


def test_resposta_ausente_e_ok() -> None:
    assert resolver.Resposta(resolver.NXDOMAIN).ausente
    assert resolver.Resposta(resolver.VAZIO).ausente
    assert not resolver.Resposta(resolver.ERRO, erro="x").ausente
    assert resolver.Resposta(resolver.OK, ("a",)).ok
    assert not resolver.Resposta(resolver.OK).ok


def test_hosts_mx_ordena_e_ignora_mx_nulo() -> None:
    assert resolver.hosts_mx(
        resolver.Resposta(resolver.OK, ("20 b.exemplo.", "10 a.exemplo."))
    ) == [
        "a.exemplo",
        "b.exemplo",
    ]
    assert resolver.hosts_mx(resolver.Resposta(resolver.OK, ("0 .",))) == []


def test_nomes_e_importado_pelo_pacote() -> None:
    import eigan.checks.dns as pacote

    assert pacote.nomes is nomes
