"""Sequestro de subdomínio: CNAME para serviço desativado, sempre com prova concreta."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

import pytest
from fakes_dns import FALHA, ZonaFalsa, fato_dominio, rodar
from helpers import CheckOutcome, LocalServer, Route, run_check

from eigan.checks.dns import takeover
from eigan.checks.dns.nomes import dentro_de
from eigan.core.context import ScanContext
from eigan.core.models import Confidence, Severity
from eigan.core.settings import Settings
from eigan.core.target import parse_target
from eigan.data import load_json

ORG = "exemplo.com.br"
WWW = f"www.{ORG}"
S3 = "site-antigo.s3-website-us-east-1.amazonaws.com"
PAGINA_S3 = (
    "<html><body><h1>404 Not Found</h1><ul><li>Code: NoSuchBucket</li>"
    "<li>Message: The specified bucket does not exist</li></ul></body></html>"
)


def _rodar(
    monkeypatch: pytest.MonkeyPatch, registros: dict[str, Any], dominio: str = ORG
) -> tuple[CheckOutcome, ZonaFalsa]:
    zona = ZonaFalsa(registros).instalar(monkeypatch)
    return rodar("dns.takeover", dominio), zona


def _com_pagina(
    monkeypatch: pytest.MonkeyPatch,
    serve: Callable[..., LocalServer],
    registros: dict[str, Any],
    rota: Route,
) -> tuple[CheckOutcome, LocalServer]:
    srv = serve({"/": rota}, default=rota)
    monkeypatch.setattr(takeover, "urls_para", lambda nome: [srv.url])
    saida, _ = _rodar(monkeypatch, registros)
    return saida, srv


# -- destino inexistente em serviço que permite recriar o nome -----------------------------
def test_azure_app_service_inexistente(monkeypatch: pytest.MonkeyPatch) -> None:
    saida, _ = _rodar(monkeypatch, {WWW: {"CNAME": ["loja-antiga.azurewebsites.net."]}})
    [achado] = saida.by_id("dns.takeover.possivel")
    assert achado.severity == Severity.HIGH and achado.confidence == Confidence.FIRM
    assert achado.asset == WWW
    assert achado.details["prova"] == "nxdomain"
    assert "loja-antiga.azurewebsites.net" in achado.evidence


@pytest.mark.parametrize(
    "destino",
    [
        "antigo.trafficmanager.net",
        "conta.blob.core.windows.net",
        "api.azure-api.net",
        "vm.eastus.cloudapp.azure.com",
        "app.us-east-1.elasticbeanstalk.com",
        "app.elasticbeanstalk.com",
        "forum.trydiscourse.com",
    ],
)
def test_servicos_com_prova_por_nxdomain(monkeypatch: pytest.MonkeyPatch, destino: str) -> None:
    saida, _ = _rodar(monkeypatch, {WWW: {"CNAME": [destino]}})
    assert saida.ids() == {"dns.takeover.possivel"}


def test_destino_ativo_vira_ponto_forte(monkeypatch: pytest.MonkeyPatch) -> None:
    destino = "loja.azurewebsites.net"
    saida, _ = _rodar(monkeypatch, {WWW: {"CNAME": [destino]}, destino: {"A": ["192.0.2.1"]}})
    assert saida.findings == []
    assert [p.control for p in saida.passed] == ["dns.takeover"]


def test_txt_de_verificacao_impede_a_tomada(monkeypatch: pytest.MonkeyPatch) -> None:
    saida, _ = _rodar(
        monkeypatch,
        {WWW: {"CNAME": ["loja-antiga.azurewebsites.net"]}, f"asuid.{WWW}": {"TXT": ["ABC123"]}},
    )
    assert saida.ids() == {"dns.cname.orfao"}
    assert "asuid" in saida.findings[0].evidence
    assert saida.findings[0].severity == Severity.LOW


def test_txt_de_verificacao_sem_resposta_nao_afirma_nada(monkeypatch: pytest.MonkeyPatch) -> None:
    saida, _ = _rodar(
        monkeypatch, {WWW: {"CNAME": ["loja-antiga.azurewebsites.net"]}, f"asuid.{WWW}": FALHA}
    )
    assert saida.findings == []
    assert any("não verificado" in linha for linha in saida.logs)


# -- destino inexistente que outra conta não consegue recriar ------------------------------
@pytest.mark.parametrize(
    "destino",
    [
        "contoso-a6gqaeashthkhkeu.eastus-01.azurewebsites.net",  # nome padrão único do App Service
        "contoso.fjdng2acavhkevd8.westus.cloudapp.azure.com",  # rótulo com escopo do IP público
        "conta.privatelink.blob.core.windows.net",
        "app.eba-v6c3p3ia.us-east-1.elasticbeanstalk.com",
    ],
)
def test_formato_com_identificador_unico_e_so_orfao(
    monkeypatch: pytest.MonkeyPatch, destino: str
) -> None:
    saida, _ = _rodar(monkeypatch, {WWW: {"CNAME": [destino]}})
    assert saida.ids() == {"dns.cname.orfao"}
    assert "identificador único" in saida.findings[0].evidence


@pytest.mark.parametrize(
    ("destino", "trecho"),
    [
        ("antigo.azureedge.net", "Azure CDN"),
        ("antigo.azurefd.net", "Front Door"),
        ("antigo-abc123.z01.azurefd.net", "Front Door"),
        ("antigo.cloudapp.net", "Cloud Services"),
    ],
)
def test_servico_aposentado_e_so_orfao(
    monkeypatch: pytest.MonkeyPatch, destino: str, trecho: str
) -> None:
    dono = ".".join(destino.split(".")[-2:])
    saida, _ = _rodar(
        monkeypatch, {WWW: {"CNAME": [destino]}, dono: {"SOA": ["ns. admin. 1 2 3 4 5"]}}
    )
    assert saida.ids() == {"dns.cname.orfao"}
    assert trecho in saida.findings[0].evidence


# -- prova pela página do subdomínio -------------------------------------------------------
def test_s3_sem_bucket_confirmado_pela_pagina(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer]
) -> None:
    saida, srv = _com_pagina(
        monkeypatch, serve, {WWW: {"CNAME": [S3]}, S3: {"A": ["192.0.2.1"]}}, Route(404, PAGINA_S3)
    )
    [achado] = saida.by_id("dns.takeover.possivel")
    assert achado.confidence == Confidence.CONFIRMED
    assert achado.details["prova"] == "assinatura" and achado.details["url"] == srv.url
    assert "The specified bucket does not exist" in achado.evidence


def test_s3_ativo_nao_e_achado(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer]
) -> None:
    saida, _ = _com_pagina(
        monkeypatch,
        serve,
        {WWW: {"CNAME": [S3]}, S3: {"A": ["192.0.2.1"]}},
        Route(200, "<html>Loja</html>"),
    )
    assert saida.findings == [] and saida.passed


def test_soft_404_sem_assinatura_nao_e_achado(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer]
) -> None:
    saida, _ = _com_pagina(
        monkeypatch,
        serve,
        {WWW: {"CNAME": ["blog.ghost.io"]}, "blog.ghost.io": {"A": ["192.0.2.1"]}},
        Route(200, "<html>Página inicial: tudo responde 200</html>"),
    )
    assert saida.findings == []


def test_assinatura_em_servico_fora_do_catalogo_nao_conta(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer]
) -> None:
    saida, srv = _com_pagina(
        monkeypatch,
        serve,
        {WWW: {"CNAME": ["cdn.exemplo.net"]}, "cdn.exemplo.net": {"A": ["192.0.2.1"]}},
        Route(404, PAGINA_S3),
    )
    assert saida.findings == [] and srv.requests == []


@pytest.mark.parametrize(
    "destino",
    ["balanceador-123.us-east-1.elb.amazonaws.com", "ec2-192-0-2-1.compute-1.amazonaws.com"],
)
def test_outros_servicos_da_aws_nao_contam_como_s3(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer], destino: str
) -> None:
    # a aplicação atrás do balanceador pode repetir a mensagem de erro do S3
    saida, _ = _com_pagina(
        monkeypatch,
        serve,
        {WWW: {"CNAME": [destino]}, destino: {"A": ["192.0.2.1"]}},
        Route(500, PAGINA_S3),
    )
    assert "dns.takeover.possivel" not in saida.ids()


@pytest.mark.parametrize(
    "destino",
    [
        "conta.github.io",  # "Edge case" na fonte
        "app.herokuapp.com",  # "Edge case" na fonte
        "d111111abcdef8.cloudfront.net",  # "Not vulnerable" na fonte
    ],
)
def test_servicos_que_a_fonte_nao_marca_como_vulneraveis(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer], destino: str
) -> None:
    saida, srv = _com_pagina(
        monkeypatch,
        serve,
        {WWW: {"CNAME": [destino]}, destino: {"A": ["192.0.2.1"]}},
        Route(404, "There isn't a GitHub Pages site here. No such app"),
    )
    assert saida.findings == [] and srv.requests == []


def test_pagina_inacessivel_e_nao_verificada(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(takeover, "urls_para", lambda nome: ["http://127.0.0.1:1/"])
    saida, _ = _rodar(monkeypatch, {WWW: {"CNAME": [S3]}, S3: {"A": ["192.0.2.1"]}})
    assert saida.findings == [] and saida.passed == []
    assert any("sem resposta HTTP" in linha for linha in saida.logs)


def test_servico_de_assinatura_com_destino_inexistente_e_orfao(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    saida, _ = _rodar(monkeypatch, {WWW: {"CNAME": ["blog.ghost.io"]}})
    assert saida.ids() == {"dns.cname.orfao"}


def test_paginas_lidas_nos_dois_esquemas() -> None:
    assert takeover.urls_para(WWW) == [f"http://{WWW}/", f"https://{WWW}/"]


# -- assinaturas -------------------------------------------------------------------------
def _servico(rotulo: str) -> dict[str, Any]:
    return next(s for s in takeover.servicos() if s["servico"] == rotulo)


@pytest.mark.parametrize(
    ("rotulo", "pagina"),
    [
        ("Ghost", "<h1>Site unavailable.</h1>"),
        ("Ghost", "Failed to resolve DNS path for this host"),
        ("WordPress.com", "Do you want to register blog-x.wordpress.com?"),
        ("Ngrok", "Tunnel abc123.ngrok.io not found"),
        (
            "Worksites",
            "Hello! Sorry, but the website you&rsquo;re looking for doesn&rsquo;t exist.",
        ),
        ("Worksites", "Hello! Sorry, but the website you’re looking for doesn’t exist."),
        ("Help Juice", "We could not find what you&#39;re looking for."),
        ("Airee.ru", "Ошибка 402. Сервис Айри.рф не оплачен"),
    ],
)
def test_assinaturas_casam(rotulo: str, pagina: str) -> None:
    assert takeover.trecho_assinatura(_servico(rotulo), pagina)


@pytest.mark.parametrize(
    ("rotulo", "pagina"),
    [
        ("Ghost", "Site unavailable sem o ponto"),
        ("WordPress.com", "Welcome to my blog"),
        ("Ngrok", "Tunnel found"),
        ("AWS S3", "the specified bucket does not exist"),  # a assinatura diferencia maiúsculas
    ],
)
def test_assinaturas_nao_casam(rotulo: str, pagina: str) -> None:
    assert takeover.trecho_assinatura(_servico(rotulo), pagina) is None


def test_servico_sem_assinatura_nao_casa() -> None:
    assert takeover.trecho_assinatura(_servico("Discourse"), "qualquer coisa") is None


@pytest.mark.parametrize(
    "destino",
    [
        "bucket.s3.amazonaws.com",
        "bucket.s3-us-west-2.amazonaws.com",
        "bucket.s3.us-west-2.amazonaws.com",
        "bucket.s3-website-us-east-1.amazonaws.com",
        "bucket.s3-website.us-east-2.amazonaws.com",
        "bucket.s3.dualstack.us-west-2.amazonaws.com",
        "assets.exemplo.com.s3.amazonaws.com",
    ],
)
def test_formatos_de_endpoint_do_s3(destino: str) -> None:
    casado = takeover.servico_de([destino])
    assert casado is not None and casado.servico["servico"] == "AWS S3"


def test_sufixo_nao_casa_no_meio_do_nome() -> None:
    assert takeover.servico_de(["azurewebsites.net.exemplo.com"]) is None
    assert takeover.servico_de(["naoazurewebsites.net"]) is None


# -- destino fora do catálogo ----------------------------------------------------------------
def test_dominio_do_destino_nao_existe(monkeypatch: pytest.MonkeyPatch) -> None:
    saida, _ = _rodar(monkeypatch, {WWW: {"CNAME": ["app.fornecedor-extinto.com"]}})
    [achado] = saida.by_id("dns.takeover.dominio_livre")
    assert achado.severity == Severity.HIGH and achado.confidence == Confidence.FIRM
    assert achado.details["dominio_destino"] == "fornecedor-extinto.com"


def test_dominio_do_destino_existe_e_so_o_nome_sumiu(monkeypatch: pytest.MonkeyPatch) -> None:
    saida, _ = _rodar(
        monkeypatch,
        {
            WWW: {"CNAME": ["app.fornecedor.com"]},
            "fornecedor.com": {"SOA": ["ns. admin. 1 2 3 4 5"]},
        },
    )
    assert saida.ids() == {"dns.cname.orfao"}


def test_nome_sob_plataforma_nao_e_dominio_livre(monkeypatch: pytest.MonkeyPatch) -> None:
    # github.io é um sufixo privado da lista, mas é github.io que se registra
    saida, _ = _rodar(
        monkeypatch,
        {WWW: {"CNAME": ["conta.github.io"]}, "github.io": {"SOA": ["ns. admin. 1 2 3 4 5"]}},
    )
    assert saida.ids() == {"dns.cname.orfao"}


def test_nome_do_proprio_dominio_nao_e_dominio_livre(monkeypatch: pytest.MonkeyPatch) -> None:
    saida, _ = _rodar(monkeypatch, {WWW: {"CNAME": [f"antigo.{ORG}"]}})
    assert saida.ids() == {"dns.cname.orfao"}


@pytest.mark.parametrize("destino", ["servidor.interno.local", "intranet.corp", "app.lan"])
def test_nome_interno_nao_e_dominio_livre(monkeypatch: pytest.MonkeyPatch, destino: str) -> None:
    saida, _ = _rodar(monkeypatch, {WWW: {"CNAME": [destino]}})
    assert saida.ids() == {"dns.cname.orfao"}


def test_soa_sem_resposta_nao_afirma_dominio_livre(monkeypatch: pytest.MonkeyPatch) -> None:
    saida, _ = _rodar(
        monkeypatch, {WWW: {"CNAME": ["app.fornecedor.com"]}, "fornecedor.com": {"SOA": FALHA}}
    )
    assert saida.ids() == {"dns.cname.orfao"}


def test_destino_com_outro_tipo_de_registro_existe(monkeypatch: pytest.MonkeyPatch) -> None:
    destino = "app.fornecedor.com"
    saida, _ = _rodar(monkeypatch, {WWW: {"CNAME": [destino]}, destino: {"AAAA": ["2001:db8::1"]}})
    assert saida.findings == [] and saida.passed


# -- cadeia de CNAMEs ------------------------------------------------------------------------
def test_segue_a_cadeia_ate_o_servico(monkeypatch: pytest.MonkeyPatch) -> None:
    saida, _ = _rodar(
        monkeypatch,
        {
            WWW: {"CNAME": ["intermediario.exemplo.net"]},
            "intermediario.exemplo.net": {"CNAME": ["antigo.azurewebsites.net"]},
        },
    )
    [achado] = saida.by_id("dns.takeover.possivel")
    assert "intermediario.exemplo.net -> antigo.azurewebsites.net" in achado.evidence


def test_laco_de_cnames_nao_prende_a_checagem(monkeypatch: pytest.MonkeyPatch) -> None:
    zona = ZonaFalsa(
        {
            WWW: {"CNAME": ["a.exemplo.net"]},
            "a.exemplo.net": {"CNAME": ["b.exemplo.net"], "A": ["192.0.2.1"]},
            "b.exemplo.net": {"CNAME": ["a.exemplo.net"], "A": ["192.0.2.1"]},
        }
    ).instalar(monkeypatch)
    rodar("dns.takeover", ORG)
    assert len(zona.consultas) < 12


def test_cadeia_longa_para_no_limite(monkeypatch: pytest.MonkeyPatch) -> None:
    registros: dict[str, Any] = {WWW: {"CNAME": ["n0.exemplo.net"]}}
    registros.update(
        {
            f"n{i}.exemplo.net": {"CNAME": [f"n{i + 1}.exemplo.net"], "A": ["192.0.2.1"]}
            for i in range(20)
        }
    )
    zona = ZonaFalsa(registros).instalar(monkeypatch)
    scan = ScanContext(parse_target("https://exemplo.com.br/"), Settings())
    run_check("dns.takeover", fato_dominio(WWW), scan=scan)
    assert sum(tipo == "CNAME" for _, tipo in zona.consultas) == takeover.MAX_SALTOS


# -- nomes avaliados ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("dominio", "org", "esperado"),
    [
        (ORG, ORG, [ORG, WWW]),
        (WWW, ORG, [WWW]),
        (f"loja.{ORG}", ORG, [f"loja.{ORG}", f"www.loja.{ORG}", WWW]),
    ],
)
def test_candidatos(dominio: str, org: str, esperado: list[str]) -> None:
    assert takeover.candidatos(dominio, org) == esperado


def test_dominio_informado_tambem_e_avaliado(monkeypatch: pytest.MonkeyPatch) -> None:
    alvo = f"loja.{ORG}"
    zona = ZonaFalsa({alvo: {"CNAME": ["antigo.azurewebsites.net"]}}).instalar(monkeypatch)
    saida = rodar("dns.takeover", alvo)
    assert saida.by_id("dns.takeover.possivel")[0].asset == alvo
    assert (f"www.{alvo}", "CNAME") in zona.consultas and (WWW, "CNAME") in zona.consultas


def test_sem_cname_nao_ha_nada_a_dizer(monkeypatch: pytest.MonkeyPatch) -> None:
    saida, _ = _rodar(monkeypatch, {WWW: {"A": ["192.0.2.1"]}, ORG: {"A": ["192.0.2.1"]}})
    assert saida.findings == [] and saida.passed == []


def test_nomes_ja_avaliados_nao_se_repetem(monkeypatch: pytest.MonkeyPatch) -> None:
    zona = ZonaFalsa({WWW: {"CNAME": ["antigo.azurewebsites.net"]}}).instalar(monkeypatch)
    scan = ScanContext(parse_target("https://exemplo.com.br/"), Settings())
    run_check("dns.takeover", fato_dominio(ORG), scan=scan)
    run_check("dns.takeover", fato_dominio(WWW), scan=scan)
    assert zona.consultas.count((WWW, "CNAME")) == 1
    assert len(scan.findings) == 1


# -- DNS fora do ar ------------------------------------------------------------------------------
def test_sem_rede_nao_gera_achado(monkeypatch: pytest.MonkeyPatch) -> None:
    ZonaFalsa(sem_rede=True).instalar(monkeypatch)
    saida = rodar("dns.takeover", ORG)
    assert saida.findings == [] and saida.passed == []
    assert any("não verificado" in linha for linha in saida.logs)


def test_destino_sem_resposta_nao_vira_achado(monkeypatch: pytest.MonkeyPatch) -> None:
    saida, _ = _rodar(
        monkeypatch,
        {WWW: {"CNAME": ["antigo.azurewebsites.net"]}, "antigo.azurewebsites.net": FALHA},
    )
    assert saida.findings == []
    assert any("não verificado" in linha for linha in saida.logs)


# -- catálogo embarcado ------------------------------------------------------------------------
def test_catalogo_registra_origem_e_licenca() -> None:
    dados = load_json("dns_takeover.json")
    assert dados["url"] == "https://github.com/EdOverflow/can-i-take-over-xyz"
    assert "CC BY 4.0" in dados["licenca"]
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", dados["atualizado"])
    assert all(ref.startswith("https://") for ref in dados["referencias"])


def test_catalogo_bem_formado() -> None:
    assert takeover.servicos()
    for servico in takeover.servicos():
        assert servico["servico"] and servico["cname"], servico
        tem_assinatura = bool(servico.get("assinatura"))
        assert servico["nxdomain"] != tem_assinatura, f"prova ambígua: {servico['servico']}"
        if servico.get("regex"):
            re.compile(servico["assinatura"])
        if servico.get("cname_regex"):
            re.compile(servico["cname_regex"])


def test_catalogo_so_tem_servicos_marcados_como_vulneraveis() -> None:
    fora = (
        "github.io",
        "herokuapp.com",
        "herokudns.com",
        "myshopify.com",
        "netlify.app",
        "vercel.app",
        "wixdns.net",
        "webflow.io",
        "tumblr.com",
        "cloudfront.net",
        "fastly.net",
        "zendesk.com",
        "web.app",
        "azureedge.net",
        "azurefd.net",
        "cloudapp.net",
    )
    for servico in takeover.servicos():
        for padrao in servico["cname"]:
            assert not any(dentro_de(padrao, item) for item in fora), padrao
