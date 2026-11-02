"""Política de CORS (``web.cors``)."""

from __future__ import annotations

import pytest
from fakes_web import fake_scan, response
from helpers import Route, http_fact, run_check

from eigan.checks.web.cors import (
    TEST_ORIGIN,
    CorsAnswer,
    judge,
    prefix_origin,
    read_answer,
)
from eigan.core.models import Confidence, Severity
from eigan.core.settings import Settings

HOME = "<html><body>olá</body></html>"
SITE = "https://loja.exemplo.test/"
PREFIXED = "https://loja.exemplo.test.eigan-auditoria.invalid"
CREDS = ("Access-Control-Allow-Credentials", "true")


def cors_server(serve, policy):
    """``policy(origem) -> cabeçalhos`` decide o que o servidor responde a cada origem."""

    def handler(request):
        return Route(200, HOME, headers=list(policy(request.headers.get("Origin"))))

    return serve({"/": handler})


def audit(serve, policy):
    return run_check("web.cors", http_fact(cors_server(serve, policy).url))


def reflect(*extra):
    def policy(origin):
        return [("Access-Control-Allow-Origin", origin), *extra] if origin else []

    return policy


def fake_handler(policy):
    def handler(method, url, headers):
        return response(url, 200, HOME, policy(headers.get("Origin")))

    return handler


# -- origem refletida -------------------------------------------------------------------------


def test_origem_refletida_com_credenciais_e_alta(serve):
    out = audit(serve, reflect(CREDS))
    [finding] = out.by_id("web.cors.reflete_origem_credenciais")
    assert finding.severity is Severity.HIGH
    assert finding.confidence is Confidence.FIRM  # depende de a home servir dados do usuário
    assert TEST_ORIGIN in finding.evidence and "Allow-Credentials: true" in finding.evidence
    assert "HTTP 200" in finding.evidence
    assert finding.details["credenciais"] is True and finding.details["status"] == 200
    assert not any(p.control == "web.cors" for p in out.passed)


def test_origem_refletida_sem_credenciais_e_baixa(serve):
    out = audit(serve, reflect())
    found = out.by_id("web.cors.reflete_origem")
    assert {f.discriminator for f in found} == {"", "null"}
    assert all(f.severity is Severity.LOW for f in found)
    assert "web.cors.reflete_origem_credenciais" not in out.ids()


def test_credenciais_so_valem_com_true_exato(serve):
    """O Fetch compara ``true`` byte a byte: ``True`` não libera cookies."""
    out = audit(serve, reflect(("Access-Control-Allow-Credentials", "True")))
    assert "web.cors.reflete_origem_credenciais" not in out.ids()
    assert "web.cors.reflete_origem" in out.ids()


def test_resposta_de_erro_reduz_a_confianca(serve):
    srv = serve(
        {"/": lambda h: Route(403, HOME, headers=list(reflect(CREDS)(h.headers.get("Origin"))))}
    )
    [finding] = run_check("web.cors", http_fact(srv.url)).by_id(
        "web.cors.reflete_origem_credenciais"
    )
    assert finding.confidence is Confidence.FIRM and "HTTP 403" in finding.evidence


# -- origem null -------------------------------------------------------------------------------


def test_null_com_credenciais_e_alta(serve):
    def policy(origin):
        return [("Access-Control-Allow-Origin", "null"), CREDS] if origin == "null" else []

    out = audit(serve, policy)
    [finding] = out.by_id("web.cors.null_credenciais")
    assert finding.severity is Severity.HIGH
    assert finding.discriminator == "null"
    assert "Origin: null" in finding.evidence
    assert "web.cors.reflete_origem_credenciais" not in out.ids()


def test_null_estatico_com_credenciais_nao_vale_para_outras_origens(serve):
    out = audit(serve, lambda origin: [("Access-Control-Allow-Origin", "null"), CREDS])
    assert out.ids() == {"web.cors.null_credenciais"}


def test_null_sem_credenciais_e_baixa(serve):
    def policy(origin):
        return [("Access-Control-Allow-Origin", "null")] if origin == "null" else []

    [finding] = audit(serve, policy).by_id("web.cors.reflete_origem")
    assert finding.discriminator == "null" and finding.severity is Severity.LOW


# -- curinga -----------------------------------------------------------------------------------


def test_curinga_com_credenciais_e_baixa(serve):
    out = audit(serve, lambda origin: [("Access-Control-Allow-Origin", "*"), CREDS])
    [finding] = out.by_id("web.cors.curinga_credenciais")
    assert finding.severity is Severity.LOW
    assert "web.cors.curinga" not in out.ids()


def test_curinga_sem_credenciais_e_informativo(serve):
    out = audit(serve, lambda origin: [("Access-Control-Allow-Origin", "*")])
    [finding] = out.by_id("web.cors.curinga")
    assert finding.severity is Severity.INFO
    assert not finding.is_actionable
    assert len(out.findings) == 1  # a sonda null não repete o aviso
    assert not any(p.control == "web.cors" for p in out.passed)


# -- falsos positivos --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "headers",
    [
        [],
        [("Access-Control-Allow-Origin", "https://parceiro.exemplo.test")],
        [("Access-Control-Allow-Origin", "https://parceiro.exemplo.test"), CREDS],
        [("Access-Control-Allow-Credentials", "true")],
        [("Vary", "Origin")],
    ],
)
def test_lista_fixa_ou_sem_cors_vira_ponto_forte(serve, headers):
    out = audit(serve, lambda origin: headers)
    assert out.findings == []
    assert any(p.control == "web.cors" for p in out.passed)


def test_navegador_recusa_varias_copias_do_cabecalho(serve):
    def policy(origin):
        return (
            [("Access-Control-Allow-Origin", origin), ("Access-Control-Allow-Origin", "https://b.test"), CREDS]
            if origin
            else []
        )  # fmt: skip

    out = audit(serve, policy)
    assert out.findings == []


def test_lista_em_um_valor_tambem_nao_vale():
    resp = response(
        SITE, headers=[("Access-Control-Allow-Origin", f"{TEST_ORIGIN}, https://b.test"), CREDS]
    )
    assert judge(read_answer(TEST_ORIGIN, resp)) is None


def test_barra_no_fim_nao_e_a_mesma_origem():
    resp = response(SITE, headers=[("Access-Control-Allow-Origin", f"{TEST_ORIGIN}/"), CREDS])
    assert judge(read_answer(TEST_ORIGIN, resp)) is None


def test_ponto_forte_exige_as_duas_sondas_respondidas():
    """Sonda sem resposta não é controle verificado."""

    def only_external(method, url, headers):
        return None if headers.get("Origin") == "null" else response(url, 200, HOME)

    scan, _ = fake_scan(only_external, settings=Settings(profile="rapido"))
    out = run_check("web.cors", http_fact(SITE), scan=scan)
    assert out.findings == [] and out.passed == []
    assert any("não foi confirmada" in line for line in out.logs)


def test_nenhuma_sonda_respondida_nao_gera_ponto_forte():
    def only_home(method, url, headers):
        return None if "Origin" in headers else response(url, 200, HOME)

    scan, _ = fake_scan(only_home)
    out = run_check("web.cors", http_fact(SITE), scan=scan)
    assert out.findings == [] and out.passed == []


def test_achado_mesmo_com_uma_sonda_sem_resposta():
    def handler(method, url, headers):
        origin = headers.get("Origin")
        if origin == "null":
            return None
        return response(url, 200, HOME, reflect(CREDS)(origin))

    scan, _ = fake_scan(handler)
    out = run_check("web.cors", http_fact(SITE), scan=scan)
    assert out.ids() == {"web.cors.reflete_origem_credenciais"}


# -- origem por prefixo (validação frouxa) ------------------------------------------------------


def test_validacao_por_prefixo_e_detectada():
    def policy(origin):
        if origin and origin.startswith("https://loja.exemplo.test"):
            return [("Access-Control-Allow-Origin", origin), CREDS]
        return []

    scan, fake = fake_scan(fake_handler(policy))
    out = run_check("web.cors", http_fact(SITE), scan=scan)
    [finding] = out.by_id("web.cors.reflete_origem_credenciais")
    assert finding.discriminator == "prefixo"
    assert finding.title == "CORS aceita origens que só começam com o domínio do site"
    assert PREFIXED in finding.evidence
    assert [c.headers.get("Origin") for c in fake.calls if "Origin" in c.headers] == [
        TEST_ORIGIN,
        "null",
        PREFIXED,
    ]


def test_prefixo_nao_e_testado_no_perfil_rapido():
    scan, fake = fake_scan(fake_handler(lambda origin: []), settings=Settings(profile="rapido"))
    run_check("web.cors", http_fact(SITE), scan=scan)
    assert PREFIXED not in {c.headers.get("Origin") for c in fake.calls}


def test_prefixo_e_dispensado_quando_a_reflexao_ja_foi_vista():
    scan, fake = fake_scan(fake_handler(reflect(CREDS)))
    run_check("web.cors", http_fact(SITE), scan=scan)
    assert PREFIXED not in {c.headers.get("Origin") for c in fake.calls}


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("Loja.Exemplo.test", PREFIXED),
        ("127.0.0.1", None),
        ("::1", None),
        ("[::1]", None),
        ("", None),
    ],
)
def test_origem_por_prefixo(host, expected):
    assert prefix_origin(host) == expected


@pytest.mark.parametrize(
    ("origin", "allow", "creds", "expected"),
    [
        (TEST_ORIGIN, TEST_ORIGIN, True, ("web.cors.reflete_origem_credenciais", "")),
        (TEST_ORIGIN, TEST_ORIGIN, False, ("web.cors.reflete_origem", "")),
        ("null", "null", True, ("web.cors.null_credenciais", "null")),
        ("null", "null", False, ("web.cors.reflete_origem", "null")),
        (PREFIXED, PREFIXED, True, ("web.cors.reflete_origem_credenciais", "prefixo")),
        (PREFIXED, PREFIXED, False, ("web.cors.reflete_origem", "prefixo")),
        (TEST_ORIGIN, "*", True, ("web.cors.curinga_credenciais", "")),
        (TEST_ORIGIN, "*", False, ("web.cors.curinga", "")),
        ("null", "*", True, None),
        (PREFIXED, "*", False, None),
        (TEST_ORIGIN, None, True, None),
        (TEST_ORIGIN, "https://parceiro.test", True, None),
    ],
)
def test_julgamento(origin, allow, creds, expected):
    verdict = judge(CorsAnswer(origin, allow, creds, 200))
    assert (verdict.finding, verdict.discriminator) == expected if expected else verdict is None


# -- não intrusivo e fluxo ---------------------------------------------------------------------


def test_so_faz_get_com_as_origens_de_auditoria(serve):
    srv = cors_server(serve, lambda origin: [])
    run_check("web.cors", http_fact(srv.url))
    assert {r.method for r in srv.requests} == {"GET"}
    assert [r.headers.get("Origin") for r in srv.requests] == [None, TEST_ORIGIN, "null"]


def test_redirecionamento_para_fora_nao_e_avaliado(serve):
    srv = serve({"/": Route(302, "", headers=[("Location", "https://outro.exemplo.test/")])})
    out = run_check("web.cors", http_fact(srv.url))
    assert out.findings == [] and out.passed == []
    assert len(srv.requests) == 1


def test_avalia_o_destino_do_redirecionamento_interno(serve):
    srv = serve(
        {
            "/": Route(302, "", headers=[("Location", "/inicio")]),
            "/inicio": lambda h: Route(200, HOME, headers=list(reflect(CREDS)(h.headers.get("Origin")))),
        }
    )  # fmt: skip
    out = run_check("web.cors", http_fact(srv.url))
    [finding] = out.by_id("web.cors.reflete_origem_credenciais")
    assert finding.asset == srv.url
    assert "/inicio" in finding.evidence
    assert all(r.path.startswith("/inicio") for r in srv.requests if "Origin" in r.headers)


def test_http_com_contraparte_https_fica_para_o_https():
    scan, fake = fake_scan(fake_handler(reflect(CREDS)))
    out = run_check("web.cors", http_fact("http://loja.exemplo.test/"), scan=scan)
    assert out.findings == []
    assert not any("Origin" in c.headers for c in fake.calls)


def test_sem_resposta_nao_gera_achado():
    scan, _ = fake_scan(lambda m, url, h: None)
    out = run_check("web.cors", http_fact(SITE), scan=scan)
    assert out.findings == [] and out.passed == []
    assert any("não respondeu" in line for line in out.logs)


def test_site_que_responde_200_para_tudo_nao_e_cors_aberto(serve):
    srv = serve({}, default=Route(200, HOME))
    out = run_check("web.cors", http_fact(srv.url))
    assert out.findings == []


def test_exemplo_de_correcao_acompanha_a_tecnologia(serve):
    out = audit(serve, lambda origin: [("Server", "nginx"), *reflect(CREDS)(origin)])
    assert "nginx" in out.by_id("web.cors.reflete_origem_credenciais")[0].tech


# -- regressões da revisão ---------------------------------------------------------------------


def test_prefix_origin_idn_vira_ascii():
    from eigan.checks.web.cors import prefix_origin

    value = prefix_origin("café.com.br")
    assert value is not None and value.isascii()


def test_origem_null_sem_credenciais_tem_titulo_proprio():
    from eigan.checks.web.cors import CorsAnswer, judge

    verdict = judge(CorsAnswer("null", "null", False, 200))
    assert verdict is not None and verdict.title and "null" in verdict.title
