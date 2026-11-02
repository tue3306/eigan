"""Cabeçalhos de segurança e avaliador de CSP (``web.headers``)."""

from __future__ import annotations

import pytest
from fakes_web import fake_scan, response
from helpers import Route, http_fact, run_check

from eigan.checks.web.csp import evaluate, parse_policies, parse_policy
from eigan.checks.web.headers import effective_referrer_policy, framing_protection, nosniff_enabled
from eigan.checks.web.kb_headers import CSP_VALUE
from eigan.core.models import Severity

HOME = "<html><head><title>Início</title></head><body>olá</body></html>"
STRONG_CSP = "default-src 'self'; object-src 'none'; base-uri 'self'"
SITE = "https://loja.exemplo.test/"


def run_home(serve, *headers: tuple[str, str], body: str = HOME, **route):
    srv = serve({"/": Route(200, body, headers=list(headers), **route)})
    return run_check("web.headers", http_fact(srv.url))


def codes(policy: str) -> set[str]:
    return {issue.code for issue in evaluate(parse_policies([policy]))}


def passed(out) -> set[str]:
    return {item.control for item in out.passed}


# -- Content-Security-Policy ----------------------------------------------------------------


def test_csp_ausente_em_html_e_media(serve):
    out = run_home(serve)
    [finding] = out.by_id("web.csp.ausente")
    assert finding.severity is Severity.MEDIUM
    assert finding.details["report_only"] is False
    assert "web.csp" not in passed(out)


def test_so_report_only_conta_como_ausente(serve):
    out = run_home(serve, ("Content-Security-Policy-Report-Only", STRONG_CSP))
    [finding] = out.by_id("web.csp.ausente")
    assert finding.details["report_only"] is True
    assert "Report-Only" in finding.evidence


def test_csp_forte_vira_ponto_forte(serve):
    out = run_home(serve, ("Content-Security-Policy", STRONG_CSP))
    assert not {"web.csp.ausente", "web.csp.fraca"} & out.ids()
    assert "web.csp" in passed(out)


@pytest.mark.parametrize(
    ("policy", "code", "severity"),
    [
        ("script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'", "unsafe_inline", Severity.MEDIUM),
        ("default-src 'self' 'UNSAFE-INLINE'; base-uri 'self'", "unsafe_inline", Severity.MEDIUM),
        ("script-src 'self'; script-src-attr 'unsafe-inline'; object-src 'none'; base-uri 'self'", "unsafe_inline", Severity.MEDIUM),
        ("script-src 'self' 'unsafe-eval'; object-src 'none'; base-uri 'self'", "unsafe_eval", Severity.LOW),
        ("script-src *; object-src 'none'; base-uri 'self'", "origem_ampla", Severity.MEDIUM),
        ("script-src https:; object-src 'none'; base-uri 'self'", "origem_ampla", Severity.MEDIUM),
        ("script-src http:; object-src 'none'; base-uri 'self'", "origem_ampla", Severity.MEDIUM),
        ("script-src 'self' data:; object-src 'none'; base-uri 'self'", "origem_ampla", Severity.MEDIUM),
        ("default-src *; base-uri 'self'", "origem_ampla", Severity.MEDIUM),
        ("script-src http://cdn.exemplo.test; object-src 'none'; base-uri 'self'", "http", Severity.LOW),
        ("img-src 'self'; object-src 'none'; base-uri 'self'", "sem_script_src", Severity.LOW),
        ("frame-ancestors 'none'", "sem_script_src", Severity.LOW),
        ("script-src 'self'; base-uri 'self'", "sem_object_src", Severity.LOW),
        ("script-src 'self'; object-src *; base-uri 'self'", "object_src_amplo", Severity.LOW),
        ("default-src 'self'; object-src 'none'", "sem_base_uri", Severity.LOW),
        ("default-src 'self'; object-src 'none'; base-uri *", "sem_base_uri", Severity.LOW),
        ("script-src 'nonce-abc'; object-src 'none'", "sem_base_uri", Severity.MEDIUM),
        ("script-src 'sha256-abc=' 'strict-dynamic'; object-src 'none'", "sem_base_uri", Severity.MEDIUM),
    ],
)  # fmt: skip
def test_csp_com_brecha(serve, policy, code, severity):
    out = run_home(serve, ("Content-Security-Policy", policy))
    [finding] = out.by_id("web.csp.fraca")
    assert code in finding.details["problemas"]
    assert finding.severity is severity
    assert policy in finding.evidence
    assert "web.csp" not in passed(out)


@pytest.mark.parametrize(
    "policy",
    [
        STRONG_CSP,
        CSP_VALUE,
        # nonce/hash/strict-dynamic anulam 'unsafe-inline' e as origens listadas
        "script-src 'nonce-rAnd0m' 'unsafe-inline'; object-src 'none'; base-uri 'none'",
        "script-src 'sha256-abc=' 'unsafe-inline'; object-src 'none'; base-uri 'self'",
        "script-src 'nonce-rAnd0m' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'",
        # 'unsafe-inline' só em estilos não libera scripts
        "default-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'",
        # script-src próprio vence o default-src permissivo
        "default-src * 'unsafe-inline'; script-src 'self'; object-src 'none'; base-uri 'self'",
        # domínios exatos, curinga de subdomínio e HTTPS explícito não são "qualquer origem"
        "script-src 'self' https://cdn.exemplo.test *.exemplo.test; object-src 'none'; base-uri 'self'",
        "default-src 'none'; base-uri 'none'",
        # 'wasm-unsafe-eval' não é 'unsafe-eval'
        "script-src 'self' 'wasm-unsafe-eval'; object-src 'none'; base-uri 'self'",
        # nome de diretiva e palavras-chave não diferenciam maiúsculas
        "DEFAULT-SRC 'SELF'; OBJECT-SRC 'NONE'; BASE-URI 'SELF'",
    ],
)
def test_csp_sem_brecha_nao_gera_alerta(policy):
    assert evaluate(parse_policies([policy])) == []


def test_varias_politicas_basta_uma_forte():
    weak, strong = (
        "script-src 'self' 'unsafe-inline'",
        "script-src 'self'; object-src 'none'; base-uri 'self'",
    )
    assert evaluate(parse_policies([weak, strong])) == []
    assert evaluate(parse_policies([f"{weak}, {strong}"])) == []
    only_weak = parse_policies([weak, "script-src 'unsafe-inline' https:"])
    assert "unsafe_inline" in {issue.code for issue in evaluate(only_weak)}


def test_csp_no_meta_tambem_vale(serve):
    html = (
        f'<html><head><meta http-equiv="Content-Security-Policy" content="{STRONG_CSP}">'
        "</head><body>x</body></html>"
    )
    out = run_home(serve, body=html)
    assert not {"web.csp.ausente", "web.csp.fraca"} & out.ids()
    assert "web.csp" in passed(out)
    weak = html.replace("'self'; object-src", "'self' 'unsafe-inline'; object-src")
    out = run_home(serve, body=weak)
    [finding] = out.by_id("web.csp.fraca")
    assert finding.details["origem"] == ["meta"]


def test_leitura_da_politica_ignora_repeticao_e_preserva_nonce():
    policy = parse_policy("Script-Src 'NONCE-AbC' HTTPS:; script-src *; ; img-src")
    assert policy.directives["script-src"] == ["'nonce-AbC'", "https:"]
    assert policy.directives["img-src"] == []


# -- clickjacking ---------------------------------------------------------------------------


def test_sem_protecao_contra_enquadramento_em_pagina_estatica_e_baixa(serve):
    out = run_home(serve)
    [finding] = out.by_id("web.clickjacking.ausente")
    assert finding.severity is Severity.LOW
    assert "sem X-Frame-Options e sem CSP frame-ancestors" in finding.evidence


@pytest.mark.parametrize(
    "headers",
    [
        [("X-Frame-Options", "DENY")],
        [("X-Frame-Options", "sameorigin")],
        [("X-Frame-Options", "DENY, SAMEORIGIN")],  # valores conflitantes bloqueiam
        [("Content-Security-Policy", "frame-ancestors 'none'")],
        [("Content-Security-Policy", "frame-ancestors 'self' https://parceiro.exemplo.test")],
        [("Content-Security-Policy", "frame-ancestors")],  # lista vazia equivale a 'none'
    ],
)
def test_protecao_contra_enquadramento_reconhecida(serve, headers):
    out = run_home(serve, *headers)
    assert "web.clickjacking.ausente" not in out.ids()
    assert "web.clickjacking" in passed(out)


@pytest.mark.parametrize(
    ("headers", "trecho"),
    [
        ([("X-Frame-Options", "ALLOW-FROM https://parceiro.exemplo.test")], "valor inválido"),
        ([("X-Frame-Options", "ALLOWALL")], "valor inválido"),
        ([("X-Frame-Options", "foo, bar")], "valores inválidos"),
        # frame-ancestors amplo faz o navegador ignorar o X-Frame-Options
        ([("X-Frame-Options", "DENY"), ("Content-Security-Policy", "frame-ancestors *")], "qualquer site"),
        ([("Content-Security-Policy", "frame-ancestors https:")], "qualquer site"),
    ],
)  # fmt: skip
def test_protecao_contra_enquadramento_ineficaz(serve, headers, trecho):
    out = run_home(serve, *headers)
    [finding] = out.by_id("web.clickjacking.ausente")
    assert trecho in finding.evidence


def test_frame_ancestors_no_meta_nao_protege(serve):
    html = (
        "<html><head><meta http-equiv='Content-Security-Policy' content=\"frame-ancestors 'none'\">"
        "</head><body>x</body></html>"
    )
    out = run_home(serve, body=html)
    [finding] = out.by_id("web.clickjacking.ausente")
    assert "<meta> é ignorada" in finding.evidence


def test_um_frame_ancestors_restrito_vence_o_amplo():
    resp = response(SITE, headers=[("X-Frame-Options", "foo")])
    policies = parse_policies(["frame-ancestors *", "frame-ancestors 'self'"])
    protected, description = framing_protection(resp, policies)
    assert protected and "'self'" in description


# -- respostas em que os cabeçalhos não se aplicam --------------------------------------------


@pytest.mark.parametrize(
    "content_type",
    ["application/json", "text/plain; charset=utf-8", "image/png", "application/pdf"],
)
def test_nao_html_so_avalia_nosniff(serve, content_type):
    srv = serve({"/": Route(200, '{"ok": true}', content_type=content_type)})
    out = run_check("web.headers", http_fact(srv.url))
    assert out.ids() == {"web.nosniff.ausente"}
    assert any("não é HTML" in line for line in out.logs)


def test_texto_plano_com_html_dentro_nao_e_pagina(serve):
    srv = serve({"/": Route(200, HOME, content_type="text/plain")})
    out = run_check("web.headers", http_fact(srv.url))
    assert out.ids() == {"web.nosniff.ausente"}


def test_sem_content_type_fareja_o_conteudo(serve):
    srv = serve({"/": Route(200, HOME, content_type=None)})
    assert "web.csp.ausente" in run_check("web.headers", http_fact(srv.url)).ids()
    other = serve({"/": Route(200, "apenas texto", content_type=None)})
    assert run_check("web.headers", http_fact(other.url)).ids() == {"web.nosniff.ausente"}


@pytest.mark.parametrize("status", [401, 403, 404, 500, 503])
def test_resposta_de_erro_nao_e_avaliada(serve, status):
    srv = serve({"/": Route(status, HOME)})
    out = run_check("web.headers", http_fact(srv.url))
    assert out.findings == [] and out.passed == []
    assert any(f"HTTP {status}" in line for line in out.logs)


def test_redirecionamento_para_fora_nao_e_avaliado(serve):
    srv = serve({"/": Route(302, "", headers=[("Location", "https://outro.exemplo.test/")])})
    out = run_check("web.headers", http_fact(srv.url))
    assert out.findings == []
    assert any("redireciona para https://outro.exemplo.test/" in line for line in out.logs)


def test_redirecionamento_interno_avalia_o_destino(serve):
    srv = serve(
        {
            "/": Route(302, "", headers=[("Location", "/inicio")]),
            "/inicio": Route(200, HOME, headers=[("X-Frame-Options", "DENY")]),
        }
    )
    out = run_check("web.headers", http_fact(srv.url))
    assert "web.clickjacking.ausente" not in out.ids()
    assert "web.csp.ausente" in out.ids()


def test_http_com_contraparte_https_fica_para_o_https():
    scan, fake = fake_scan(lambda m, url, h: response(url, 200, HOME))
    out = run_check("web.headers", http_fact("http://loja.exemplo.test/"), scan=scan)
    assert out.findings == []
    assert any("também responde em HTTPS" in line for line in out.logs)
    assert "https://loja.exemplo.test/" in fake.urls()


def test_sem_resposta_nao_gera_achado():
    scan, _ = fake_scan(lambda m, url, h: None)
    out = run_check("web.headers", http_fact(SITE), scan=scan)
    assert out.findings == [] and out.passed == []


def test_site_que_responde_200_para_tudo_so_e_avaliado_na_home():
    scan, fake = fake_scan(lambda m, url, h: response(url, 200, HOME))
    run_check("web.headers", http_fact(SITE), scan=scan)
    assert fake.urls() == [SITE]  # nenhuma sonda extra: só a página inicial


def test_asset_e_a_origem_com_porta(serve):
    srv = serve({"/": Route(302, "", headers=[("Location", "/a/b")]), "/a/b": Route(200, HOME)})
    out = run_check("web.headers", http_fact(srv.url))
    assert {finding.asset for finding in out.findings} == {srv.url}


# -- X-Content-Type-Options ------------------------------------------------------------------


def test_sem_nosniff_e_baixa(serve):
    out = run_home(serve)
    [finding] = out.by_id("web.nosniff.ausente")
    assert finding.severity is Severity.LOW


@pytest.mark.parametrize(
    ("value", "ok"),
    [("nosniff", True), ("NoSniff", True), ("nosniff, outro", True), ("outro, nosniff", False), ("sniff", False)],
)  # fmt: skip
def test_regra_do_nosniff(serve, value, ok):
    assert nosniff_enabled(response(SITE, headers=[("X-Content-Type-Options", value)])) is ok
    out = run_home(serve, ("X-Content-Type-Options", value))
    assert ("web.nosniff.ausente" in out.ids()) is (not ok)
    assert ("web.nosniff" in passed(out)) is ok


# -- Referrer-Policy --------------------------------------------------------------------------


def test_referrer_ausente_e_informativo(serve):
    out = run_home(serve)
    [finding] = out.by_id("web.referrer.ausente")
    assert finding.severity is Severity.INFO
    assert not finding.is_actionable


@pytest.mark.parametrize("value", ["unsafe-url", "no-referrer-when-downgrade", "UNSAFE-URL"])
def test_referrer_inseguro(serve, value):
    out = run_home(serve, ("Referrer-Policy", value))
    [finding] = out.by_id("web.referrer.inseguro")
    assert finding.severity is Severity.LOW
    assert finding.details["politica"] == value.lower()
    assert "web.referrer.ausente" not in out.ids()


@pytest.mark.parametrize(
    "value",
    ["no-referrer", "same-origin", "origin", "strict-origin", "strict-origin-when-cross-origin"],
)
def test_referrer_adequado(serve, value):
    out = run_home(serve, ("Referrer-Policy", value))
    assert not {"web.referrer.ausente", "web.referrer.inseguro"} & out.ids()
    assert "web.referrer" in passed(out)


def test_referrer_invalido_conta_como_ausente(serve):
    out = run_home(serve, ("Referrer-Policy", "qualquer-coisa"))
    [finding] = out.by_id("web.referrer.ausente")
    assert "nenhum valor válido" in finding.evidence


@pytest.mark.parametrize(
    ("headers", "meta", "expected"),
    [
        (["origin, unsafe-url"], [], "unsafe-url"),  # vale o último válido
        (["unsafe-url, origin, futuro-valor"], [], "origin"),  # desconhecido não sobrescreve
        (["origin", "same-origin"], [], "same-origin"),  # várias cópias são a mesma lista
        (["unsafe-url"], ["no-referrer"], "no-referrer"),  # o <meta> vence o cabeçalho
        (["no-referrer"], ["always"], "unsafe-url"),  # nome antigo do HTML Standard
        ([], ["never"], "no-referrer"),
        ([], ["origin-when-crossorigin"], "origin-when-cross-origin"),
        (["origin"], ["inexistente"], "origin"),
        ([], [], None),
    ],
)
def test_politica_efetiva_de_referrer(headers, meta, expected):
    resp = response(SITE, headers=[("Referrer-Policy", value) for value in headers])
    assert effective_referrer_policy(resp, meta) == expected


def test_meta_referrer_evita_o_achado(serve):
    html = '<html><head><meta name="referrer" content="no-referrer"></head><body>x</body></html>'
    out = run_home(serve, body=html)
    assert "web.referrer.ausente" not in out.ids()
    assert "web.referrer" in passed(out)


# -- defesa em profundidade -------------------------------------------------------------------


def test_permissions_policy_e_coop_ausentes_sao_informativos(serve):
    out = run_home(serve)
    for finding_id in ("web.permissions_policy.ausente", "web.coop.ausente"):
        [finding] = out.by_id(finding_id)
        assert finding.severity is Severity.INFO


@pytest.mark.parametrize(
    "header",
    [("Permissions-Policy", "camera=()"), ("Feature-Policy", "camera 'none'")],
)
def test_permissions_policy_presente(serve, header):
    out = run_home(serve, header)
    assert "web.permissions_policy.ausente" not in out.ids()
    assert "web.permissions_policy" in passed(out)


@pytest.mark.parametrize(
    "value",
    ["same-origin", "SAME-ORIGIN", "same-origin-allow-popups", 'same-origin; report-to="coop"'],
)
def test_coop_que_isola(serve, value):
    out = run_home(serve, ("Cross-Origin-Opener-Policy", value))
    assert "web.coop.ausente" not in out.ids()
    assert "web.coop" in passed(out)


@pytest.mark.parametrize("value", ["unsafe-none", "qualquer-coisa"])
def test_coop_que_nao_isola(serve, value):
    out = run_home(serve, ("Cross-Origin-Opener-Policy", value))
    [finding] = out.by_id("web.coop.ausente")
    assert value in finding.evidence


@pytest.mark.parametrize("value", ["1", "1; mode=block"])
def test_filtro_xss_antigo_ligado_e_informativo(serve, value):
    out = run_home(serve, ("X-XSS-Protection", value))
    [finding] = out.by_id("web.xss_protection.ativo")
    assert finding.severity is Severity.INFO
    assert value in finding.evidence


def test_filtro_xss_desligado_ou_ausente_nao_gera_achado(serve):
    assert "web.xss_protection.ativo" not in run_home(serve, ("X-XSS-Protection", "0")).ids()
    assert "web.xss_protection.ativo" not in run_home(serve).ids()


def test_site_bem_configurado_nao_tem_achados(serve):
    out = run_home(
        serve,
        ("Content-Security-Policy", CSP_VALUE),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "strict-origin-when-cross-origin"),
        ("Permissions-Policy", "camera=(), microphone=()"),
        ("Cross-Origin-Opener-Policy", "same-origin"),
    )
    assert out.findings == []
    assert {"web.csp", "web.clickjacking", "web.nosniff", "web.referrer"} <= passed(out)
    assert {"web.permissions_policy", "web.coop"} <= passed(out)


def test_exemplo_de_correcao_acompanha_a_tecnologia(serve):
    out = run_home(serve, ("Server", "nginx"))
    [finding] = out.by_id("web.csp.ausente")
    assert "nginx" in finding.tech


# -- regressões da revisão ---------------------------------------------------------------------


def test_csp_so_com_frame_ancestors_nao_e_grave():
    from eigan.checks.web.csp import evaluate, parse_policies

    issues = evaluate(parse_policies(["frame-ancestors 'self'"], "cabeçalho"))
    assert any(i.code == "sem_script_src" for i in issues)
    assert not any(i.grave for i in issues if i.code == "sem_script_src")


def test_csp_curinga_de_hospedagem_publica():
    from eigan.checks.web.csp import evaluate, parse_policies

    policy = "default-src 'self'; script-src *.cloudfront.net; object-src 'none'; base-uri 'self'"
    issues = evaluate(parse_policies([policy], "cabeçalho"))
    assert [i.code for i in issues] == ["host_publico"]


def test_clickjacking_em_pagina_com_login_e_medio(serve):
    html = '<html><body><form method="post"><input type="password" name="p"></form></body></html>'
    srv = serve({"/": Route(200, html)})
    out = run_check("web.headers", http_fact(srv.url))
    [finding] = out.by_id("web.clickjacking.ausente")
    assert finding.severity is Severity.MEDIUM
