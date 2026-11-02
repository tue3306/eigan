"""Atributos dos cookies (``web.cookies``)."""

from __future__ import annotations

import pytest
from fakes_web import fake_scan, response
from helpers import Route, http_fact, run_check

from eigan.checks.web.cookies import (
    Cookie,
    collect_cookies,
    hsts_covers,
    hsts_policy,
    parse_set_cookie,
    prefix_problem,
)
from eigan.core.models import Confidence, Severity

HOME = "<html><body>olá</body></html>"
HSTS = ("Strict-Transport-Security", "max-age=31536000")
SITE = "https://loja.exemplo.test/"
SECRET = "valor-secreto-do-cookie"
OK_SESSION = f"PHPSESSID={SECRET}; Path=/; Secure; HttpOnly; SameSite=Lax"


def audit(serve, *cookies: str, tls: bool = True, extra=()):
    headers = [("Set-Cookie", value) for value in cookies] + list(extra)
    srv = serve({"/": Route(200, HOME, headers=headers)}, tls=tls)
    return run_check("web.cookies", http_fact(srv.url))


def cookie(text: str) -> Cookie:
    parsed = parse_set_cookie(text)
    assert parsed is not None
    return parsed


# -- Secure ---------------------------------------------------------------------------------


def test_cookie_de_sessao_sem_secure_em_https_e_medio(serve):
    out = audit(serve, f"PHPSESSID={SECRET}; Path=/; HttpOnly; SameSite=Lax")
    [finding] = out.by_id("web.cookie.sem_secure")
    assert finding.severity is Severity.MEDIUM
    assert finding.confidence is Confidence.CONFIRMED
    assert finding.discriminator == "PHPSESSID"
    assert finding.title == "Cookie sem o atributo Secure: PHPSESSID"
    assert finding.details["sessao"] is True and finding.details["hsts"] is False


def test_cookie_comum_sem_secure_em_https_e_baixo(serve):
    out = audit(serve, "lang=pt-BR; Path=/")
    [finding] = out.by_id("web.cookie.sem_secure")
    assert finding.severity is Severity.LOW
    assert finding.details["sessao"] is False


def test_hsts_reduz_o_peso_da_falta_de_secure(serve):
    out = audit(
        serve, f"PHPSESSID={SECRET}; Path=/; HttpOnly; SameSite=Lax", "lang=pt-BR", extra=[HSTS]
    )
    found = {finding.discriminator: finding for finding in out.by_id("web.cookie.sem_secure")}
    assert found["PHPSESSID"].severity is Severity.LOW
    assert found["lang"].severity is Severity.INFO
    assert "HSTS" in found["PHPSESSID"].evidence


def test_em_http_puro_nao_cobra_secure(serve):
    out = audit(serve, f"PHPSESSID={SECRET}; Path=/; HttpOnly; SameSite=Lax", tls=False)
    assert out.findings == []


def test_cookie_com_todos_os_atributos_vira_ponto_forte(serve):
    out = audit(serve, OK_SESSION, "lang=pt; Path=/; Secure")
    assert out.findings == []
    [item] = [p for p in out.passed if p.control == "web.cookies"]
    assert "2 cookie(s)" in item.text


# -- HttpOnly -------------------------------------------------------------------------------


def test_cookie_de_sessao_sem_httponly(serve):
    out = audit(serve, f"sessionid={SECRET}; Path=/; Secure; SameSite=Lax")
    [finding] = out.by_id("web.cookie.sem_httponly")
    assert finding.severity is Severity.MEDIUM
    assert finding.discriminator == "sessionid"


def test_cookie_comum_e_token_csrf_podem_ser_lidos_por_script(serve):
    out = audit(
        serve,
        "tema=escuro; Path=/; Secure",
        "csrftoken=abc; Path=/; Secure; SameSite=Lax",
        "XSRF-TOKEN=abc; Path=/; Secure",
    )
    assert out.findings == []


# -- SameSite -------------------------------------------------------------------------------


def test_cookie_de_sessao_sem_samesite(serve):
    out = audit(serve, f"connect.sid={SECRET}; Path=/; Secure; HttpOnly")
    [finding] = out.by_id("web.cookie.sem_samesite")
    assert finding.severity is Severity.LOW
    assert "sem SameSite" in finding.evidence


def test_samesite_invalido_conta_como_ausente(serve):
    out = audit(serve, f"laravel_session={SECRET}; Path=/; Secure; HttpOnly; SameSite=Qualquer")
    [finding] = out.by_id("web.cookie.sem_samesite")
    assert "SameSite=Qualquer é inválido" in finding.evidence


@pytest.mark.parametrize("value", ["Lax", "Strict", "strict", "LAX", "None"])
def test_samesite_valido_nao_gera_achado(serve, value):
    out = audit(serve, f"JSESSIONID={SECRET}; Path=/; Secure; HttpOnly; SameSite={value}")
    assert out.findings == []


def test_cookie_comum_sem_samesite_nao_gera_achado(serve):
    assert audit(serve, "tema=escuro; Path=/; Secure").findings == []


def test_samesite_none_sem_secure(serve):
    out = audit(serve, "widget=1; Path=/; SameSite=None", tls=False)
    [finding] = out.by_id("web.cookie.samesite_none_sem_secure")
    assert finding.severity is Severity.LOW
    assert finding.discriminator == "widget"


def test_samesite_none_com_secure_e_correto(serve):
    out = audit(serve, "widget=1; Path=/; SameSite=None; Secure")
    assert "web.cookie.samesite_none_sem_secure" not in out.ids()
    assert out.findings == []


# -- prefixos -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("header", "missing"),
    [
        ("__Host-a=1; Secure; Path=/", None),
        ("__Secure-a=1; Secure", None),
        ("__Secure-a=1; Secure; Domain=exemplo.test; Path=/app", None),
        ("__Host-a=1; Path=/", "Secure"),
        ("__Host-a=1; Secure", "Path=/"),
        ("__Host-a=1; Secure; Path=/app", "Path=/"),
        ("__Host-a=1; Secure; Path=/; Domain=exemplo.test", "sem Domain"),
        ("__host-a=1; Path=/", "Secure"),  # o prefixo não diferencia maiúsculas
        ("__Secure-a=1", "Secure"),
        ("__SECURE-a=1", "Secure"),
        ("comum=1", None),
        ("Host-a=1", None),
    ],
)
def test_regra_dos_prefixos(header, missing):
    assert prefix_problem(cookie(header)) == missing


def test_prefixo_mal_configurado_gera_achado(serve):
    out = audit(serve, "__Host-tema=1; Secure; Path=/app")
    [finding] = out.by_id("web.cookie.prefixo_invalido")
    assert finding.severity is Severity.LOW
    assert finding.discriminator == "__Host-tema"
    assert "Path=/" in finding.evidence


def test_prefixo_bem_configurado_nao_gera_achado(serve):
    out = audit(serve, "__Host-tema=1; Secure; Path=/", "__Secure-lang=pt; Secure; Path=/")
    assert out.findings == []


# -- quais cookies contam --------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "PHPSESSID",
        "JSESSIONID",
        "ASP.NET_SessionId",
        "ASPSESSIONIDQQABCDEF",
        ".ASPXAUTH",
        ".AspNetCore.Cookies",
        ".AspNetCore.Identity.Application",
        "laravel_session",
        "sessionid",
        "connect.sid",
        "sid",
        "SESSd41d8cd98f00b204e9800998ecf8427e",
        "SSESSd41d8cd98f00b204e9800998ecf8427e",
        "wordpress_logged_in_abc",
        "wordpress_sec_abc",
        "auth_token",
        "jwt",
        "remember_me",
        "access_token",
    ],
)
def test_nomes_de_sessao(name):
    assert cookie(f"{name}=1").is_session


@pytest.mark.parametrize(
    "name",
    [
        "lang",
        "tema",
        "_ga",
        "cart",
        "author",
        "authors_list",
        "wordpress_test_cookie",
        "csrftoken",
        "XSRF-TOKEN",
        "__RequestVerificationToken",
        "csrf_session_guard",
        "consent",
    ],
)
def test_nomes_que_nao_sao_de_sessao(name):
    assert not cookie(f"{name}=1").is_session


@pytest.mark.parametrize(
    "name",
    [
        "__cf_bm",
        "_cfuvid",
        "AWSALB",
        "AWSALBCORS",
        "BIGipServerpool",
        "ARRAffinity",
        "incap_ses_1_2",
    ],
)
def test_cookies_de_infraestrutura_ficam_de_fora(serve, name):
    out = audit(serve, f"{name}=1; Path=/")
    assert out.findings == []
    assert not any(p.control == "web.cookies" for p in out.passed)


@pytest.mark.parametrize(
    "header",
    [
        "sessao=; Max-Age=0; Path=/",
        "sessao=; Max-Age=-1; Path=/",
        "sessao=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/",
        "sessao=; Expires=Thu, 01-Jan-1970 00:00:01 GMT; Path=/",
        "sessao=x; Expires=Wed, 01 Jan 2020 00:00:00 GMT; Max-Age=0",
    ],
)
def test_cookie_sendo_apagado_nao_conta(serve, header):
    assert cookie(header).expired
    out = audit(serve, header)
    assert out.findings == []


@pytest.mark.parametrize(
    "header",
    [
        "a=1",
        "a=1; Max-Age=3600",
        "a=1; Max-Age=3600; Expires=Thu, 01 Jan 1970 00:00:00 GMT",  # Max-Age vence Expires
        "a=1; Max-Age=muito; Expires=Fri, 01 Jan 2100 00:00:00 GMT",  # Max-Age inválido é ignorado
        "a=1; Expires=Fri, 01 Jan 2100 00:00:00 GMT",
        "a=1; Expires=data-ilegivel",
        "a=1; Expires=Fri, 01 Jan 2100 00:00:00 +99999999999999999999",
    ],
)
def test_cookie_que_continua_valido(header):
    assert not cookie(header).expired


@pytest.mark.parametrize("header", ["semigual", "=valor", "; Secure", ""])
def test_set_cookie_sem_nome_e_ignorado(header):
    assert parse_set_cookie(header) is None


def test_atributo_repetido_vale_o_ultimo():
    assert cookie("a=1; SameSite=Lax; SAMESITE=Strict").samesite == "strict"


def test_cadeia_de_redirecionamento_vale_o_ultimo_set_cookie(serve):
    srv = serve(
        {
            "/": Route(
                302,
                "",
                headers=[
                    ("Location", "/inicio"),
                    ("Set-Cookie", f"PHPSESSID={SECRET}; Path=/"),
                    ("Set-Cookie", "SID=temporario; Path=/"),
                ],
            ),
            "/inicio": Route(
                200,
                HOME,
                headers=[
                    ("Set-Cookie", f"PHPSESSID={SECRET}; Path=/; Secure; HttpOnly; SameSite=Lax"),
                    ("Set-Cookie", "SID=; Path=/; Max-Age=0"),
                ],
            ),
        },
        tls=True,
    )
    out = run_check("web.cookies", http_fact(srv.url))
    assert out.findings == []


def test_cookies_do_redirecionamento_sao_auditados(serve):
    srv = serve(
        {"/": Route(302, "", headers=[("Location", "https://outro.exemplo.test/"), ("Set-Cookie", "sid=1")])},
        tls=True,
    )  # fmt: skip
    out = run_check("web.cookies", http_fact(srv.url))
    assert out.ids() == {
        "web.cookie.sem_secure",
        "web.cookie.sem_httponly",
        "web.cookie.sem_samesite",
    }


def test_mesmo_nome_em_caminhos_diferentes_conta_duas_vezes_no_navegador():
    chain = [
        response(SITE, headers=[("Set-Cookie", "a=1; Path=/x"), ("Set-Cookie", "a=2; Path=/y")])
    ]
    assert len(collect_cookies(chain)) == 2


# -- HSTS -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("max-age=31536000", (31536000, False)),
        ('MAX-AGE="600"; includeSubDomains', (600, True)),
        ("includeSubDomains", None),
        ("max-age=abc", None),
        ("max-age=1; max-age=2", None),  # diretiva repetida invalida o cabeçalho
        ("", None),
        (None, None),
    ],
)
def test_leitura_do_hsts(value, expected):
    assert hsts_policy(value) == expected


def test_hsts_so_cobre_o_que_o_navegador_nao_envia_por_http():
    host = "loja.exemplo.test"
    simple = [response(SITE, headers=[HSTS])]
    assert hsts_covers(simple, host, cookie("a=1"))
    assert not hsts_covers(simple, host, cookie("a=1; Domain=exemplo.test"))
    with_subs = [
        response(SITE, headers=[("Strict-Transport-Security", "max-age=60; includeSubDomains")])
    ]
    assert hsts_covers(with_subs, host, cookie("a=1; Domain=loja.exemplo.test"))
    assert not hsts_covers(with_subs, host, cookie("a=1; Domain=exemplo.test"))
    disabled = [response(SITE, headers=[("Strict-Transport-Security", "max-age=0")])]
    assert not hsts_covers(disabled, host, cookie("a=1"))
    over_http = [response("http://loja.exemplo.test/", headers=[HSTS])]
    assert not hsts_covers(over_http, host, cookie("a=1"))


# -- evidência e fluxo ------------------------------------------------------------------------


def test_valor_do_cookie_nunca_aparece(serve):
    out = audit(serve, f"PHPSESSID={SECRET}; Path=/; x-extra={SECRET}")
    assert out.findings
    for finding in out.findings:
        assert SECRET not in finding.evidence
        assert SECRET not in str(finding.details)
        assert "<valor omitido>" in finding.evidence
    assert "atributo(s) desconhecido(s) omitido(s)" in out.findings[0].evidence


def test_cada_cookie_e_um_achado_separado(serve):
    out = audit(serve, "sid=1; Path=/", "ident_sid=2; Path=/", "lang=pt; Path=/")
    found = {finding.discriminator for finding in out.by_id("web.cookie.sem_secure")}
    assert found == {"sid", "ident_sid", "lang"}
    assert {finding.discriminator for finding in out.by_id("web.cookie.sem_httponly")} == {
        "sid",
        "ident_sid",
    }


def test_sem_cookies_nao_gera_achado_nem_ponto_forte(serve):
    out = audit(serve)
    assert out.findings == [] and out.passed == []
    assert any("não emitiu cookies" in line for line in out.logs)


def test_http_com_contraparte_https_fica_para_o_https():
    def handler(method, url, headers):
        return response(url, 200, HOME, [("Set-Cookie", "sid=1; Path=/")])

    scan, _ = fake_scan(handler)
    out = run_check("web.cookies", http_fact("http://loja.exemplo.test/"), scan=scan)
    assert out.findings == []
    assert any("também responde em HTTPS" in line for line in out.logs)


def test_sem_resposta_nao_gera_achado():
    scan, _ = fake_scan(lambda m, url, h: None)
    out = run_check("web.cookies", http_fact(SITE), scan=scan)
    assert out.findings == [] and out.passed == []
    assert any("não respondeu" in line for line in out.logs)


def test_exemplo_de_correcao_acompanha_a_tecnologia(serve):
    out = audit(serve, f"PHPSESSID={SECRET}; Path=/")
    assert "php" in out.by_id("web.cookie.sem_httponly")[0].tech


def test_todos_os_achados_em_uma_auditoria_real(serve):
    out = audit(serve, f"PHPSESSID={SECRET}; SameSite=None", "__Secure-x=1")
    assert out.ids() == {
        "web.cookie.sem_secure",
        "web.cookie.sem_httponly",
        "web.cookie.samesite_none_sem_secure",
        "web.cookie.prefixo_invalido",
    }
    assert {finding.asset for finding in out.findings} == {out.findings[0].asset}


# -- regressões da revisão ---------------------------------------------------------------------


@pytest.mark.parametrize("name", ["cookie_consent_token", "token_expiry", "__stripe_sid"])
def test_nome_nao_sessao_nao_eleva_severidade(serve, name):
    out = audit(serve, f"{name}=1; Path=/")
    sev = {f.severity for f in out.by_id("web.cookies.sem_secure")}
    assert Severity.MEDIUM not in sev
    assert not out.by_id("web.cookies.sem_httponly")


def test_hsts_max_age_hostil_nao_quebra():
    assert hsts_policy("max-age=²") is None
    assert hsts_policy("max-age=" + "9" * 5000) is None
