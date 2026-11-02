"""Identificação de tecnologias e divulgação de versão (``web.fingerprint``)."""

from __future__ import annotations

import pytest
from fakes_web import fake_scan, response, without_server_header
from helpers import Route, http_fact, run_check

from eigan.checks.web.fingerprint import error_page_banner, same_site_target
from eigan.checks.web.techdetect import (
    disclosed_version,
    from_generator,
    from_powered_by,
    from_server,
    parse_product_tokens,
)

HOME = "<html><head><title>Início</title></head><body>olá</body></html>"
APACHE_404 = (
    "<!DOCTYPE HTML PUBLIC><html><head><title>404 Not Found</title></head><body>"
    "<h1>Not Found</h1><p>The requested URL was not found on this server.</p><hr>"
    "<address>Apache/2.4.29 (Ubuntu) Server at 127.0.0.1 Port 80</address></body></html>"
)
NGINX_404 = (
    "<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1>"
    "</center><hr><center>nginx/1.18.0 (Ubuntu)</center></body></html>"
)


def techs(out) -> dict[str, dict]:
    return {f.data["name"]: f.data for f in out.facts if f.kind == "tech"}


def site(serve, routes, default=None):
    """Servidor de teste sem o Server automático do http.server."""
    return without_server_header(serve(routes, default=default))


def test_server_com_versao_gera_achado_e_inventario(serve):
    srv = site(serve, {"/": Route(200, HOME, headers=[("Server", "Apache/2.4.41 (Ubuntu)")])})
    out = run_check("web.fingerprint", http_fact(srv.url))
    [finding] = out.by_id("web.divulgacao.versao")
    assert finding.evidence == "Server: Apache/2.4.41 (Ubuntu)"
    assert finding.discriminator == "server" and finding.details["versao"] == "2.4.41"
    assert finding.title == "Versão divulgada no cabeçalho Server"
    found = techs(out)
    assert found["apache"]["version"] == "2.4.41" and found["apache"]["kind"] == "server"
    assert found["ubuntu"]["kind"] == "os"
    assert "apache" in finding.tech


def test_cada_cabecalho_com_versao_e_um_achado(serve):
    srv = site(
        serve,
        {
            "/": Route(
                200,
                HOME,
                headers=[
                    ("Server", "Microsoft-IIS/10.0"),
                    ("X-Powered-By", "ASP.NET"),
                    ("X-AspNet-Version", "4.0.30319"),
                    ("X-AspNetMvc-Version", "5.2"),
                ],
            )
        },
    )
    out = run_check("web.fingerprint", http_fact(srv.url))
    found = {f.discriminator: f for f in out.by_id("web.divulgacao.versao")}
    assert set(found) == {"server", "x-aspnet-version", "x-aspnetmvc-version"}
    assert found["x-aspnet-version"].details["versao"] == "4.0.30319"
    assert {"iis", "aspnet"} <= set(found["x-aspnet-version"].tech)
    assert techs(out)["aspnet"]["kind"] == "framework"


def test_x_powered_by_e_x_generator(serve):
    srv = site(
        serve,
        {
            "/": Route(
                200,
                HOME,
                headers=[
                    ("X-Powered-By", "PHP/7.4.3"),
                    ("X-Generator", "Drupal 10 (https://www.drupal.org)"),
                ],
            )
        },
    )
    out = run_check("web.fingerprint", http_fact(srv.url))
    found = {f.discriminator: f for f in out.by_id("web.divulgacao.versao")}
    assert found["x-powered-by"].details["versao"] == "7.4.3"
    assert found["x-generator"].details["versao"] == "10"
    assert techs(out)["php"]["kind"] == "language"
    assert techs(out)["drupal"]["kind"] == "cms"


def test_cabecalhos_sem_versao_nao_geram_achado(serve):
    srv = site(
        serve, {"/": Route(200, HOME, headers=[("Server", "nginx"), ("X-Powered-By", "Express")])}
    )
    out = run_check("web.fingerprint", http_fact(srv.url))
    assert "web.divulgacao.versao" not in out.ids()
    assert any(p.control == "web.divulgacao" for p in out.passed)
    assert {"nginx", "express"} <= set(techs(out))


def test_versoes_fixas_nao_sao_divulgacao(serve):
    srv = site(
        serve,
        {
            "/": Route(
                200,
                HOME,
                headers=[
                    ("Server", "Apache-Coyote/1.1"),
                    ("X-Powered-By", "Servlet/3.0 JSP/2.2"),
                ],
            ),
            "/api": Route(200, "{}", headers=[("Server", "Microsoft-HTTPAPI/2.0")]),
        },
    )
    out = run_check("web.fingerprint", http_fact(srv.url))
    assert "web.divulgacao.versao" not in out.ids()
    assert techs(out)["tomcat"]["version"] is None
    api = run_check("web.fingerprint", http_fact(srv.url + "api"))
    assert "web.divulgacao.versao" not in api.ids()


def test_meta_generator_com_versao(serve):
    html = (
        '<html><head><meta name="generator" content="WordPress 6.4.2"></head><body>x</body></html>'
    )
    srv = site(serve, {"/": Route(200, html)})
    out = run_check("web.fingerprint", http_fact(srv.url))
    [finding] = out.by_id("web.divulgacao.versao")
    assert finding.discriminator == "meta-generator"
    assert finding.details["versao"] == "6.4.2"
    assert 'content="WordPress 6.4.2"' in finding.evidence
    assert techs(out)["wordpress"]["kind"] == "cms"
    assert "wordpress" in finding.tech


def test_meta_generator_sem_versao_so_entra_no_inventario(serve):
    html = '<html><head><meta name="generator" content="Wix.com Website Builder"></head></html>'
    srv = site(serve, {"/": Route(200, html)})
    out = run_check("web.fingerprint", http_fact(srv.url))
    assert "web.divulgacao.versao" not in out.ids()
    assert techs(out)["wix"]["kind"] == "cms"


@pytest.mark.parametrize(
    ("page", "tech", "version"),
    [(APACHE_404, "apache", "2.4.29"), (NGINX_404, "nginx", "1.18.0")],
)
def test_pagina_de_erro_padrao_revela_versao(serve, page, tech, version):
    srv = site(serve, {"/": Route(200, HOME)}, default=Route(404, page))
    out = run_check("web.fingerprint", http_fact(srv.url))
    [finding] = out.by_id("web.divulgacao.versao")
    assert finding.discriminator == "pagina-de-erro"
    assert finding.details["versao"] == version
    assert techs(out)[tech]["version"] == version


def test_pagina_de_erro_propria_nao_gera_achado(serve):
    custom = "<html><body><h1>Ops! Página não encontrada</h1><a href='/'>voltar</a></body></html>"
    srv = site(serve, {"/": Route(200, HOME)}, default=Route(404, custom))
    out = run_check("web.fingerprint", http_fact(srv.url))
    assert out.findings == []


def test_mesma_versao_no_cabecalho_e_na_pagina_de_erro_e_um_achado_so(serve):
    srv = site(
        serve,
        {"/": Route(200, HOME, headers=[("Server", "Apache/2.4.29 (Ubuntu)")])},
        default=Route(404, APACHE_404),
    )
    out = run_check("web.fingerprint", http_fact(srv.url))
    assert [f.discriminator for f in out.by_id("web.divulgacao.versao")] == ["server"]


def test_cdn_waf_e_cookies_entram_no_inventario(serve):
    srv = site(
        serve,
        {
            "/": Route(
                200,
                HOME,
                headers=[
                    ("Server", "cloudflare"),
                    ("CF-RAY", "8c1d2e3f4a5b6c7d-GRU"),
                    ("X-Sucuri-ID", "11005"),
                    ("Set-Cookie", "PHPSESSID=abc; Path=/; HttpOnly"),
                ],
            )
        },
    )
    out = run_check("web.fingerprint", http_fact(srv.url))
    found = techs(out)
    assert found["cloudflare"]["kind"] == "cdn"
    assert found["sucuri"]["kind"] == "waf"
    assert found["php"]["kind"] == "language"
    assert out.findings == []


@pytest.mark.parametrize(
    ("header", "value", "expected"),
    [
        ("Server", "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f", "2.4.41"),
        ("Server", "Jetty(9.4.43.v20210629)", "9.4.43"),
        ("Server", "openresty/1.21.4.1", "1.21.4.1"),
        ("Server", "nginx", None),
        ("Server", "Apache/2", None),
        ("Server", "Apache-Coyote/1.1", None),
        ("Server", "Microsoft-HTTPAPI/2.0", None),
        ("X-Powered-By", "Servlet/3.0 JSP/2.2", None),
        ("X-Powered-By", "Next.js", None),
        ("X-AspNet-Version", "4.0.30319", "4.0.30319"),
        ("X-Generator", "WordPress 6.4.2", "6.4.2"),
        ("X-Generator", "Wix.com Website Builder", None),
    ],
)
def test_disclosed_version(header, value, expected):
    assert disclosed_version(header, value) == expected


def test_produtos_do_server():
    assert parse_product_tokens("Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f") == [
        ("apache", "2.4.41"),
        ("openssl", "1.1.1f"),
    ]
    [coyote] = from_server("Apache-Coyote/1.1")
    assert (coyote.name, coyote.version) == ("tomcat", None)
    names = [hit.name for hit in from_server("Microsoft-IIS/10.0")]
    assert names == ["iis"]


def test_frases_nao_viram_tecnologia():
    assert from_powered_by("Powered by a lot of coffee") == []
    assert [h.name for h in from_powered_by("PHP/8.2.1, PleskLin")] == ["php", "plesk"]
    hit = from_generator("Joomla! - Open Source Content Management", "meta generator")
    assert hit is not None and hit.name == "joomla" and hit.version is None


def test_rodape_da_pagina_de_erro():
    assert error_page_banner(APACHE_404) == ("Apache/2.4.29 (Ubuntu)", "apache")
    assert error_page_banner(NGINX_404) == ("nginx/1.18.0 (Ubuntu)", "nginx")
    tomcat = "<html><body><h3>Apache Tomcat/9.0.65</h3></body></html>"
    assert error_page_banner(tomcat) == ("Apache Tomcat/9.0.65", "tomcat")
    assert error_page_banner("<html><center>nginx</center></html>") is None


@pytest.mark.parametrize(
    ("host", "target", "expected"),
    [
        ("exemplo.com.br", "https://www.exemplo.com.br/inicio", "https://www.exemplo.com.br/"),
        ("www.exemplo.com.br", "http://exemplo.com.br/", "http://exemplo.com.br/"),
        ("exemplo.com.br", "https://outro.com.br/", None),
        ("10.0.0.5", "https://www.10.0.0.5/", None),
        ("exemplo.com.br", "https://www.exemplo.com.br:abc/", None),
        ("exemplo.com.br", "ftp://www.exemplo.com.br/", None),
    ],
)
def test_redirecionamento_para_o_mesmo_site(host, target, expected):
    assert same_site_target(host, target) == expected


# -- CDN, WAF e cookies de sessão ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("headers", "name", "kind"),
    [
        ([("CF-RAY", "8c1d-GRU")], "cloudflare", "cdn"),
        ([("Server", "cloudflare")], "cloudflare", "cdn"),
        ([("X-Sucuri-ID", "11005")], "sucuri", "waf"),
        ([("Server", "Sucuri/Cloudproxy")], "sucuri", "waf"),
        ([("Server", "AkamaiGHost")], "akamai", "cdn"),
        ([("X-Akamai-Transformed", "9 - 0 pmb=mRUM,1")], "akamai", "cdn"),
        ([("X-Amz-Cf-Id", "abc==")], "cloudfront", "cdn"),
        ([("Via", "1.1 abc.cloudfront.net (CloudFront)")], "cloudfront", "cdn"),
        ([("X-Cache", "Miss from cloudfront")], "cloudfront", "cdn"),
        ([("X-Fastly-Request-ID", "abc")], "fastly", "cdn"),
        ([("X-Served-By", "cache-gru1234-GRU")], "fastly", "cdn"),
        ([("X-Iinfo", "1-2-3 NNNN")], "incapsula", "waf"),
        ([("X-CDN", "Imperva")], "incapsula", "waf"),
        ([("X-Azure-Ref", "0abc")], "azure-front-door", "cdn"),
        ([("Via", "1.1 varnish")], "varnish", "server"),
        ([("X-Vercel-Id", "gru1::abc")], "vercel", "cdn"),
    ],
)
def test_cdn_e_waf_pelos_cabecalhos(serve, headers, name, kind):
    srv = site(serve, {"/": Route(200, HOME, headers=headers)})
    out = run_check("web.fingerprint", http_fact(srv.url))
    assert techs(out)[name]["kind"] == kind
    assert "web.divulgacao.versao" not in out.ids()


@pytest.mark.parametrize(
    ("headers", "absent"),
    [
        ([("X-Cache", "HIT")], "cloudfront"),
        ([("X-Served-By", "web01")], "fastly"),
        ([("Via", "1.1 proxy.interno")], "varnish"),
        ([("X-CDN", "propria")], "incapsula"),
    ],
)
def test_valores_genericos_nao_viram_cdn(serve, headers, absent):
    srv = site(serve, {"/": Route(200, HOME, headers=headers)})
    assert absent not in techs(run_check("web.fingerprint", http_fact(srv.url)))


@pytest.mark.parametrize(
    ("cookie", "name", "kind"),
    [
        ("PHPSESSID", "php", "language"),
        ("JSESSIONID", "java", "language"),
        ("ASP.NET_SessionId", "aspnet", "framework"),
        (".AspNetCore.Cookies", "aspnet", "framework"),
        ("laravel_session", "laravel", "framework"),
        ("connect.sid", "express", "framework"),
        ("wordpress_logged_in_abc", "wordpress", "cms"),
        ("wp-settings-1", "wordpress", "cms"),
        ("SESSd41d8cd98f00b204e9800998ecf8427e", "drupal", "cms"),
    ],
)
def test_tecnologia_pelo_nome_do_cookie(serve, cookie, name, kind):
    srv = site(serve, {"/": Route(200, HOME, headers=[("Set-Cookie", f"{cookie}=abc; Path=/")])})
    out = run_check("web.fingerprint", http_fact(srv.url))
    fact = techs(out)[name]
    assert fact["kind"] == kind and cookie in fact["evidence"]
    assert "abc" not in fact["evidence"].replace(cookie, "")  # o valor não vai para a evidência


def test_cookie_generico_nao_vira_tecnologia(serve):
    srv = site(serve, {"/": Route(200, HOME, headers=[("Set-Cookie", "lang=pt; Path=/")])})
    assert techs(run_check("web.fingerprint", http_fact(srv.url))) == {}


# -- casos de borda ------------------------------------------------------------------------------


def test_soft_404_com_rodape_de_erro_nao_conta_como_pagina_de_erro(serve):
    """Site que responde 200 para tudo: a "página de erro" não é a do servidor."""
    srv = site(serve, {}, default=Route(200, HOME + APACHE_404))
    out = run_check("web.fingerprint", http_fact(srv.url))
    assert "web.divulgacao.versao" not in out.ids()


def test_nao_html_nao_tem_meta_generator(serve):
    srv = site(
        serve,
        {"/": Route(200, '{"generator": "WordPress 6.4.2"}', content_type="application/json")},
    )
    out = run_check("web.fingerprint", http_fact(srv.url))
    assert out.findings == [] and "wordpress" not in techs(out)


def test_cabecalho_do_redirecionamento_tambem_conta(serve):
    srv = site(
        serve,
        {
            "/": Route(302, "", headers=[("Location", "/inicio"), ("X-Powered-By", "PHP/8.2.1")]),
            "/inicio": Route(200, HOME),
        },
    )
    out = run_check("web.fingerprint", http_fact(srv.url))
    [finding] = out.by_id("web.divulgacao.versao")
    assert finding.discriminator == "x-powered-by"


def test_sem_resposta_nao_gera_nada():
    scan, _ = fake_scan(lambda m, url, h: None)
    out = run_check("web.fingerprint", http_fact("https://loja.exemplo.test/"), scan=scan)
    assert out.findings == [] and out.passed == [] and out.facts == []


def test_redirecionamento_para_www_ensina_o_novo_servico():
    def handler(method, url, headers):
        if url.startswith("https://exemplo.test"):
            return response(url, 301, "", [("Location", "https://www.exemplo.test/")])
        return response(url, 404, "<html>x</html>")

    scan, _ = fake_scan(handler)
    out = run_check("web.fingerprint", http_fact("https://exemplo.test/"), scan=scan)
    assert "https://www.exemplo.test/" in out.fact_keys("http.service")
    assert "www.exemplo.test:443" in out.fact_keys("tls.service")


def test_redirecionamento_para_outro_site_nao_ensina_servico():
    def handler(method, url, headers):
        return response(url, 301, "", [("Location", "https://parceiro.test/")])

    scan, _ = fake_scan(handler)
    out = run_check("web.fingerprint", http_fact("https://exemplo.test/"), scan=scan)
    assert out.fact_keys("http.service") == set()


# -- HTTP com versão HTTPS no mesmo host ---------------------------------------------------------


def twin_scan(http_headers, https_headers, https_body=HOME):
    def handler(method, url, headers):
        if url.startswith("https://"):
            return response(url, 200, https_body, https_headers)
        if url.startswith("http://"):
            return response(url, 200, HOME, http_headers)
        return None

    return fake_scan(handler)[0]


def test_mesmo_cabecalho_em_http_e_https_e_reportado_so_no_https():
    server = [("Server", "nginx/1.18.0")]
    scan = twin_scan(server, server)
    out = run_check("web.fingerprint", http_fact("http://loja.exemplo.test/"), scan=scan)
    assert out.findings == []
    assert out.passed == []  # o veredito fica com o fato HTTPS


def test_cabecalho_so_em_http_e_reportado_em_http():
    scan = twin_scan([("Server", "nginx/1.18.0")], [("Server", "nginx")])
    out = run_check("web.fingerprint", http_fact("http://loja.exemplo.test/"), scan=scan)
    [finding] = out.by_id("web.divulgacao.versao")
    assert finding.asset == "http://loja.exemplo.test/"


def test_meta_generator_nao_e_repetido_no_http():
    html = '<html><head><meta name="generator" content="WordPress 6.4.2"></head></html>'
    scan = twin_scan([], [], https_body=html)
    plain = run_check("web.fingerprint", http_fact("http://loja.exemplo.test/"), scan=scan)
    assert plain.findings == []
    secure = run_check("web.fingerprint", http_fact("https://loja.exemplo.test/"), scan=scan)
    assert [f.discriminator for f in secure.by_id("web.divulgacao.versao")] == ["meta-generator"]


def test_passenger_com_versao_entre_parenteses():
    [hit] = from_powered_by("Phusion Passenger(R) 6.0.4")
    assert (hit.name, hit.version) == ("passenger", "6.0.4")


# -- regressões da revisão ---------------------------------------------------------------------


def test_banner_hostil_de_tomcat_nao_trava():
    import time

    from eigan.checks.web.fingerprint import error_page_banner

    start = time.monotonic()
    error_page_banner("<h3>Apache Tomcat/1" + ".1" * 32768)
    assert time.monotonic() - start < 1.0


@pytest.mark.parametrize(
    "header,value",
    [("Server", "awselb/2.0"), ("Server", "Windows-Azure-Web/1.0"), ("Server", "Pepyaka/1.19.10")],
)
def test_banners_constantes_nao_revelam_versao(header, value):
    from eigan.checks.web.techdetect import disclosed_version

    assert disclosed_version(header, value) is None


def test_gerador_estatico_nao_revela_versao():
    from eigan.checks.web.techdetect import disclosed_version

    assert disclosed_version("x-generator", "Hugo 0.120.4") is None


def test_cookies_genericos_nao_viram_django():
    from eigan.checks.web.techdetect import from_cookies

    assert from_cookies(["sessionid"]) == []
    assert [h.name for h in from_cookies(["sessionid", "csrftoken"])] == ["django"]


def test_marca_de_cms_em_recurso_de_terceiro_e_ignorada():
    from eigan.checks.web.htmlscan import parse_html
    from eigan.checks.web.techdetect import from_html

    html = '<html><body><img src="https://blog.outro.com/wp-content/a.png"></body></html>'
    assert from_html(parse_html(html, "https://site.test/"), html) == []
    own = '<html><body><img src="/wp-content/a.png"></body></html>'
    assert [h.name for h in from_html(parse_html(own, "https://site.test/"), own)] == ["wordpress"]
