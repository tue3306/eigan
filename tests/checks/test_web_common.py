"""Apoios compartilhados das checagens web: página inicial, soft 404 e robustez."""

from __future__ import annotations

import secrets
import threading
from urllib.parse import quote, urlsplit

import pytest
from fakes_web import check_context, fake_scan, ipv6_available, ipv6_server, response, run_in
from helpers import Route, http_fact, run_check

from eigan.checks.web import common
from eigan.core.context import ScanContext
from eigan.core.settings import Settings
from eigan.core.target import parse_target

SITE = "https://loja.exemplo.test/"
TEMPLATE = (
    "<html><head><title>Loja Exemplo</title></head><body><nav>menu</nav>"
    "<main>{conteudo}</main><footer>req {token}</footer></body></html>"
)


def page_html(conteudo: str = "vitrine de produtos") -> str:
    return TEMPLATE.format(conteudo=conteudo, token=secrets.token_hex(16))


def real_ctx(url: str, settings: Settings | None = None):
    scan = ScanContext(parse_target("https://127.0.0.1/"), settings or Settings(http_timeout=5.0))
    return check_context(scan, url)


def path_of(url: str) -> str:
    return urlsplit(url).path


# -- página inicial ---------------------------------------------------------------------


def test_segue_redirecionamento_dentro_da_origem(serve):
    srv = serve(
        {"/": Route(302, "", headers=[("Location", "/inicio")]), "/inicio": Route(200, page_html())}
    )
    page = common.load_page(real_ctx(srv.url), srv.url)
    assert page is not None
    assert [r.status for r in page.chain] == [302, 200]
    assert page.final.url.endswith("/inicio")
    assert page.ok and page.html and not page.is_redirect and page.left_to is None


def test_redirecionamento_para_outra_origem_nao_e_seguido():
    scan, fake = fake_scan(
        lambda m, url, h: response(url, 301, "", [("Location", "https://outro.exemplo.test/")])
    )
    ctx = check_context(scan, SITE)
    page = common.load_page(ctx, SITE)
    assert page is not None and page.is_redirect
    assert page.left_to == "https://outro.exemplo.test/"
    assert fake.urls() == [SITE]  # o destino de fora não é buscado aqui
    assert "redireciona para https://outro.exemplo.test/" in (common.skip_reason(ctx, page) or "")


@pytest.mark.parametrize("location", ["http://[::1", "http://127.0.0.1:porta/"])
def test_location_malformado_nao_derruba(serve, location):
    srv = serve({"/": Route(302, "", headers=[("Location", location)])})
    ctx = real_ctx(srv.url)
    page = common.load_page(ctx, srv.url)
    assert page is not None and page.is_redirect and len(page.chain) == 1
    assert common.skip_reason(ctx, page)  # explica o pulo, sem exceção
    out = run_check("web.headers", http_fact(srv.url))
    assert out.findings == []


def test_laco_de_redirecionamento_para(serve):
    srv = serve(
        {
            "/": Route(302, "", headers=[("Location", "/a")]),
            "/a": Route(302, "", headers=[("Location", "/b")]),
            "/b": Route(302, "", headers=[("Location", "/a")]),
        }
    )
    page = common.load_page(real_ctx(srv.url), srv.url)
    assert page is not None
    assert len(page.chain) == 3 and page.is_redirect
    assert len(srv.requests) == 3


def test_corpo_limitado_ao_teto_configurado(serve):
    srv = serve({"/": Route(200, "<html><body>" + "a" * 300_000 + "</body></html>")})
    page = common.load_page(
        real_ctx(srv.url, Settings(http_timeout=5.0, http_max_bytes=50_000)), srv.url
    )
    assert page is not None
    assert page.final.truncated and len(page.final.body) == 50_000


def test_resposta_nao_html_nao_vira_documento(serve):
    srv = serve({"/": Route(200, '{"ok": true}', content_type="application/json")})
    ctx = real_ctx(srv.url)
    page = common.load_page(ctx, srv.url)
    assert page is not None and not page.html
    assert common.page_doc(ctx, page) is None


def test_bytes_invalidos_e_charset_desconhecido_nao_derrubam(serve):
    body = b"<html><head><title>T\xff\xfe</title></head><body>\x80\x81 ok</body></html>"
    srv = serve(
        {
            "/": Route(200, body, content_type="text/html; charset=utf-8"),
            "/x": Route(200, body, content_type="text/html; charset=nao-existe"),
        }
    )
    for url in (srv.url, srv.url + "x"):
        ctx = real_ctx(url)
        page = common.load_page(ctx, url)
        assert page is not None
        doc = common.page_doc(ctx, page)
        assert doc is not None and "ok" in page.final.text


def test_sem_resposta_devolve_none_sem_excecao():
    scan, _ = fake_scan(lambda m, url, h: None)
    ctx = check_context(scan, SITE)
    assert common.load_page(ctx, SITE) is None
    assert common.baseline(ctx, SITE) is None
    out = run_check("web.headers", http_fact(SITE), scan=scan)
    assert out.findings == [] and any("não respondeu" in line for line in out.logs)


def test_pagina_buscada_uma_vez_por_auditoria():
    scan, fake = fake_scan(lambda m, url, h: response(url, 200, page_html()))
    for check_id in ("web.headers", "web.cookies", "web.fingerprint"):
        run_in(scan, check_id, SITE)
    assert fake.urls().count(SITE) == 1


def test_contraparte_https_so_para_http_na_porta_80():
    scan, fake = fake_scan(lambda m, url, h: response(url, 200, page_html()))
    ctx = check_context(scan, "http://loja.exemplo.test:8080/")
    page = common.load_page(ctx, "http://loja.exemplo.test:8080/")
    assert page is not None and not common.has_https_counterpart(ctx, page)
    plain = common.load_page(ctx, "http://loja.exemplo.test/")
    assert plain is not None and common.has_https_counterpart(ctx, plain)
    assert "https://loja.exemplo.test/" in fake.urls()


# -- IPv6 -------------------------------------------------------------------------------


@pytest.mark.skipif(not ipv6_available(), reason="sem IPv6 local (::1)")
def test_host_ipv6_vira_url_com_colchetes():
    with ipv6_server(
        {"/": Route(302, "", headers=[("Location", "/inicio")]), "/inicio": Route(200, page_html())}
    ) as srv:
        ctx = real_ctx(srv.url)
        page = common.load_page(ctx, srv.url)
        assert page is not None and page.ok
        assert page.origin == f"http://[::1]:{srv.port}/" and page.host == "::1"
        assert common.https_counterpart_url(page) == "https://[::1]/"
        out = run_check("web.headers", http_fact(srv.url))
        assert "web.csp.ausente" in out.ids()
        assert {f.asset for f in out.findings} == {page.origin}


# -- soft 404 ---------------------------------------------------------------------------


def soft404_ctx(handler):
    scan, fake = fake_scan(handler)
    ctx = check_context(scan, SITE)
    page = common.load_page(ctx, SITE)
    assert page is not None
    return ctx, page, fake


def test_site_que_responde_200_para_tudo_e_soft404():
    ctx, page, _ = soft404_ctx(lambda m, url, h: response(url, 200, page_html()))
    probe = response(SITE + ".env", 200, page_html())
    assert common.is_soft404(ctx, page, "/.env", probe)


def test_pagina_real_diferente_nao_e_soft404():
    def handler(method, url, headers):
        if path_of(url) == "/":
            return response(url, 200, page_html())
        return response(url, 404, "<html><body>Not Found</body></html>")

    ctx, page, _ = soft404_ctx(handler)
    probe = response(
        SITE + ".env", 200, "DB_PASSWORD=abc\nAPP_KEY=base64:xyz\n", content_type="text/plain"
    )
    assert not common.is_soft404(ctx, page, "/.env", probe)


def test_pagina_que_repete_o_caminho_e_soft404():
    def handler(method, url, headers):
        path = path_of(url)
        return response(url, 200, page_html(f"A página {path} não existe ({quote(path)})"))

    ctx, page, _ = soft404_ctx(handler)
    probe = response(
        SITE + "backup.zip", 200, page_html("A página /backup.zip não existe (/backup.zip)")
    )
    assert common.is_soft404(ctx, page, "/backup.zip", probe)


def test_redirecionamento_para_login_e_soft404_mas_outro_destino_nao():
    def handler(method, url, headers):
        path = path_of(url)
        if path in ("/", "/login"):
            return response(url, 200, page_html("login"))
        return response(url, 302, "", [("Location", f"/login?next={quote(path, safe='')}")])

    ctx, page, _ = soft404_ctx(handler)
    same = response(SITE + "admin/", 302, "", [("Location", "/login?next=%2Fadmin%2F")])
    other = response(SITE + "admin/", 302, "", [("Location", "/admin/painel")])
    assert common.is_soft404(ctx, page, "/admin/", same)
    assert not common.is_soft404(ctx, page, "/admin/", other)


def test_corpo_cortado_na_linha_de_base_ainda_casa():
    big = "<html><head><title>Loja</title></head><body>" + "produto " * 30_000 + "</body></html>"

    def handler(method, url, headers):
        if path_of(url) == "/":
            return response(url, 200, "<html><body>home</body></html>")
        return response(url, 200, big)

    ctx, page, _ = soft404_ctx(handler)
    base = common.baseline(ctx, page.origin, "dir")
    assert base is not None and base.truncated  # a linha de base lê só o começo
    probe = response(SITE + "painel/", 200, big)  # sonda lida por inteiro
    assert common.is_soft404(ctx, page, "/painel/", probe)


def test_mesmo_titulo_com_tamanho_muito_diferente_nao_e_soft404():
    def handler(method, url, headers):
        if path_of(url) == "/":
            return response(url, 200, "<html><body>home</body></html>")
        return response(url, 200, page_html("nada aqui"))

    ctx, page, _ = soft404_ctx(handler)
    listing = page_html("".join(f"<a href='/arquivo{i}.pdf'>arquivo {i}</a>" for i in range(400)))
    probe = response(SITE + "arquivos/", 200, listing)
    assert not common.is_soft404(ctx, page, "/arquivos/", probe)


def test_linha_de_base_calculada_uma_vez_por_origem_e_formato():
    ctx, page, fake = soft404_ctx(lambda m, url, h: response(url, 404, "<html>Not Found</html>"))
    others = [check_context(ctx.scan, SITE, "web.cookies") for _ in range(6)]
    threads = [
        threading.Thread(target=common.baseline, args=(other, page.origin, "plain"))
        for other in others
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    common.baseline(ctx, page.origin, "plain")
    common.baseline(ctx, page.origin, "ext:php")
    probes = [url for url in fake.urls() if "/eigan-" in url]
    assert len(probes) == 2
    assert sum(url.endswith(".php") for url in probes) == 1


def test_normalizacao_preserva_letras_e_troca_tokens():
    assert common._normalized(b"banana", "/a") == b"banana"  # eco curto não é removido
    token = secrets.token_urlsafe(32).encode()
    assert common._normalized(b"id: " + token + b" t=1712", "/") == b"id: T t=0"


def test_reivindicacao_so_vale_uma_vez():
    scan, _ = fake_scan(lambda m, url, h: None)
    first, second = check_context(scan, SITE), check_context(scan, SITE, "web.methods")
    assert common.claim(first, "web.methods:x")
    assert not common.claim(second, "web.methods:x")


@pytest.mark.parametrize(
    ("host", "site"),
    [
        ("www.exemplo.com.br", "exemplo.com.br"),
        ("api.exemplo.com", "exemplo.com"),
        ("192.168.0.10", "192.168.0.10"),
        ("[::1]", "::1"),
    ],
)
def test_site_of(host, site):
    assert common.site_of(host) == site


# -- robustez contra respostas hostis --------------------------------------------------------


@pytest.mark.parametrize("charset", ["undefined", "idna", "nao-existe", "base64"])
def test_charset_hostil_nao_derruba_as_checagens(serve, charset):
    srv = serve(
        {"/": Route(200, b"<html><body>caf\xc3\xa9</body></html>", content_type=f"text/html; charset={charset}")},
        default=Route(404, b"<html>Not Found</html>", content_type=f"text/html; charset={charset}"),
    )  # fmt: skip
    ctx = real_ctx(srv.url)
    page = common.load_page(ctx, srv.url)
    assert page is not None and "café" in page.final.text
    assert common.page_doc(ctx, page) is not None
    for check_id in ("web.fingerprint", "web.headers", "web.cookies", "web.cors", "web.methods"):
        run_check(check_id, http_fact(srv.url))


def test_charset_com_byte_nulo_nao_derruba():
    scan, _ = fake_scan(
        lambda m, url, h: response(
            url, 200, b"<html>ok</html>", content_type="text/html; charset=a\x00b"
        )
    )
    ctx = check_context(scan, SITE)
    page = common.load_page(ctx, SITE)
    assert page is not None and page.html and "ok" in page.final.text
    base = common.baseline(ctx, page.origin)
    assert base is not None and "ok" in base.text
    probe = response(SITE + "x", 200, b"<html>ok</html>", content_type="text/html; charset=a\x00b")
    assert common.is_soft404(ctx, page, "/x", probe)


def test_location_com_acento_e_espaco_e_seguido(serve):
    # O servidor manda UTF-8 cru: o http.client entrega esses bytes como latin-1.
    raw = "/página nova".encode().decode("latin-1")
    srv = serve(
        {
            "/": Route(302, "", headers=[("Location", raw)]),
            "/p%C3%A1gina%20nova": Route(200, page_html()),
        }
    )
    page = common.load_page(real_ctx(srv.url), srv.url)
    assert page is not None and page.ok and len(page.chain) == 2
    assert srv.requests[-1].path == "/p%C3%A1gina%20nova"


def test_location_ja_codificado_nao_e_codificado_de_novo():
    resp = response(SITE, 302, "", [("Location", "/a%20b?x=1&y=%C3%A9#topo")])
    assert common.safe_location(resp) == "https://loja.exemplo.test/a%20b?x=1&y=%C3%A9#topo"


def test_safe_location_sem_location():
    assert common.safe_location(response(SITE)) is None


@pytest.mark.parametrize("url", ["http://127.0.0.1:9/pagína", "http://127.0.0.1:99999/"])
def test_endereco_invalido_no_fato_nao_derruba(url):
    ctx = real_ctx(SITE)
    assert common.load_page(ctx, url) is None
    assert common.safe_get(ctx, url, 1024) is None


def test_script_com_acento_no_endereco(serve):
    srv = serve(
        {
            "/js/a%C3%A7%C3%BAcar.js": Route(200, "var a = 1;", content_type="text/javascript"),
            "/erro.js": Route(500, "falhou", content_type="text/javascript"),
            "/pagina.js": Route(200, "<!doctype html><html></html>", content_type="text/html"),
        }
    )
    ctx = real_ctx(srv.url)
    found = common.fetch_script(ctx, srv.url + "js/açúcar.js")
    assert found is not None and found.text == "var a = 1;"
    assert common.fetch_script(ctx, srv.url + "erro.js") is None
    assert common.fetch_script(ctx, srv.url + "pagina.js") is None


def test_tamanho_parecido_com_conteudo_diferente_nao_e_soft404():
    """Um ``.env`` pequeno não pode sumir só por ter o tamanho do "Not found" do site."""

    def handler(method, url, headers):
        if path_of(url) == "/":
            return response(url, 200, page_html())
        return response(url, 200, "Not found", content_type="text/plain")

    ctx, page, _ = soft404_ctx(handler)
    probe = response(SITE + ".env", 200, "DB_PASSWORD=abc\n", content_type="text/plain")
    assert not common.is_soft404(ctx, page, "/.env", probe)


def test_conteudo_que_so_troca_de_ordem_e_soft404():
    def handler(method, url, headers):
        if path_of(url) == "/":
            return response(url, 200, page_html())
        words = ["alfa", "beta", "gama", "delta"]
        secrets.SystemRandom().shuffle(words)
        return response(url, 200, " ".join(words), content_type="text/plain")

    ctx, page, _ = soft404_ctx(handler)
    probe = response(SITE + "x", 200, "delta gama beta alfa", content_type="text/plain")
    assert common.is_soft404(ctx, page, "/x", probe)


def test_home_devolvida_em_qualquer_caminho_e_soft404():
    """O caminho aleatório dá 404, mas a sonda devolve a própria home (roteamento parcial)."""
    body = page_html()

    def handler(method, url, headers):
        return response(url, 200 if path_of(url) == "/" else 404, body)

    ctx, page, _ = soft404_ctx(handler)
    assert common.is_soft404(ctx, page, "/admin", response(SITE + "admin", 200, body))


def test_requisicao_cancelada_nao_vira_achado():
    scan, _ = fake_scan(lambda m, url, h: None)
    scan.cancel.set()
    ctx = check_context(scan, SITE)
    assert ctx.cancelled and common.load_page(ctx, SITE) is None


def test_laco_em_paralelo_devolve_so_os_resultados():
    scan, _ = fake_scan(lambda m, url, h: None)
    ctx = check_context(scan, SITE)
    assert sorted(common.run_parallel(ctx, [1, 2, 3], lambda n: n * 2 if n != 2 else None)) == [
        2,
        6,
    ]
    assert common.run_parallel(ctx, [], lambda n: n) == []


@pytest.mark.parametrize(("profile", "level"), [("rapido", 0), ("padrao", 1), ("completo", 2)])
def test_nivel_do_perfil(profile, level):
    assert common.profile_level(real_ctx(SITE, Settings(profile=profile))) == level


def test_dicas_de_tecnologia_incluem_equivalentes():
    assert common.with_aliases(["openresty", "laravel", "php"]) == [
        "openresty",
        "nginx",
        "laravel",
        "php",
    ]


@pytest.mark.parametrize(
    ("path", "shape"),
    [("/admin/", "dir"), ("/.env", "dot"), ("/a/b.PHP", "ext:php"), ("/admin", "plain")],
)
def test_formato_do_caminho(path, shape):
    assert common.shape_of(path) == shape


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("<!DOCTYPE html><html></html>", True),
        ("  <!-- comentário --> <html>", True),
        ("<title>Erro</title>", True),
        ("DB_PASSWORD=abc", False),
        ('{"a": 1}', False),
        ("<?xml version='1.0'?>", False),
    ],
)
def test_parece_html(text, expected):
    assert common.looks_html(text) is expected


# -- web.transport: Location malformado e redirecionamento 303 ----------------------------------


def test_transport_com_location_malformado_em_http():
    def handler(method, url, headers):
        if url.startswith("http://"):
            return response(url, 302, "", [("Location", "http://[::1")])
        return response(url, 200, page_html())

    scan, _ = fake_scan(handler)
    out = run_check("web.transport", http_fact("http://loja.exemplo.test/"), scan=scan)
    [finding] = out.by_id("web.https.sem_redirecionamento")
    assert "sem redirecionar" in finding.evidence


def test_transport_com_location_malformado_no_meio_da_cadeia(serve):
    srv = serve(
        {
            "/": Route(302, "", headers=[("Location", "/a")]),
            "/a": Route(302, "", headers=[("Location", "http://[::1")]),
        },
        tls=True,
    )
    out = run_check("web.transport", http_fact(srv.url))
    assert "web.hsts.ausente" in out.ids()


def test_transport_com_location_malformado_em_https(serve):
    srv = serve({"/": Route(302, "", headers=[("Location", "http://[::1")])}, tls=True)
    out = run_check("web.transport", http_fact(srv.url))
    assert "web.hsts.ausente" in out.ids()


def test_transport_aceita_303_para_https():
    def handler(method, url, headers):
        if url.startswith("http://"):
            return response(url, 303, "", [("Location", "https://loja.exemplo.test/")])
        return response(url, 200, page_html())

    scan, _ = fake_scan(handler)
    out = run_check("web.transport", http_fact("http://loja.exemplo.test/"), scan=scan)
    assert "web.https.sem_redirecionamento" not in out.ids()
    assert any(item.control == "web.https.forcado" for item in out.passed)


# -- texto hostil: tempo de execução e tamanho da evidência --------------------------------------


def test_comentarios_repetidos_nao_travam_a_deteccao_de_html():
    """A regex antiga dobrava de tempo a cada comentário: 2 KiB bastariam para travar."""
    assert common.looks_html("<!---->" * 290 + "<html>") is True
    assert common.looks_html("<!---->" * 290 + "x") is False
    assert common.looks_html("<!-- sem fim") is False


def test_titulo_com_tags_repetidas_e_linear():
    assert common._title_of("<title>" * 9000, "/x") == ""
    assert common._title_of("<TITLE lang='pt'> Loja /xyz-123 </TITLE>", "/xyz-123") == "loja"
    assert common._title_of("sem titulo", "/x") == ""
    assert common._title_of("<title>sem fim", "/x") == ""
    assert common._title_of("<title", "/x") == ""


def test_valores_enormes_de_cabecalho_nao_viram_evidencia_enorme(serve):
    huge = "a." * 20_000
    srv = serve(
        {
            "/": Route(
                200,
                page_html(),
                headers=[
                    ("Server", f"nginx/1.18.0 {huge}"),
                    ("X-Powered-By", huge),
                    ("X-Frame-Options", huge),
                    ("X-Content-Type-Options", huge),
                    ("Referrer-Policy", huge),
                    ("Cross-Origin-Opener-Policy", huge),
                    ("X-XSS-Protection", f"1 {huge}"),
                    ("Set-Cookie", f"sid=1; Path=/{huge}"),
                    ("Set-Cookie", f"{huge}=1"),
                    ("Access-Control-Allow-Origin", huge),
                    ("Allow", huge),
                    ("DAV", huge),
                ],
            )
        }
    )
    for check_id in ("web.fingerprint", "web.headers", "web.cookies", "web.cors", "web.methods"):
        out = run_check(check_id, http_fact(srv.url))
        assert all(len(found.evidence) < 2_000 for found in out.findings), check_id
        for fact in out.facts:
            assert len(str(fact.data)) < 2_000, check_id


def test_short_so_corta_o_que_passa_do_limite():
    assert common.short("abc") == "abc"
    assert common.short("a" * 201) == "a" * 200 + "…"
    assert common.short("abcd", 2) == "ab…"


def test_location_ipv6_e_query_ficam_intactos():
    resp = response("http://[::1]:8080/", 302, "", [("Location", "http://[::1]:8080/x?a=[1]")])
    assert common.safe_location(resp) == "http://[::1]:8080/x?a=[1]"


# -- regressões da revisão ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "host,site",
    [
        ("www.silva.adv.br", "silva.adv.br"),
        ("www.joao.eti.br", "joao.eti.br"),
        ("x.clinica.med.br", "clinica.med.br"),
        ("www.exemplo.com.br", "exemplo.com.br"),
        ("www.exemplo.co.uk", "exemplo.co.uk"),
    ],
)
def test_site_of_categorias_br(host, site):
    from eigan.checks.web.common import site_of

    assert site_of(host) == site
