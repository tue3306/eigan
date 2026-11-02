"""Leitura tolerante de HTML (``htmlscan``)."""

from __future__ import annotations

from eigan.checks.web.htmlscan import parse_html

URL = "https://loja.exemplo.test/pagina/"


def test_scripts_externos_e_embutidos():
    doc = parse_html(
        '<script src="/a.js"></script><script src="//cdn.outro.test/b.js" integrity="x"></script>'
        "<script>var k = 1;</script><script src='data:text/javascript,1'></script>",
        URL,
    )
    assert doc.script_urls() == ["https://loja.exemplo.test/a.js", "https://cdn.outro.test/b.js"]
    assert doc.inline_scripts() == ["var k = 1;"]
    assert doc.scripts[1].attrs["integrity"] == "x"


def test_noscript_e_template_sao_inertes():
    doc = parse_html(
        '<noscript><img src="http://px.test/a.gif"><script src="/n.js"></script></noscript>'
        '<template><iframe src="http://t.test/"></iframe></template><img src="/ok.png">',
        URL,
    )
    assert doc.script_urls() == []
    assert [url for _, url in doc.resources()] == ["https://loja.exemplo.test/ok.png"]


def test_tag_base_muda_a_resolucao():
    doc = parse_html(
        '<base href="https://static.exemplo.test/x/"><script src="a.js"></script>', URL
    )
    assert doc.script_urls() == ["https://static.exemplo.test/x/a.js"]


def test_formularios_campos_e_acao():
    doc = parse_html(
        '<form method="post" action="/login"><input name="u"><input type="PASSWORD" name="s">'
        '<input type="hidden" name="csrf" value="v"></form>'
        '<form action="javascript:enviar()"><input type="password"></form>'
        '<input type="password" name="solta">',
        URL,
    )
    login, scripted = doc.forms
    assert login.method == "POST" and login.action == "https://loja.exemplo.test/login"
    assert login.has_password and login.hidden_names() == ["csrf"]
    assert scripted.scripted
    assert doc.has_orphan_password()


def test_form_sem_action_usa_a_propria_pagina_e_metodo_padrao_get():
    [form] = parse_html("<form><input name='q'></form>", URL).forms
    assert form.action == URL and form.method == "GET"


def test_metas_titulo_e_links():
    doc = parse_html(
        "<title> Minha\n Loja </title><meta name='Generator' content='WordPress 6.5'>"
        "<meta http-equiv='Content-Security-Policy' content='upgrade-insecure-requests'>"
        "<a href='/x'>x</a><a href='#topo'>t</a><a href='mailto:a@b.c'>m</a><a href='/x'>y</a>",
        URL,
    )
    assert doc.title == "Minha Loja"
    assert doc.meta_values("generator") == ["WordPress 6.5"]
    assert doc.http_equiv("content-security-policy") == ["upgrade-insecure-requests"]
    assert doc.links() == ["https://loja.exemplo.test/x"]


def test_srcset_e_enderecos_quebrados_nao_levantam():
    doc = parse_html(
        '<img srcset="a.png 1x, http://b.test/b.png 2x"><a href="http://[::1">x</a>', URL
    )
    assert doc.srcset("a.png 1x, http://b.test/b.png 2x") == [
        "https://loja.exemplo.test/pagina/a.png",
        "http://b.test/b.png",
    ]
    assert doc.links() == []


def test_html_malformado_devolve_o_que_entendeu():
    doc = parse_html("<html><script src=/a.js><form><input type=password><<<>>> <div", URL)
    assert doc.script_urls() == ["https://loja.exemplo.test/a.js"]
    assert parse_html("", URL).scripts == []


def test_formulario_em_template_e_marcado_como_inerte():
    doc = parse_html(
        '<template><form method="post"><input type="password"></form><input type="password"></template>'
        '<form method="post"><input type="password"></form>',
        URL,
    )
    assert [f.inert for f in doc.forms] == [True, False]
    assert not doc.has_orphan_password()


def test_milhares_de_urls_distintas_sao_limitadas_e_rapidas():
    import time

    from eigan.checks.web import htmlscan

    html = "".join(f'<script src="/s{n}.js"></script><a href="/p{n}">x</a>' for n in range(30_000))
    inicio = time.monotonic()
    doc = parse_html(html, URL)
    assert len(doc.script_urls()) == htmlscan.MAX_URLS
    assert len(doc.links()) == htmlscan.MAX_URLS
    assert time.monotonic() - inicio < 10
