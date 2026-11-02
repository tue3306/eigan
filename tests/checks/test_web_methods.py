"""Métodos HTTP aceitos (``web.methods``)."""

from __future__ import annotations

import pytest
from fakes_web import fake_scan, response, run_in
from helpers import Route, http_fact, run_check

from eigan.checks.web.methods import allowed_methods, is_trace_echo
from eigan.core.models import Confidence, Severity

HOME = "<html><body>olá</body></html>"
SITE = "https://loja.exemplo.test/"


def trace_echo(request) -> str:
    """Eco fiel de um TRACE (RFC 9110): a requisição recebida, em ``message/http``."""
    lines = [f"TRACE {request.path} HTTP/1.1"]
    lines += [f"{name}: {value}" for name, value in request.headers.items()]
    return "\r\n".join(lines) + "\r\n\r\n"


def method_server(serve, *, options=(), trace=None, status_options=200):
    """Servidor com a home normal e as respostas dadas para OPTIONS e TRACE."""

    def handler(request):
        if request.command == "OPTIONS":
            return Route(status_options, "", headers=list(options))
        if request.command == "TRACE":
            return trace(request) if trace else Route(405, "Method Not Allowed")
        return Route(200, HOME)

    return serve({"/": handler})


def audit(serve, **kwargs):
    srv = method_server(serve, **kwargs)
    return srv, run_check("web.methods", http_fact(srv.url))


def echoed(request) -> Route:
    return Route(200, trace_echo(request), content_type="message/http")


def controls(out) -> set[str]:
    return {item.control for item in out.passed}


# -- TRACE -----------------------------------------------------------------------------------


def test_trace_que_ecoa_a_requisicao_e_confirmado(serve):
    _, out = audit(serve, trace=echoed)
    [finding] = out.by_id("web.metodos.trace")
    assert finding.severity is Severity.LOW
    assert finding.confidence is Confidence.CONFIRMED
    assert "HTTP 200" in finding.evidence
    assert "web.metodos.trace" not in controls(out)


def test_eco_sem_o_tipo_message_http_tambem_conta(serve):
    _, out = audit(serve, trace=lambda r: Route(200, trace_echo(r), content_type="text/plain"))
    assert "web.metodos.trace" in out.ids()


@pytest.mark.parametrize("status", [405, 501])
def test_trace_recusado_vira_ponto_forte(serve, status):
    _, out = audit(serve, trace=lambda r: Route(status, "não"))
    assert "web.metodos.trace" not in out.ids()
    assert "web.metodos.trace" in controls(out)


def test_pagina_que_repete_cabecalhos_nao_e_trace(serve):
    """200 para qualquer método com os cabeçalhos no HTML não é o eco do TRACE."""

    def page(request):
        listed = "".join(f"<li>{k}: {v}</li>" for k, v in request.headers.items())
        return Route(200, f"<html><body><ul>{listed}</ul></body></html>")

    _, out = audit(serve, trace=page)
    assert "web.metodos.trace" not in out.ids()
    assert "web.metodos.trace" not in controls(out)


def test_site_que_responde_200_para_tudo_nao_tem_trace(serve):
    srv = serve({}, default=Route(200, HOME))
    out = run_check("web.methods", http_fact(srv.url))
    assert out.findings == []
    assert "web.metodos.trace" not in controls(out)


def test_message_http_sem_o_cabecalho_de_teste_nao_conta(serve):
    _, out = audit(
        serve, trace=lambda r: Route(200, "TRACE / HTTP/1.1\r\n\r\n", content_type="message/http")
    )
    assert "web.metodos.trace" not in out.ids()


@pytest.mark.parametrize(
    ("status", "body", "content_type", "expected"),
    [
        (200, "TRACE / HTTP/1.1\r\nX-Eigan-Trace: t0k3n\r\n\r\n", "message/http", True),
        (200, "  trace / HTTP/1.1\r\nX-Eigan-Trace: t0k3n\r\n", "text/plain", True),
        (200, "X-Eigan-Trace: t0k3n\r\n", "message/http", True),
        (200, "<html>t0k3n</html>", "text/html", False),
        (200, "TRACE / HTTP/1.1\r\n", "message/http", False),
        (405, "TRACE / HTTP/1.1\r\nX-Eigan-Trace: t0k3n\r\n", "message/http", False),
    ],
)
def test_eco_do_trace(status, body, content_type, expected):
    resp = response(SITE, status, body, content_type=content_type)
    assert is_trace_echo(resp, "t0k3n") is expected


# -- OPTIONS: WebDAV ----------------------------------------------------------------------------


def test_metodos_webdav_no_allow(serve):
    allow = "OPTIONS, GET, HEAD, POST, PROPFIND, MKCOL, COPY, MOVE"
    _, out = audit(serve, options=[("Allow", allow)])
    [finding] = out.by_id("web.metodos.webdav")
    assert finding.severity is Severity.MEDIUM
    assert finding.confidence is Confidence.TENTATIVE
    assert "PROPFIND" in finding.details["metodos"]
    assert "web.metodos" not in controls(out)


def test_cabecalho_public_do_iis(serve):
    _, out = audit(serve, options=[("Public", "OPTIONS, TRACE, GET, HEAD, POST, PROPFIND, LOCK")])
    assert "web.metodos.webdav" in out.ids()


def test_cabecalho_dav_sem_allow(serve):
    _, out = audit(serve, options=[("DAV", "1,2")])
    [finding] = out.by_id("web.metodos.webdav")
    assert finding.details["dav"] == "1,2" and "DAV: 1,2" in finding.evidence


def test_webdav_nao_esconde_put_e_delete(serve):
    _, out = audit(serve, options=[("Allow", "GET, PUT, DELETE, PROPFIND")])
    assert "web.metodos.webdav" in out.ids()
    assert "web.metodos.perigosos" in out.ids()


# -- OPTIONS: PUT e DELETE ------------------------------------------------------------------------


@pytest.mark.parametrize("allow", ["GET, HEAD, PUT", "GET, DELETE", "get, put, delete"])
def test_put_delete_anunciados_sao_indicio(serve, allow):
    _, out = audit(serve, options=[("Allow", allow)])
    [finding] = out.by_id("web.metodos.perigosos")
    assert finding.severity is Severity.LOW
    assert finding.confidence is Confidence.TENTATIVE
    assert {"PUT", "DELETE"} & set(finding.details["metodos"])
    assert "OPTIONS" in finding.evidence


def test_put_delete_nunca_sao_enviados(serve):
    srv, _ = audit(serve, options=[("Allow", "GET, PUT, DELETE, PROPFIND, PATCH")], trace=echoed)
    assert {r.method for r in srv.requests} == {"GET", "OPTIONS", "TRACE"}


def test_allow_seguro_vira_ponto_forte(serve):
    _, out = audit(serve, options=[("Allow", "GET, HEAD, POST, OPTIONS")])
    assert not {"web.metodos.webdav", "web.metodos.perigosos"} & out.ids()
    [item] = [p for p in out.passed if p.control == "web.metodos"]
    assert "GET, HEAD, OPTIONS, POST" in item.text


def test_trace_anunciado_mas_recusado_nao_e_achado(serve):
    """O IIS lista TRACE no Allow e responde 501: vale o teste, não o anúncio."""
    _, out = audit(
        serve,
        options=[("Allow", "OPTIONS, TRACE, GET, HEAD, POST")],
        trace=lambda r: Route(501, "Not Implemented"),
    )
    assert out.findings == []


def test_405_com_allow_e_lido(serve):
    _, out = audit(serve, options=[("Allow", "GET, PUT")], status_options=405)
    assert "web.metodos.perigosos" in out.ids()


def test_cabecalho_de_preflight_nao_conta_como_metodo_aceito(serve):
    _, out = audit(serve, options=[("Access-Control-Allow-Methods", "GET, PUT, DELETE, PROPFIND")])
    assert not {"web.metodos.webdav", "web.metodos.perigosos"} & out.ids()
    assert "web.metodos" not in controls(out)


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ([("Allow", "GET, HEAD"), ("Public", "PUT")], {"GET", "HEAD", "PUT"}),
        ([("Allow", " get ,, post ")], {"GET", "POST"}),
        ([("Allow", "GET"), ("Allow", "POST")], {"GET", "POST"}),
        ([], set()),
    ],
)
def test_leitura_dos_metodos(headers, expected):
    assert allowed_methods(response(SITE, headers=headers)) == expected


# -- fluxo ---------------------------------------------------------------------------------------


def test_um_unico_trace_por_origem():
    def handler(method, url, headers):
        if method == "TRACE":
            return response(url, 405, "não")
        return response(url, 200, HOME, [("Allow", "GET, HEAD")])

    scan, fake = fake_scan(handler)
    run_in(scan, "web.methods", SITE)
    run_in(scan, "web.methods", SITE + "outra-pagina")
    assert fake.methods().count("TRACE") == 1
    assert fake.methods().count("OPTIONS") == 1


def test_redirecionamento_para_fora_nao_e_avaliado(serve):
    srv = serve({"/": Route(301, "", headers=[("Location", "https://outro.exemplo.test/")])})
    out = run_check("web.methods", http_fact(srv.url))
    assert out.findings == [] and out.passed == []
    assert [r.method for r in srv.requests] == ["GET"]


def test_avalia_o_destino_do_redirecionamento_interno(serve):
    def inicio(request):
        if request.command == "OPTIONS":
            return Route(200, "", headers=[("Allow", "GET, PUT")])
        return Route(200, HOME)

    srv = serve({"/": Route(302, "", headers=[("Location", "/inicio")]), "/inicio": inicio})
    out = run_check("web.methods", http_fact(srv.url))
    [finding] = out.by_id("web.metodos.perigosos")
    assert finding.asset == srv.url and "/inicio" in finding.evidence


def test_http_com_contraparte_https_fica_para_o_https():
    scan, fake = fake_scan(lambda m, url, h: response(url, 200, HOME, [("Allow", "GET, PUT")]))
    out = run_check("web.methods", http_fact("http://loja.exemplo.test/"), scan=scan)
    assert out.findings == []
    assert "TRACE" not in fake.methods() and "OPTIONS" not in fake.methods()


def test_sem_resposta_nao_gera_achado():
    scan, _ = fake_scan(lambda m, url, h: None)
    out = run_check("web.methods", http_fact(SITE), scan=scan)
    assert out.findings == [] and out.passed == []
    assert any("não respondeu" in line for line in out.logs)


def test_options_e_trace_sem_resposta_nao_viram_ponto_forte():
    scan, _ = fake_scan(lambda m, url, h: response(url, 200, HOME) if m == "GET" else None)
    out = run_check("web.methods", http_fact(SITE), scan=scan)
    assert out.findings == [] and out.passed == []


def test_exemplo_de_correcao_acompanha_a_tecnologia(serve):
    def handler(request):
        if request.command == "OPTIONS":
            return Route(200, "", headers=[("Allow", "GET, PUT")])
        return Route(200, HOME, headers=[("Server", "Apache")])

    srv = serve({"/": handler})
    out = run_check("web.methods", http_fact(srv.url))
    assert "apache" in out.by_id("web.metodos.perigosos")[0].tech


# -- regressões da revisão ---------------------------------------------------------------------


def test_search_sozinho_nao_e_webdav(serve):
    _, out = audit(serve, options=[("Allow", "GET, HEAD, OPTIONS, SEARCH")])
    assert not out.by_id("web.metodos.webdav")


def test_webdav_e_put_sao_reportados_juntos(serve):
    _, out = audit(serve, options=[("Allow", "GET, PROPFIND, MKCOL, PUT")])
    assert out.by_id("web.metodos.webdav")
    assert out.by_id("web.metodos.perigosos")


def test_trace_404_nao_e_ponto_forte(serve):
    def handler(request):
        if request.command == "TRACE":
            return Route(404, "nada")
        return Route(200, HOME)

    srv = serve({"/": handler})
    out = run_check("web.methods", http_fact(srv.url))
    assert "web.metodos.trace" not in controls(out)
