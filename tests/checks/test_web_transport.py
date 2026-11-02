from helpers import Route, http_fact, run_check


def test_https_sem_hsts_e_http_sem_redirecionar(serve):
    srv = serve({"/": Route(200, "<html>ok</html>")}, tls=True)
    out = run_check("web.transport", http_fact(srv.url))
    assert "web.hsts.ausente" in out.ids()


def test_hsts_valido_vira_ponto_forte(serve):
    srv = serve(
        {
            "/": Route(
                200,
                "<html>ok</html>",
                headers=[("Strict-Transport-Security", "max-age=31536000; includeSubDomains")],
            )
        },
        tls=True,
    )
    out = run_check("web.transport", http_fact(srv.url))
    assert "web.hsts.ausente" not in out.ids()
    assert "web.hsts.fraco" not in out.ids()
    assert any(p.control == "web.hsts" for p in out.passed)


def test_hsts_curto(serve):
    srv = serve(
        {"/": Route(200, "ok", headers=[("Strict-Transport-Security", "max-age=3600")])}, tls=True
    )
    out = run_check("web.transport", http_fact(srv.url))
    [finding] = out.by_id("web.hsts.fraco")
    assert finding.details["max_age"] == 3600


def test_site_so_http_sem_https(serve):
    srv = serve({"/": Route(200, "<html>ok</html>")})
    out = run_check("web.transport", http_fact(srv.url))
    # A porta 443 de 127.0.0.1 não tem HTTPS neste teste.
    assert "web.https.ausente" in out.ids()


def test_hsts_em_alvo_por_ip_e_tentativo_e_baixo(serve):
    from eigan.core.models import Confidence, Severity

    srv = serve({"/": Route(200, "<html>ok</html>")}, tls=True)
    out = run_check("web.transport", http_fact(srv.url))
    [finding] = out.by_id("web.hsts.ausente")
    assert finding.confidence == Confidence.TENTATIVE
    assert finding.severity == Severity.LOW


def test_hsts_com_max_age_gigante_nao_quebra(serve):
    srv = serve(
        {"/": Route(200, "ok", headers=[("Strict-Transport-Security", "max-age=" + "9" * 5000)])},
        tls=True,
    )
    out = run_check("web.transport", http_fact(srv.url))
    assert "web.hsts.fraco" not in out.ids()
