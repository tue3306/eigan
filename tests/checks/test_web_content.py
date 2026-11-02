"""Conteúdo das páginas (``web.content``)."""

from __future__ import annotations

import random
import time

from fakes_web_content import audit, ids

from eigan.checks.web import content
from eigan.core.models import Confidence, Severity
from eigan.core.settings import Settings

CHECK = "web.content"
AWS = "AKIA" + "QWERTY2345672345"
STRIPE = "sk_" + "live_" + "abcdefghijklmnopqrstuvwx12"
GITHUB = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
GOOGLE = "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"
SLACK_HOOK = (
    "https://hooks.slack.com/services/" + "T01ABCDEF2G/B01ABCDEF2G/abcdEFGHijklMNOPqrst1234"
)


def page(body: str, head: str = "") -> str:
    return f"<!doctype html><html><head><title>Loja</title>{head}</head><body>{body}</body></html>"


def run(body: str, head: str = "", **kw):
    return audit(CHECK, {"/": page(body, head)}, **kw)


# -- conteúdo misto ---------------------------------------------------------------------------


def test_misto_ativo_e_passivo():
    out = run(
        '<script src="http://cdn.outro.test/a.js"></script>'
        '<link rel="stylesheet" href="http://x.test/s.css">'
        '<img src="http://img.exemplo.test/f.png">'
    )
    [ativo] = [f for f in out if f.check_id == "web.conteudo.misto_ativo"]
    assert "http://cdn.outro.test/a.js" in ativo.evidence and "s.css" in ativo.evidence
    assert "web.conteudo.misto_passivo" in ids(out)


def test_misto_upgrade_insecure_requests_nao_reporta():
    out = run(
        '<img src="http://img.exemplo.test/f.png"><script src="http://x.test/a.js"></script>',
        head='<meta http-equiv="Content-Security-Policy" content="upgrade-insecure-requests">',
    )
    assert not ids(out) & {"web.conteudo.misto_ativo", "web.conteudo.misto_passivo"}


def test_misto_ignora_noscript_links_e_recursos_https():
    out = run(
        '<noscript><img src="http://px.test/p.gif"></noscript><a href="http://outro.test/">link</a>'
        '<link rel="icon" href="http://x.test/i.ico"><img src="https://ok.test/a.png">'
    )
    assert not ids(out) & {"web.conteudo.misto_ativo", "web.conteudo.misto_passivo"}


def test_misto_em_pagina_http_nao_se_aplica():
    out = audit(
        CHECK,
        {"/": page('<script src="http://cdn.outro.test/a.js"></script>')},
        base="http://loja.exemplo.test",
    )
    assert "web.conteudo.misto_ativo" not in ids(out)


# -- SRI --------------------------------------------------------------------------------------


def test_sri_ausente_em_script_de_terceiro():
    out = run('<script src="https://cdn.outro.test/lib.js"></script>')
    [f] = [f for f in out if f.check_id == "web.conteudo.sri_ausente"]
    assert "cdn.outro.test/lib.js" in f.evidence and f.severity is Severity.LOW


def test_sri_presente_mesmo_site_e_scripts_dinamicos_nao_reportam():
    out = run(
        '<script src="https://cdn.outro.test/lib.js" integrity="sha384-abc" crossorigin></script>'
        '<script src="https://static.exemplo.test/app.js"></script>'
        '<script src="https://www.googletagmanager.com/gtm.js?id=GTM-1"></script>'
    )
    assert "web.conteudo.sri_ausente" not in ids(out)


# -- formulários ------------------------------------------------------------------------------


def test_senha_em_pagina_http():
    out = audit(
        CHECK,
        {"/": page('<form method="post" action="/login"><input type="password" name="s"></form>')},
        base="http://loja.exemplo.test",
    )
    [f] = [f for f in out if f.check_id == "web.formulario.senha_http"]
    assert f.severity is Severity.HIGH


def test_senha_em_pagina_https_nao_e_senha_http():
    out = run('<form method="post" action="/login"><input type="password" name="s"></form>')
    assert "web.formulario.senha_http" not in ids(out)


def test_envio_para_http_a_partir_de_https():
    out = run(
        '<form method="post" action="http://pagamento.exemplo.test/pagar"><input name="c"></form>'
    )
    assert "web.formulario.envio_http" in ids(out)


def test_formulario_get_de_busca_para_http_ou_destino_https_nao_reporta():
    out = run(
        '<form action="http://busca.exemplo.test/q"><input name="q"></form>'
        '<form method="post" action="https://ok.exemplo.test/x"><input name="a"></form>'
    )
    assert "web.formulario.envio_http" not in ids(out)


def test_sem_csrf_e_tentativo():
    out = run(
        '<form method="post" action="/login"><input name="u"><input type="password" name="s"></form>'
    )
    [f] = [f for f in out if f.check_id == "web.formulario.sem_csrf"]
    assert f.confidence is Confidence.TENTATIVE


def test_com_token_csrf_nao_reporta():
    campo = '<input type="hidden" name="csrfmiddlewaretoken" value="x">'
    meta = '<meta name="csrf-token" content="abc">'
    valor = '<input type="hidden" name="k" value="Zx9Qw8Er7Ty6Ui5Op4As3">'
    casos = (
        (f'<form method="post">{campo}<input type="password" name="s"></form>', ""),
        ('<form method="post"><input type="password" name="s"></form>', meta),
        (f'<form method="post">{valor}<input type="password" name="s"></form>', ""),
        ('<form method="get"><input type="password" name="s"></form>', ""),
        ('<form method="post"><input name="comentario"></form>', ""),
    )
    for corpo, head in casos:
        assert "web.formulario.sem_csrf" not in ids(run(corpo, head))


# -- segredos ---------------------------------------------------------------------------------


def test_segredos_no_html_ficam_mascarados():
    out = run(
        f"<script>var a='{AWS}'; var s='{STRIPE}'; var g='{GITHUB}'; var h='{SLACK_HOOK}';</script>"
    )
    segredos = [f for f in out if f.check_id == "web.conteudo.segredo"]
    assert len(segredos) == 4
    stripe = next(f for f in segredos if "Stripe" in f.title or "stripe" in f.title)
    assert stripe.severity is Severity.CRITICAL
    dump = repr([(f.evidence, f.details, f.title) for f in segredos])
    for full in (AWS, STRIPE, GITHUB, SLACK_HOOK):
        assert full not in dump


def test_segredo_em_script_da_mesma_origem():
    out = audit(CHECK, {"/": page('<script src="/app.js"></script>'), "/app.js": f"var k='{AWS}';"})
    [f] = [f for f in out if f.check_id == "web.conteudo.segredo"]
    assert f.asset.endswith("/app.js")


def test_chave_privada_nao_mostra_o_conteudo():
    corpo = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7" * 3
    out = run(f"<pre>-----BEGIN PRIVATE KEY-----\n{corpo}\n-----END PRIVATE KEY-----</pre>")
    [f] = [f for f in out if f.check_id == "web.conteudo.segredo"]
    assert f.severity is Severity.CRITICAL and "MIIEvQ" not in f.evidence


def test_chave_google_e_baixa():
    out = run(f"<script>var k='{GOOGLE}'</script>")
    [f] = [f for f in out if f.check_id == "web.conteudo.chave_google"]
    assert f.severity is Severity.LOW and GOOGLE not in f.evidence


def test_segredos_falsos_positivos():
    out = run(
        "<p>Exemplo: AKIAIOSFODNN7EXAMPLE, AKIA, sk_live_xxxx, ghp_curto, "
        "-----BEGIN PRIVATE KEY----- (cabeçalho citado em texto), xoxb-token</p>"
        "<p>sk_live_" + "X" * 28 + "</p>"
    )
    assert not ids(out) & {"web.conteudo.segredo", "web.conteudo.chave_google"}


# -- erros verbosos e depuração ---------------------------------------------------------------

PYTHON = (
    '<pre>Traceback (most recent call last):\n  File "/srv/app/views.py", line 42, in index\n'
    "    x = 1/0\nZeroDivisionError: division by zero</pre>"
)
JAVA = (
    "<pre>java.lang.NullPointerException\n\tat com.loja.web.Pedido.total(Pedido.java:88)\n"
    "\tat com.loja.web.Servlet.doGet(Servlet.java:31)\n</pre>"
)
ASPNET = (
    "<html><body><h1>Server Error in '/' Application.</h1><b>Stack Trace:</b>"
    "<pre>[NullReferenceException]</pre></body></html>"
)
PHP = (
    "<br /><b>Warning</b>:  include(x.php): failed to open stream in "
    "<b>/var/www/html/a.php</b> on line <b>7</b><br />"
)
NODE = (
    "<pre>Error: falhou<br> &nbsp; &nbsp;at handler (/app/server.js:10:11)<br>"
    " &nbsp; &nbsp;at next (/app/node_modules/express/lib/router/layer.js:95:5)</pre>"
)
DJANGO = (
    "<html><body>Using the URLconf defined in loja.urls, Django tried these URL patterns. "
    "You're seeing this error because you have DEBUG = True in your Django settings file.</body></html>"
)


def erro(corpo: str, status: int = 500):
    return audit(CHECK, {"/": page("ok")}, fallback=(status, corpo))


def test_erros_verbosos_por_tecnologia():
    for corpo in (PYTHON, JAVA, ASPNET, PHP, NODE):
        out = erro(corpo)
        assert "web.erro.detalhado" in ids(out), corpo[:40]
        assert "web.debug.modo_debug" not in ids(out)


def test_modo_debug_do_framework_e_alto():
    [f] = [f for f in erro(DJANGO, 404) if f.check_id == "web.debug.modo_debug"]
    assert f.severity is Severity.HIGH


def test_soft404_e_pagina_de_erro_comum_nao_geram_achado():
    generica = page("<h1>Ops!</h1><p>Algo deu errado.</p>")
    assert not ids(audit(CHECK, {"/": page("ok")}, fallback=(200, generica)))
    assert not ids(audit(CHECK, {"/": page("ok")}))  # 404 padrão
    assert not ids(erro("<html><body>Traceback é uma palavra comum em blogs.</body></html>"))


def test_werkzeug_console():
    console = (
        "<html><head><title>Console // Werkzeug Debugger</title><script>var CONSOLE_MODE = true,"
        ' EVALEX = true, EVALEX_TRUSTED = false, SECRET = "abc";</script></head>'
        "<body><h1>Interactive Console</h1></body></html>"
    )
    out = audit(CHECK, {"/": page("ok"), "/console": console})
    [f] = [f for f in out if f.check_id == "web.debug.werkzeug"]
    assert f.severity is Severity.HIGH and "PIN" in f.evidence  # com PIN, não é crítico


def test_console_que_e_pagina_generica_nao_e_werkzeug():
    out = audit(CHECK, {"/": page("ok")}, fallback=(200, page("<h1>Console de jogos</h1>")))
    assert "web.debug.werkzeug" not in ids(out)


def test_perfil_completo_examina_links_da_mesma_origem():
    rotas = {
        "/": page('<a href="/login">Entrar</a><a href="/sair">Sair</a>'),
        "/login": page('<form method="post"><input type="password" name="s"></form>'),
        "/sair": page(f"<p>{AWS}</p>"),
    }
    comum = audit(CHECK, rotas)
    completo = audit(CHECK, rotas, settings=Settings(http_timeout=5.0, profile="completo"))
    assert "web.formulario.sem_csrf" not in ids(comum)
    assert "web.formulario.sem_csrf" in ids(completo)
    assert "web.conteudo.segredo" not in ids(completo)  # links de saída não são visitados


# -- regressões da revisão ----------------------------------------------------------------------


def test_werkzeug_sem_pin_e_critico():
    console = (
        "<html><head><title>Console // Werkzeug Debugger</title><script>var CONSOLE_MODE = true,"
        ' EVALEX = true, EVALEX_TRUSTED = true, SECRET = "abc";</script></head>'
        "<body><h1>Interactive Console</h1></body></html>"
    )
    out = audit(CHECK, {"/": page("ok"), "/console": console})
    [f] = [f for f in out if f.check_id == "web.debug.werkzeug"]
    assert f.severity is Severity.CRITICAL


def test_corpo_hostil_nao_trava_a_busca_de_erros():
    inicio = time.monotonic()
    nl = chr(10)
    for corpo in (
        nl * 65_536,
        (nl + " ") * 32_000,
        "(/" * 32_000,
        nl + " at a.b.c(X.java:1)" * 3_000,
    ):
        content.match_error(corpo)
    assert time.monotonic() - inicio < 5


def test_busca_de_segredos_com_milhares_de_chaves_e_rapida():
    sorteio = random.Random(7)
    alfabeto = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    chaves = " ".join(
        "AKIA" + "".join(sorteio.choices(alfabeto, k=16)) + "2" for _ in range(20_000)
    ).replace("2 ", " ")
    inicio = time.monotonic()
    achados = content.find_secrets(chaves)
    assert time.monotonic() - inicio < 5
    assert 0 < len(achados) <= content.MAX_SECRETS


def test_erro_so_vale_com_status_de_erro_ou_tela_de_debug():
    tutorial = page("<h1>Tutorial</h1>" + PYTHON)
    # site que responde 200 a tudo e mostra um traceback de exemplo: não é erro do servidor
    out = audit(CHECK, {"/": tutorial}, fallback=(200, tutorial))
    assert not ids(out) & {"web.erro.detalhado", "web.debug.modo_debug"}


def test_erros_em_json_e_em_portugues():
    import json

    spring = json.dumps(
        {
            "trace": "java.lang.IllegalStateException: x\n\tat com.foo.A.b(A.java:1)\n\tat com.foo.B.c(B.java:2)"
        }
    )
    node = json.dumps(
        {"stack": "Error: x\n    at handler (/app/server.js:10:11)\n    at next (/app/l.js:9:5)"}
    )
    aspnet_pt = (
        "<h1>Erro de Servidor no Aplicativo '/'.</h1><b>Rastreamento de Pilha:</b><pre>x</pre>"
    )
    xdebug = "<table><tr><td>Fatal error: Uncaught x in /var/www/a.php on line <i>7</i></td></tr></table>"
    for corpo in (spring, node, aspnet_pt, xdebug):
        assert content.match_error(corpo) is not None, corpo[:40]


def test_whoops_solto_nao_e_modo_debug_mas_com_laravel_sim():
    amigavel = page("<h1>Whoops! There was an error.</h1><p>Tente de novo mais tarde.</p>")
    assert "web.debug.modo_debug" not in ids(erro(amigavel, 500))
    laravel = amigavel + "<pre>Illuminate\\Database\\QueryException in /var/www/vendor/x.php</pre>"
    assert "web.debug.modo_debug" in ids(erro(laravel, 500))


def test_chave_privada_precisa_de_corpo_e_rodape():
    vazio = run("<pre>-----BEGIN PRIVATE KEY-----" + " " * 100 + "</pre>")
    truncada = run(
        "<pre>-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAy8Dm2...f9...\n"
        "-----END RSA PRIVATE KEY-----</pre>"
    )
    assert "web.conteudo.segredo" not in ids(vazio) | ids(truncada)


def test_aws_so_com_alfabeto_base32_e_isolado_nao_e_alto():
    assert not content.find_secrets("const REGION = 'ASIAPACIFICMARKETING';")
    out = run(f"<script>var a='{AWS}'</script>")
    [f] = [f for f in out if f.check_id == "web.conteudo.segredo"]
    assert f.severity is Severity.MEDIUM and f.confidence is Confidence.TENTATIVE
    segredo = "wJalrXUtnFEMIK7MDENGbPxRfiCYzQ4x9a2B5c8D"
    junto = run(f"<script>var a='{AWS}', aws_secret_access_key='{segredo}'</script>")
    severidades = {f.severity for f in junto if f.check_id == "web.conteudo.segredo"}
    assert Severity.HIGH in severidades and Severity.CRITICAL in severidades


def test_chave_google_terminada_em_hifen_e_stripe_longa():
    google = "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6" + "-"
    assert [r.key for r, _ in content.find_secrets(f'key="{google}";')] == ["google"]
    longa = "sk_" + "live_" + "a1B2c3D4" * 15
    assert [r.key for r, _ in content.find_secrets(longa)] == ["stripe"]


def test_formulario_em_template_e_ignorado():
    out = run(
        '<template><form method="post" action="http://x.test/l">'
        '<input type="password"></form></template>'
    )
    assert not ids(out) & {"web.formulario.envio_http", "web.formulario.sem_csrf"}


def test_campo_oculto_com_palavras_nao_conta_como_token():
    form = (
        '<form method="post"><input type="hidden" name="returnUrl" value="dashboard_overview_page">'
        '<input type="password" name="s"></form>'
    )
    assert "web.formulario.sem_csrf" in ids(run(form))


def test_preload_ativo_e_loopback_falso():
    out = run('<link rel="preload" as="script" href="http://a.test/x.js">')
    assert "web.conteudo.misto_ativo" in ids(out)
    out = run('<img src="http://127.0.0.1.atacante.test/x.png">')
    assert "web.conteudo.misto_passivo" in ids(out)
    assert "web.conteudo.misto_passivo" not in ids(run('<img src="http://127.0.0.1/x.png">'))


def test_url_com_credencial_nao_vaza_no_achado_de_segredo():
    out = audit(
        CHECK,
        {
            "/": page(f'<script src="/app.js?token={GITHUB}"></script>'),
            "/app.js": f"var k='{AWS}';",
        },
    )
    [f] = [f for f in out if f.details.get("regra") == "aws"]
    assert GITHUB not in repr((f.title, f.asset, f.details, f.evidence))
