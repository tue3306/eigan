"""Token em localStorage e credencial literal no JavaScript (``web.content``)."""

from __future__ import annotations

import pytest
from fakes_web import fake_scan, run_in
from fakes_web_content import BASE, audit, ids, site

from eigan.checks.web import jsscan
from eigan.core import facts
from eigan.core.models import Confidence, Severity

CHECK = "web.content"
TOKEN = "web.conteudo.token_localstorage"
CRED = "web.conteudo.credencial_literal"


def page(body: str = "", src: str = "/app.js") -> str:
    tag = f'<script src="{src}"></script>' if src else ""
    return f"<!doctype html><html><head><title>Demo</title></head><body>{body}{tag}</body></html>"


def with_js(js: str, **kw):
    return audit(CHECK, {"/": page(), "/app.js": js}, **kw)


# -- token em storage -------------------------------------------------------------------------


def test_token_em_localstorage_no_script():
    out = with_js('fetch("/api/login").then(d=>localStorage.setItem("token", d.token))')
    [f] = [f for f in out if f.check_id == TOKEN]
    assert f.severity is Severity.LOW and f.confidence is Confidence.TENTATIVE
    assert f.asset.endswith("/app.js") and "localStorage" in f.evidence


def test_token_variantes():
    achados = jsscan.find_stored_tokens(
        'const KEY="authToken"; sessionStorage.setItem(KEY, x); localStorage["sessao"]=s;'
        'localStorage.jwt = t; window.localStorage.setItem("usuario", jwt);'
    )
    assert {(t.storage, t.key) for t in achados} == {
        ("sessionStorage", "authToken"),
        ("localStorage", "sessao"),
        ("localStorage", "jwt"),
        ("localStorage", "usuario"),
    }


def test_token_inline_na_pagina():
    html = page("<script>localStorage.setItem('session_id', sid)</script>", src="")
    assert TOKEN in ids(audit(CHECK, {"/": html}))


def test_token_ignora_preferencias_e_limpeza():
    js = (
        'localStorage.setItem("theme","dark");localStorage.setItem("lang","pt-BR");'
        'localStorage.setItem("cart", JSON.stringify(c));localStorage.setItem("cookie-consent","1");'
        'localStorage.setItem("authorName", n);localStorage.setItem("token","");'
        'localStorage.removeItem("token");sessionStorage.setItem("sidebarOpen","1");'
        'localStorage.setItem("consent_token_banner", "1")'
    )
    assert TOKEN not in ids(with_js(js))


def test_token_de_terceiros_nao_dispara():
    out = audit(
        CHECK,
        {"/": page(src="https://cdn.outro.test/lib.js")},
        fallback=(200, 'localStorage.setItem("token", t)', "application/javascript"),
    )
    assert TOKEN not in ids(out)


# -- credencial literal -----------------------------------------------------------------------


def test_credencial_literal_mascarada():
    out = with_js('const demo={usuario:"admin@loja.test",senha:"teste123"}; ')
    [f] = [f for f in out if f.check_id == CRED]
    assert f.severity is Severity.MEDIUM and f.confidence is Confidence.TENTATIVE
    assert "teste123" not in repr((f.evidence, f.details, f.title))
    assert f.details["par_usuario_senha"] is True


def test_credencial_em_comparacao():
    assert CRED in ids(with_js('if (password === "abc123") { entrar(); }'))


def test_credencial_falsos_positivos_i18n():
    js = (
        'const pt={"login":{"password":"Senha","forgotPassword":"Esqueceu sua senha?",'
        '"passwordRequired":"A senha é obrigatória","confirmPassword":"Confirmar senha",'
        '"passwordPlaceholder":"Digite sua senha","passwordMismatch":"As senhas não conferem"}};'
        'const en={password:"Password",passwordHint:"Use 8 characters or more",'
        'password_label:"Your password"}; const fr={password:"Mot de passe"};'
        'const es={password:"Contraseña"}; const de={password:"Passwort"};'
        'i18n.t("auth.password.label"); t("senha_obrigatoria"); senha:"auth.senha.titulo";'
    )
    assert jsscan.find_literal_credentials(js) == []


def test_credencial_falsos_positivos_formularios():
    js = (
        '{name:"password",type:"password",label:"Senha",placeholder:"Digite sua senha",'
        'autocomplete:"current-password",id:"senha",required:true}; '
        'const f={password:"",senha:"",pwd:null,password:"password",senha:"senha",'
        'passwordField:"password-input",senha:"********",password:"••••••••",'
        'passwordSelector:"#password",password:yup.string().required("Senha obrigatória"),'
        'minPassword:"12345678",senhaIcon:"eye-off"}; '
        'html=\'<input type="password" name="senha" placeholder="Senha" value="">\';'
        "if(a.password!==b.password){}; user.password=hash;"
    )
    assert jsscan.find_literal_credentials(js) == []


def test_credencial_sem_literal_minificado():
    js = 'var a={password:e,senha:t.value,pwd:n,passwd:"",password:"e"};x.password=r(o);'
    assert jsscan.find_literal_credentials(js) == []


def test_credencial_sozinha_e_composta():
    found = jsscan.find_literal_credentials('c={adminPassword:"x9y8z7"}; s.senha="trocar123"')
    assert {c.key for c in found} == {"adminPassword", "senha"}


# -- ponta a ponta contra o site falso ---------------------------------------------------------


def test_fim_a_fim_site_falso_registra_fato_sem_back_end():
    routes = {
        "/": page("<h1>Demo</h1>"),
        "/app.js": 'localStorage.setItem("token", t); const u={usuario:"demo",senha:"demo1234"};',
    }
    scan, _ = fake_scan(site(routes), target=BASE + "/")
    out = run_in(scan, CHECK, BASE + "/")
    assert {TOKEN, CRED} <= ids(out)
    [fato] = scan.facts_of(facts.WEB_FRONTEND)
    assert fato.data["backend"] is False


def test_fato_com_back_end_por_formulario():
    form = '<form method="post" action="/entrar"><input name="u"></form>'
    scan, _ = fake_scan(site({"/": page(form, src="")}), target=BASE + "/")
    run_in(scan, CHECK, BASE + "/")
    [fato] = scan.facts_of(facts.WEB_FRONTEND)
    assert fato.data["backend"] is True and fato.data["sinais"]


# -- lacunas do teste real ---------------------------------------------------------------------


def chaves(js: str) -> set[str]:
    return {t.key for t in jsscan.find_stored_tokens(js)}


def test_token_chave_com_sistema_nao_vira_tema():
    assert chaves('localStorage.setItem("sistema_token", t)') == {"sistema_token"}
    assert chaves('localStorage.setItem("token_sistema", t)') == {"token_sistema"}
    assert chaves('localStorage.setItem("tema_token", t)') == set()  # palavra inteira "tema"


@pytest.mark.parametrize(
    "js",
    [
        'localStorage.setItem("x", csrfToken)',
        'localStorage.setItem("meta", xsrfToken)',
        'localStorage.setItem("nextPage", nextPageToken)',
        'localStorage.setItem("pageToken", t)',
    ],
)
def test_token_ignora_csrf_e_paginacao(js):
    assert chaves(js) == set()


@pytest.mark.parametrize(
    "js",
    [
        'sessionStorage.setItem("sessionExpired","1")',
        'localStorage.setItem("sessionStart", Date.now())',
        '// localStorage.setItem("token", t)',
        '/* localStorage.setItem("token", t) */',
        "var s = \"use localStorage.setItem('token', x) ...\";",
        'var e="token"; function g(e,t){localStorage.setItem(e,t)}',
    ],
)
def test_token_ignora_bandeira_comentario_texto_e_escopo(js):
    assert chaves(js) == set()


def test_token_comentario_nao_esconde_codigo_real():
    js = '// http://x.test\nlocalStorage.setItem("token", t) /* fim */'
    assert chaves(js) == {"token"}


def test_token_segue_apelido_do_storage():
    assert chaves('const s = window.localStorage; s.setItem("token", x)') == {"token"}
    achados = jsscan.find_stored_tokens('var st=sessionStorage;st.authToken=t;st["jwt"]=t')
    assert {(a.storage, a.key) for a in achados} == {
        ("sessionStorage", "authToken"),
        ("sessionStorage", "jwt"),
    }
    assert chaves("const s = localStorage.getItem('a'); s.setItem(x,1)") == set()


def test_token_chave_com_controle_sai_limpa():
    [achado] = jsscan.find_stored_tokens(
        'localStorage.setItem("token\x1b[2J\x1b]0;PWNED\x07<b>", v)'
    )
    assert all(c.isprintable() for c in achado.key)
    assert "\x1b" not in achado.key and "\x07" not in achado.key


@pytest.mark.parametrize(
    "js",
    [
        'if (senha !== "admin123") {}',
        'if (senha != "admin123") {}',
        'if ("admin123" === senha) {}',
        'if ("admin123" != form.senha) {}',
        'document.getElementById("senha").value === "admin123"',
        'password.value == "x1y2z3"',
        'form.senha.value == "teste"',
        '{pass:"secret1"}',
    ],
)
def test_credencial_comparacoes_e_propriedades(js):
    assert len(jsscan.find_literal_credentials(js)) == 1


@pytest.mark.parametrize(
    "js",
    [
        'if ("username" in usernamePasswordInOptions) {}',
        'const ok = "username" in password',
        'password = "abc123" + salt',
        'password = "abc123".trim()',
        'senha = a ? "abc123" : null; x = password("abc123")',
        'password:"required|min:8"',
        'password:"auth/weak-password"',
        'var bypass="abcdef"; var passed="abcdef"',
    ],
)
def test_credencial_ignora_expressao_maior_e_regras(js):
    assert jsscan.find_literal_credentials(js) == []


def test_credencial_custo_linear_em_texto_hostil():
    import time

    for texto in ("-senha" * 250_000, "-password-" * 150_000, "a-" * 750_000 + " senha"):
        inicio = time.perf_counter()
        jsscan.find_literal_credentials(texto)
        assert time.perf_counter() - inicio < 1.5


def test_heuristica_do_js_nao_consome_cota_dos_segredos():
    scripts = "".join(
        "<script>"
        + "".join(f'localStorage.setItem("token{n}_{i}", v);' for i in range(5))
        + "</script>"
        for n in range(5)
    )
    key = "AKIA" + "IOSFODNN7REALKEY"
    out = audit(
        CHECK,
        {"/": page(scripts), "/app.js": f'var k="{key}";'},
    )
    assert "web.conteudo.segredo" in ids(out)
    assert TOKEN in ids(out)


def test_titulo_do_token_nao_leva_caractere_de_controle():
    out = with_js('localStorage.setItem("token\x1b[2J\x07", v)')
    [f] = [f for f in out if f.check_id == TOKEN]
    for texto in (f.title, f.evidence, str(f.details)):
        assert "\x1b" not in texto and "\x07" not in texto
