"""WordPress, Joomla e Drupal (``web.cms``): servidor local, sem login e sem rede."""

from __future__ import annotations

from datetime import date

from fakes_web import response
from fakes_web_exposure import HOME, json_route, settings, site, text
from helpers import Route, http_fact, run_check

from eigan.checks.web import cms, kb_cms

WP_HOME = (
    "<html><head><meta name='generator' content='WordPress {version}'>"
    "<link rel='stylesheet' href='/wp-content/themes/t/style.css'></head><body>blog</body></html>"
)
XMLRPC = Route(405, "XML-RPC server accepts POST requests only.", content_type="text/plain")
USERS = json_route('[{"id":1,"slug":"admin","name":"Admin"},{"id":2,"slug":"maria","name":"M"}]')
README = "<html><head><title>WordPress &#8250; ReadMe</title></head><body><br /> Version 5.0.1</body></html>"
LISTING = (
    "<html><head><title>Index of /wp-content/uploads/</title></head><body>"
    "<h1>Index of /wp-content/uploads/</h1><a href='a.jpg'>a.jpg</a></body></html>"
)
LOGIN = (
    "<html><head><title>Log In</title></head><body><form name='loginform' id='loginform' "
    "action='https://exemplo.com.br/wp-login.php' method='post'>"
    "<input type='password' name='pwd'></form></body></html>"
)


def run(srv, profile: str = "padrao"):
    return run_check("web.cms", http_fact(srv.url), settings=settings(profile))


def wordpress(serve, version: str = "6.9.11", extra: dict | None = None, soft404: bool = False):
    routes = {"/": Route(200, WP_HOME.format(version=version))}
    routes.update(extra or {})
    return site(serve, routes, soft404=soft404)


# -- WordPress --------------------------------------------------------------------------------


def test_wordpress_reconhecido_registra_tecnologia(serve):
    out = run(wordpress(serve, "6.9.11"))
    names = {f.data["name"]: f.data for f in out.facts if f.kind == "tech"}
    assert names["wordpress"]["kind"] == "cms"
    assert names["wordpress"]["version"] == "6.9.11"


def test_xmlrpc_e_usuarios_expostos(serve):
    srv = wordpress(serve, extra={"/xmlrpc.php": XMLRPC, "/wp-json/wp/v2/users": USERS})
    out = run(srv, "rapido")
    assert out.by_id("web.cms.xmlrpc")
    [users] = out.by_id("web.cms.usuarios")
    assert users.details["usuarios"] == ["admin", "maria"]


def test_enumeracao_pelo_author_redireciona_para_o_login(serve):
    redirect = Route(301, "", headers=[("Location", "/author/joana/")])
    home = Route(200, WP_HOME.format(version="6.9.11"))

    def root(handler):  # o servidor de teste roteia só pelo caminho, sem a query
        return redirect if handler.path.startswith("/?author=") else home

    srv = wordpress(serve, extra={"/": root})
    out = run(srv)
    [users] = out.by_id("web.cms.usuarios")
    assert users.details["usuarios"] == ["joana"]


def test_arquivos_padrao_uploads_e_login(serve):
    srv = wordpress(
        serve,
        extra={
            "/readme.html": Route(200, README),
            "/wp-content/uploads/": Route(200, LISTING),
            "/wp-login.php": Route(200, LOGIN),
        },
    )
    out = run(srv)
    [readme] = out.by_id("web.cms.arquivos_padrao")
    assert readme.details["caminho"] == "/readme.html"
    assert out.by_id("web.cms.uploads_listagem")
    assert out.by_id("web.cms.login")


def test_perfil_rapido_nao_procura_readme_nem_login(serve):
    srv = wordpress(serve, extra={"/readme.html": Route(200, README)})
    out = run(srv, "rapido")
    assert not out.by_id("web.cms.arquivos_padrao")
    assert "/readme.html" not in [r.path for r in srv.requests]


def test_versao_com_falha_explorada_e_critica_e_so_indicio(serve):
    out = run(wordpress(serve, "5.0.1"))
    [finding] = out.by_id("web.cms.versao_vulneravel")
    assert "CVE-2026-87902" in finding.cves
    assert finding.kev
    assert finding.confidence.name == "TENTATIVE"


def test_wordpress_4_5_perdeu_o_suporte(serve):
    out = run(wordpress(serve, "4.5.2"))
    [finding] = out.by_id("web.cms.fim_de_suporte")
    assert finding.details["serie"] == "4.1 a 4.6"


def test_wordpress_atual_vira_ponto_forte_sem_achado_de_versao(serve):
    out = run(wordpress(serve, "7.1.4"))
    assert not out.by_id("web.cms.versao_vulneravel")
    assert not out.by_id("web.cms.fim_de_suporte")
    assert not out.by_id("web.cms.desatualizado")
    assert any(p.control == "web.cms.versao" for p in out.passed)


def test_wordpress_sem_correcao_recente_mas_sem_falha_conhecida_e_desatualizado(serve):
    out = run(wordpress(serve, "6.9.11"))
    assert not out.by_id("web.cms.versao_vulneravel")
    [finding] = out.by_id("web.cms.desatualizado")
    assert finding.details["referencia"] == "7.1.4"


def test_site_que_responde_200_para_tudo_nao_acusa_nada(serve):
    srv = wordpress(serve, "7.1.4", soft404=True)
    srv.default = Route(200, WP_HOME.format(version="7.1.4"))
    out = run(srv, "completo")
    for finding_id in (
        "web.cms.xmlrpc",
        "web.cms.usuarios",
        "web.cms.arquivos_padrao",
        "web.cms.uploads_listagem",
        "web.cms.login",
    ):
        assert not out.by_id(finding_id), finding_id


def test_xmlrpc_sem_a_mensagem_do_wordpress_nao_conta(serve):
    srv = wordpress(serve, extra={"/xmlrpc.php": Route(405, "Method not allowed")})
    assert not run(srv, "rapido").by_id("web.cms.xmlrpc")


def test_usuarios_com_lista_que_nao_e_do_wordpress_nao_conta(serve):
    srv = wordpress(serve, extra={"/wp-json/wp/v2/users": json_route('[{"nome":"x"}]')})
    out = run(srv, "rapido")
    assert not out.by_id("web.cms.usuarios")
    assert any(p.control == "web.cms.usuarios" for p in out.passed)


def test_site_sem_cms_nao_gera_nada(serve):
    out = run(site(serve, {}), "completo")
    assert not out.findings
    assert not [f for f in out.facts if f.kind == "tech" and f.data.get("kind") == "cms"]


def test_wordpress_sem_anuncio_e_descoberto_pelo_wp_login(serve):
    srv = site(serve, {"/wp-login.php": Route(200, LOGIN)})
    out = run(srv)
    assert {f.data["name"] for f in out.facts if f.kind == "tech"} >= {"wordpress"}
    assert out.by_id("web.cms.login")


# -- Joomla -----------------------------------------------------------------------------------

JOOMLA_HOME = (
    "<html><head><meta name='generator' content='Joomla! - Open Source Content Management'>"
    "<script src='/media/system/js/core.js'></script></head><body>x</body></html>"
)


def joomla_manifest(version: str) -> Route:
    xml = f"<extension><name>files_joomla</name><version>{version}</version></extension>"
    return Route(200, xml, content_type="application/xml")


def test_joomla_versao_pelo_manifesto_com_falha_conhecida(serve):
    path = "/administrator/manifests/files/joomla.xml"
    srv = site(serve, {"/": Route(200, JOOMLA_HOME), path: joomla_manifest("4.2.7")})
    out = run(srv, "rapido")
    [file_finding] = out.by_id("web.cms.arquivos_padrao")
    assert file_finding.details["caminho"] == path
    [vuln] = out.by_id("web.cms.versao_vulneravel")
    assert "CVE-2023-23752" in vuln.cves
    assert out.by_id("web.cms.fim_de_suporte")  # Joomla 4 perdeu o suporte em 2025-10-17
    techs = {f.data["name"]: f.data for f in out.facts if f.kind == "tech"}
    assert techs["joomla"]["version"] == "4.2.7"


def test_joomla_atual_nao_gera_achado_de_versao(serve):
    path = "/administrator/manifests/files/joomla.xml"
    srv = site(serve, {"/": Route(200, JOOMLA_HOME), path: joomla_manifest("6.2.0")})
    out = run(srv, "rapido")
    assert not out.by_id("web.cms.versao_vulneravel")
    assert not out.by_id("web.cms.fim_de_suporte")
    assert not out.by_id("web.cms.desatualizado")


def test_manifesto_do_joomla_inexistente_nao_gera_achado(serve):
    out = run(site(serve, {"/": Route(200, JOOMLA_HOME)}, soft404=True), "rapido")
    assert not out.by_id("web.cms.arquivos_padrao")


# -- Drupal -----------------------------------------------------------------------------------

DRUPAL_CHANGELOG = "Drupal 7.50, 2016-07-07\n-----------------------\n- Fixed security issues.\n"


def test_drupal_7_changelog_revela_versao_e_fim_de_suporte(serve):
    home = Route(200, HOME, headers=[("X-Generator", "Drupal 7 (https://www.drupal.org)")])
    srv = site(serve, {"/": home, "/CHANGELOG.txt": text(DRUPAL_CHANGELOG)})
    out = run(srv, "rapido")
    [file_finding] = out.by_id("web.cms.arquivos_padrao")
    assert "7.50" in file_finding.evidence
    [eol] = out.by_id("web.cms.fim_de_suporte")
    assert eol.details["fim"] == "2025-01-05"
    assert out.by_id("web.cms.versao_vulneravel")


def test_drupal_so_pelo_x_generator_avalia_apenas_a_serie(serve):
    home = Route(200, HOME, headers=[("X-Generator", "Drupal 8 (https://www.drupal.org)")])
    out = run(site(serve, {"/": home}), "rapido")
    assert out.by_id("web.cms.fim_de_suporte")  # a série 8 acabou em 2021
    assert not out.by_id("web.cms.versao_vulneravel")  # sem versão exata não há faixa de CVE


def test_changelog_em_html_nao_e_drupal(serve):
    out = run(site(serve, {}, soft404=True), "completo")
    assert not out.by_id("web.cms.arquivos_padrao")


# -- funções de assinatura e dados ----------------------------------------------------------


def test_assinaturas_basicas():
    url = "http://127.0.0.1/"
    assert cms.drupal_generator_major("Drupal 10 (https://www.drupal.org)") == "10"
    assert cms.drupal_generator_major("WordPress 6") is None
    assert (
        cms.wp_feed_version(
            response(url, 200, "<generator>https://wordpress.org/?v=6.4.2</generator>")
        )
        == "6.4.2"
    )
    assert cms.drupal_changelog_version(response(url, 200, DRUPAL_CHANGELOG)) == "7.50"
    assert cms.drupal_changelog_version(response(url, 200, "<html>Drupal 7.50, 2016-07-07")) is None
    assert cms.wp_xmlrpc(response(url, 200, "ok")) is None


def test_base_de_versoes():
    day = date(2026, 11, 2)
    assert kb_cms.end_of_life("drupal", "7.50", day)["data"] == "2025-01-05"
    assert kb_cms.end_of_life("drupal", "11.1.0", day) is None
    assert kb_cms.end_of_life("drupal", "10.3.0", date(2026, 6, 1)) is None  # ainda tinha suporte
    assert kb_cms.known_cves("wordpress", "7.1.4") == []
    assert kb_cms.outdated("wordpress", "7.1.4") is None
    assert kb_cms.outdated("wordpress", "7.0.8") == ("7.1.4", False)
