"""Exposição de arquivos e áreas sensíveis (``web.exposure``): servidor local, sem rede."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

from fakes_web_exposure import HOME, binary, json_route, settings, site, text
from helpers import Route, http_fact, run_check

from eigan.checks.web.exposure_catalog import PROBES, decoy_path, select
from eigan.core.models import Severity

ENV_BODY = "APP_NAME=loja\nDB_HOST=db.interno\nDB_PASSWORD=Sup3rSegred0!\nAPP_KEY=base64:AbCdEf123456789xyz\n"
SQL_BODY = (
    "-- MySQL dump 10.13\nCREATE TABLE `usuarios` (id int);\nINSERT INTO `usuarios` VALUES (1);\n"
)


def run(srv, profile: str = "padrao"):
    return run_check("web.exposure", http_fact(srv.url), settings=settings(profile))


def paths(srv) -> list[str]:
    return [r.path.split("?", 1)[0] for r in srv.requests]


# -- arquivos confirmados pelo conteúdo ------------------------------------------------------


def test_git_head_legivel_vira_repositorio(serve):
    srv = site(serve, {"/.git/HEAD": text("ref: refs/heads/main\n")})
    out = run(srv, "rapido")
    [finding] = out.by_id("web.exposicao.repositorio")
    assert finding.details["caminho"] == "/.git/HEAD"
    assert "ref: refs/heads/main" in finding.evidence


def test_env_com_segredos_e_critico_e_nao_mostra_o_valor(serve):
    srv = site(serve, {"/.env": text(ENV_BODY)})
    out = run(srv, "rapido")
    [finding] = out.by_id("web.exposicao.env")
    assert finding.severity == Severity.CRITICAL
    assert "Sup3rSegred0" not in finding.evidence
    assert "Sup3rSegred0" not in str(finding.details)


def test_env_so_com_marcadores_de_exemplo_nao_e_critico(serve):
    body = "APP_NAME=loja\nDB_PASSWORD=changeme\nAPP_KEY=\n"
    srv = site(serve, {"/.env": text(body)})
    [finding] = run(srv, "rapido").by_id("web.exposicao.env")
    assert finding.severity != Severity.CRITICAL


def test_dump_sql_e_backup_zip_por_assinatura(serve):
    srv = site(
        serve,
        {"/backup.sql": text(SQL_BODY), "/backup.zip": binary(b"PK\x03\x04" + b"\x00" * 64)},
    )
    out = run(srv, "rapido")
    assert out.by_id("web.exposicao.dump_sql")
    assert out.by_id("web.exposicao.backup")


def test_phpinfo_e_server_status(serve):
    info = "<html><head><title>phpinfo()</title></head><body>PHP Version 8.1.2</body></html>"
    status = "<html><title>Apache Status</title><h1>Apache Server Status for example</h1></html>"
    srv = site(serve, {"/phpinfo.php": Route(200, info), "/server-status": Route(200, status)})
    out = run(srv, "rapido")
    assert out.by_id("web.exposicao.phpinfo")
    assert out.by_id("web.exposicao.status")


def test_actuator_com_heapdump_no_indice_nunca_baixa_o_heapdump(serve):
    body = (
        '{"_links":{"self":{"href":"/actuator"},"heapdump":{"href":"/actuator/heapdump"},'
        '"env":{"href":"/actuator/env"}}}'
    )
    srv = site(serve, {"/actuator": json_route(body)})
    out = run(srv, "completo")
    [finding] = out.by_id("web.exposicao.actuator")
    assert finding.severity == Severity.CRITICAL
    assert not any("heapdump" in p for p in paths(srv))


def test_painel_phpmyadmin(serve):
    page = (
        "<html><head><title>phpMyAdmin</title><link href='phpmyadmin.css'></head>"
        "<body>pma_</body></html>"
    )
    srv = site(serve, {"/phpmyadmin/": Route(200, page)})
    assert run(srv).by_id("web.painel.exposto")


def test_swagger_publico(serve):
    spec = '{"openapi":"3.0.1","info":{"title":"Loja API","version":"1"},"paths":{}}'
    srv = site(serve, {"/openapi.json": json_route(spec)})
    assert run(srv).by_id("web.exposicao.api_docs")


def test_crossdomain_com_curinga(serve):
    xml = (
        '<?xml version="1.0"?><cross-domain-policy>'
        '<allow-access-from domain="*"/></cross-domain-policy>'
    )
    srv = site(serve, {"/crossdomain.xml": Route(200, xml, content_type="text/xml")})
    assert run(srv).by_id("web.exposicao.crossdomain")


# -- falsos positivos -----------------------------------------------------------------------


def test_site_que_responde_200_para_tudo_nao_gera_achados(serve):
    srv = site(serve, {}, soft404=True)
    out = run(srv, "completo")
    assert not {i for i in out.ids() if i.startswith("web.exposicao.")}
    assert not out.by_id("web.painel.exposto")


def test_site_limpo_vira_ponto_forte(serve):
    out = run(site(serve, {}))
    assert not [i for i in out.ids() if i.startswith("web.exposicao.")]
    assert any(p.control == "web.exposicao" for p in out.passed)


def test_isca_descarta_servidor_que_devolve_env_para_qualquer_caminho(serve):
    srv = serve({"/": Route(200, HOME)}, default=text(ENV_BODY))
    assert not run(srv, "rapido").by_id("web.exposicao.env")


def test_html_com_status_200_no_lugar_do_arquivo_e_ignorado(serve):
    srv = site(serve, {"/.git/HEAD": Route(200, HOME), "/.env": Route(200, HOME)})
    out = run(srv, "rapido")
    assert not out.by_id("web.exposicao.repositorio")
    assert not out.by_id("web.exposicao.env")


def test_zip_falso_sem_numero_magico_e_ignorado(serve):
    srv = site(serve, {"/backup.zip": binary(b"isto nao e um zip, e so texto qualquer")})
    assert not run(srv, "rapido").by_id("web.exposicao.backup")


def test_painel_generico_igual_ao_soft_404_nao_conta(serve):
    login = "<html><body><form><input type='password' name='p'> login admin</form></body></html>"
    srv = serve({"/": Route(200, HOME)}, default=Route(200, login))
    assert not run(srv).by_id("web.painel.exposto")


# -- perfis ---------------------------------------------------------------------------------


def test_perfis_rapido_padrao_completo_aumentam_a_lista():
    rapido, padrao, completo = (select(n, set(), "exemplo.com.br") for n in (0, 1, 2))
    assert 0 < len(rapido) < len(padrao) < len(completo)
    assert {p.path for p in rapido} <= {p.path for p in padrao} <= {p.path for p in completo}
    assert len(completo) >= 56


def test_perfil_rapido_nao_pede_caminhos_do_completo(serve):
    srv = site(serve, {})
    run(srv, "rapido")
    assert "/.env" in paths(srv)
    assert "/.env.staging" not in paths(srv)
    srv2 = site(serve, {})
    run(srv2, "completo")
    assert "/.env.staging" in paths(srv2)


def test_tecnologia_conhecida_promove_sonda_do_completo():
    comum = {p.path for p in select(1, set(), "exemplo.com")}
    wordpress = {p.path for p in select(1, {"wordpress"}, "exemplo.com")}
    assert "/wp-config.php~" not in comum
    assert "/wp-config.php~" in wordpress


def test_caminho_com_nome_do_site_so_vale_para_dominio():
    assert any(p.path == "/{name}.zip" for p in select(2, set(), "exemplo.com.br"))
    assert not any(p.needs_name() for p in select(2, set(), "127.0.0.1"))


def test_isca_mantem_a_pasta_e_a_extensao():
    assert decoy_path("/backup.zip").endswith(".zip") and decoy_path("/backup.zip") != "/backup.zip"
    assert decoy_path("/admin/").startswith("/eigan-") and decoy_path("/admin/").endswith("/")
    assert decoy_path("/.env").startswith("/.eigan-")
    assert len(PROBES) >= 100


# -- listagem, source map, GraphQL ----------------------------------------------------------


def test_listagem_de_diretorio_com_arquivo_sensivel(serve):
    home = "<html><body><img src='/static/img/logo.png'></body></html>"
    listing = (
        "<html><head><title>Index of /static/</title></head><body><h1>Index of /static/</h1>"
        "<a href='db.sql'>db.sql</a><a href='a.css'>a.css</a></body></html>"
    )
    srv = site(serve, {"/": Route(200, home), "/static/": Route(200, listing)})
    [finding] = run(srv).by_id("web.exposicao.listagem")
    assert finding.details["pasta"] == "/static/"
    assert finding.severity == Severity.MEDIUM


def test_pagina_inicial_e_listagem_e_pagina_padrao(serve):
    listing = (
        "<html><head><title>Index of /</title></head><body><h1>Index of /</h1>"
        "<a href='x'>x</a></body></html>"
    )
    assert run(serve({"/": Route(200, listing)}), "rapido").by_id("web.exposicao.listagem")
    nginx = "<html><head><title>Welcome to nginx!</title></head><body>nginx</body></html>"
    assert run(serve({"/": Route(200, nginx)}), "rapido").by_id("web.exposicao.pagina_padrao")


def test_pagina_inicial_comum_nao_e_listagem_nem_padrao(serve):
    out = run(site(serve, {}), "rapido")
    assert not out.by_id("web.exposicao.listagem")
    assert not out.by_id("web.exposicao.pagina_padrao")


SCRIPT_HOME = "<html><head><script src='/app.js'></script></head><body>x</body></html>"
SCRIPT = "console.log(1);\n//# sourceMappingURL=app.js.map\n"


def test_source_map_do_proprio_site(serve):
    smap = '{"version":3,"sources":["src/main.ts"],"mappings":"AAAA"}'
    srv = site(
        serve,
        {
            "/": Route(200, SCRIPT_HOME),
            "/app.js": Route(200, SCRIPT, content_type="application/javascript"),
            "/app.js.map": json_route(smap),
        },
    )
    [finding] = run(srv).by_id("web.exposicao.sourcemap")
    assert finding.details["mapas"][0].endswith("/app.js.map")


def test_script_cujo_mapa_e_uma_pagina_html_nao_gera_achado(serve):
    srv = site(
        serve,
        {
            "/": Route(200, SCRIPT_HOME),
            "/app.js": Route(200, SCRIPT, content_type="application/javascript"),
        },
        soft404=True,
    )
    assert not run(srv).by_id("web.exposicao.sourcemap")


def test_graphql_com_introspecao_aberta(serve):
    ok = json_route('{"data":{"__schema":{"queryType":{"name":"Query"}}}}')
    srv = site(serve, {"/graphql": ok})
    [finding] = run(srv).by_id("web.exposicao.graphql")
    assert finding.details["endpoint"].endswith("/graphql")
    posts = [r for r in srv.requests if r.method == "POST"]
    assert posts and b"__schema" in posts[0].body


def test_graphql_que_recusa_introspecao_vira_ponto_forte(serve):
    body = '{"errors":[{"message":"GraphQL introspection is not allowed"}]}'
    out = run(site(serve, {"/graphql": json_route(body)}))
    assert not out.by_id("web.exposicao.graphql")
    assert any(p.control == "web.graphql" for p in out.passed)


# -- robots.txt e security.txt --------------------------------------------------------------


def test_robots_com_caminho_sensivel(serve):
    robots = "User-agent: *\nDisallow: /backup-antigo/\nDisallow: /wp-admin/\nDisallow: /busca\n"
    srv = site(serve, {"/robots.txt": text(robots)})
    [finding] = run(srv, "rapido").by_id("web.robots.sensivel")
    assert "/backup-antigo/" in finding.details["caminhos"]
    assert "/wp-admin/" not in finding.details["caminhos"]


def test_robots_comum_nao_gera_achado(serve):
    robots = "User-agent: *\nDisallow: /busca\nDisallow: /wp-admin/\n"
    srv = site(serve, {"/robots.txt": text(robots)})
    assert not run(srv, "rapido").by_id("web.robots.sensivel")


def future(days: int) -> str:
    return (datetime.now(UTC) + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_security_txt_expirado(serve):
    old = f"Contact: mailto:seg@exemplo.com\nExpires: {future(-30)}\n"
    srv = site(serve, {"/.well-known/security.txt": text(old)})
    assert run(srv, "rapido").by_id("web.securitytxt.expirado")


def test_security_txt_sem_campos_obrigatorios(serve):
    srv = site(serve, {"/.well-known/security.txt": text("Preferred-Languages: pt\nContact: x\n")})
    [finding] = run(srv, "rapido").by_id("web.securitytxt.invalido")
    assert finding.details["faltando"] == ["Expires"]


def test_security_txt_valido_e_ponto_forte(serve):
    good = f"Contact: mailto:seg@exemplo.com\nExpires: {future(200)}\n"
    out = run(site(serve, {"/.well-known/security.txt": text(good)}), "rapido")
    assert not out.by_id("web.securitytxt.expirado")
    assert not out.by_id("web.securitytxt.invalido")
    assert any(p.control == "web.securitytxt" for p in out.passed)


def test_security_txt_ausente_nao_e_cobrado_em_ip_com_http(serve):
    assert not run(site(serve, {}), "rapido").by_id("web.securitytxt.ausente")


def test_pagina_html_no_lugar_do_security_txt_nao_conta(serve):
    srv = site(serve, {"/.well-known/security.txt": Route(200, HOME)})
    assert not run(srv, "rapido").by_id("web.securitytxt.invalido")


def test_alvo_que_nao_responde_nao_quebra():
    start = time.monotonic()
    out = run_check("web.exposure", http_fact("http://127.0.0.1:1/"), settings=settings("rapido"))
    assert not out.findings
    assert time.monotonic() - start < 30


# -- regressões da revisão ---------------------------------------------------------------------


def test_bloqueio_total_nao_vira_ponto_forte(serve):
    srv = serve({"/": Route(200, HOME)}, default=Route(403, "negado"))
    out = run(srv, "rapido")
    assert not any(p.control == "web.exposicao" for p in out.passed)


def test_security_txt_ausente_so_com_resposta_definitiva():
    from eigan.checks.web import exposure

    assert hasattr(exposure, "Coverage")
    cov = exposure.Coverage()
    assert not cov.enough(10)


def test_security_txt_nao_e_cobrado_quando_a_leitura_falha(serve):
    srv = serve({"/": Route(200, HOME)}, default=Route(503, "indisponível"))
    assert not run(srv, "rapido").by_id("web.securitytxt.ausente")
