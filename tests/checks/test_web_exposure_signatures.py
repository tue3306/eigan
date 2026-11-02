"""Assinaturas de conteúdo da exposição: cada formato reconhecido e o que NÃO pode casar."""

from __future__ import annotations

import gzip

import pytest
from fakes_web import response

from eigan.checks.web import signatures as sig
from eigan.checks.web import signatures_pages as pages
from eigan.core.models import Severity

URL = "http://127.0.0.1/x"
HTML = "<html><head><title>Início</title></head><body><p>olá mundo</p></body></html>"
SHA = "a" * 40


def r(body: bytes | str, status: int = 200, headers=(), ctype: str | None = "text/plain"):
    return response(URL, status, body, headers, ctype)


# (assinatura, corpo que deve casar, texto esperado na evidência)
POSITIVOS = [
    (sig.git_head, "ref: refs/heads/main\n", "HEAD"),
    (sig.git_head, SHA + "\n", "commit"),
    (
        sig.git_config,
        '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://x/y.git\n',
        "remoto",
    ),
    (sig.git_index, b"DIRC\x00\x00\x00\x02\x00\x00\x00\x05" + b"\x00" * 20, "5 arquivos"),
    (sig.svn_entries, "12\n", "Subversion"),
    (sig.sqlite_db, b"SQLite format 3\x00" + b"\x00" * 40, "SQLite"),
    (sig.hg_requires, "revlogv1\nstore\nfncache\n", "Mercurial"),
    (sig.bzr_format, "Bazaar-NG meta directory, format 1\n", "Bazaar"),
    (sig.dotenv, "DB_HOST=db\nDB_PASSWORD=Sup3rSegred0!\n", "variáveis"),
    (sig.php_source, "<?php\ndefine('DB_PASSWORD', 'abc');\n", "PHP"),
    (sig.php_backup, "<?php echo 1;", "PHP"),
    (sig.vim_swap, b"b0VIM 8.2" + b"\x00" * 20, "Vim"),
    (sig.htaccess, "RewriteEngine On\nRewriteRule ^a$ b [L]\n", ".htaccess"),
    (sig.htpasswd, "admin:$apr1$abc$defghijk\n", "usuário"),
    (sig.ds_store, b"\x00\x00\x00\x01Bud1" + b"\x00" * 20, ".DS_Store"),
    (sig.private_key, "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n", "Chave privada"),
    (sig.aws_credentials, "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n", "AWS"),
    (sig.npmrc, "//registry.npmjs.org/:_authToken=npm_abcdefghijklmnop123\n", ".npmrc"),
    (sig.git_credentials, "https://usuario:senha123@github.com\n", "git-credentials"),
    (sig.docker_config, '{"auths":{"r.io":{"auth":"dXNlcjpwYXNz"}}}', "Docker"),
    (sig.archive, b"PK\x03\x04" + b"\x00" * 32, "ZIP"),
    (sig.archive, b"\x1f\x8b\x08\x00" + b"\x00" * 32, "gzip"),
    (sig.sql_dump, "-- MySQL dump 10.13\nCREATE TABLE a (id int);\n", "SQL"),
    (pages.phpinfo, "<title>phpinfo()</title> PHP Version 8.2.1", "phpinfo"),
    (pages.apache_status, "<h1>Apache Server Status for host</h1>", "server-status"),
    (
        pages.nginx_status,
        "Active connections: 3 \nserver accepts handled requests\n 1 1 1\n",
        "nginx",
    ),
    (pages.actuator_env, '{"propertySources":[{"name":"x"}]}', "env"),
    (pages.openapi_json, '{"openapi":"3.0.0","info":{"title":"API"}}', "OpenAPI"),
    (pages.swagger_ui, "<script>SwaggerUIBundle({})</script>", "Swagger"),
    (
        pages.crossdomain,
        '<cross-domain-policy><allow-access-from domain="*"/></cross-domain-policy>',
        "crossdomain",
    ),
    (pages.sourcemap, '{"version":3,"sources":["a.ts"],"mappings":"AAAA"}', "source map"),
    (pages.directory_listing, "<title>Index of /x</title><a href='a'>a</a>", "Listagem"),
    (pages.default_page, "<title>Welcome to nginx!</title>", "nginx"),
    (pages.dockerfile, "FROM alpine\nRUN echo oi\n", "Dockerfile"),
    (pages.compose_file, "services:\n  web:\n    image: nginx\n", "docker-compose"),
    (pages.composer_json, '{"require":{"php":">=8"}}', "composer.json"),
    (pages.package_json, '{"name":"x","dependencies":{"a":"1"}}', "package.json"),
    (
        pages.log_file,
        "[2024-01-02 10:00:00] production.ERROR: x\n[2024-01-02 10:00:01] production.ERROR: y\n",
        "log",
    ),
]


@pytest.mark.parametrize(("signature", "body", "expected"), POSITIVOS)
def test_assinatura_reconhece_o_formato(signature, body, expected):
    match = signature(r(body))
    assert match is not None
    assert expected.lower() in match.evidence.lower()


# O mesmo HTML de página comum e um texto qualquer nunca devem casar com formato nenhum.
SO_ARQUIVOS = [
    sig.git_head, sig.git_config, sig.git_index, sig.svn_entries, sig.sqlite_db, sig.hg_requires,
    sig.bzr_format, sig.dotenv, sig.php_source, sig.php_backup, sig.vim_swap, sig.htaccess,
    sig.htpasswd, sig.ds_store, sig.private_key, sig.aws_credentials, sig.npmrc,
    sig.git_credentials, sig.docker_config, sig.archive, sig.sql_dump, sig.compressed_dump,
    sig.kubeconfig, sig.terraform_state, sig.sftp_config, sig.netrc_or_pypirc, sig.rails_database,
    pages.phpinfo, pages.apache_status, pages.nginx_status, pages.actuator_index,
    pages.actuator_env, pages.openapi_json, pages.swagger_ui, pages.crossdomain, pages.sourcemap,
    pages.directory_listing, pages.default_page, pages.dockerfile, pages.compose_file,
    pages.composer_json, pages.package_json, pages.log_file, pages.robots_sensitive,
    pages.graphql_introspection, pages.phpmyadmin, pages.adminer, pages.elmah, pages.trace_axd,
]  # fmt: skip


@pytest.mark.parametrize("signature", SO_ARQUIVOS, ids=lambda f: f.__name__)
def test_pagina_comum_html_nao_casa(signature):
    assert signature(r(HTML, ctype="text/html")) is None


@pytest.mark.parametrize("signature", SO_ARQUIVOS, ids=lambda f: f.__name__)
def test_corpo_vazio_nao_casa(signature):
    assert signature(r(b"")) is None


# -- casos de borda -------------------------------------------------------------------------


def test_git_head_com_varias_linhas_ou_html_nao_vale():
    assert sig.git_head(r("ref: refs/heads/main\noutra linha\n")) is None
    assert sig.git_head(r("<html>ref: refs/heads/main</html>")) is None


def test_git_config_esconde_a_senha_da_url_e_fica_critico():
    body = (
        "[core]\n\trepositoryformatversion = 0\n[remote]\n\turl = https://bot:s3nha@git.x/r.git\n"
    )
    match = sig.git_config(r(body))
    assert match is not None and match.severity == Severity.CRITICAL
    assert "s3nha" not in match.evidence


def test_env_com_valor_de_exemplo_nao_e_critico_e_um_so_par_fraco_nao_conta():
    assert sig.dotenv(r("DB_PASSWORD=changeme\nAPP_ENV=local\n")).severity is None
    assert sig.dotenv(r("TITULO=abc\n")) is None
    assert sig.dotenv(r("DB_PASSWORD=Sup3rSegred0!\n")).severity == Severity.CRITICAL


def test_env_example_so_conta_com_segredo_preenchido():
    assert sig.dotenv_template(r("DB_PASSWORD=changeme\nAPP_ENV=local\n")) is None
    assert sig.dotenv_template(r("DB_PASSWORD=Sup3rSegred0!\nAPP_ENV=local\n")) is not None


def test_php_que_so_aparece_em_um_artigo_html_nao_vale():
    article = "<html><body><pre>&lt;?php define('X', 1); ?&gt;</pre> exemplo: <?php define('X',1);</body></html>"
    assert sig.php_source(r(article, ctype="text/html")) is None


def test_chave_privada_protegida_por_senha_e_alta_e_o_corpo_nao_vaza():
    body = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nSEGREDOSEGREDO\n"
    match = sig.private_key(r(body))
    assert match is not None and match.severity == Severity.HIGH
    assert "SEGREDOSEGREDO" not in match.evidence


def test_credencial_aws_e_token_npm_saem_mascarados():
    aws = sig.aws_credentials(r("aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"))
    assert aws is not None and "AKIAIOSFODNN7EXAMPLE" not in aws.evidence
    npm = sig.npmrc(r("//r/:_authToken=npm_abcdefghijklmnop123\n"))
    assert npm is not None and "abcdefghijklmnop123" not in npm.evidence
    assert sig.npmrc(r("//r/:_authToken=${NPM_TOKEN}\n")) is None


def test_sql_dump_exige_marcadores_de_sql_de_verdade():
    assert sig.sql_dump(r("Vou fazer um INSERT INTO na tabela depois.")) is None
    assert sig.sql_dump(r("<html>CREATE TABLE a; INSERT INTO a</html>")) is None


def test_sql_gzip_vira_despejo_sql_e_gzip_comum_vira_backup():
    dump = gzip.compress(b"-- MySQL dump 10.13\nCREATE TABLE a (id int);\n")
    match = sig.compressed_dump(r(dump, ctype="application/gzip"))
    assert match is not None and match.finding == "web.exposicao.dump_sql"
    other = gzip.compress(b"nada de banco de dados aqui, so texto " * 4)
    match = sig.compressed_dump(r(other, ctype="application/gzip"))
    assert match is not None and match.finding is None


def test_arquivo_zip_exige_o_numero_magico():
    assert sig.archive(r(b"PK nao e zip")) is None
    assert sig.archive(r(b"BZhx" + b"\x00" * 8)) is None  # bzip2 exige dígito após BZh


def test_htpasswd_ignora_texto_comum():
    assert sig.htpasswd(r("Olá: tudo bem?\nSegunda linha\n")) is None


def test_it_works_do_apache_so_vale_em_pagina_curta():
    assert pages.default_page(r("<html><body><h1>It works!</h1></body></html>")) is not None
    longa = "<html><body><h1>It works!</h1>" + "x" * 4000 + "</body></html>"
    assert pages.default_page(r(longa)) is None


def test_actuator_heapdump_no_indice_e_critico_e_health_simples_nao_conta():
    index = '{"_links":{"heapdump":{"href":"/h"},"self":{"href":"/"}}}'
    match = pages.actuator_index(r(index))
    assert match is not None and match.severity == Severity.CRITICAL
    assert (
        pages.actuator_index(r('{"_links":{"self":{"href":"/"},"health":{"href":"/h"}}}')) is None
    )
    assert pages.actuator_health(r('{"status":"UP"}')) is None
    assert pages.actuator_health(r('{"status":"UP","components":{"db":{}}}')) is not None


def test_tomcat_manager_so_com_401_e_o_realm():
    ok = r("", 401, [("WWW-Authenticate", 'Basic realm="Tomcat Manager Application"')])
    assert pages.tomcat_manager(ok) is not None
    assert pages.tomcat_manager(r("", 401, [("WWW-Authenticate", 'Basic realm="outro"')])) is None
    assert pages.tomcat_manager(r("", 200)) is None


def test_painel_generico_aceita_401_ou_formulario_de_senha():
    assert pages.admin_login(r("", 401, [("WWW-Authenticate", "Basic realm=x")])) is not None
    form = "<html><body>Entrar <input type='password' name='s'></body></html>"
    assert pages.admin_login(r(form, ctype="text/html")) is not None
    assert pages.admin_login(r(HTML, ctype="text/html")) is None


def test_graphql_introspecao_hint_e_erro():
    ok = '{"data":{"__schema":{"queryType":{"name":"Query"}}}}'
    assert pages.graphql_introspection(r(ok, ctype="application/json")) is not None
    assert pages.graphql_introspection(r('{"data":null}')) is None
    err = '{"errors":[{"message":"Must provide query string."}]}'
    assert pages.graphql_hint(r(err, ctype="application/json")) is not None
    assert pages.graphql_hint(r('{"erro":"x"}')) is None


def test_robots_ignora_caminhos_padrao_e_pega_sensiveis():
    robots = "User-agent: *\nDisallow: /wp-admin/\nDisallow: /private-files/\nDisallow: /busca\n"
    match = pages.robots_sensitive(r(robots))
    assert match is not None and match.details["caminhos"] == ["/private-files/"]
    assert (
        pages.robots_sensitive(r("User-agent: *\nDisallow: /wp-admin/\nDisallow: /busca\n")) is None
    )
    assert pages.robots_sensitive(r(HTML, ctype="text/html")) is None


def test_security_txt_extrai_campos_e_data():
    info = pages.security_txt(r("Contact: mailto:a@b.com\nExpires: 2099-01-01T00:00:00Z\n"))
    assert info is not None and info.contact and info.expires is not None
    assert info.expires.year == 2099
    assert pages.security_txt(r("Expires: data-invalida\n")).expires is None
    assert pages.security_txt(r(HTML, ctype="text/html")) is None
    assert pages.security_txt(r("Contact: mailto:a@b.com\n", 404)) is None


def test_source_map_exige_versao_3_e_campos():
    assert pages.sourcemap(r('{"version":2,"sources":["a"]}')) is None
    assert pages.sourcemap(r('{"version":3,"file":"a.js"}')) is None
    assert pages.sourcemap(r(")]}'\n" + '{"version":3,"sources":["a.ts"]}')) is not None


def test_listagem_destaca_arquivos_sensiveis():
    body = "<title>Index of /d</title><a href='dump.sql'>dump.sql</a><a href='a.css'>a</a>"
    match = pages.directory_listing(r(body))
    assert match is not None and match.severity == Severity.MEDIUM
    assert match.details["arquivos"] == ["dump.sql"]


# -- regressões da revisão: corpos hostis, rótulos e confiança -------------------------------


def _bounded(func, body: str, limit: float = 3.0) -> None:
    import time

    start = time.monotonic()
    func(r(body))
    assert time.monotonic() - start < limit


def test_corpos_hostis_nao_travam_as_assinaturas():
    _bounded(sig.htaccess, "\n" * 65_000)
    _bounded(sig.rails_database, "\n" * 65_000)
    _bounded(pages.directory_listing, "<title>Index of /</title>" + "<a " * 40_000)
    _bounded(pages.directory_listing, "<title>Index of /</title>" + "href=a.a.a.a.a.a" * 15_000)
    _bounded(pages.dockerfile, "FROM x\nRUN " + "PASSWORD" * 8_000)
    _bounded(pages.compose_file, "services:\n image: x\n" + "PASSWORD" * 8_000)


def test_json_profundo_e_numeros_unicode_nao_levantam_excecao():
    assert sig.json_body(r("[" * 60_000)) is None
    assert sig.svn_entries(r("²\n")) is None
    assert sig.total_size(r(b"PK\x03\x04abc", headers=[("Content-Length", "²")])) is None


def test_authorized_keys_com_opcoes_nao_vira_known_hosts():
    body = 'from="10.0.0.1" ssh-rsa AAAAB3NzaC1yc2E user@host\n'
    match = sig.ssh_public_keys(r(body))
    assert match is not None and "authorized_keys" in match.evidence


def test_npmrc_ignora_chave_que_so_termina_em_password():
    assert sig.npmrc(r("db_host=localhost\ndb_password=Sup3rS3cret!\n")) is None
    assert sig.npmrc(r("//registry.npmjs.org/:_authToken=npm_abcdef123456\n")) is not None


def test_url_com_arroba_na_senha_nao_vaza():
    assert "ss@" not in sig._hide_userinfo("https://user:p@ss@host/repo.git")


def test_actuator_so_com_link_no_indice_e_indicio():
    body = '{"_links": {"heapdump": {"href": "http://x/actuator/heapdump"}}}'
    match = pages.actuator_index(r(body))
    assert match is not None and match.confidence.name == "TENTATIVE"
