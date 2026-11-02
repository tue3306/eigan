"""Catálogo de sondas da checagem ``web.exposure``.

Cada sonda é um caminho + a assinatura de conteúdo que confirma a exposição +
o nível de perfil em que roda (0 = rápido, 1 = padrão, 2 = completo). Sondas
ligadas a uma tecnologia sobem um nível quando ela já foi reconhecida no site
(ex.: ``/wp-config.php~`` vira "padrão" em sites WordPress).

Só leituras: nenhuma sonda grava, executa ou dispara rotinas pesadas no alvo
(o ``/actuator/heapdump``, por exemplo, nunca é pedido — nem com HEAD, que o
Spring atende como GET e gera o despejo de memória). Arquivos potencialmente
grandes (backups, logs) são lidos com ``Range`` para o servidor mandar só o
começo.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass

from ...core.http import Response
from ...core.models import Severity
from ...core.target import is_ip
from . import signatures as sig
from . import signatures_pages as pages
from .common import BINARY_PROBE_BYTES, TEXT_PROBE_BYTES, site_of
from .signatures import Match

Signature = Callable[[Response], Match | None]

SECRET_BYTES = 8_192
SQL_BYTES = 8_192
LOG_BYTES = 32_768


@dataclass(frozen=True)
class Probe:
    path: str  # pode conter {host} ou {name} (nome do site sem o sufixo)
    finding: str
    signature: Signature
    level: int = 1
    group: str = ""  # sondas do mesmo grupo viram um achado só
    max_bytes: int = TEXT_PROBE_BYTES
    weak: bool = False  # assinatura fraca: só vale se diferente do soft 404
    techs: tuple[str, ...] = ()  # tecnologias que tornam a sonda mais provável
    statuses: tuple[int, ...] = (200,)
    severity: Severity | None = None  # substitui a da base (a da assinatura vence)
    title: str | None = None
    reveals: tuple[str, str] | None = None  # (tecnologia, tipo) confirmada pela sonda
    ranged: bool = False  # pede só o começo do arquivo (Range: bytes=0-N)

    @property
    def key(self) -> str:
        return self.group or self.path

    @property
    def headers(self) -> dict[str, str] | None:
        return {"Range": f"bytes=0-{self.max_bytes - 1}"} if self.ranged else None

    def accepts(self, status: int) -> bool:
        """Código aceito (206 = leitura parcial pedida com Range vale como 200)."""
        return status in self.statuses or (self.ranged and status == 206 and 200 in self.statuses)

    def needs_name(self) -> bool:
        return "{" in self.path

    def effective_level(self, known: set[str]) -> int:
        """Sondas do perfil completo sobem para o padrão quando a tecnologia é conhecida."""
        if self.level == 2 and known.intersection(self.techs):
            return 1
        return self.level

    def path_for(self, host: str) -> str:
        if not self.needs_name():
            return self.path
        site = site_of(host)
        return self.path.format(host=host, name=site.split(".", 1)[0])


def select(level: int, known: set[str], host: str) -> list[Probe]:
    """Sondas que cabem no perfil (sem repetir caminho)."""
    chosen: dict[str, Probe] = {}
    for probe in PROBES:
        if probe.effective_level(known) > level:
            continue
        if probe.needs_name() and (not host or is_ip(host)):
            continue
        path = probe.path_for(host)
        chosen.setdefault(path, probe)
    return list(chosen.values())


def decoy_path(path: str) -> str:
    """Caminho inexistente "irmão" da sonda: mesma pasta e mesma extensão.

    Se o servidor devolver conteúdo que também passa na assinatura para este
    caminho aleatório, ele responde a mesma coisa para qualquer endereço
    (armadilha, página genérica) e o achado é descartado.
    """
    bare = path.split("?", 1)[0]
    token = "eigan-" + secrets.token_hex(6)
    if bare.endswith("/"):  # /admin/ -> /eigan-x/ (um painel pode atender /admin/* inteiro)
        parent = bare.rstrip("/").rpartition("/")[0]
        return f"{parent}/{token}/"
    folder, _, name = bare.rpartition("/")
    if name.startswith(".") and name.count(".") == 1:
        return f"{folder}/.{token}"
    stem, dot, ext = name.rpartition(".")
    if dot and stem:
        return f"{folder}/{token}.{ext}"
    return f"{folder}/{token}"


_PHP = ("php", "wordpress", "joomla", "drupal", "laravel")
_ASPNET = ("aspnet", "iis")
_JAVA = ("spring", "spring-boot", "tomcat", "jetty", "java")
_NODE = ("express", "nextjs", "nuxt", "node")
_REPO = "web.exposicao.repositorio"
_CONFIG = "web.exposicao.config"
_CREDS = "web.exposicao.credenciais"

VCS = (
    Probe("/.git/HEAD", _REPO, sig.git_head, 0, group="git"),
    Probe("/.git/config", _REPO, sig.git_config, 1, group="git"),
    Probe(
        "/.git/index",
        _REPO,
        sig.git_index,
        2,
        group="git",
        max_bytes=BINARY_PROBE_BYTES,
        ranged=True,
    ),
    Probe("/.svn/entries", _REPO, sig.svn_entries, 1, group="svn"),
    Probe(
        "/.svn/wc.db",
        _REPO,
        sig.sqlite_db,
        2,
        group="svn",
        max_bytes=BINARY_PROBE_BYTES,
        ranged=True,
    ),
    Probe("/.hg/requires", _REPO, sig.hg_requires, 2, group="hg"),
    Probe("/.bzr/branch-format", _REPO, sig.bzr_format, 2, group="bzr"),
)

ENV = (
    *(
        Probe(path, "web.exposicao.env", sig.dotenv, level)
        for path, level in (
            ("/.env", 0),
            ("/.env.local", 1),
            ("/.env.production", 1),
            ("/.env.prod", 2),
            ("/.env.dev", 2),
            ("/.env.staging", 2),
            ("/.env.stage", 2),
            ("/.env.live", 2),
            ("/.env.www", 2),
            ("/.env.dev.local", 2),
            ("/.env.development.local", 2),
            ("/.env.prod.local", 2),
            ("/.env.production.local", 2),
            ("/.env.bak", 2),
            ("/.env.backup", 2),
            ("/.env.save", 2),
            ("/.env.old", 2),
            ("/.env_1", 2),
            ("/.env.{name}", 2),
            ("/api/.env", 2),
        )
    ),
    *(
        Probe(path, "web.exposicao.env", sig.dotenv_template, 2)
        for path in ("/.env.example", "/.env_sample")
    ),
)

CONFIG_FILES = (
    Probe("/wp-config.php.bak", _CONFIG, sig.php_or_vim, 1, techs=("wordpress",)),
    *(
        Probe(path, _CONFIG, sig.php_or_vim, 2, techs=("wordpress",))
        for path in (
            "/wp-config.php~",
            "/wp-config.php.old",
            "/wp-config.php.save",
            "/wp-config.php.orig",
            "/wp-config.txt",
            "/.wp-config.php.swp",
        )
    ),
    Probe("/configuration.php.bak", _CONFIG, sig.php_or_vim, 2, techs=("joomla",)),
    Probe("/configuration.php~", _CONFIG, sig.php_or_vim, 2, techs=("joomla",)),
    Probe("/sites/default/settings.php.bak", _CONFIG, sig.php_or_vim, 2, techs=("drupal",)),
    Probe("/config.php.bak", _CONFIG, sig.php_or_vim, 2, techs=_PHP),
    Probe("/config.inc.php.bak", _CONFIG, sig.php_or_vim, 2, techs=_PHP),
    *(
        Probe(path, _CONFIG, sig.php_backup, 2, techs=_PHP)
        for path in ("/index.php.bak", "/index.php~", "/index.php.old")
    ),
    *(
        Probe(path, _CONFIG, sig.vim_swap, 2, techs=_PHP, max_bytes=BINARY_PROBE_BYTES, ranged=True)
        for path in ("/.index.php.swp", "/.config.php.swp", "/.env.swp")
    ),
    Probe("/.htaccess", _CONFIG, sig.htaccess, 2, techs=("apache", "litespeed")),
    Probe("/.idea/workspace.xml", _CONFIG, sig.idea_workspace, 2),
    Probe("/web.config", _CONFIG, sig.webconfig_source, 2, techs=_ASPNET),
    Probe("/web.config.bak", _CONFIG, sig.webconfig_source, 2, techs=_ASPNET),
    Probe("/web.config.old", _CONFIG, sig.webconfig_source, 2, techs=_ASPNET),
    Probe("/WEB-INF/web.xml", _CONFIG, sig.java_webxml, 2, techs=_JAVA),
    Probe("/config/database.yml", _CONFIG, sig.rails_database, 2, techs=("rails", "ruby")),
)

SECRETS = (
    Probe("/.htpasswd", "web.exposicao.htpasswd", sig.htpasswd, 1, techs=("apache", "litespeed")),
    Probe(
        "/.DS_Store",
        "web.exposicao.ds_store",
        sig.ds_store,
        1,
        max_bytes=BINARY_PROBE_BYTES,
        ranged=True,
    ),
    Probe("/.ssh/id_rsa", _CREDS, sig.private_key, 1, max_bytes=SECRET_BYTES),
    Probe("/id_rsa", _CREDS, sig.private_key, 1, max_bytes=SECRET_BYTES),
    *(
        Probe(path, _CREDS, sig.private_key, 2, max_bytes=SECRET_BYTES)
        for path in (
            "/.ssh/id_ed25519",
            "/id_ed25519",
            "/server.key",
            "/privkey.pem",
            "/private.key",
            "/private.pem",
            "/key.pem",
            "/config/jwt/private.pem",
            "/jwt/private.pem",
        )
    ),
    Probe("/.ssh/authorized_keys", _CREDS, sig.ssh_public_keys, 2, max_bytes=SECRET_BYTES),
    Probe("/.ssh/known_hosts", _CREDS, sig.ssh_public_keys, 2, max_bytes=SECRET_BYTES),
    Probe("/.aws/credentials", _CREDS, sig.aws_credentials, 1, max_bytes=SECRET_BYTES),
    Probe("/.npmrc", _CREDS, sig.npmrc, 1, max_bytes=SECRET_BYTES),
    Probe("/.git-credentials", _CREDS, sig.git_credentials, 1, max_bytes=SECRET_BYTES),
    Probe("/.docker/config.json", _CREDS, sig.docker_config, 2, max_bytes=SECRET_BYTES),
    Probe("/.netrc", _CREDS, sig.netrc_or_pypirc, 2, max_bytes=SECRET_BYTES),
    Probe("/.pypirc", _CREDS, sig.netrc_or_pypirc, 2, max_bytes=SECRET_BYTES),
    Probe("/.kube/config", _CREDS, sig.kubeconfig, 2),
    Probe("/terraform.tfstate", _CREDS, sig.terraform_state, 2),
    Probe("/terraform.tfstate.backup", _CREDS, sig.terraform_state, 2),
    Probe("/.vscode/sftp.json", _CREDS, sig.sftp_config, 2, max_bytes=SECRET_BYTES),
    Probe("/sftp-config.json", _CREDS, sig.sftp_config, 2, max_bytes=SECRET_BYTES),
    Probe("/ftpsync.settings", _CREDS, sig.sftp_config, 2, max_bytes=SECRET_BYTES),
)

_ARCHIVES = (
    ("/backup.zip", 0),
    ("/{host}.zip", 1),
    ("/site.zip", 1),
    ("/www.zip", 1),
    ("/backup.tar.gz", 1),
    ("/{name}.zip", 2),
    ("/{host}.tar.gz", 2),
    ("/backup.tgz", 2),
    ("/backup.tar", 2),
    ("/backup.rar", 2),
    ("/backup.7z", 2),
    ("/html.zip", 2),
    ("/public_html.zip", 2),
    ("/web.zip", 2),
)
_COMPRESSED_DUMPS = (("/backup.sql.gz", 2), ("/dump.sql.gz", 2), ("/database.sql.gz", 2))
_DUMPS = (
    ("/backup.sql", 0),
    ("/dump.sql", 0),
    ("/database.sql", 1),
    ("/db.sql", 1),
    ("/{host}.sql", 1),
    ("/{name}.sql", 2),
    ("/data.sql", 2),
    ("/mysql.sql", 2),
    ("/db_backup.sql", 2),
    ("/1.sql", 2),
    ("/wp-content/uploads/dump.sql", 2),
)
BACKUPS = (
    *(
        Probe(p, "web.exposicao.backup", sig.archive, lv, max_bytes=BINARY_PROBE_BYTES, ranged=True)
        for p, lv in _ARCHIVES
    ),
    *(
        Probe(
            p,
            "web.exposicao.backup",
            sig.compressed_dump,
            lv,
            max_bytes=BINARY_PROBE_BYTES,
            ranged=True,
        )
        for p, lv in _COMPRESSED_DUMPS
    ),
    *(
        Probe(p, "web.exposicao.dump_sql", sig.sql_dump, lv, max_bytes=SQL_BYTES, ranged=True)
        for p, lv in _DUMPS
    ),
)

_SPRING = ("spring-boot", "framework")
_APACHE = ("apache", "server")
_NGINX = ("nginx", "server")
_FPM = ("php-fpm", "server")
_ASP = ("aspnet", "framework")
_LARAVEL = ("laravel", "framework")
_JOLOKIA = ("jolokia", "service")
_STATUS = "web.exposicao.status"


def _phpinfo(path: str, level: int = 2) -> Probe:
    reveals = ("php", "language")
    return Probe(path, "web.exposicao.phpinfo", pages.phpinfo, level, techs=_PHP, reveals=reveals)


def _actuator(path: str, signature: Signature, level: int = 2) -> Probe:
    finding = "web.exposicao.actuator"
    return Probe(path, finding, signature, level, group="actuator", techs=_JAVA, reveals=_SPRING)


def _debug(
    path: str,
    signature: Signature,
    techs: tuple[str, ...] = (),
    reveals: tuple[str, str] | None = None,
    group: str = "",
) -> Probe:
    finding = "web.exposicao.diagnostico"
    return Probe(path, finding, signature, 2, group=group, techs=techs, reveals=reveals)


def _log(path: str, level: int = 2, techs: tuple[str, ...] = ()) -> Probe:
    finding = "web.exposicao.logs"
    return Probe(
        path, finding, pages.log_file, level, techs=techs, max_bytes=LOG_BYTES, ranged=True
    )


DIAGNOSTICS = (
    _phpinfo("/phpinfo.php", 0),
    _phpinfo("/info.php", 1),
    _phpinfo("/php_info.php"),
    _phpinfo("/test.php"),
    _phpinfo("/i.php"),
    _phpinfo("/php.php"),
    _phpinfo("/_profiler/phpinfo"),
    Probe("/server-status", _STATUS, pages.apache_status, 0, techs=_APACHE[:1], reveals=_APACHE),
    Probe("/server-info", _STATUS, pages.apache_status, 1, techs=_APACHE[:1], reveals=_APACHE),
    Probe("/nginx_status", _STATUS, pages.nginx_status, 1, techs=_NGINX[:1], reveals=_NGINX),
    Probe("/basic_status", _STATUS, pages.nginx_status, 2, techs=_NGINX[:1], reveals=_NGINX),
    Probe("/fpm-status", _STATUS, pages.php_fpm_status, 2, "php-fpm", techs=_PHP, reveals=_FPM),
    Probe("/status", _STATUS, pages.php_fpm_status, 2, "php-fpm", techs=_PHP, reveals=_FPM),
    Probe("/metrics", _STATUS, pages.prometheus_metrics, 2, "metricas"),
    Probe("/actuator/prometheus", _STATUS, pages.prometheus_metrics, 2, "metricas", techs=_JAVA),
    _actuator("/actuator", pages.actuator_index, 0),
    _actuator("/actuator/env", pages.actuator_env, 1),
    _actuator("/actuator/configprops", pages.actuator_configprops),
    _actuator("/env", pages.actuator_env),
    _actuator("/trace", pages.spring_trace),
    Probe(
        "/actuator/health",
        "web.exposicao.actuator",
        pages.actuator_health,
        1,
        group="actuator-health",
        techs=_JAVA,
        title="Actuator /health mostra detalhes internos",
        reveals=_SPRING,
    ),
    _debug("/elmah.axd", pages.elmah, _ASPNET, _ASP, "elmah"),
    _debug("/elmah", pages.elmah, _ASPNET, _ASP, "elmah"),
    _debug("/trace.axd", pages.trace_axd, _ASPNET, _ASP),
    _debug(
        "/_profiler/empty/search/results?limit=10",
        pages.symfony_profiler,
        ("symfony",),
        ("symfony", "framework"),
    ),
    _debug("/telescope", pages.telescope, ("laravel",), _LARAVEL),
    _debug("/_ignition/health-check", pages.ignition_health, ("laravel",), _LARAVEL),
    _debug("/debug/pprof/", pages.pprof_index, (), ("go", "language")),
    _debug("/jolokia/", pages.jolokia, _JAVA, _JOLOKIA, "jolokia"),
    _debug("/actuator/jolokia", pages.jolokia, _JAVA, _JOLOKIA, "jolokia"),
)

LOGS = (
    _log("/storage/logs/laravel.log", techs=("laravel",)),
    _log("/wp-content/debug.log", techs=("wordpress",)),
    _log("/error_log", 1, _PHP),
    _log("/error.log"),
    _log("/debug.log"),
    _log("/logs/error.log"),
    _log("/access.log"),
    _log("/npm-debug.log"),
)

MANIFESTS = (
    Probe("/composer.json", "web.exposicao.manifesto", pages.composer_json, 1),
    Probe("/composer.lock", "web.exposicao.manifesto", pages.composer_lock, 2, techs=_PHP),
    Probe("/package.json", "web.exposicao.manifesto", pages.package_json, 1),
    Probe("/package-lock.json", "web.exposicao.manifesto", pages.package_lock, 2, techs=_NODE),
    Probe("/yarn.lock", "web.exposicao.manifesto", pages.yarn_lock, 2, techs=_NODE),
    Probe("/pnpm-lock.yaml", "web.exposicao.manifesto", pages.other_lock, 2),
    Probe("/Gemfile.lock", "web.exposicao.manifesto", pages.other_lock, 2),
    Probe("/docker-compose.yml", "web.exposicao.docker", pages.compose_file, 1),
    *(
        Probe(path, "web.exposicao.docker", pages.compose_file, 2)
        for path in (
            "/docker-compose.yaml",
            "/compose.yaml",
            "/docker-compose.prod.yml",
            "/docker-compose.production.yml",
            "/docker-compose.staging.yml",
            "/docker-compose.dev.yml",
            "/docker-compose-dev.yml",
            "/docker-compose.override.yml",
        )
    ),
    Probe("/Dockerfile", "web.exposicao.docker", pages.dockerfile, 2),
    Probe("/crossdomain.xml", "web.exposicao.crossdomain", pages.crossdomain, 1),
    Probe("/clientaccesspolicy.xml", "web.exposicao.crossdomain", pages.crossdomain, 2),
)

API_DOCS = (
    *(
        Probe(
            path, "web.exposicao.api_docs", pages.openapi_json, level, group="api-docs", techs=techs
        )
        for path, level, techs in (
            ("/swagger.json", 1, ()),
            ("/openapi.json", 1, ()),
            ("/v3/api-docs", 1, _JAVA),
            ("/v2/api-docs", 2, _JAVA),
            ("/swagger/v1/swagger.json", 2, _ASPNET),
            ("/api-docs", 2, ()),
            ("/api/swagger.json", 2, ()),
            ("/api/openapi.json", 2, ()),
        )
    ),
    *(
        Probe(
            path,
            "web.exposicao.api_docs",
            pages.swagger_ui,
            level,
            group="api-docs",
            weak=True,
            techs=techs,
        )
        for path, level, techs in (
            ("/swagger-ui/index.html", 1, ()),
            ("/swagger-ui.html", 2, _JAVA),
            ("/swagger/index.html", 2, _ASPNET),
            ("/docs", 2, ()),
            ("/redoc", 2, ()),
            ("/api/docs", 2, ()),
        )
    ),
)

_PANEL = "web.painel.exposto"


def _panel(
    path: str,
    signature: Signature,
    level: int,
    group: str,
    reveals: tuple[str, str] | None = None,
    techs: tuple[str, ...] = (),
) -> Probe:
    return Probe(path, _PANEL, signature, level, group=group, techs=techs, reveals=reveals)


def _generic_admin(path: str, level: int) -> Probe:
    """Área administrativa genérica: assinatura fraca, comparada com o soft 404."""
    statuses = (200, 401)
    signature = pages.admin_login
    low = Severity.LOW
    return Probe(
        path, _PANEL, signature, level, "admin", weak=True, statuses=statuses, severity=low
    )


_PMA = ("phpmyadmin", "service")
ADMIN_PANELS = (
    _panel("/phpmyadmin/", pages.phpmyadmin, 1, "phpmyadmin", _PMA),
    _panel("/phpMyAdmin/", pages.phpmyadmin, 2, "phpmyadmin", _PMA),
    _panel("/pma/", pages.phpmyadmin, 2, "phpmyadmin", _PMA),
    _panel("/adminer.php", pages.adminer, 1, "adminer", ("adminer", "service")),
    Probe(
        "/manager/html",
        _PANEL,
        pages.tomcat_manager,
        2,
        group="tomcat-manager",
        techs=("tomcat",),
        statuses=(401,),
        reveals=("tomcat", "server"),
    ),
    _panel("/h2-console/", pages.h2_console, 2, "h2", ("h2", "service"), _JAVA),
    _panel(
        "/script", pages.jenkins_script_console, 2, "jenkins", ("jenkins", "service"), ("jenkins",)
    ),
    _generic_admin("/admin/", 1),
    _generic_admin("/administrator/", 2),
)

PROBES: tuple[Probe, ...] = (
    *VCS,
    *ENV,
    *CONFIG_FILES,
    *SECRETS,
    *BACKUPS,
    *DIAGNOSTICS,
    *LOGS,
    *MANIFESTS,
    *API_DOCS,
    *ADMIN_PANELS,
)

#: pastas comuns para procurar listagem de diretório (perfil completo)
LISTING_DIRS = (
    "/uploads/",
    "/files/",
    "/backup/",
    "/backups/",
    "/tmp/",  # nosec B108
    "/logs/",
    "/images/",
    "/.vscode/",
)
#: caminhos de GraphQL (uma consulta mínima em cada, até o primeiro que responder como GraphQL)
GRAPHQL_PATHS = ("/graphql", "/api/graphql")
SECURITY_TXT_PATHS = ("/.well-known/security.txt", "/security.txt")
