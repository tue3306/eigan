"""Checagem de arquivos de configuração inseguros (servidores web e frameworks).

Encontra os arquivos pelo nome e confirma pelo conteúdo, entrega cada um ao leitor
certo (``config_servers``, ``config_iis_php``, ``config_frameworks``, ``config_spring``)
e transforma o resultado em achados e pontos fortes. Só lê os arquivos do projeto:
nada é importado nem executado.

Arquivos de desenvolvimento (``settings/dev.py``, ``application-local.yml``,
``.env.local``...) não geram os achados que ali são o esperado; pastas de testes e de
exemplos têm a severidade e a confiança reduzidas.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from ...core import facts, kb
from ...core.context import CheckContext
from ...core.models import Category, Fact
from ...core.registry import check
from . import (
    config_frameworks as frameworks,
)
from . import (
    config_iis_php as iis_php,
)
from . import (
    config_servers as servers,
)
from . import (
    config_spring as spring,
)
from . import (
    kb_config,  # noqa: F401  (registra as entradas da base)
)
from .config_common import (
    CONFIG_FINDINGS,
    DEV_EXPECTED,
    ConfigResult,
    Directive,
    is_dev_name,
    is_prod_name,
)
from .files import SourceFile, asset, context_adjust, path_context, project_files, read_text

#: limite de leitura para arquivos ``.conf``/``.ini`` genéricos, confirmados pelo conteúdo
_GENERIC_MAX_BYTES = 512_000
#: limite de achados por execução (um projeto gerado por modelo não pode inundar o relatório)
MAX_FINDINGS = 300

_APACHE_MARK = re.compile(
    r"^\s*(?:<VirtualHost\b|<Directory\b|<DirectoryMatch\b|<Location\b|ServerTokens\b|ServerSignature\b|"
    r"DocumentRoot\b|SSLProtocol\b|TraceEnable\b|Options\s+[+-]?(?:Indexes|All|FollowSymLinks)\b)",
    re.I | re.M,
)
_NGINX_MARK = re.compile(
    r"^\s*(?:(?:server|http|upstream|events)\s*\{|server_name\s|proxy_pass\s|fastcgi_pass\s|"
    r"ssl_protocols\s|server_tokens\s|listen\s+[\w.:\[\]]+[^=\n]*;)",
    re.M,
)
_FPM_MARK = re.compile(r"^\s*php_(?:admin_)?(?:value|flag)\[", re.M)
_PHP_INI_MARK = re.compile(
    r"^\s*(?:display_errors|expose_php|allow_url_include|allow_url_fopen|memory_limit|"
    r"upload_max_filesize|post_max_size|max_execution_time)\s*=",
    re.M,
)
_APACHE_MAIN = frozenset({"httpd.conf", "apache2.conf"})
_BUILD_FILES = frozenset({"pom.xml", "build.gradle", "build.gradle.kts"})
_NOT_PHP_INI = frozenset(
    {"tox.ini", "pytest.ini", "mypy.ini", "setup.cfg", "alembic.ini", "uwsgi.ini"}
)


@dataclass
class _Parsed:
    item: SourceFile
    text: str
    directives: list[Directive]


@dataclass
class _Inventory:
    """Arquivos de configuração do projeto, separados por tipo e com o texto já lido."""

    nginx: list[_Parsed] = field(default_factory=list)
    apache: list[_Parsed] = field(default_factory=list)
    web_config: list[tuple[SourceFile, str]] = field(default_factory=list)
    transforms: list[tuple[SourceFile, str]] = field(default_factory=list)
    php: list[tuple[SourceFile, str, str]] = field(default_factory=list)
    django: list[tuple[SourceFile, str]] = field(default_factory=list)
    flask: list[tuple[SourceFile, str]] = field(default_factory=list)
    spring: list[tuple[SourceFile, str]] = field(default_factory=list)
    env_files: list[tuple[SourceFile, str]] = field(default_factory=list)
    rails: list[tuple[SourceFile, str]] = field(default_factory=list)
    spring_secured: bool = False


@check(
    id="code.config",
    name="Arquivos de configuração inseguros",
    category=Category.CODE,
    consumes=facts.PROJECT,
    description=(
        "Lê as configurações do projeto (nginx, Apache, IIS/web.config, php.ini, Django, Flask, "
        "Spring Boot, Laravel e Rails) e aponta depuração ligada, listagem de diretórios, TLS "
        "antigo, versão divulgada, Actuator exposto e cookies desprotegidos. Nada é executado."
    ),
    findings=CONFIG_FINDINGS,
    order=35,
)
def check_config(ctx: CheckContext, fact: Fact) -> None:
    root = Path(str(fact.data.get("path") or fact.key))
    if not root.is_dir():
        return
    inventory = _gather(ctx, root)
    reporter = _Reporter(ctx)
    _check_servers(inventory, reporter)
    _check_iis_php(inventory, reporter)
    _check_frameworks(inventory, reporter)
    if reporter.omitted:
        ctx.log(
            f"Configuração: {reporter.omitted} ocorrências além do limite de {MAX_FINDINGS} foram omitidas."
        )


# -- identificação dos arquivos ----------------------------------------------------------


def _gather(ctx: CheckContext, root: Path) -> _Inventory:
    listing = project_files(ctx, root)
    max_bytes = ctx.settings.max_file_bytes
    inventory = _Inventory()
    has_manage = any(item.lname == "manage.py" for item in listing.files)
    for index, item in enumerate(listing.readable(max_bytes)):
        if index % 256 == 0:
            ctx.check_cancel()
        _classify(item, inventory, max_bytes, has_manage)
    return inventory


def _classify(item: SourceFile, inventory: _Inventory, max_bytes: int, has_manage: bool) -> None:
    name, ext = item.lname, item.ext
    if name in _BUILD_FILES:
        _read_build(item, inventory, max_bytes)
    elif ext == ".py":
        _classify_python(item, inventory, max_bytes, has_manage)
    elif name == ".htaccess" or name in _APACHE_MAIN:
        _add_apache(item, inventory, max_bytes)
    elif name == "web.config":
        _add_pair(item, inventory.web_config, max_bytes)
    elif name.startswith("web.") and name.endswith(".config"):
        _add_pair(item, inventory.transforms, max_bytes)
    elif name == ".user.ini":
        _add_php(item, inventory, max_bytes, ".user.ini")
    elif name.startswith("php") and ".ini" in name:
        _add_php(item, inventory, max_bytes, "php.ini")
    elif frameworks.is_env_file(name):
        _add_pair(item, inventory.env_files, max_bytes)
    elif spring.is_spring_config(name):
        _add_pair(item, inventory.spring, max_bytes)
    elif frameworks.is_rails_production(item.rel):
        _add_pair(item, inventory.rails, max_bytes)
    elif (
        name == "nginx.conf"
        or name.endswith(".nginx")
        or (name.startswith("nginx") and ".conf" in name)
    ):
        _add_nginx(item, inventory, max_bytes)
    elif ext == ".ini" and name not in _NOT_PHP_INI and item.size <= _GENERIC_MAX_BYTES:
        _classify_ini(item, inventory)
    elif _is_conf_name(name) and item.size <= _GENERIC_MAX_BYTES:
        _classify_conf(item, inventory)


def _is_conf_name(name: str) -> bool:
    return name.endswith((".conf", ".vhost")) or ".conf." in name


def _classify_python(
    item: SourceFile, inventory: _Inventory, max_bytes: int, has_manage: bool
) -> None:
    text = read_text(item.path, max_bytes)
    if text is None:
        return
    if frameworks.is_django_candidate(item.rel) and frameworks.is_django_settings(
        item.rel, text, has_manage=has_manage
    ):
        inventory.django.append((item, text))
    elif frameworks.looks_like_flask(text):
        inventory.flask.append((item, text))


def _classify_ini(item: SourceFile, inventory: _Inventory) -> None:
    text = read_text(item.path, _GENERIC_MAX_BYTES)
    if text is not None and _PHP_INI_MARK.search(text):
        inventory.php.append((item, text, "php.ini"))


def _classify_conf(item: SourceFile, inventory: _Inventory) -> None:
    """``.conf`` genérico: o conteúdo decide (Apache, PHP-FPM ou nginx)."""
    text = read_text(item.path, _GENERIC_MAX_BYTES)
    if text is None:
        return
    if _APACHE_MARK.search(text):
        inventory.apache.append(_Parsed(item, text, servers.parse_apache(text)))
    elif _FPM_MARK.search(text):
        inventory.php.append((item, text, "php-fpm"))
    elif _NGINX_MARK.search(text):
        inventory.nginx.append(_Parsed(item, text, servers.parse_nginx(text)))


def _read_build(item: SourceFile, inventory: _Inventory, max_bytes: int) -> None:
    text = read_text(item.path, max_bytes)
    if text is not None and spring.has_spring_security(text):
        inventory.spring_secured = True


def _add_pair(item: SourceFile, bucket: list[tuple[SourceFile, str]], max_bytes: int) -> None:
    text = read_text(item.path, max_bytes)
    if text is not None:
        bucket.append((item, text))


def _add_php(item: SourceFile, inventory: _Inventory, max_bytes: int, kind: str) -> None:
    text = read_text(item.path, max_bytes)
    if text is not None:
        inventory.php.append((item, text, kind))


def _add_apache(item: SourceFile, inventory: _Inventory, max_bytes: int) -> None:
    text = read_text(item.path, max_bytes)
    if text is not None:
        inventory.apache.append(_Parsed(item, text, servers.parse_apache(text)))


def _add_nginx(item: SourceFile, inventory: _Inventory, max_bytes: int) -> None:
    text = read_text(item.path, max_bytes)
    if text is not None:
        inventory.nginx.append(_Parsed(item, text, servers.parse_nginx(text)))


# -- avaliação ----------------------------------------------------------------------------


def _check_servers(inventory: _Inventory, reporter: _Reporter) -> None:
    nginx_tokens = [f.item.rel for f in inventory.nginx if servers.nginx_sets_tokens(f.directives)]
    for parsed in inventory.nginx:
        elsewhere = any(rel != parsed.item.rel for rel in nginx_tokens)
        reporter.report(
            parsed.item,
            servers.check_nginx(parsed.text, parsed.directives, tokens_elsewhere=elsewhere),
        )
    apache_tokens = [
        f.item.rel for f in inventory.apache if servers.apache_sets_tokens(f.directives)
    ]
    for parsed in inventory.apache:
        elsewhere = any(rel != parsed.item.rel for rel in apache_tokens)
        reporter.report(
            parsed.item,
            servers.check_apache(
                parsed.text,
                parsed.directives,
                main=parsed.item.lname in _APACHE_MAIN,
                htaccess=parsed.item.lname == ".htaccess",
                tokens_elsewhere=elsewhere,
            ),
        )


def _check_iis_php(inventory: _Inventory, reporter: _Reporter) -> None:
    for item, text in inventory.web_config:
        reporter.report(item, iis_php.check_web_config(text, _sibling_transforms(item, inventory)))
    for item, text, kind in inventory.php:
        if not is_dev_name(item.rel):
            reporter.report(item, iis_php.check_php_ini(text, kind=kind))


def _sibling_transforms(item: SourceFile, inventory: _Inventory) -> iis_php.Transforms:
    """Transformações de publicação ao lado do ``web.config`` (``Web.Release.config``...)."""
    folder = item.path.parent
    texts = {
        other.name: text
        for other, text in inventory.transforms
        if other.path.parent == folder
        and not is_dev_name(other.lname)
        and "debug" not in other.lname
    }
    return iis_php.read_transforms(texts)


def _check_frameworks(inventory: _Inventory, reporter: _Reporter) -> None:
    _check_django(inventory, reporter)
    for item, text in inventory.flask:
        reporter.report(item, frameworks.check_flask(text))
    _check_spring(inventory, reporter)
    for item, text in inventory.env_files:
        reporter.report(item, frameworks.check_env_file(text))
    for item, text in inventory.rails:
        reporter.report(item, frameworks.check_rails(text))


def _check_django(inventory: _Inventory, reporter: _Reporter) -> None:
    defined = {item.rel: frameworks.django_defined(text) for item, text in inventory.django}
    for item, text in inventory.django:
        others = frozenset(
            name for rel, names in defined.items() if rel != item.rel for name in names
        )
        result = frameworks.check_django(text, rel=item.rel, defined_elsewhere=others)
        if result is None:
            reporter.ctx.log(
                f"{item.rel}: não foi possível analisar como Python; configuração do Django ignorada."
            )
            continue
        reporter.report(item, result)


def _check_spring(inventory: _Inventory, reporter: _Reporter) -> None:
    override = any(
        is_prod_name(item.lname) and spring.overrides_exposure(item.lname, text)
        for item, text in inventory.spring
    )
    for item, text in inventory.spring:
        base = not is_prod_name(item.lname)
        reporter.report(
            item,
            spring.check_spring(
                item.lname,
                text,
                secured=inventory.spring_secured,
                prod_override=override and base,
            ),
        )


# -- achados ------------------------------------------------------------------------------


class _Reporter:
    """Aplica as regras de contexto (dev, testes, exemplos) e reporta os achados."""

    def __init__(self, ctx: CheckContext) -> None:
        self.ctx = ctx
        self.count = 0
        self.omitted = 0

    def report(self, item: SourceFile, result: ConfigResult) -> None:
        self.ctx.check_cancel()
        dev = is_dev_name(item.rel)
        for issue in result.issues:
            if dev and issue.finding in DEV_EXPECTED:
                continue
            if self.count >= MAX_FINDINGS:
                self.omitted += 1
                continue
            self.count += 1
            base = issue.severity or kb.require(issue.finding).severity
            severity, confidence, where = context_adjust(item.rel, base, issue.confidence)
            details = dict(issue.details)
            details["arquivo"] = item.rel
            if where:
                details["contexto"] = where
            self.ctx.report(
                issue.finding,
                asset=asset(item.rel, issue.line),
                title=issue.title,
                severity=severity,
                confidence=confidence,
                evidence=issue.evidence,
                details=details,
                discriminator=issue.discriminator,
                tech=_techs(str(details.get("tipo", ""))),
            )
        if not dev and not path_context(item.rel):
            for strength in result.strengths:
                self.ctx.passed(strength.control, strength.text, item.rel)


def _techs(kind: str) -> list[str]:
    """Tecnologias usadas para escolher o exemplo de correção."""
    if kind == "iis":
        return ["iis", "aspnet"]
    return [kind] if kind else []
