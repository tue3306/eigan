"""Leitores de configuração de frameworks: Django, Flask, Laravel/Symfony e Rails.

Os arquivos Python são lidos com ``ast`` — o código do projeto **nunca** é importado
nem executado — e só contam atribuições de valor literal no nível do módulo: o que
está dentro de ``if``/``try`` depende do ambiente e não vira achado. O Spring Boot
fica em ``config_spring``.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Any

from ...core.models import Confidence, Severity
from ...core.redact import mask
from .config_common import (
    COOKIE,
    DEBUG,
    ERRORS,
    HOSTS,
    SECRET_KEY,
    ConfigIssue,
    ConfigResult,
    clip,
    env_value_kind,
    is_prod_name,
    truthy,
    unquote,
)

# -- Django ---------------------------------------------------------------------------

_DJANGO_MARK = re.compile(
    r"\b(?:INSTALLED_APPS|ROOT_URLCONF|WSGI_APPLICATION|ASGI_APPLICATION|"
    r"DJANGO_SETTINGS_MODULE|AUTH_PASSWORD_VALIDATORS)\b|\bdjango\.(?:contrib|middleware|db)\b"
)
#: chamadas que leem o ambiente: os.environ.get, os.getenv, env(), env.bool(), config()...
_ENV_READERS = frozenset({"get", "getenv", "env", "config", "bool", "str", "list"})
#: ajustes que o ``check --deploy`` cobra e cujo padrão do Django é inseguro (False)
_SECURE_DEFAULT_OFF = {
    "SESSION_COOKIE_SECURE": "django.contrib.sessions",
    "CSRF_COOKIE_SECURE": "CsrfViewMiddleware",
}


def is_django_settings(rel: str, text: str, *, has_manage: bool) -> bool:
    """``settings.py`` de Django de verdade (e não um ``settings.py`` qualquer)."""
    if _DJANGO_MARK.search(text):
        return True
    parts = rel.lower().split("/")
    in_settings_dir = len(parts) > 1 and parts[-2] == "settings"
    return has_manage and (in_settings_dir or parts[-1] == "settings.py")


def is_django_candidate(rel: str) -> bool:
    """O nome do arquivo sugere configuração do Django (``settings.py``, ``settings/prod.py``...)."""
    parts = rel.lower().split("/")
    return parts[-1].endswith(".py") and ("settings" in parts[-1] or "settings" in parts[-2:-1])


@dataclass
class _Assignments:
    """Atribuições de um módulo: a última no nível principal e as condicionais."""

    top: dict[str, ast.Assign | ast.AnnAssign] = field(default_factory=dict)
    conditional: set[str] = field(default_factory=set)


def _collect(body: list[ast.stmt], found: _Assignments, *, nested: bool = False) -> None:
    for node in body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                _record(target, node, found, nested)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            _record(node.target, node, found, nested)
        elif isinstance(node, ast.If):
            _collect(node.body, found, nested=True)
            _collect(node.orelse, found, nested=True)
        elif isinstance(node, ast.Try):
            _collect(node.body, found, nested=True)
            _collect(node.orelse, found, nested=True)
            _collect(node.finalbody, found, nested=True)
            for handler in node.handlers:
                _collect(handler.body, found, nested=True)
        elif isinstance(node, ast.With | ast.For):
            _collect(node.body, found, nested=True)


def _record(
    target: ast.expr, node: ast.Assign | ast.AnnAssign, found: _Assignments, nested: bool
) -> None:
    if not isinstance(target, ast.Name):
        return
    if nested:
        found.conditional.add(target.id)
    else:
        found.top[target.id] = node


def _env_default(node: ast.expr) -> tuple[bool, Any]:
    """``(lê do ambiente, valor padrão literal)`` de ``os.environ.get("X", padrão)`` e afins."""
    if isinstance(node, ast.Compare) and len(node.comparators) == 1:
        reads, default = _env_default(node.left)
        wanted = node.comparators[0]
        if reads and isinstance(wanted, ast.Constant) and isinstance(node.ops[0], ast.Eq):
            return True, default == wanted.value and default is not None
        return reads, None
    if not isinstance(node, ast.Call):
        return _env_subscript(node), None
    func = node.func
    name = (
        func.attr
        if isinstance(func, ast.Attribute)
        else func.id
        if isinstance(func, ast.Name)
        else ""
    )
    if isinstance(func, ast.Attribute) and name in ("split", "strip", "lower", "upper"):
        return _env_default(func.value)
    if name not in _ENV_READERS:
        return False, None
    candidate: ast.expr | None = node.args[1] if len(node.args) >= 2 else None
    for keyword in node.keywords:
        if keyword.arg == "default":
            candidate = keyword.value
    return True, _literal(candidate)


def _env_subscript(node: ast.expr) -> bool:
    """``os.environ["X"]`` (sem valor padrão)."""
    if not isinstance(node, ast.Subscript):
        return False
    value = node.value
    return isinstance(value, ast.Attribute) and value.attr == "environ"


def _literal(node: ast.expr | None) -> Any:
    if node is None:
        return None
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return None


def _line(lines: list[str], node: ast.stmt) -> str:
    number = node.lineno
    return clip(lines[number - 1].strip()) if 1 <= number <= len(lines) else ""


def _details(setting: str, value: str, recommended: str) -> dict[str, Any]:
    return {"tipo": "django", "diretiva": setting, "valor": value, "recomendado": recommended}


def check_django(
    text: str,
    *,
    rel: str,
    defined_elsewhere: frozenset[str] = frozenset(),
) -> ConfigResult | None:
    """Avalia um módulo de configuração do Django; ``None`` se não for Python válido.

    ``defined_elsewhere``: ajustes definidos em outros módulos de configuração do
    projeto (nesse caso a ausência aqui não quer dizer nada).
    """
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None
    found = _Assignments()
    _collect(tree.body, found)
    lines = text.splitlines()
    result = ConfigResult()
    _django_debug(found, lines, result, base=_is_base_settings(rel))
    _django_hosts(found, lines, result)
    _django_secret(found, result)
    _django_cookies(found, lines, result)
    _django_cookies_absent(text, rel, found, defined_elsewhere, result)
    return result


def _certainty(name: str, found: _Assignments) -> Confidence:
    """Reatribuição dentro de ``if``/``try`` pode trocar o valor em produção."""
    return Confidence.TENTATIVE if name in found.conditional else Confidence.FIRM


def _value_of(node: ast.Assign | ast.AnnAssign) -> ast.expr:
    value = node.value
    assert value is not None  # _collect só guarda atribuições com valor
    return value


def _is_base_settings(rel: str) -> bool:
    """Módulo-base (``base.py``, ``common.py``), que outro módulo importa e sobrescreve."""
    stem = rel.replace("\\", "/").rsplit("/", 1)[-1].rsplit(".", 1)[0].lower()
    return stem in ("base", "common", "default", "defaults", "settings_base", "base_settings")


def _django_debug(
    found: _Assignments, lines: list[str], result: ConfigResult, *, base: bool = False
) -> None:
    node = found.top.get("DEBUG")
    if node is None:
        return
    value = _value_of(node)
    if isinstance(value, ast.Constant) and value.value is True:
        result.add(
            ConfigIssue(
                DEBUG,
                node.lineno,
                "Django com DEBUG = True",
                _line(lines, node),
                confidence=Confidence.TENTATIVE if base else _certainty("DEBUG", found),
                discriminator="django:DEBUG",
                details=_details(
                    "DEBUG", "True", 'DEBUG = os.environ.get("DJANGO_DEBUG", "0") == "1"'
                ),
            )
        )
    elif isinstance(value, ast.Constant) and value.value is False:
        result.ok("code.config.debug", "Django com DEBUG = False")
    else:
        reads, default = _env_default(value)
        if reads and default is not None and _is_on(default):
            result.add(
                ConfigIssue(
                    DEBUG,
                    node.lineno,
                    "Django com DEBUG ligado se a variável de ambiente não existir",
                    _line(lines, node),
                    confidence=Confidence.TENTATIVE,
                    discriminator="django:DEBUG",
                    details=_details(
                        "DEBUG", "padrão ligado", 'os.environ.get("DJANGO_DEBUG", "0") == "1"'
                    ),
                )
            )


def _is_on(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return isinstance(value, str) and truthy(value)


def _django_hosts(found: _Assignments, lines: list[str], result: ConfigResult) -> None:
    node = found.top.get("ALLOWED_HOSTS")
    if node is None:
        return
    value = _value_of(node)
    literal = _literal(value)
    if isinstance(literal, list | tuple | set):
        if "*" in literal:
            result.add(
                _hosts_issue(
                    node, lines, _certainty("ALLOWED_HOSTS", found), "ALLOWED_HOSTS com '*'"
                )
            )
        elif literal:
            result.ok("code.config.hosts", "Django com ALLOWED_HOSTS restrito a nomes definidos")
        return
    reads, default = _env_default(value)
    if reads and (default == "*" or (isinstance(default, list | tuple) and "*" in default)):
        title = "ALLOWED_HOSTS com '*' se a variável de ambiente não existir"
        result.add(_hosts_issue(node, lines, Confidence.TENTATIVE, title))


def _hosts_issue(
    node: ast.Assign | ast.AnnAssign, lines: list[str], confidence: Confidence, title: str
) -> ConfigIssue:
    return ConfigIssue(
        HOSTS,
        node.lineno,
        f"Django com {title}",
        _line(lines, node),
        confidence=confidence,
        discriminator="django:ALLOWED_HOSTS",
        details=_details("ALLOWED_HOSTS", "*", 'ALLOWED_HOSTS = ["exemplo.com.br"]'),
    )


def _django_secret(found: _Assignments, result: ConfigResult) -> None:
    node = found.top.get("SECRET_KEY")
    if node is None:
        return
    value = _value_of(node)
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        if value.value.strip():
            _secret_issue(node, value.value, _certainty("SECRET_KEY", found), result)
        return
    reads, default = _env_default(value)
    if isinstance(default, str) and default.strip():
        _secret_issue(node, default, Confidence.TENTATIVE, result, fallback=True)
    elif reads or _env_subscript(value):
        result.ok("code.config.secret_key", "Django lê a SECRET_KEY do ambiente")


def _secret_issue(
    node: ast.Assign | ast.AnnAssign,
    secret: str,
    confidence: Confidence,
    result: ConfigResult,
    *,
    fallback: bool = False,
) -> None:
    """O valor nunca sai inteiro: evidência e detalhes levam só o começo e o tamanho."""
    masked = mask(secret)
    title = "Django com SECRET_KEY escrita no código"
    if fallback:
        title = "Django com valor padrão da SECRET_KEY escrito no código"
    elif secret.startswith("django-insecure-"):
        title = "Django com SECRET_KEY de desenvolvimento (django-insecure-) no código"
    result.add(
        ConfigIssue(
            SECRET_KEY,
            node.lineno,
            title,
            f"SECRET_KEY = '{masked}'",
            confidence=confidence,
            discriminator="django:SECRET_KEY",
            details=_details("SECRET_KEY", masked, 'SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]'),
        )
    )


def _django_cookies(found: _Assignments, lines: list[str], result: ConfigResult) -> None:
    for setting in ("SESSION_COOKIE_SECURE", "CSRF_COOKIE_SECURE", "SESSION_COOKIE_HTTPONLY"):
        node = found.top.get(setting)
        if node is None:
            continue
        value = _value_of(node)
        if not isinstance(value, ast.Constant):
            continue
        if value.value is False:
            result.add(
                ConfigIssue(
                    COOKIE,
                    node.lineno,
                    f"Django com {setting} = False",
                    _line(lines, node),
                    confidence=_certainty(setting, found),
                    discriminator=f"django:{setting}",
                    details=_details(setting, "False", f"{setting} = True"),
                )
            )
        elif value.value is True:
            result.ok(f"code.config.cookies.{setting.lower()}", f"Django com {setting} = True")


def _django_cookies_absent(
    text: str,
    rel: str,
    found: _Assignments,
    defined_elsewhere: frozenset[str],
    result: ConfigResult,
) -> None:
    """Ajuste ausente em quem define o ambiente final: só um indício (o padrão é ``False``)."""
    name = rel.rsplit("/", 1)[-1].lower()
    if not (name == "settings.py" or is_prod_name(rel)) or "local_settings" in text:
        return
    for setting, requirement in _SECURE_DEFAULT_OFF.items():
        if setting in found.top or setting in found.conditional or setting in defined_elsewhere:
            continue
        if requirement not in text and not is_prod_name(rel):
            continue
        result.add(
            ConfigIssue(
                COOKIE,
                0,
                f"Django sem {setting} = True (o padrão é False)",
                "",
                severity=Severity.LOW,
                confidence=Confidence.TENTATIVE,
                discriminator=f"django:{setting}:ausente",
                details=_details(setting, "(ausente: padrão False)", f"{setting} = True"),
            )
        )


def django_defined(text: str) -> frozenset[str]:
    """Quais ajustes de cookie um módulo de configuração define (para olhar entre arquivos)."""
    return frozenset(
        name for name in _SECURE_DEFAULT_OFF if re.search(rf"^\s*{name}\s*=", text, re.M)
    )


# -- Flask ----------------------------------------------------------------------------

_FLASK_MARK = re.compile(r"^\s*(?:from\s+flask\b|import\s+flask\b)", re.M)
_ANY_HOST = frozenset({"0.0.0.0", "::"})  # nosec B104  # valores procurados no código do projeto


def looks_like_flask(text: str) -> bool:
    return "debug" in text.lower() and _FLASK_MARK.search(text) is not None


def check_flask(text: str) -> ConfigResult:
    """``app.run(debug=True)``, ``app.debug = True`` e ``app.config["DEBUG"] = True``."""
    result = ConfigResult()
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return result
    lines = text.splitlines()
    guarded = _main_guard_lines(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            _flask_run(node, lines, guarded, result)
        elif isinstance(node, ast.Assign):
            _flask_assign(node, lines, result)
    return result


def _main_guard_lines(tree: ast.Module) -> set[int]:
    """Linhas dentro de ``if __name__ == "__main__":`` (não rodam sob Gunicorn/uWSGI)."""
    lines: set[int] = set()
    for node in tree.body:
        if not (isinstance(node, ast.If) and isinstance(node.test, ast.Compare)):
            continue
        left = node.test.left
        if isinstance(left, ast.Name) and left.id == "__name__":
            for child in node.body:
                lines.update(range(child.lineno, (child.end_lineno or child.lineno) + 1))
    return lines


def _flask_run(node: ast.Call, lines: list[str], guarded: set[int], result: ConfigResult) -> None:
    func = node.func
    if not (isinstance(func, ast.Attribute) and func.attr == "run"):
        return
    options = {kw.arg: kw.value for kw in node.keywords if kw.arg}
    debug = options.get("debug")
    if not (isinstance(debug, ast.Constant) and debug.value is True):
        return
    host = options.get("host")
    public = isinstance(host, ast.Constant) and host.value in _ANY_HOST
    local_only = node.lineno in guarded and not public
    title = "Flask com app.run(debug=True): depurador do Werkzeug ligado"
    if public:
        title = "Flask com app.run(debug=True) aberto na rede (host 0.0.0.0)"
    result.add(
        ConfigIssue(
            DEBUG,
            node.lineno,
            title,
            _source_line(lines, node.lineno),
            severity=Severity.MEDIUM if local_only else Severity.HIGH,
            confidence=Confidence.TENTATIVE if local_only else Confidence.FIRM,
            discriminator="flask:debug",
            details={
                "tipo": "flask",
                "diretiva": "app.run",
                "valor": "debug=True",
                "recomendado": "app.run()  # e em produção: gunicorn -w 4 app:app",
                "somente_script": local_only,
            },
        )
    )


def _flask_assign(node: ast.Assign, lines: list[str], result: ConfigResult) -> None:
    if not (isinstance(node.value, ast.Constant) and node.value.value is True):
        return
    for target in node.targets:
        if _is_flask_debug_target(target):
            result.add(
                ConfigIssue(
                    DEBUG,
                    node.lineno,
                    "Flask com o modo de depuração ligado no código",
                    _source_line(lines, node.lineno),
                    severity=Severity.HIGH,
                    discriminator="flask:debug",
                    details={
                        "tipo": "flask",
                        "diretiva": "app.debug",
                        "valor": "True",
                        "recomendado": "não ligar o modo de depuração em produção",
                    },
                )
            )


def _is_flask_debug_target(target: ast.expr) -> bool:
    """``app.debug`` ou ``app.config["DEBUG"]``."""
    if isinstance(target, ast.Attribute):
        return (
            target.attr == "debug"
            and isinstance(target.value, ast.Name)
            and target.value.id == "app"
        )
    if isinstance(target, ast.Subscript):
        base, key = target.value, target.slice
        is_config = isinstance(base, ast.Attribute) and base.attr == "config"
        return is_config and isinstance(key, ast.Constant) and key.value == "DEBUG"
    return False


def _source_line(lines: list[str], number: int) -> str:
    return clip(lines[number - 1].strip()) if 1 <= number <= len(lines) else ""


# -- Laravel / Symfony (.env) -----------------------------------------------------------

_ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


def is_env_file(name: str) -> bool:
    """``.env``, ``.env.production``... (nome em minúsculas)."""
    return name == ".env" or name.startswith(".env.")


def parse_dotenv(text: str) -> dict[str, tuple[str, int, str]]:
    """``nome -> (valor, linha, texto da linha)`` de um ``.env`` (a última definição vale)."""
    values: dict[str, tuple[str, int, str]] = {}
    for number, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _ENV_LINE.match(stripped)
        if match is None:
            continue
        value = match.group(2)
        if not value.startswith(("'", '"')):
            value = value.split(" #", 1)[0].strip()
        values[match.group(1)] = (unquote(value), number, clip(stripped))
    return values


def check_env_file(text: str) -> ConfigResult:
    """``APP_DEBUG`` ligado: o padrão do Laravel para ``APP_ENV`` ausente é ``production``."""
    result = ConfigResult()
    values = parse_dotenv(text)
    debug = values.get("APP_DEBUG")
    if debug is None:
        return result
    environment = values.get("APP_ENV")
    kind = env_value_kind(environment[0]) if environment else "prod"
    if not truthy(debug[0]):
        if kind == "prod":
            result.ok("code.config.debug", "APP_DEBUG desligado no ambiente de produção")
        return result
    if kind == "dev":
        return result
    in_production = kind == "prod"
    title = (
        "APP_DEBUG ligado com APP_ENV de produção"
        if environment
        else "APP_DEBUG ligado sem APP_ENV"
    )
    if not in_production:
        title = f"APP_DEBUG ligado no ambiente {environment[0] if environment else ''}".strip()
    result.add(
        ConfigIssue(
            DEBUG,
            debug[1],
            title,
            debug[2],
            severity=Severity.HIGH if in_production else Severity.MEDIUM,
            confidence=Confidence.FIRM if in_production else Confidence.TENTATIVE,
            discriminator="laravel:APP_DEBUG",
            details={
                "tipo": "laravel",
                "diretiva": "APP_DEBUG",
                "valor": debug[0],
                "app_env": environment[0] if environment else "(ausente: production por padrão)",
                "recomendado": "APP_DEBUG=false",
            },
        )
    )
    return result


# -- Rails ------------------------------------------------------------------------------

_RAILS_ERRORS = re.compile(r"^\s*config\.consider_all_requests_local\s*=\s*(true|false)\b", re.M)


def is_rails_production(rel: str) -> bool:
    return rel.lower().endswith("config/environments/production.rb")


def check_rails(text: str) -> ConfigResult:
    """``config.consider_all_requests_local = true`` em ``production.rb``."""
    result = ConfigResult()
    for match in _RAILS_ERRORS.finditer(text):
        line = text.count("\n", 0, match.start()) + 1
        if match.group(1) == "true":
            result.add(
                ConfigIssue(
                    ERRORS,
                    line,
                    "Rails com consider_all_requests_local = true em produção",
                    clip(match.group(0)),
                    discriminator="rails:consider_all_requests_local",
                    details={
                        "tipo": "rails",
                        "diretiva": "config.consider_all_requests_local",
                        "valor": "true",
                        "recomendado": "config.consider_all_requests_local = false",
                    },
                )
            )
        else:
            result.ok(
                "code.config.erros", "Rails com consider_all_requests_local = false em produção"
            )
    return result
