"""Peças comuns da checagem de arquivos de configuração (servidores web e frameworks).

Cada leitor (nginx, Apache, IIS, php.ini, Django, Flask, Spring, Laravel, Rails)
devolve um :class:`ConfigResult` com os problemas encontrados e os controles
aprovados; quem transforma isso em achados é ``config_files``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ...core.models import Confidence, Severity

VERSION = "code.config.versao_divulgada"
LISTING = "code.config.listagem_diretorio"
TLS_OLD = "code.config.tls_protocolo_antigo"
TRACE = "code.config.trace_habilitado"
DEBUG = "code.config.debug_ativo"
ERRORS = "code.config.debug_erros_detalhados"
URL_INCLUDE = "code.config.php_url_include"
HOSTS = "code.config.allowed_hosts_curinga"
SECRET_KEY = "code.config.chave_secreta_fixa"
COOKIE = "code.config.cookie_inseguro"
ACTUATOR = "code.config.actuator_exposto"

CONFIG_FINDINGS = (
    VERSION,
    LISTING,
    TLS_OLD,
    TRACE,
    DEBUG,
    ERRORS,
    URL_INCLUDE,
    HOSTS,
    SECRET_KEY,
    COOKIE,
    ACTUATOR,
)

#: achados que, num arquivo de desenvolvimento (``settings/dev.py``,
#: ``application-local.yml``, ``.env.local``...), são o esperado e não viram achado
DEV_EXPECTED = frozenset({DEBUG, ERRORS, HOSTS, SECRET_KEY, COOKIE, ACTUATOR})

_DEV_TOKENS = frozenset(
    {"dev", "devel", "develop", "development", "local", "test", "tests", "testing", "ci"}
)
_PROD_TOKENS = frozenset({"prod", "production", "producao", "live"})
_TRUE = frozenset({"on", "1", "true", "yes"})


@dataclass
class ConfigIssue:
    """Um problema encontrado por um leitor de configuração (vira um achado)."""

    finding: str
    line: int
    title: str
    evidence: str
    severity: Severity | None = None
    confidence: Confidence = Confidence.FIRM
    discriminator: str = ""
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Strength:
    """Um controle verificado e aprovado (vira "ponto forte")."""

    control: str
    text: str


@dataclass
class ConfigResult:
    """O que um leitor encontrou em um arquivo."""

    issues: list[ConfigIssue] = field(default_factory=list)
    strengths: list[Strength] = field(default_factory=list)

    def add(self, issue: ConfigIssue) -> None:
        self.issues.append(issue)

    def ok(self, control: str, text: str) -> None:
        self.strengths.append(Strength(control, text))


@dataclass(frozen=True)
class Directive:
    """Uma diretiva de servidor web: nome, argumentos, linha e blocos onde está."""

    name: str
    args: tuple[str, ...]
    line: int
    context: tuple[str, ...] = ()

    @property
    def lname(self) -> str:
        return self.name.lower()

    @property
    def where(self) -> str:
        """Bloco mais interno (ex.: ``location /arquivos/``) ou ``""`` no nível principal."""
        return self.context[-1] if self.context else ""

    def text(self) -> str:
        return " ".join((self.name, *self.args)).strip()


def name_tokens(rel: str) -> set[str]:
    """Palavras do nome do arquivo e o nome da pasta onde ele está.

    ``settings/prod.py`` -> ``{"prod", "py", "settings"}``; só a pasta imediata
    conta, para que caminhos como ``docker/usr/local/etc/php/php.ini`` não pareçam
    configuração "local".
    """
    parts = rel.lower().split("/")
    tokens = {token for token in re.split(r"[^a-z0-9]+", parts[-1]) if token}
    if len(parts) > 1:
        tokens.add(parts[-2])
    return tokens


def is_dev_name(rel: str) -> bool:
    """O nome indica configuração de desenvolvimento/teste (dev, local, test...)."""
    return bool(name_tokens(rel) & _DEV_TOKENS)


def is_prod_name(rel: str) -> bool:
    """O nome indica configuração de produção (prod, production...)."""
    return bool(name_tokens(rel) & _PROD_TOKENS)


def env_value_kind(value: str) -> str:
    """Classifica um nome de ambiente: ``dev``, ``prod`` ou ``outro`` (homologação etc.)."""
    lowered = value.strip().strip("'\"").lower()
    if lowered in _DEV_TOKENS:
        return "dev"
    if lowered in _PROD_TOKENS:
        return "prod"
    return "outro"


def truthy(value: str) -> bool:
    """``On``/``1``/``true``/``yes`` (sem diferenciar maiúsculas)."""
    return value.strip().strip("'\"").lower() in _TRUE


def unquote(value: str) -> str:
    text = value.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        return text[1:-1]
    return text


def clip(text: str, limit: int = 200) -> str:
    """Uma linha de evidência sem espaços extras e com tamanho limitado."""
    compact = " ".join(text.split())
    return compact if len(compact) <= limit else compact[: limit - 1] + "…"
