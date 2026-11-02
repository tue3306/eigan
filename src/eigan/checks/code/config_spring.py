"""Leitor de configuração do Spring Boot: exposição do Actuator.

Lê ``application*.properties`` e ``application*.yml`` (também ``bootstrap*``) sem
biblioteca de YAML: um leitor por indentação transforma o arquivo em chaves com
pontos e números de linha. Cada "documento" do arquivo (``---`` no YAML, ``#---``
nas properties) é avaliado à parte, porque pode valer só para um perfil.

Fonte das regras: https://docs.spring.io/spring-boot/reference/actuator/endpoints.html
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ...core.models import Confidence, Severity
from .config_common import ACTUATOR, ConfigIssue, ConfigResult, clip, env_value_kind, unquote

_PREFIX = "management.endpoints.web.exposure."
_INCLUDE = _PREFIX + "include"
_EXCLUDE = _PREFIX + "exclude"
_SERVER_ADDRESS = "management.server.address"
_SERVER_PORT = "management.server.port"
_PROFILE_KEYS = ("spring.config.activate.on-profile", "spring.profiles")
#: endpoints que mostram configuração/memória/dados ou alteram a aplicação
_HIGH = frozenset(
    {
        "env",
        "heapdump",
        "threaddump",
        "configprops",
        "logfile",
        "shutdown",
        "loggers",
        "sessions",
        "jolokia",
        "httptrace",
        "httpexchanges",
    }
)
#: endpoints que revelam a estrutura interna da aplicação
_MEDIUM = frozenset(
    {"beans", "mappings", "conditions", "scheduledtasks", "quartz", "caches", "flyway", "liquibase"}
)
_LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})
_SHOW_VALUES = re.compile(r"^management\.endpoint\.([a-z]+)\.show-values$")
_PLACEHOLDER = re.compile(r"^\$\{[^:}]+(?::(.*))?\}$")
_SECURITY_DEPENDENCY = re.compile(r"spring-boot-starter-security|spring-security-(?:web|config)")


@dataclass(frozen=True)
class Prop:
    """Uma propriedade: nome com pontos, valor e linha."""

    name: str
    value: str
    line: int


def is_spring_config(lname: str) -> bool:
    """``application*.properties|yml|yaml`` e ``bootstrap*`` (nome em minúsculas)."""
    if not lname.endswith((".properties", ".yml", ".yaml")):
        return False
    return lname.startswith(("application", "bootstrap"))


def has_spring_security(build_text: str) -> bool:
    """O ``pom.xml``/``build.gradle`` traz o Spring Security para o projeto."""
    return _SECURITY_DEPENDENCY.search(build_text) is not None


def parse_properties(text: str) -> list[list[Prop]]:
    """Documentos de um ``.properties`` (``#---`` separa documentos)."""
    documents: list[list[Prop]] = [[]]
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        number = index + 1
        current = lines[index].strip()
        index += 1
        if current in ("#---", "!---"):
            documents.append([])
            continue
        if not current or current[0] in "#!":
            continue
        while current.endswith("\\") and index < len(lines):
            current = current[:-1] + lines[index].strip()
            index += 1
        match = re.match(r"([^=:\s]+)\s*[=:\s]\s*(.*)$", current)
        if match is not None:
            documents[-1].append(Prop(match.group(1).lower(), unquote(match.group(2)), number))
    return documents


def _yaml_value(raw: str) -> str:
    """Valor escalar sem aspas nem comentário; ``[a, b]`` vira ``a,b``."""
    value = raw.strip()
    if value[:1] in ("'", '"'):
        end = value.find(value[0], 1)
        return value[1:end] if end > 0 else value[1:]
    value = value.split(" #", 1)[0].strip()
    if value.startswith("[") and value.endswith("]"):
        return ",".join(unquote(part) for part in value[1:-1].split(","))
    return value


def parse_spring_yaml(text: str) -> list[list[Prop]]:
    """Documentos de um YAML do Spring, com as chaves aninhadas viradas em nomes com pontos."""
    documents: list[list[Prop]] = [[]]
    stack: list[tuple[int, str]] = []
    for number, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if stripped.startswith("---"):
            documents.append([])
            stack = []
            continue
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        if stripped.startswith("- "):
            _append_item(documents[-1], stack, stripped[2:], number)
            continue
        match = re.match(r"""(?:"([^"]+)"|'([^']+)'|([^:#\s][^:#]*?))\s*:(?:\s+(.*))?$""", stripped)
        if match is None:
            continue
        key = match.group(1) or match.group(2) or match.group(3)
        while stack and stack[-1][0] >= indent:
            stack.pop()
        path = ".".join([*(part for _, part in stack), key]).lower()
        value = _yaml_value(match.group(4) or "")
        if value and not value.startswith(("|", ">")):
            documents[-1].append(Prop(path, value, number))
        else:
            stack.append((indent, key))
    return documents


def _append_item(document: list[Prop], stack: list[tuple[int, str]], item: str, line: int) -> None:
    """``- env`` abaixo de ``include:``: junta tudo em ``include = a,b``."""
    if not stack:
        return
    path = ".".join(part for _, part in stack).lower()
    value = _yaml_value(item)
    for position, prop in enumerate(document):
        if prop.name == path:
            document[position] = Prop(path, f"{prop.value},{value}", prop.line)
            return
    document.append(Prop(path, value, line))


def parse_spring(lname: str, text: str) -> list[list[Prop]]:
    """Documentos de um arquivo de configuração do Spring."""
    return parse_properties(text) if lname.endswith(".properties") else parse_spring_yaml(text)


def _names(value: str) -> tuple[frozenset[str], bool]:
    """Conjunto de endpoints de um valor; o segundo item diz se veio de um padrão ``${X:padrão}``."""
    text = value.strip()
    placeholder = _PLACEHOLDER.match(text)
    if placeholder is not None:
        return frozenset(
            p.strip().lower() for p in (placeholder.group(1) or "").split(",") if p.strip()
        ), True
    return frozenset(p.strip().lower() for p in text.split(",") if p.strip()), False


def _active_for_dev_only(document: list[Prop]) -> bool:
    """Documento ativado só em perfis de desenvolvimento (``on-profile: dev``)."""
    for prop in document:
        if prop.name in _PROFILE_KEYS:
            names = [p.strip().lstrip("!") for p in re.split(r"[,&|]", prop.value) if p.strip()]
            return bool(names) and all(env_value_kind(name) == "dev" for name in names)
    return False


def overrides_exposure(lname: str, text: str) -> bool:
    """Um arquivo de produção define a exposição sem ``*`` (o arquivo base não vale lá)."""
    for document in parse_spring(lname, text):
        for prop in document:
            if prop.name == _INCLUDE and "*" not in prop.value:
                return True
    return False


def check_spring(
    lname: str,
    text: str,
    *,
    secured: bool = False,
    prod_override: bool = False,
) -> ConfigResult:
    """Avalia um arquivo do Spring Boot.

    ``secured``: o Spring Security está no projeto (protege os endpoints por padrão).
    ``prod_override``: um arquivo de produção redefine a exposição sem ``*``.
    """
    result = ConfigResult()
    lines = text.splitlines()
    tentative = secured or prod_override
    for document in parse_spring(lname, text):
        if not _active_for_dev_only(document):
            _check_document(document, lines, result, tentative=tentative)
    if any(issue.finding == ACTUATOR for issue in result.issues):
        # um documento expõe o Actuator: não declare "ponto forte" por outro perfil do mesmo arquivo
        result.strengths = [s for s in result.strengths if s.control != "code.config.actuator"]
    return result


def _check_document(
    document: list[Prop], lines: list[str], result: ConfigResult, *, tentative: bool
) -> None:
    props = {prop.name: prop for prop in document}
    if _not_reachable(props):
        result.ok(
            "code.config.actuator", "Actuator do Spring Boot só acessível pela interface local"
        )
        return
    include = props.get(_INCLUDE)
    if include is not None:
        _exposure(include, props.get(_EXCLUDE), lines, result, tentative=tentative)
    for prop in document:
        match = _SHOW_VALUES.match(prop.name)
        if match is not None and prop.value.strip().lower() == "always":
            result.add(
                _issue(
                    prop,
                    lines,
                    f"Spring Boot mostra os valores de /{match.group(1)} a qualquer usuário (show-values=always)",
                    f"{prop.name}=when-authorized",
                    Severity.HIGH,
                    tentative=tentative,
                )
            )
    _shutdown(props, lines, result, tentative=tentative)


def _not_reachable(props: dict[str, Prop]) -> bool:
    """Actuator preso à interface local ou desligado no HTTP (``port=-1``)."""
    address = props.get(_SERVER_ADDRESS)
    port = props.get(_SERVER_PORT)
    if port is not None and port.value.strip() == "-1":
        return True
    return address is not None and address.value.strip().lower() in _LOOPBACK


def _exposure(
    include: Prop,
    exclude: Prop | None,
    lines: list[str],
    result: ConfigResult,
    *,
    tentative: bool,
) -> None:
    names, from_placeholder = _names(include.value)
    denied = _names(exclude.value)[0] if exclude is not None else frozenset()
    if "*" in denied:
        return
    tentative = tentative or from_placeholder
    if "*" in names:
        left = (_HIGH | _MEDIUM) - denied
        if left & _HIGH or left:
            severity = Severity.HIGH if left & _HIGH else Severity.MEDIUM
            title = "Spring Boot expõe todos os endpoints do Actuator (include=*)"
            result.add(
                _issue(include, lines, title, f"{_INCLUDE}=health", severity, tentative=tentative)
            )
        return
    exposed = names - denied
    high, medium = exposed & _HIGH, exposed & _MEDIUM
    if high or medium:
        listed = ", ".join(sorted(high | medium))
        severity = Severity.HIGH if high else Severity.MEDIUM
        title = f"Spring Boot expõe endpoints sensíveis do Actuator ({listed})"
        issue = _issue(include, lines, title, f"{_INCLUDE}=health", severity, tentative=tentative)
        issue.details["endpoints"] = sorted(high | medium)
        result.add(issue)
    elif names <= {"health", "info", "metrics", "prometheus"}:
        result.ok(
            "code.config.actuator", "Actuator do Spring Boot expõe só endpoints não sensíveis"
        )


def _shutdown(
    props: dict[str, Prop], lines: list[str], result: ConfigResult, *, tentative: bool
) -> None:
    enabled = props.get("management.endpoint.shutdown.enabled")
    access = props.get("management.endpoint.shutdown.access")
    if enabled is not None and enabled.value.strip().lower() == "true":
        result.add(
            _issue(
                enabled,
                lines,
                "Spring Boot com o endpoint shutdown habilitado",
                "management.endpoint.shutdown.enabled=false",
                Severity.HIGH,
                tentative=tentative,
            )
        )
    if access is not None and access.value.strip().lower() == "unrestricted":
        result.add(
            _issue(
                access,
                lines,
                "Spring Boot com o endpoint shutdown sem restrição de acesso",
                "management.endpoint.shutdown.access=none",
                Severity.HIGH,
                tentative=tentative,
            )
        )


def _issue(
    prop: Prop,
    lines: list[str],
    title: str,
    recommended: str,
    severity: Severity,
    *,
    tentative: bool,
) -> ConfigIssue:
    evidence = (
        clip(lines[prop.line - 1].strip())
        if 1 <= prop.line <= len(lines)
        else f"{prop.name}={prop.value}"
    )
    if tentative:
        severity = Severity.MEDIUM if severity is Severity.HIGH else severity
    return ConfigIssue(
        ACTUATOR,
        prop.line,
        title,
        evidence,
        severity=severity,
        confidence=Confidence.TENTATIVE if tentative else Confidence.FIRM,
        discriminator=f"spring:{prop.name}",
        details={
            "tipo": "spring",
            "diretiva": prop.name,
            "valor": prop.value,
            "recomendado": recommended,
        },
    )
