"""Leitores de configuração do IIS/ASP.NET (``web.config``) e do PHP (``php.ini``).

O ``web.config`` é lido com expressões regulares depois de apagar os comentários
XML (sem interpretar DTD nem entidades). As transformações de publicação
(``Web.Release.config`` etc.) são consultadas: se uma delas corrige o item
(``RemoveAttributes(debug)``, ``customErrors`` trocado), o arquivo base não vira
achado — o valor inseguro só vale no ambiente de desenvolvimento.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from ...core.models import Confidence, Severity
from .config_common import (
    COOKIE,
    DEBUG,
    ERRORS,
    LISTING,
    URL_INCLUDE,
    VERSION,
    ConfigIssue,
    ConfigResult,
    clip,
    truthy,
    unquote,
)

_COMMENT = re.compile(r"<!--.*?-->", re.S)
_ATTR = re.compile(r"""([\w:.-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')""")


@dataclass(frozen=True)
class Element:
    """Um elemento XML: nome, atributos (chaves em minúsculas), linha e texto da tag."""

    tag: str
    attrs: dict[str, str]
    line: int
    raw: str

    def attr(self, name: str) -> str:
        return self.attrs.get(name.lower(), "").strip()


def strip_xml_comments(text: str) -> str:
    """Apaga ``<!-- ... -->`` mantendo as quebras de linha (números de linha intactos)."""
    return _COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)


def elements(text: str, tag: str) -> Iterator[Element]:
    """Elementos ``<tag ...>`` (sem diferenciar maiúsculas) de um XML já sem comentários."""
    pattern = re.compile(rf"<{re.escape(tag)}(?=[\s/>])([^>]*)>", re.I)
    for match in pattern.finditer(text):
        attrs = {key.lower(): a if a or not b else b for key, a, b in _ATTR.findall(match.group(1))}
        line = text.count("\n", 0, match.start()) + 1
        yield Element(tag, attrs, line, clip(match.group(0)))


def _first(text: str, tag: str) -> Element | None:
    return next(elements(text, tag), None)


@dataclass(frozen=True)
class Transforms:
    """O que as transformações (``Web.*.config``) corrigem ao publicar."""

    removes_debug: bool = False
    fixes_custom_errors: bool = False
    fixes_http_errors: bool = False
    sets_require_ssl: bool = False
    names: tuple[str, ...] = ()


def read_transforms(texts: dict[str, str]) -> Transforms:
    """Analisa as transformações irmãs do ``web.config`` (nome -> conteúdo)."""
    removes_debug = custom = http_errors = require_ssl = False
    for raw in texts.values():
        text = strip_xml_comments(raw)
        for element in elements(text, "compilation"):
            transform = element.attr("xdt:Transform").lower()
            if "removeattributes" in transform and "debug" in transform:
                removes_debug = True
            elif element.attr("debug").lower() == "false" and transform:
                removes_debug = True
        for element in elements(text, "customErrors"):
            if element.attr("xdt:Transform") and element.attr("mode").lower() in (
                "on",
                "remoteonly",
            ):
                custom = True
        for element in elements(text, "httpErrors"):
            mode = element.attr("errorMode").lower()
            if element.attr("xdt:Transform") and mode in ("custom", "detailedlocalonly"):
                http_errors = True
        for element in elements(text, "httpCookies"):
            if element.attr("xdt:Transform") and element.attr("requireSSL").lower() == "true":
                require_ssl = True
    return Transforms(removes_debug, custom, http_errors, require_ssl, tuple(sorted(texts)))


def check_web_config(raw: str, transforms: Transforms | None = None) -> ConfigResult:
    """Avalia um ``web.config`` (IIS e ASP.NET clássico)."""
    fixes = transforms or Transforms()
    text = strip_xml_comments(raw)
    result = ConfigResult()
    _directory_browse(text, result)
    _custom_errors(text, result, fixes)
    _http_errors(text, result, fixes)
    _compilation(text, result, fixes)
    _trace(text, result)
    _http_cookies(text, result, fixes)
    return result


def _iis_issue(
    finding: str,
    element: Element,
    title: str,
    attribute: str,
    recommended: str,
    **extra: Any,
) -> ConfigIssue:
    details: dict[str, Any] = {
        "tipo": "iis",
        "diretiva": f"<{element.tag}>",
        "valor": f'{attribute}="{element.attr(attribute)}"',
        "recomendado": recommended,
    }
    details.update(extra)
    return ConfigIssue(
        finding,
        element.line,
        title,
        element.raw,
        discriminator=f"iis:{element.tag.lower()}",
        details=details,
    )


def _directory_browse(text: str, result: ConfigResult) -> None:
    for element in elements(text, "directoryBrowse"):
        if element.attr("enabled").lower() == "true":
            result.add(
                _iis_issue(
                    LISTING,
                    element,
                    "IIS com directoryBrowse habilitado",
                    "enabled",
                    '<directoryBrowse enabled="false" />',
                )
            )


def _custom_errors(text: str, result: ConfigResult, fixes: Transforms) -> None:
    for element in elements(text, "customErrors"):
        mode = element.attr("mode").lower()
        if mode == "off" and not fixes.fixes_custom_errors:
            result.add(
                _iis_issue(
                    ERRORS,
                    element,
                    'ASP.NET com customErrors mode="Off" (erros detalhados para todos)',
                    "mode",
                    '<customErrors mode="RemoteOnly" />',
                )
            )
        elif mode in ("on", "remoteonly"):
            result.ok(
                "code.config.erros", f'ASP.NET com customErrors mode="{element.attr("mode")}"'
            )


def _http_errors(text: str, result: ConfigResult, fixes: Transforms) -> None:
    for element in elements(text, "httpErrors"):
        if element.attr("errorMode").lower() == "detailed" and not fixes.fixes_http_errors:
            result.add(
                _iis_issue(
                    ERRORS,
                    element,
                    'IIS com httpErrors errorMode="Detailed" (erros detalhados para todos)',
                    "errorMode",
                    '<httpErrors errorMode="DetailedLocalOnly" />',
                )
            )


def _compilation(text: str, result: ConfigResult, fixes: Transforms) -> None:
    for element in elements(text, "compilation"):
        if element.attr("debug").lower() != "true":
            continue
        if fixes.removes_debug:
            result.ok(
                "code.config.debug",
                'web.config com debug="true" só no desenvolvimento (a transformação de '
                "publicação remove o atributo)",
            )
            continue
        result.add(
            _iis_issue(
                DEBUG,
                element,
                'ASP.NET com compilation debug="true"',
                "debug",
                '<compilation debug="false" />',
            )
        )


def _trace(text: str, result: ConfigResult) -> None:
    for element in elements(text, "trace"):
        enabled = element.attr("enabled").lower() == "true"
        if enabled and element.attr("localOnly").lower() == "false":
            issue = _iis_issue(
                DEBUG,
                element,
                "ASP.NET com trace habilitado para qualquer computador (Trace.axd)",
                "localOnly",
                '<trace enabled="false" localOnly="true" />',
            )
            issue.severity = Severity.HIGH
            result.add(issue)


def _http_cookies(text: str, result: ConfigResult, fixes: Transforms) -> None:
    cookies = _first(text, "httpCookies")
    if cookies is not None:
        for attribute in ("requireSSL", "httpOnlyCookies"):
            if cookies.attr(attribute).lower() == "false":
                issue = _iis_issue(
                    COOKIE,
                    cookies,
                    f'ASP.NET com httpCookies {attribute}="false"',
                    attribute,
                    '<httpCookies requireSSL="true" httpOnlyCookies="true" />',
                )
                issue.discriminator = f"iis:httpcookies:{attribute.lower()}"
                result.add(issue)
        if cookies.attr("requireSSL").lower() == "true":
            result.ok("code.config.cookies", 'ASP.NET com httpCookies requireSSL="true"')
            return
        if not cookies.attr("requireSSL") and not fixes.sets_require_ssl:
            issue = _iis_issue(
                COOKIE,
                cookies,
                "ASP.NET com httpCookies sem requireSSL (cookies também trafegam por HTTP)",
                "requireSSL",
                '<httpCookies requireSSL="true" httpOnlyCookies="true" />',
            )
            issue.severity = Severity.LOW
            issue.confidence = Confidence.TENTATIVE
            issue.discriminator = "iis:httpcookies:ausente"
            result.add(issue)
        return
    forms_ssl = any(e.attr("requireSSL").lower() == "true" for e in elements(text, "forms"))
    if forms_ssl or fixes.sets_require_ssl or not _uses_session_cookies(text):
        return
    system_web = _first(text, "system.web")
    result.add(
        ConfigIssue(
            COOKIE,
            system_web.line if system_web else 0,
            "ASP.NET sem httpCookies requireSSL (cookies também trafegam por HTTP)",
            system_web.raw if system_web else "",
            severity=Severity.LOW,
            confidence=Confidence.TENTATIVE,
            discriminator="iis:httpcookies:ausente",
            details={
                "tipo": "iis",
                "diretiva": "<httpCookies>",
                "valor": "(ausente: requireSSL=false por padrão)",
                "recomendado": '<httpCookies requireSSL="true" httpOnlyCookies="true" />',
            },
        )
    )


def _uses_session_cookies(text: str) -> bool:
    """ASP.NET clássico com autenticação ou sessão configuradas (há cookies a proteger)."""
    if _first(text, "system.web") is None:
        return False
    return any(_first(text, tag) is not None for tag in ("authentication", "sessionState", "forms"))


# -- PHP ------------------------------------------------------------------------------

_INI_LINE = re.compile(r"^\s*([A-Za-z0-9_.\[\]-]+)\s*=\s*(.*?)\s*$")
_FPM_KEY = re.compile(r"^(php_(?:admin_)?(?:value|flag))\[([A-Za-z0-9_.]+)\]$", re.I)


@dataclass(frozen=True)
class IniSetting:
    name: str
    value: str
    line: int
    raw: str
    setter: str = ""  # php_admin_value, php_flag... (pools do PHP-FPM)


def parse_php_ini(text: str) -> list[IniSetting]:
    """Diretivas ``nome = valor`` (comentários ``;`` e seções ignorados)."""
    found: list[IniSetting] = []
    for number, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith((";", "#", "[")):
            continue
        match = _INI_LINE.match(stripped)
        if match is None:
            continue
        key, value = match.group(1), _ini_value(match.group(2))
        fpm = _FPM_KEY.match(key)
        if fpm is not None:
            found.append(
                IniSetting(
                    fpm.group(2).lower(), value, number, clip(stripped), fpm.group(1).lower()
                )
            )
        else:
            found.append(IniSetting(key.lower(), value, number, clip(stripped)))
    return found


def _ini_value(raw: str) -> str:
    value = raw.strip()
    if value[:1] in ("'", '"'):
        end = value.find(value[0], 1)
        return value[1:end] if end > 0 else value[1:]
    return unquote(value.split(";", 1)[0].strip())


def check_php_ini(text: str, *, kind: str = "php.ini") -> ConfigResult:
    """Avalia ``php.ini`` (``kind``: ``php.ini``, ``.user.ini`` ou ``php-fpm``).

    ``expose_php`` só vale no php.ini e ``allow_url_include`` (INI_SYSTEM) não pode
    ser mudado pelo ``.user.ini``: nesses arquivos os dois são ignorados.
    """
    result = ConfigResult()
    for setting in parse_php_ini(text):
        if setting.name == "display_errors":
            _display_errors(setting, result)
        elif setting.name == "expose_php" and kind == "php.ini":
            _expose_php(setting, result)
        elif setting.name == "allow_url_include" and kind != ".user.ini" and truthy(setting.value):
            result.add(
                _php_issue(
                    URL_INCLUDE,
                    setting,
                    "PHP com allow_url_include ligado",
                    "allow_url_include = Off",
                )
            )
    return result


def _display_errors(setting: IniSetting, result: ConfigResult) -> None:
    value = setting.value.lower()
    if truthy(value) or value == "stdout":
        result.add(
            _php_issue(
                ERRORS,
                setting,
                "PHP com display_errors ligado (erros na página)",
                "display_errors = Off",
            )
        )
    elif value in ("off", "0", "false", "no", "stderr"):
        result.ok("code.config.erros", "PHP com display_errors desligado")


def _expose_php(setting: IniSetting, result: ConfigResult) -> None:
    if truthy(setting.value):
        result.add(
            _php_issue(
                VERSION,
                setting,
                "PHP com expose_php ligado (cabeçalho X-Powered-By)",
                "expose_php = Off",
            )
        )
    elif setting.value.lower() in ("off", "0", "false", "no"):
        result.ok("code.config.versao", "PHP com expose_php desligado")


def _php_issue(finding: str, setting: IniSetting, title: str, recommended: str) -> ConfigIssue:
    details: dict[str, Any] = {
        "tipo": "php",
        "diretiva": setting.name,
        "valor": setting.value,
        "recomendado": recommended,
    }
    if setting.setter:
        details["pool_php_fpm"] = setting.setter
    return ConfigIssue(
        finding,
        setting.line,
        title,
        setting.raw,
        discriminator=f"php:{setting.name}",
        details=details,
    )
