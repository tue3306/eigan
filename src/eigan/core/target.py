"""Interpretação e validação do alvo informado pelo usuário.

O alvo vira um :class:`Target` tipado e, a partir dele, os fatos iniciais que
põem o motor de regras para andar (``seed_facts``).
"""

from __future__ import annotations

import ipaddress
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from .models import Fact, TargetKind

_HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-_]{1,63}(?<!-)(\.(?!-)[a-z0-9-_]{1,63}(?<!-))*\.?$", re.I
)
_LOCAL_ALIASES = {"local", "@local", "esta-maquina", "esta maquina", "localhost-audit"}
_LOG_SUFFIXES = {".log", ".txt", ".json", ".jsonl", ".csv", ".xml", ".gz", ".evtx"}


class TargetError(ValueError):
    """Alvo inválido — a mensagem é exibida ao usuário."""


@dataclass(frozen=True)
class Target:
    kind: TargetKind
    raw: str
    display: str
    url: str | None = None
    host: str | None = None
    port: int | None = None
    path: str | None = None
    network: str | None = None  # faixa CIDR (servidores)
    is_ip: bool = False


def is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text.strip("[]"))
        return True
    except ValueError:
        return False


def valid_hostname(host: str) -> bool:
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return False
    return bool(_HOST_RE.match(ascii_host))


def _clean(text: str) -> str:
    cleaned = (text or "").strip().strip('"').strip("'").strip()
    if any(ord(ch) < 32 for ch in cleaned):
        raise TargetError("O alvo contém caracteres de controle.")
    return cleaned


def detect_kind(text: str) -> TargetKind:
    """Adivinha o tipo do alvo quando o usuário não informa."""
    cleaned = _clean(text)
    lowered = cleaned.lower()
    if lowered in _LOCAL_ALIASES:
        return TargetKind.LOCAL
    if lowered.startswith(("http://", "https://")):
        return TargetKind.URL
    candidate = Path(cleaned).expanduser()
    if cleaned and (candidate.exists() or cleaned.startswith((".", "/", "\\", "~"))):
        if candidate.is_file() and candidate.suffix.lower() in _LOG_SUFFIXES:
            return TargetKind.LOGS
        return TargetKind.PROJECT
    if re.match(r"^[a-zA-Z]:[\\/]", cleaned):
        return TargetKind.PROJECT
    if "/" in cleaned and not lowered.startswith(("http:", "https:")):
        try:
            ipaddress.ip_network(cleaned, strict=False)
            return TargetKind.HOST
        except ValueError:
            pass
    if is_ip(cleaned):
        return TargetKind.HOST
    return TargetKind.URL


def parse_target(text: str, kind: TargetKind | str | None = None) -> Target:
    cleaned = _clean(text)
    if not cleaned and kind not in (TargetKind.LOCAL, "local"):
        raise TargetError("Informe o alvo da auditoria.")
    resolved = TargetKind(kind) if kind else detect_kind(cleaned)
    if resolved is TargetKind.LOCAL:
        return _parse_local()
    if resolved is TargetKind.URL:
        return _parse_url(cleaned)
    if resolved is TargetKind.HOST:
        return _parse_host(cleaned)
    if resolved is TargetKind.PROJECT:
        return _parse_path(cleaned, TargetKind.PROJECT)
    return _parse_path(cleaned, TargetKind.LOGS)


def _parse_local() -> Target:
    import platform

    name = platform.node() or "esta máquina"
    return Target(kind=TargetKind.LOCAL, raw="local", display=f"Esta máquina ({name})")


def _parse_url(text: str) -> Target:
    candidate = text if re.match(r"^[a-z][a-z0-9+.-]*://", text, re.I) else f"https://{text}"
    parts = urlsplit(candidate)
    if parts.scheme.lower() not in ("http", "https"):
        raise TargetError("Use um endereço http:// ou https://.")
    host = (parts.hostname or "").lower()
    if not host:
        raise TargetError("Não encontrei o domínio no endereço informado.")
    host_is_ip = is_ip(host)
    if not host_is_ip and not valid_hostname(host):
        raise TargetError(f"Domínio inválido: {host}")
    try:
        port = parts.port
    except ValueError as exc:
        raise TargetError("Porta inválida no endereço.") from exc
    netloc = f"[{host}]" if ":" in host else host
    if port:
        netloc = f"{netloc}:{port}"
    path = parts.path or "/"
    url = urlunsplit((parts.scheme.lower(), netloc, path, parts.query, ""))
    return Target(
        kind=TargetKind.URL,
        raw=text,
        display=url,
        url=url,
        host=host,
        port=port or (443 if parts.scheme.lower() == "https" else 80),
        is_ip=host_is_ip,
    )


def _parse_host(text: str) -> Target:
    value = text.strip().lower()
    if value.startswith(("http://", "https://")):
        value = urlsplit(value).hostname or ""
    if "/" in value:
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise TargetError(f"Faixa de rede inválida: {value}") from exc
        if net.num_addresses > 4096:
            raise TargetError("Faixa grande demais: use até /20 (4096 endereços) por auditoria.")
        if net.num_addresses == 1:
            return _parse_host(str(net.network_address))
        return Target(
            kind=TargetKind.HOST, raw=text, display=str(net), network=str(net), is_ip=True
        )
    value = value.strip("[]")
    if is_ip(value):
        return Target(kind=TargetKind.HOST, raw=text, display=value, host=value, is_ip=True)
    if ":" in value and value.count(":") == 1:
        host_part, _, port_part = value.partition(":")
        if port_part.isdigit() and valid_hostname(host_part):
            value = host_part
    if not valid_hostname(value):
        raise TargetError(f"Servidor inválido: {text}")
    return Target(kind=TargetKind.HOST, raw=text, display=value, host=value)


def _parse_path(text: str, kind: TargetKind) -> Target:
    path = Path(os.path.expandvars(text)).expanduser()
    try:
        path = path.resolve()
    except OSError as exc:
        raise TargetError(f"Caminho inválido: {text}") from exc
    if not path.exists():
        raise TargetError(f"Caminho não encontrado: {path}")
    if kind is TargetKind.PROJECT and not path.is_dir():
        raise TargetError("Para auditar um projeto, informe uma pasta.")
    return Target(kind=kind, raw=text, display=str(path), path=str(path))


def current_platform() -> str:
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "darwin"
    return "linux"


def seed_facts(target: Target, *, include_ports: bool = False) -> list[Fact]:
    """Fatos iniciais de cada tipo de alvo — o ponto de partida do raciocínio."""
    facts: list[Fact] = []
    if target.kind is TargetKind.URL and target.url and target.host:
        scheme = target.url.split(":", 1)[0]
        facts.append(
            Fact(
                "http.service",
                target.url,
                {
                    "url": target.url,
                    "host": target.host,
                    "port": target.port,
                    "scheme": scheme,
                    "label": target.url,
                },
                reason=f"Endereço informado: {target.url}",
            )
        )
        if scheme == "https":
            facts.append(
                Fact(
                    "tls.service",
                    f"{target.host}:{target.port}",
                    {
                        "host": target.host,
                        "port": target.port,
                        "sni": None if target.is_ip else target.host,
                        "label": f"{target.host}:{target.port}",
                    },
                    reason=f"{target.url} usa HTTPS",
                )
            )
        if not target.is_ip:
            facts.append(
                Fact(
                    "dns.domain",
                    target.host,
                    {"domain": target.host, "label": target.host},
                    reason=f"O site usa o domínio {target.host}",
                )
            )
        if include_ports:
            facts.append(
                Fact(
                    "host",
                    target.host,
                    {"host": target.host, "label": target.host},
                    reason="Opção de auditar também as portas do servidor do site",
                )
            )
    elif target.kind is TargetKind.HOST:
        if target.network:
            facts.append(
                Fact(
                    "network",
                    target.network,
                    {"network": target.network, "label": target.network},
                    reason=f"Faixa de rede informada: {target.network}",
                )
            )
        elif target.host:
            facts.append(
                Fact(
                    "host",
                    target.host,
                    {"host": target.host, "label": target.host},
                    reason=f"Servidor informado: {target.host}",
                )
            )
            if not target.is_ip:
                facts.append(
                    Fact(
                        "dns.domain",
                        target.host,
                        {"domain": target.host, "label": target.host},
                        reason=f"O servidor tem nome de domínio ({target.host})",
                    )
                )
    elif target.kind is TargetKind.LOCAL:
        facts.append(
            Fact(
                "local",
                current_platform(),
                {"platform": current_platform(), "label": target.display},
                reason="Auditoria de configuração desta máquina",
            )
        )
    elif target.kind is TargetKind.PROJECT and target.path:
        facts.append(
            Fact(
                "project",
                target.path,
                {"path": target.path, "label": target.path},
                reason=f"Pasta de projeto informada: {target.path}",
            )
        )
    elif target.kind is TargetKind.LOGS and target.path:
        facts.append(
            Fact(
                "logs.source",
                target.path,
                {"path": target.path, "label": target.path},
                reason=f"Logs informados: {target.path}",
            )
        )
    return facts
