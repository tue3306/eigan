"""Contexto compartilhado da auditoria (o "quadro" de fatos) e a visão de cada checagem."""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import Any, TypeVar
from urllib.parse import urlsplit

from . import facts, kb
from .facts import base_url
from .http import HttpClient
from .models import (
    Confidence,
    Fact,
    Finding,
    PassedControl,
    Severity,
)
from .redact import redact
from .registry import Check
from .settings import Settings
from .target import Target, current_platform, is_ip

T = TypeVar("T")
EventSink = Callable[[dict[str, Any]], None]

MAX_EVIDENCE = 4000


class Cancelled(Exception):
    """A auditoria foi cancelada pelo usuário ou estourou o tempo total."""


class ScanContext:
    """Estado compartilhado por todas as checagens de uma auditoria."""

    def __init__(
        self,
        target: Target,
        settings: Settings,
        *,
        emit: EventSink | None = None,
        cancel: threading.Event | None = None,
    ) -> None:
        self.target = target
        self.settings = settings
        self.platform = current_platform()
        self.cancel = cancel or threading.Event()
        self.http = HttpClient(settings, self.cancel)
        self._emit = emit
        self._lock = threading.RLock()
        self._memo_locks: dict[str, threading.Lock] = {}
        self._memo: dict[str, Any] = {}
        self.findings: dict[str, Finding] = {}
        self.passed: list[PassedControl] = []
        self.facts: dict[tuple[str, str], Fact] = {}
        self.pending: list[Fact] = []
        self.logs: list[str] = []

    # -- eventos -----------------------------------------------------------------
    def emit(self, event: dict[str, Any]) -> None:
        if self._emit is None:
            return
        try:
            self._emit(event)
        except Exception:  # noqa: BLE001 — quem escuta não pode derrubar a auditoria
            pass

    # -- fatos -------------------------------------------------------------------
    def add_fact(self, fact: Fact) -> Fact:
        with self._lock:
            key = (fact.kind, fact.key)
            existing = self.facts.get(key)
            if existing is not None:
                for name, value in fact.data.items():
                    existing.data.setdefault(name, value)
                return existing
            self.facts[key] = fact
            self.pending.append(fact)
        self.emit({"type": "fact", "kind": fact.kind, "key": fact.key, "label": fact.label})
        return fact

    def take_pending(self) -> list[Fact]:
        with self._lock:
            items, self.pending = self.pending, []
            return items

    def facts_of(self, kind: str) -> list[Fact]:
        with self._lock:
            return [f for f in self.facts.values() if f.kind == kind]

    # -- achados -----------------------------------------------------------------
    def add_finding(self, finding: Finding) -> Finding:
        finding.evidence = redact(finding.evidence)[:MAX_EVIDENCE]
        with self._lock:
            current = self.findings.get(finding.fingerprint)
            if current is not None:
                if finding.severity.rank > current.severity.rank:
                    current.severity = finding.severity
                    current.title = finding.title
                if finding.evidence and finding.evidence not in current.evidence:
                    current.evidence = (current.evidence + "\n" + finding.evidence)[:MAX_EVIDENCE]
                for cve in finding.cves:
                    if cve not in current.cves:
                        current.cves.append(cve)
                current.kev = current.kev or finding.kev
                return current
            self.findings[finding.fingerprint] = finding
        self.emit(
            {
                "type": "finding",
                "finding": {
                    "check_id": finding.check_id,
                    "title": finding.title,
                    "severity": finding.severity.value,
                    "asset": finding.asset,
                    "fingerprint": finding.fingerprint,
                },
            }
        )
        return finding

    def add_passed(self, control: PassedControl) -> None:
        with self._lock:
            if any(p.control == control.control and p.asset == control.asset for p in self.passed):
                return
            self.passed.append(control)

    # -- utilidades --------------------------------------------------------------
    def log(self, text: str) -> None:
        with self._lock:
            self.logs.append(text)
        self.emit({"type": "log", "text": text})

    def memo(self, key: str, factory: Callable[[], T]) -> T:
        """Calcula ``factory()`` uma única vez por auditoria (seguro entre threads)."""
        with self._lock:
            if key in self._memo:
                return self._memo[key]
            lock = self._memo_locks.setdefault(key, threading.Lock())
        with lock:
            with self._lock:
                if key in self._memo:
                    return self._memo[key]
            value = factory()
            with self._lock:
                self._memo[key] = value
            return value

    def check_cancel(self) -> None:
        if self.cancel.is_set():
            raise Cancelled()


class CheckContext:
    """O que uma checagem enxerga: a auditoria, a si mesma e o fato que a disparou."""

    def __init__(self, scan: ScanContext, check: Check, fact: Fact) -> None:
        self.scan = scan
        self.check = check
        self.fact = fact
        self.findings_reported = 0
        self.abandoned = False

    @property
    def http(self) -> HttpClient:
        return self.scan.http

    @property
    def settings(self) -> Settings:
        return self.scan.settings

    @property
    def target(self) -> Target:
        return self.scan.target

    @property
    def profile(self) -> str:
        return self.scan.settings.profile

    @property
    def platform(self) -> str:
        return self.scan.platform

    @property
    def cancelled(self) -> bool:
        return self.scan.cancel.is_set() or self.abandoned

    def check_cancel(self) -> None:
        if self.cancelled:
            raise Cancelled()

    def report(
        self,
        check_id: str,
        *,
        asset: str,
        title: str | None = None,
        severity: Severity | str | None = None,
        evidence: str = "",
        details: dict[str, Any] | None = None,
        confidence: Confidence = Confidence.FIRM,
        cves: list[str] | None = None,
        kev: bool = False,
        discriminator: str = "",
        tech: list[str] | None = None,
    ) -> Finding | None:
        """Reporta um achado. ``check_id`` precisa existir na base de conhecimento."""
        if self.abandoned:
            return None
        entry = kb.require(check_id)
        finding = Finding(
            check_id=check_id,
            title=title or entry.title,
            severity=Severity.parse(severity) if severity is not None else entry.severity,
            asset=asset,
            evidence=evidence,
            details=details or {},
            confidence=confidence,
            cves=sorted(set(cves or [])),
            kev=kev,
            discriminator=discriminator,
            tech=[t.lower() for t in (tech or [])],
            source=self.check.id,
        )
        self.findings_reported += 1
        return self.scan.add_finding(finding)

    def passed(self, control: str, text: str, asset: str = "") -> None:
        """Registra um controle verificado e aprovado (vai para "pontos fortes")."""
        if not self.abandoned:
            self.scan.add_passed(PassedControl(control=control, text=text, asset=asset))

    def add_fact(self, kind: str, key: str, /, reason: str = "", **data: Any) -> Fact | None:
        """Ensina um fato ao motor. ``kind`` e ``key`` são posicionais: ``data`` pode ter ``kind``."""
        if self.abandoned:
            return None
        data.setdefault("label", key)
        return self.scan.add_fact(
            Fact(kind=kind, key=key, data=data, source=self.check.id, reason=reason)
        )

    def facts(self, kind: str) -> list[Fact]:
        return self.scan.facts_of(kind)

    # -- atalhos para fatos padronizados (ver core/facts.py) ----------------------
    def add_http_service(self, url: str, reason: str) -> Fact | None:
        parts = urlsplit(url)
        host = parts.hostname or ""
        scheme = (parts.scheme or "https").lower()
        port = parts.port or (443 if scheme == "https" else 80)
        key = url if parts.path not in ("", "/") else base_url(scheme, host, port)
        fact = self.add_fact(
            facts.HTTP_SERVICE, key, reason, url=key, host=host, port=port, scheme=scheme
        )
        if scheme == "https":
            self.add_tls_service(host, port, reason=f"{key} usa HTTPS")
        return fact

    def add_tls_service(
        self, host: str, port: int, reason: str, sni: str | None = None
    ) -> Fact | None:
        server_name = sni if sni is not None else (None if is_ip(host) else host)
        return self.add_fact(
            facts.TLS_SERVICE, f"{host}:{port}", reason, host=host, port=port, sni=server_name
        )

    def add_tech(
        self,
        host: str,
        name: str,
        *,
        version: str | None = None,
        kind: str = "server",
        evidence: str = "",
        reason: str = "",
    ) -> Fact | None:
        clean = name.strip().lower()
        label = f"{name} {version}" if version else name
        fact = self.add_fact(
            facts.TECH,
            f"{host}:{clean}",
            reason or f"Tecnologia identificada em {host}: {label}",
            host=host,
            name=clean,
            version=version,
            kind=kind,
            evidence=evidence[:300],
            label=label,
        )
        if fact is not None and version and not fact.data.get("version"):
            fact.data["version"] = version
        return fact

    def techs(self, host: str | None = None) -> list[str]:
        """Tecnologias já identificadas (nomes em minúsculas), opcionalmente por host."""
        names: list[str] = []
        for fact in self.scan.facts_of("tech"):
            if host and fact.data.get("host") not in (None, host):
                continue
            name = str(fact.data.get("name", "")).lower()
            if name and name not in names:
                names.append(name)
        return names

    def log(self, text: str) -> None:
        self.scan.log(text)

    def memo(self, key: str, factory: Callable[[], T]) -> T:
        return self.scan.memo(key, factory)
