"""Modelos do domínio: severidade, confiança, fatos, achados e o resultado da auditoria.

Tudo aqui é dado puro (sem I/O). Os achados apontam para uma entrada da base de
conhecimento pelo ``check_id``; é a base que explica o problema e ensina a corrigir.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


def now_iso() -> str:
    """Data/hora atual em UTC, ISO 8601 (segundos)."""
    return datetime.now(UTC).replace(microsecond=0).isoformat()


class Severity(StrEnum):
    """Severidade técnica do problema (antes de considerar exposição e contexto)."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @property
    def label(self) -> str:
        return _SEVERITY_LABEL[self]

    @classmethod
    def parse(cls, value: str | Severity) -> Severity:
        """Aceita o valor canônico ou o nome em português (``alta``, ``crítica``...)."""
        if isinstance(value, Severity):
            return value
        text = str(value).strip().lower()
        text = text.replace("í", "i").replace("é", "e")
        aliases = {
            "informativo": "info",
            "informativa": "info",
            "baixa": "low",
            "media": "medium",
            "alta": "high",
            "critica": "critical",
            "critico": "critical",
        }
        return cls(aliases.get(text, text))


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
_SEVERITY_LABEL = {
    Severity.INFO: "Informativo",
    Severity.LOW: "Baixa",
    Severity.MEDIUM: "Média",
    Severity.HIGH: "Alta",
    Severity.CRITICAL: "Crítica",
}


class Confidence(StrEnum):
    """Quão certo o EIGAN está do achado."""

    CONFIRMED = "confirmed"  # comprovado pela resposta (ex.: conteúdo do .git lido)
    FIRM = "firm"  # forte indício técnico (ex.: versão vulnerável no banner)
    TENTATIVE = "tentative"  # heurística; vale conferir manualmente

    @property
    def label(self) -> str:
        return {"confirmed": "Confirmado", "firm": "Provável", "tentative": "Indício"}[self.value]

    @property
    def factor(self) -> float:
        return {"confirmed": 1.0, "firm": 0.85, "tentative": 0.6}[self.value]


class Category(StrEnum):
    WEB = "web"
    TLS = "tls"
    DNS = "dns"
    NETWORK = "rede"
    HOST = "host"
    CODE = "codigo"
    LOGS = "logs"

    @property
    def label(self) -> str:
        return {
            "web": "Web",
            "tls": "TLS / certificados",
            "dns": "DNS e e-mail",
            "rede": "Rede e serviços",
            "host": "Sistema (hardening)",
            "codigo": "Código e dependências",
            "logs": "Logs e detecção",
        }[self.value]


class TargetKind(StrEnum):
    URL = "url"
    HOST = "host"
    LOCAL = "local"
    PROJECT = "projeto"
    LOGS = "logs"

    @property
    def label(self) -> str:
        return {
            "url": "Site ou aplicação web",
            "host": "Servidor ou rede",
            "local": "Esta máquina",
            "projeto": "Pasta de projeto",
            "logs": "Logs",
        }[self.value]


class Exposure(StrEnum):
    """Onde o problema vive — pesa na prioridade (Internet pesa mais)."""

    INTERNET = "internet"
    INTERNAL = "interna"
    LOCAL = "local"
    CODE = "codigo"
    LOGS = "logs"

    @property
    def label(self) -> str:
        return {
            "internet": "Exposto à Internet",
            "interna": "Rede interna",
            "local": "Máquina local",
            "codigo": "Código-fonte",
            "logs": "Evento em log",
        }[self.value]

    @property
    def factor(self) -> float:
        return {"internet": 1.0, "interna": 0.8, "local": 0.75, "codigo": 0.8, "logs": 1.0}[
            self.value
        ]


class TriageStatus(StrEnum):
    OPEN = "aberto"
    ACCEPTED = "aceito"  # risco aceito conscientemente
    FALSE_POSITIVE = "falso_positivo"
    FIXED = "corrigido"  # marcado como corrigido (a próxima auditoria confirma)

    @property
    def label(self) -> str:
        return {
            "aberto": "Aberto",
            "aceito": "Risco aceito",
            "falso_positivo": "Falso positivo",
            "corrigido": "Marcado como corrigido",
        }[self.value]


@dataclass
class Fact:
    """Algo que o motor aprendeu sobre o alvo e que pode disparar novas checagens.

    ``kind`` é o tipo (ex.: ``http.service``), ``key`` identifica o fato para não
    repetir trabalho e ``reason`` explica, em uma frase, por que o fato existe —
    é isso que aparece na linha do tempo do raciocínio.
    """

    kind: str
    key: str
    data: dict[str, Any] = field(default_factory=dict)
    source: str = "alvo"
    reason: str = ""

    @property
    def label(self) -> str:
        return str(self.data.get("label") or self.key)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "key": self.key,
            "data": self.data,
            "source": self.source,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Fact:
        return cls(
            kind=raw["kind"],
            key=raw["key"],
            data=dict(raw.get("data") or {}),
            source=raw.get("source", "alvo"),
            reason=raw.get("reason", ""),
        )


@dataclass
class Finding:
    """Um problema encontrado. A explicação e a correção vêm da base pelo ``check_id``."""

    check_id: str
    title: str
    severity: Severity
    asset: str
    evidence: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    confidence: Confidence = Confidence.FIRM
    cves: list[str] = field(default_factory=list)
    kev: bool = False
    #: diferencia achados do mesmo tipo no mesmo ativo (ex.: nome do cookie)
    discriminator: str = ""
    #: tecnologias envolvidas — escolhem o exemplo de correção certo (nginx, iis...)
    tech: list[str] = field(default_factory=list)
    source: str = ""  # id da checagem que reportou
    # Preenchidos pela análise (intel):
    exposure: Exposure = Exposure.INTERNET
    priority: int = 0
    priority_label: str = ""
    scenarios: list[str] = field(default_factory=list)
    status: TriageStatus = TriageStatus.OPEN
    status_note: str = ""
    first_seen: str = field(default_factory=now_iso)

    @property
    def fingerprint(self) -> str:
        """Identidade estável do achado (mesmo problema no mesmo ativo)."""
        basis = "|".join(
            [self.check_id, self.asset.strip().lower(), self.discriminator.strip().lower()]
        )
        # O ativo pode vir do alvo auditado; caractere inválido não pode derrubar o relatório.
        return hashlib.sha256(basis.encode("utf-8", "backslashreplace")).hexdigest()[:16]

    @property
    def is_actionable(self) -> bool:
        return self.severity is not Severity.INFO and self.status in (
            TriageStatus.OPEN,
            TriageStatus.FIXED,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.value,
            "asset": self.asset,
            "evidence": self.evidence,
            "details": self.details,
            "confidence": self.confidence.value,
            "cves": list(self.cves),
            "kev": self.kev,
            "discriminator": self.discriminator,
            "tech": list(self.tech),
            "source": self.source,
            "exposure": self.exposure.value,
            "priority": self.priority,
            "priority_label": self.priority_label,
            "scenarios": list(self.scenarios),
            "status": self.status.value,
            "status_note": self.status_note,
            "first_seen": self.first_seen,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Finding:
        return cls(
            check_id=raw["check_id"],
            title=raw.get("title", raw["check_id"]),
            severity=Severity.parse(raw.get("severity", "info")),
            asset=raw.get("asset", ""),
            evidence=raw.get("evidence", ""),
            details=dict(raw.get("details") or {}),
            confidence=Confidence(raw.get("confidence", "firm")),
            cves=list(raw.get("cves") or []),
            kev=bool(raw.get("kev", False)),
            discriminator=raw.get("discriminator", ""),
            tech=list(raw.get("tech") or []),
            source=raw.get("source", ""),
            exposure=Exposure(raw.get("exposure", "internet")),
            priority=int(raw.get("priority", 0)),
            priority_label=raw.get("priority_label", ""),
            scenarios=list(raw.get("scenarios") or []),
            status=TriageStatus(raw.get("status", "aberto")),
            status_note=raw.get("status_note", ""),
            first_seen=raw.get("first_seen") or now_iso(),
        )


@dataclass
class PassedControl:
    """Um controle verificado e aprovado — entra em "pontos fortes" do relatório."""

    control: str
    text: str
    asset: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"control": self.control, "text": self.text, "asset": self.asset}

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> PassedControl:
        return cls(control=raw["control"], text=raw.get("text", ""), asset=raw.get("asset", ""))


@dataclass
class Decision:
    """Uma decisão do motor de regras (linha do tempo do raciocínio)."""

    at: str
    text: str
    check_id: str = ""
    fact_key: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "at": self.at,
            "text": self.text,
            "check_id": self.check_id,
            "fact_key": self.fact_key,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Decision:
        return cls(
            at=raw.get("at", ""),
            text=raw.get("text", ""),
            check_id=raw.get("check_id", ""),
            fact_key=raw.get("fact_key", ""),
        )


@dataclass
class CheckRun:
    """Registro de uma execução de checagem sobre um fato."""

    check_id: str
    name: str
    fact_key: str
    status: str  # "ok" | "erro" | "tempo_esgotado" | "cancelada"
    duration: float = 0.0
    message: str = ""
    findings: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "name": self.name,
            "fact_key": self.fact_key,
            "status": self.status,
            "duration": round(self.duration, 3),
            "message": self.message,
            "findings": self.findings,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> CheckRun:
        return cls(
            check_id=raw["check_id"],
            name=raw.get("name", raw["check_id"]),
            fact_key=raw.get("fact_key", ""),
            status=raw.get("status", "ok"),
            duration=float(raw.get("duration", 0.0)),
            message=raw.get("message", ""),
            findings=int(raw.get("findings", 0)),
        )


@dataclass
class ScanResult:
    """Tudo o que uma auditoria produziu — base do painel, dos relatórios e do histórico."""

    id: str
    target: str
    kind: TargetKind
    profile: str
    started_at: str
    finished_at: str = ""
    status: str = "em_andamento"  # em_andamento | concluida | cancelada | erro
    findings: list[Finding] = field(default_factory=list)
    facts: list[Fact] = field(default_factory=list)
    passed: list[PassedControl] = field(default_factory=list)
    decisions: list[Decision] = field(default_factory=list)
    runs: list[CheckRun] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    options: dict[str, Any] = field(default_factory=dict)
    analysis: dict[str, Any] = field(default_factory=dict)
    app_version: str = ""

    @property
    def duration(self) -> float:
        if not self.finished_at:
            return 0.0
        try:
            start = datetime.fromisoformat(self.started_at)
            end = datetime.fromisoformat(self.finished_at)
        except ValueError:
            return 0.0
        return max(0.0, (end - start).total_seconds())

    def facts_of(self, kind: str) -> list[Fact]:
        return [f for f in self.facts if f.kind == kind]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "kind": self.kind.value,
            "profile": self.profile,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration": round(self.duration, 1),
            "status": self.status,
            "findings": [f.to_dict() for f in self.findings],
            "facts": [f.to_dict() for f in self.facts],
            "passed": [p.to_dict() for p in self.passed],
            "decisions": [d.to_dict() for d in self.decisions],
            "runs": [r.to_dict() for r in self.runs],
            "errors": list(self.errors),
            "options": self.options,
            "analysis": self.analysis,
            "app_version": self.app_version,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ScanResult:
        return cls(
            id=str(raw["id"]),
            target=raw["target"],
            kind=TargetKind(raw.get("kind", "url")),
            profile=raw.get("profile", "padrao"),
            started_at=raw.get("started_at", ""),
            finished_at=raw.get("finished_at", ""),
            status=raw.get("status", "concluida"),
            findings=[Finding.from_dict(f) for f in raw.get("findings") or []],
            facts=[Fact.from_dict(f) for f in raw.get("facts") or []],
            passed=[PassedControl.from_dict(p) for p in raw.get("passed") or []],
            decisions=[Decision.from_dict(d) for d in raw.get("decisions") or []],
            runs=[CheckRun.from_dict(r) for r in raw.get("runs") or []],
            errors=list(raw.get("errors") or []),
            options=dict(raw.get("options") or {}),
            analysis=dict(raw.get("analysis") or {}),
            app_version=raw.get("app_version", ""),
        )
