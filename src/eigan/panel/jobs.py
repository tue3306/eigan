"""Auditorias em segundo plano para o painel, com eventos ao vivo.

Cada auditoria vira um ``Job`` executado em uma thread. Os eventos do motor (decisões,
progresso, achados) ficam numerados em memória para o painel acompanhar por SSE e
retomar a conexão sem perder nada (``Last-Event-ID``).
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..core.models import now_iso
from ..core.settings import Settings
from ..core.target import Target, parse_target
from ..service import run_audit
from ..storage import Store

log = logging.getLogger(__name__)

MAX_EVENTS = 20_000
MAX_PARALLEL = 2
KEEP_FINISHED = 30


@dataclass
class Job:
    id: str
    target: Target
    profile: str
    options: dict[str, Any]
    status: str = "na_fila"  # na_fila | em_andamento | concluida | cancelada | erro
    created_at: str = field(default_factory=now_iso)
    finished_at: str = ""
    error: str = ""
    done: int = 0
    total: int = 0
    counts: dict[str, int] = field(
        default_factory=lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    )
    last_decision: str = ""
    score: int | None = None
    grade: str = ""
    events: list[dict[str, Any]] = field(default_factory=list)
    first_seq: int = 0
    cancel: threading.Event = field(default_factory=threading.Event)
    cond: threading.Condition = field(default_factory=threading.Condition)

    @property
    def finished(self) -> bool:
        return self.status in ("concluida", "cancelada", "erro")

    def push(self, event: dict[str, Any]) -> None:
        kind = event.get("type")
        if kind == "progress" or kind == "check_finished":
            self.done = int(event.get("done", self.done))
            self.total = int(event.get("total", self.total))
        elif kind == "finding":
            severity = event.get("finding", {}).get("severity", "info")
            self.counts[severity] = self.counts.get(severity, 0) + 1
        elif kind == "decision":
            self.last_decision = str(event.get("text", ""))
        elif kind == "scan_saved":
            self.score = event.get("score")
            self.grade = str(event.get("grade") or "")
        with self.cond:
            event = {**event, "seq": self.first_seq + len(self.events), "t": time.time()}
            self.events.append(event)
            if len(self.events) > MAX_EVENTS:
                drop = len(self.events) - MAX_EVENTS
                del self.events[:drop]
                self.first_seq += drop
            self.cond.notify_all()

    def events_since(self, seq: int, timeout: float) -> list[dict[str, Any]]:
        """Eventos com número >= ``seq``; espera até ``timeout`` se ainda não houver."""
        with self.cond:
            if self.first_seq + len(self.events) <= seq and not self.finished:
                self.cond.wait(timeout)
            start = max(0, seq - self.first_seq)
            return list(self.events[start:])

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target.display,
            "kind": self.target.kind.value,
            "kind_label": self.target.kind.label,
            "profile": self.profile,
            "status": self.status,
            "created_at": self.created_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "done": self.done,
            "total": self.total,
            "counts": dict(self.counts),
            "last_decision": self.last_decision,
            "score": self.score,
            "grade": self.grade,
            "result_id": self.id if self.status in ("concluida", "cancelada") else None,
        }


class JobManager:
    def __init__(
        self,
        store: Store,
        settings_loader: Callable[[], Settings],
        *,
        max_parallel: int = MAX_PARALLEL,
    ) -> None:
        self.store = store
        self.settings_loader = settings_loader
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(max_parallel)

    def start(
        self,
        target_text: str,
        *,
        kind: str | None = None,
        profile: str | None = None,
        options: dict[str, Any] | None = None,
    ) -> Job:
        """Valida o alvo e enfileira a auditoria. ``TargetError`` se o alvo for inválido."""
        target = parse_target(target_text, kind)
        settings = self.settings_loader()
        if profile:
            settings = settings.with_profile(profile)
        opts = dict(options or {})
        if "include_ports" in opts:
            settings.include_ports_for_url = bool(opts["include_ports"])
        if opts.get("ports"):
            settings.ports = str(opts["ports"])
        job = Job(id=uuid.uuid4().hex[:12], target=target, profile=settings.profile, options=opts)
        with self._lock:
            self._jobs[job.id] = job
            self._trim()
        thread = threading.Thread(
            target=self._run, args=(job, settings), name=f"eigan-job-{job.id}", daemon=True
        )
        thread.start()
        return job

    def _run(self, job: Job, settings: Settings) -> None:
        job.push({"type": "queued"})
        with self._slots:
            if job.cancel.is_set():
                job.status = "cancelada"
                job.finished_at = now_iso()
                job.push({"type": "job_finished", "status": job.status})
                return
            job.status = "em_andamento"
            try:
                result = run_audit(
                    job.target.raw,
                    kind=job.target.kind.value,
                    settings=settings,
                    store=self.store,
                    emit=job.push,
                    cancel=job.cancel,
                    scan_id=job.id,
                    options=job.options,
                )
                job.status = (
                    result.status if result.status in ("concluida", "cancelada") else "concluida"
                )
            except Exception as exc:  # noqa: BLE001 — erro vira estado visível no painel
                log.exception("auditoria %s falhou", job.id)
                job.status = "erro"
                job.error = f"{type(exc).__name__}: {exc}"
            job.finished_at = now_iso()
            job.push({"type": "job_finished", "status": job.status, "error": job.error})

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def summaries(self) -> list[dict[str, Any]]:
        with self._lock:
            jobs = list(self._jobs.values())
        return [j.summary() for j in sorted(jobs, key=lambda j: j.created_at, reverse=True)]

    def active(self) -> int:
        with self._lock:
            return sum(1 for j in self._jobs.values() if not j.finished)

    def cancel(self, job_id: str) -> bool:
        job = self.get(job_id)
        if job is None or job.finished:
            return False
        job.cancel.set()
        job.push({"type": "cancel_requested"})
        return True

    def cancel_all(self) -> None:
        with self._lock:
            jobs = list(self._jobs.values())
        for job in jobs:
            if not job.finished:
                job.cancel.set()

    def _trim(self) -> None:
        finished = sorted(
            (j for j in self._jobs.values() if j.finished), key=lambda j: j.created_at
        )
        for job in finished[: max(0, len(finished) - KEEP_FINISHED)]:
            self._jobs.pop(job.id, None)
