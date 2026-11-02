"""Motor de regras: o "cérebro" determinístico do EIGAN.

Funciona por encadeamento para frente (forward chaining) sobre um quadro de
fatos. O alvo vira fatos iniciais; cada fato dispara as checagens que o
consomem; as checagens reportam achados e aprendem novos fatos (uma porta que
fala HTTP, um WordPress, um certificado...), que disparam novas checagens. Cada
decisão fica registrada com o motivo — a linha do tempo explica por que cada
verificação foi feita, sem caixa-preta e sem IA.
"""

from __future__ import annotations

import logging
import threading
import time
import traceback
import uuid
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from typing import Any

from .. import __version__
from .context import Cancelled, CheckContext, EventSink, ScanContext
from .models import CheckRun, Decision, Fact, ScanResult, now_iso
from .registry import Check, checks_for, load_builtin_checks
from .settings import Settings
from .target import Target, seed_facts

log = logging.getLogger("eigan.engine")

#: tetos de fatos por tipo — evitam que um alvo enorme vire uma auditoria sem fim
_FACT_LIMIT_SETTINGS = {"http.service": "max_http_services", "host": "max_network_hosts"}


@dataclass
class _Job:
    check: Check
    fact: Fact
    cctx: CheckContext
    started: float | None = None
    status: str = "ok"
    message: str = ""
    duration: float = 0.0
    extra: dict[str, Any] = field(default_factory=dict)


class Engine:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or Settings()

    def run(
        self,
        target: Target,
        *,
        emit: EventSink | None = None,
        cancel: threading.Event | None = None,
        scan_id: str | None = None,
        options: dict[str, Any] | None = None,
    ) -> ScanResult:
        load_builtin_checks()
        settings = self.settings
        external_cancel = cancel or threading.Event()
        internal_cancel = threading.Event()
        ctx = _LimitedScanContext(target, settings, emit=emit, cancel=internal_cancel)
        result = ScanResult(
            id=scan_id or uuid.uuid4().hex[:12],
            target=target.display,
            kind=target.kind,
            profile=settings.profile,
            started_at=now_iso(),
            options=dict(options or {}),
            app_version=__version__,
        )
        ctx.emit(
            {
                "type": "scan_started",
                "id": result.id,
                "target": result.target,
                "kind": target.kind.value,
                "profile": settings.profile,
            }
        )
        for fact in seed_facts(target, include_ports=settings.include_ports_for_url):
            ctx.add_fact(fact)

        scheduled: set[tuple[str, str]] = set()
        running: dict[Future[None], _Job] = {}
        decisions: list[Decision] = []
        runs: list[CheckRun] = []
        total = 0
        done = 0
        deadline = time.monotonic() + settings.scan_timeout
        cancelled = False
        pool = ThreadPoolExecutor(max_workers=settings.workers, thread_name_prefix="eigan-check")
        try:
            while True:
                if external_cancel.is_set() or time.monotonic() > deadline:
                    cancelled = True
                    internal_cancel.set()
                    if time.monotonic() > deadline:
                        result.errors.append(
                            "Tempo máximo da auditoria atingido; resultado parcial."
                        )
                    break

                for fact in ctx.take_pending():
                    matches = [
                        c
                        for c in checks_for(fact, settings.profile, ctx.platform)
                        if (c.id, fact.key) not in scheduled
                    ]
                    if not matches:
                        continue
                    decision = Decision(
                        at=now_iso(), text=_decision_text(fact, matches), fact_key=fact.key
                    )
                    decisions.append(decision)
                    ctx.emit({"type": "decision", "text": decision.text, "at": decision.at})
                    for item in matches:
                        scheduled.add((item.id, fact.key))
                        job = _Job(check=item, fact=fact, cctx=CheckContext(ctx, item, fact))
                        running[pool.submit(self._execute, job)] = job
                        total += 1
                    ctx.emit({"type": "progress", "done": done, "total": total})

                if not running:
                    if ctx.has_pending():
                        continue
                    break

                finished, _ = wait(list(running), timeout=0.25, return_when=FIRST_COMPLETED)
                for fut in finished:
                    job = running.pop(fut)
                    runs.append(self._record(job))
                    done += 1
                    ctx.emit(_finished_event(job, done, total))

                now = time.monotonic()
                for fut, job in list(running.items()):
                    if job.started is not None and now - job.started > job.check.timeout:
                        job.cctx.abandoned = True
                        job.status = "tempo_esgotado"
                        job.message = f"Excedeu {int(job.check.timeout)} s; resultado parcial."
                        job.duration = now - job.started
                        running.pop(fut)
                        runs.append(self._record(job))
                        done += 1
                        ctx.emit(_finished_event(job, done, total))
        finally:
            for fut, job in running.items():
                fut.cancel()
                job.cctx.abandoned = True
                job.status = "cancelada"
                runs.append(self._record(job))
            internal_cancel.set()
            pool.shutdown(wait=False, cancel_futures=True)

        result.findings = sorted(
            ctx.findings.values(), key=lambda f: (-f.severity.rank, f.check_id, f.asset)
        )
        result.facts = list(ctx.facts.values())
        result.passed = list(ctx.passed)
        result.decisions = decisions
        result.runs = runs
        result.errors.extend(
            f"{r.name}: {r.message}" for r in runs if r.status == "erro" and r.message
        )
        result.status = "cancelada" if cancelled and external_cancel.is_set() else "concluida"
        result.finished_at = now_iso()
        ctx.emit(
            {
                "type": "scan_finished",
                "id": result.id,
                "status": result.status,
                "findings": len(result.findings),
                "duration": round(result.duration, 1),
            }
        )
        return result

    @staticmethod
    def _execute(job: _Job) -> None:
        job.started = time.monotonic()
        job.cctx.scan.emit(
            {
                "type": "check_started",
                "check_id": job.check.id,
                "name": job.check.name,
                "fact": job.fact.label,
            }
        )
        try:
            job.check.func(job.cctx, job.fact)
        except Cancelled:
            job.status = "cancelada"
        except Exception as exc:  # noqa: BLE001 — uma checagem com defeito não derruba as outras
            job.status = "erro"
            job.message = f"{type(exc).__name__}: {exc}"
            log.error(
                "checagem %s falhou em %s:\n%s", job.check.id, job.fact.key, traceback.format_exc()
            )
        finally:
            if job.status not in ("tempo_esgotado",):
                job.duration = time.monotonic() - (job.started or time.monotonic())

    @staticmethod
    def _record(job: _Job) -> CheckRun:
        return CheckRun(
            check_id=job.check.id,
            name=job.check.name,
            fact_key=job.fact.key,
            status=job.status,
            duration=job.duration,
            message=job.message,
            findings=job.cctx.findings_reported,
        )


class _LimitedScanContext(ScanContext):
    """Contexto com teto de fatos por tipo (definido nas configurações)."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._warned: set[str] = set()

    def add_fact(self, fact: Fact) -> Fact:
        setting = _FACT_LIMIT_SETTINGS.get(fact.kind)
        if setting is not None and (fact.kind, fact.key) not in self.facts:
            limit = int(getattr(self.settings, setting))
            if len(self.facts_of(fact.kind)) >= limit:
                if fact.kind not in self._warned:
                    self._warned.add(fact.kind)
                    self.log(
                        f"Limite de {limit} itens do tipo '{fact.kind}' atingido; o resto foi ignorado."
                    )
                return fact
        return super().add_fact(fact)

    def has_pending(self) -> bool:
        with self._lock:
            return bool(self.pending)


def _decision_text(fact: Fact, checks: list[Check]) -> str:
    names = [c.name for c in checks]
    shown = ", ".join(names[:6])
    if len(names) > 6:
        shown += f" e mais {len(names) - 6}"
    reason = (fact.reason or f"{fact.kind}: {fact.label}").rstrip(".")
    return f"{reason}. Próximas verificações: {shown}."


def _finished_event(job: _Job, done: int, total: int) -> dict[str, Any]:
    return {
        "type": "check_finished",
        "check_id": job.check.id,
        "name": job.check.name,
        "fact": job.fact.label,
        "status": job.status,
        "duration": round(job.duration, 2),
        "findings": job.cctx.findings_reported,
        "done": done,
        "total": total,
    }
