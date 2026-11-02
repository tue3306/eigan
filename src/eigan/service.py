"""Fluxo completo de uma auditoria, usado pelo painel e pela linha de comando.

motor de regras → exposição dos ativos → triagem salva → primeira aparição →
análise (prioridade, nota, cenários, plano, comparação) → histórico.
"""

from __future__ import annotations

import threading
from typing import Any

from .core.context import EventSink
from .core.engine import Engine
from .core.models import ScanResult, TriageStatus
from .core.settings import Settings, load_settings
from .core.target import parse_target
from .intel import exposure
from .intel.analysis import analyze
from .storage import Store


def run_audit(
    target_text: str,
    *,
    kind: str | None = None,
    profile: str | None = None,
    settings: Settings | None = None,
    store: Store | None = None,
    emit: EventSink | None = None,
    cancel: threading.Event | None = None,
    scan_id: str | None = None,
    options: dict[str, Any] | None = None,
) -> ScanResult:
    """Executa a auditoria, analisa, salva no histórico e devolve o resultado."""
    target = parse_target(target_text, kind)
    settings = settings or load_settings()
    if profile:
        settings = settings.with_profile(profile)
    result = Engine(settings).run(
        target, emit=emit, cancel=cancel, scan_id=scan_id, options=options
    )
    store = store or Store()
    exposure.assign(result)
    store.apply_triage(result)
    store.mark_first_seen(result)
    analyze(result, store.previous(result))
    store.save(result)
    if emit is not None:
        posture = result.analysis.get("posture", {})
        emit(
            {
                "type": "scan_saved",
                "id": result.id,
                "status": result.status,
                "score": posture.get("score"),
                "grade": posture.get("grade"),
            }
        )
    return result


def reanalyze(store: Store, scan_id: str) -> ScanResult | None:
    result = store.get(scan_id)
    if result is None:
        return None
    analyze(result, store.previous(result))
    store.save(result)
    return result


def set_triage(
    store: Store, scan_id: str, fingerprint: str, status: TriageStatus, note: str = ""
) -> ScanResult | None:
    """Muda a triagem de um achado (vale para as próximas auditorias do mesmo alvo)."""
    result = store.get(scan_id)
    if result is None:
        return None
    finding = next((f for f in result.findings if f.fingerprint == fingerprint), None)
    if finding is None:
        return None
    store.set_triage(result.kind.value, result.target, fingerprint, status, note)
    finding.status = status
    finding.status_note = note
    analyze(result, store.previous(result))
    store.save(result)
    return result
