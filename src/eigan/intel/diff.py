"""Comparação entre duas auditorias do mesmo alvo (o que foi corrigido, o que surgiu).

Um achado só conta como **corrigido** se a checagem que o encontrou rodou de novo e não
o reportou. Se a nova auditoria usou um perfil mais leve e a checagem nem rodou, o achado
fica como **não verificado** — assim a comparação nunca dá falsa sensação de progresso.
"""

from __future__ import annotations

from typing import Any

from ..core.models import Finding, ScanResult
from . import scoring


def _brief(finding: Finding) -> dict[str, Any]:
    return {
        "fingerprint": finding.fingerprint,
        "check_id": finding.check_id,
        "title": finding.title,
        "asset": finding.asset,
        "severity": finding.severity.value,
    }


def compare(current: ScanResult, previous: ScanResult) -> dict[str, Any]:
    now = {f.fingerprint: f for f in current.findings if scoring.counts_toward_score(f)}
    before = {f.fingerprint: f for f in previous.findings if scoring.counts_toward_score(f)}
    ran_ok = {run.check_id for run in current.runs if run.status == "ok"}

    new = [now[fp] for fp in now if fp not in before]
    persisting = [now[fp] for fp in now if fp in before]
    fixed: list[Finding] = []
    unverified: list[Finding] = []
    for fp, finding in before.items():
        if fp in now:
            continue
        (fixed if finding.source in ran_ok else unverified).append(finding)

    score_before = int(
        previous.analysis.get("posture", {}).get("score", scoring.posture(previous.findings).score)
    )
    score_after = scoring.posture(current.findings).score
    return {
        "previous_id": previous.id,
        "previous_date": previous.started_at,
        "previous_profile": previous.profile,
        "new": [_brief(f) for f in new],
        "fixed": [_brief(f) for f in fixed],
        "persisting": [_brief(f) for f in persisting],
        "unverified": [_brief(f) for f in unverified],
        "score_before": score_before,
        "score_after": score_after,
        "grade_before": str(previous.analysis.get("posture", {}).get("grade", "")),
        "delta": score_after - score_before,
    }
