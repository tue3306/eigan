"""Análise completa de uma auditoria — tudo que o painel, a CLI e os relatórios mostram.

Ordem do raciocínio:

1. correlaciona os achados em cenários de risco;
2. calcula a prioridade de cada achado (com bônus para quem participa de cenário);
3. calcula a nota de postura e o plano de correção (com ganho de nota por ação);
4. simula a nota após as primeiras ações do plano ("e se eu corrigir isto?");
5. compara com a auditoria anterior do mesmo alvo, se houver;
6. escreve o resumo em português e monta conformidade e inventário.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..core import atualizacao, vulndb
from ..core.models import Category, ScanResult, Severity
from . import compliance, correlation, diff, inventory, narrative, remediation, scoring

ANALYSIS_VERSION = 1
WHAT_IF_ACTIONS = 3
QUICK_WINS = 5

_CONTROL_CATEGORY = {
    "web": Category.WEB,
    "tls": Category.TLS,
    "dns": Category.DNS,
    "net": Category.NETWORK,
    "host": Category.HOST,
    "code": Category.CODE,
    "logs": Category.LOGS,
}


def analyze(result: ScanResult, previous: ScanResult | None = None) -> dict[str, Any]:
    """Calcula a análise, grava em ``result.analysis`` e devolve o dicionário."""
    findings = result.findings
    matches = correlation.correlate(findings)
    scenarios_of: dict[str, list[str]] = defaultdict(list)
    for match in matches:
        for fp in match.fingerprints:
            if match.scenario.id not in scenarios_of[fp]:
                scenarios_of[fp].append(match.scenario.id)
    for finding in findings:
        finding.scenarios = scenarios_of.get(finding.fingerprint, [])
        finding.priority = scoring.priority_of(finding, in_scenario=bool(finding.scenarios))
        finding.priority_label = scoring.priority_band(finding.priority)[0]
    findings.sort(key=lambda f: (-f.priority, -f.severity.rank, f.check_id, f.asset))

    # Avaliado = alguma verificação respondeu: achou algo, aprovou um controle ou aprendeu
    # um fato novo. Um site fora do ar não pode ganhar nota A+ por não ter achados.
    evaluated = (
        bool(findings) or bool(result.passed) or any(f.source != "alvo" for f in result.facts)
    )
    current = scoring.posture(findings)

    def gain(fingerprints: set[str]) -> int:
        return scoring.posture(scoring.without(findings, fingerprints)).score - current.score

    plan = remediation.build_plan(findings, gain=gain)
    what_if: dict[str, Any] | None = None
    if plan:
        top = plan[:WHAT_IF_ACTIONS]
        fixed: set[str] = set()
        for action in top:
            fixed |= action.fingerprints
        after = scoring.posture(scoring.without(findings, fixed))
        what_if = {
            "actions": len(top),
            "groups": [a.group for a in top],
            "score": after.score,
            "grade": after.grade,
            "label": after.label,
        }

    comparison = diff.compare(result, previous) if previous is not None else None

    posture = current.to_dict()
    if not evaluated:
        posture.update(grade="—", label=scoring.GRADE_LABEL["—"], cap_reason="")

    active = [f for f in findings if scoring.counts_toward_score(f)]
    counts: dict[str, int] = {s.value: 0 for s in Severity}
    for finding in active:
        counts[finding.severity.value] += 1
    counts["info"] = sum(1 for f in findings if f.severity is Severity.INFO)
    counts["open"] = len(active)
    counts["triaged"] = sum(1 for f in findings if f.status in scoring.EXCLUDED)
    counts["total"] = len(findings)

    priorities = {band: 0 for band in ("P1", "P2", "P3", "P4")}
    for finding in active:
        if finding.priority_label in priorities:
            priorities[finding.priority_label] += 1

    analysis: dict[str, Any] = {
        "version": ANALYSIS_VERSION,
        "evaluated": evaluated,
        "posture": posture,
        "what_if": what_if,
        "counts": counts,
        "priorities": priorities,
        "categories": _categories(result),
        "kev": _kev(result),
        "scenarios": [m.to_dict() for m in matches],
        "plan": [a.to_dict() for a in plan],
        "quick_wins": [a.group for a in plan if a.quick_win][:QUICK_WINS],
        "narrative": narrative.build(
            result,
            posture=current,
            plan=plan,
            scenarios=matches,
            what_if=what_if,
            diff=comparison,
            evaluated=evaluated,
        ),
        "compliance": compliance.build(findings),
        "inventory": inventory.build(result.facts),
        "diff": comparison,
        "stats": _stats(result),
        "kev_catalog": vulndb.catalog_info(),
        "catalogos": atualizacao.resumo(),
    }
    if not evaluated:
        analysis["narrative"]["paragraphs"] = analysis["narrative"]["paragraphs"][:1]
    result.analysis = analysis
    return analysis


def _categories(result: ScanResult) -> list[dict[str, Any]]:
    stats: dict[Category, dict[str, Any]] = {
        c: {"id": c.value, "label": c.label, "count": 0, "worst": "", "passed": 0} for c in Category
    }
    for finding in result.findings:
        if not scoring.counts_toward_score(finding):
            continue
        slot = stats[remediation.entry_for(finding).category]
        slot["count"] += 1
        if not slot["worst"] or finding.severity.rank > Severity(slot["worst"]).rank:
            slot["worst"] = finding.severity.value
    for control in result.passed:
        category = _CONTROL_CATEGORY.get(control.control.split(".", 1)[0])
        if category is not None:
            stats[category]["passed"] += 1
    return [s for s in stats.values() if s["count"] or s["passed"]]


def _kev(result: ScanResult) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for finding in result.findings:
        if not finding.kev:
            continue
        for cve in finding.cves:
            entry = vulndb.kev_entry(cve)
            if entry is None or (cve, finding.fingerprint) in seen:
                continue
            seen.add((cve, finding.fingerprint))
            items.append(
                {
                    "cve": cve,
                    "name": entry.name,
                    "vendor": entry.vendor,
                    "product": entry.product,
                    "date_added": entry.date_added,
                    "ransomware": entry.ransomware,
                    "finding": finding.fingerprint,
                    "title": finding.title,
                    "asset": finding.asset,
                }
            )
    return items


def _stats(result: ScanResult) -> dict[str, Any]:
    by_status: dict[str, int] = defaultdict(int)
    for run in result.runs:
        by_status[run.status] += 1
    return {
        "checks": len(result.runs),
        "ok": by_status.get("ok", 0),
        "errors": by_status.get("erro", 0),
        "timeouts": by_status.get("tempo_esgotado", 0),
        "cancelled": by_status.get("cancelada", 0),
        "facts": len(result.facts),
        "passed": len(result.passed),
        "duration": round(result.duration, 1),
    }
