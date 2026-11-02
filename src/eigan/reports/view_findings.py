"""Achados para exibição: blocos por tipo de problema, ocorrências, KEV e pontos fortes.

A evidência e os detalhes passam de novo pelo mascaramento de segredos
(:func:`eigan.core.redact.redact`): o contexto da auditoria já mascara a evidência,
mas um resultado importado ou gravado por versão antiga não pode vazar um segredo
inteiro no relatório.
"""

from __future__ import annotations

from typing import Any

from ..core import fmt, kb
from ..core.kb import OWASP_2021
from ..core.models import Category, Finding, ScanResult, Severity, TriageStatus
from ..core.redact import redact
from ..intel import scoring
from ..intel.remediation import entry_for
from .common import (
    anchor,
    as_dict,
    as_list,
    band_view,
    clip,
    cve_url,
    cwe_url,
    severity_of,
    severity_view,
    web_link,
)

MAX_OCCURRENCES = 300
MAX_EVIDENCE = 4000
MAX_DETAIL = 1000
MAX_STRENGTH_ASSETS = 12

#: área do achado pelo prefixo do ``check_id`` quando o id já saiu da base de conhecimento
CATEGORY_BY_PREFIX = {
    "web": Category.WEB,
    "tls": Category.TLS,
    "dns": Category.DNS,
    "net": Category.NETWORK,
    "rede": Category.NETWORK,
    "host": Category.HOST,
    "code": Category.CODE,
    "codigo": Category.CODE,
    "logs": Category.LOGS,
}


def groups(
    result: ScanResult,
    action_of: dict[str, dict[str, Any]],
    scenario_titles: dict[str, str],
    kev_pairs: set[tuple[str, str]],
) -> list[dict[str, Any]]:
    """Um bloco por tipo de problema (``check_id``) com as ocorrências embaixo."""
    buckets: dict[str, list[Finding]] = {}
    for finding in result.findings:
        buckets.setdefault(finding.check_id, []).append(finding)
    blocks = [
        _group(check_id, items, action_of, scenario_titles, kev_pairs)
        for check_id, items in buckets.items()
    ]
    blocks.sort(
        key=lambda g: (-g["priority"], -severity_of(g["severity"]["value"]).rank, g["title"])
    )
    return blocks


def _group(
    check_id: str,
    items: list[Finding],
    action_of: dict[str, dict[str, Any]],
    scenario_titles: dict[str, str],
    kev_pairs: set[tuple[str, str]],
) -> dict[str, Any]:
    items.sort(key=lambda f: (-f.priority, -f.severity.rank, f.asset))
    entry = entry_for(items[0])
    worst = max((f.severity for f in items), key=lambda s: s.rank)
    action = next((action_of[f.fingerprint] for f in items if f.fingerprint in action_of), None)
    title = entry.title or items[0].title
    return {
        "check_id": check_id,
        "anchor": anchor("tipo", check_id),
        "title": title,
        "category": category_of(check_id, entry.category).label,
        "severity": severity_view(worst),
        "priority": max(f.priority for f in items),
        "summary": entry.summary if entry.summary != title else "",
        "explanation": entry.explanation,
        "risk": entry.risk,
        "cwe": entry.cwe or "",
        "cwe_url": cwe_url(entry.cwe or ""),
        "owasp": entry.owasp or "",
        "owasp_label": OWASP_2021.get(entry.owasp or "", ""),
        "references": [web_link(u) for u in entry.references],
        "count": len(items),
        "info_only": worst is Severity.INFO,
        "triaged_only": all(f.status is not TriageStatus.OPEN for f in items),
        "action": (
            {"anchor": action["anchor"], "index": action["index"], "title": action["title"]}
            if action
            else None
        ),
        "occurrences": [
            occurrence(f, title, worst, scenario_titles, kev_pairs) for f in items[:MAX_OCCURRENCES]
        ],
        "hidden": max(0, len(items) - MAX_OCCURRENCES),
    }


def occurrence(
    finding: Finding,
    group_title: str,
    group_worst: Severity,
    scenario_titles: dict[str, str],
    kev_pairs: set[tuple[str, str]],
) -> dict[str, Any]:
    """Uma ocorrência do problema: ativo, prioridade, situação, CVEs, evidência e detalhes."""
    evidence, clipped = clip(redact(finding.evidence.strip("\r\n")), MAX_EVIDENCE)
    band = finding.priority_label or scoring.priority_band(finding.priority)[0]
    cves = [
        {"id": cve, "url": cve_url(cve), "kev": (finding.fingerprint, cve) in kev_pairs}
        for cve in finding.cves
    ]
    return {
        "anchor": anchor("f", finding.fingerprint),
        "fingerprint": finding.fingerprint,
        "title": finding.title if finding.title != group_title else "",
        "asset": finding.asset,
        "priority": finding.priority,
        "band": band_view(band),
        "counts": scoring.counts_toward_score(finding),
        "severity": severity_view(finding.severity)
        if finding.severity is not group_worst
        else None,
        "confidence": finding.confidence.label,
        "exposure": finding.exposure.label,
        "status": {
            "value": finding.status.value,
            "label": finding.status.label,
            "note": finding.status_note,
            "open": finding.status is TriageStatus.OPEN,
        },
        "cves": cves,
        "kev": finding.kev,
        "evidence": evidence,
        "evidence_clipped": clipped,
        "details": [
            {"key": str(key), "value": clip(redact(detail_text(value)), MAX_DETAIL)[0]}
            for key, value in finding.details.items()
        ],
        "first_seen": fmt.date_time(finding.first_seen),
        "scenarios": [scenario_titles[s] for s in finding.scenarios if s in scenario_titles],
        "tech": ", ".join(str(t) for t in finding.tech),
    }


def overview(result: ScanResult) -> dict[str, int]:
    findings = result.findings
    return {
        "total": len(findings),
        "open": sum(1 for f in findings if scoring.counts_toward_score(f)),
        "triaged": sum(1 for f in findings if f.status in scoring.EXCLUDED),
        "info": sum(
            1 for f in findings if f.severity is Severity.INFO and f.status not in scoring.EXCLUDED
        ),
    }


def top_findings(result: ScanResult) -> list[dict[str, Any]]:
    """Achados que contam para a nota, do mais urgente para o menos urgente."""
    active = [f for f in result.findings if scoring.counts_toward_score(f)]
    active.sort(key=lambda f: (-f.priority, -f.severity.rank, f.check_id, f.asset))
    return [
        {
            "band": band_view(f.priority_label or scoring.priority_band(f.priority)[0]),
            "priority": f.priority,
            "severity": severity_view(f.severity),
            "title": f.title,
            "asset": f.asset,
            "kev": f.kev,
            "anchor": anchor("f", f.fingerprint),
        }
        for f in active
    ]


def category_of(check_id: str, fallback: Category) -> Category:
    if kb.get(check_id) is not None:
        return fallback
    return CATEGORY_BY_PREFIX.get(check_id.split(".", 1)[0].lower(), fallback)


def detail_text(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "sim" if value else "não"
    if isinstance(value, list | tuple | set | frozenset):
        return ", ".join(detail_text(v) for v in value) or "—"
    if isinstance(value, dict):
        return "; ".join(f"{k}: {detail_text(v)}" for k, v in value.items()) or "—"
    return str(value)


# -- KEV e pontos fortes ----------------------------------------------------------------------


def kev(raw_list: list[Any]) -> list[dict[str, Any]]:
    """Vulnerabilidades do catálogo CISA KEV encontradas, com o achado onde aparecem."""
    items = []
    for raw in raw_list:
        item = as_dict(raw)
        cve = str(item.get("cve") or "")
        if not cve:
            continue
        items.append(
            {
                "cve": cve,
                "url": cve_url(cve),
                "name": str(item.get("name") or ""),
                "vendor": str(item.get("vendor") or ""),
                "product": str(item.get("product") or ""),
                "date_added": fmt.date_only(str(item.get("date_added") or "")),
                "ransomware": bool(item.get("ransomware")),
                "title": str(item.get("title") or ""),
                "asset": str(item.get("asset") or ""),
                "finding": str(item.get("finding") or ""),
                "anchor": anchor("f", str(item.get("finding") or "")),
            }
        )
    return items


def strengths(result: ScanResult, narrative: dict[str, Any]) -> list[dict[str, Any]]:
    """Um item por controle aprovado, com todos os ativos em que ele foi verificado."""
    source = [p.to_dict() for p in result.passed] or as_list(narrative.get("strengths"))
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for raw in source:
        item = as_dict(raw)
        text = str(item.get("text") or "").strip()
        if not text:
            continue
        control = str(item.get("control") or "")
        slot = grouped.setdefault((control, text), {"control": control, "text": text, "all": []})
        asset = str(item.get("asset") or "")
        if asset and asset not in slot["all"]:
            slot["all"].append(asset)
    return [
        {
            "control": slot["control"],
            "text": slot["text"],
            "assets": slot["all"][:MAX_STRENGTH_ASSETS],
            "more": max(0, len(slot["all"]) - MAX_STRENGTH_ASSETS),
        }
        for slot in grouped.values()
    ]
