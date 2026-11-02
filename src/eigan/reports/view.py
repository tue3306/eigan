"""Modelo de apresentação compartilhado pelo relatório HTML e pelo PDF.

Lê ``result.analysis`` com tolerância (uma análise gravada por versão antiga pode não
ter todas as chaves) e entrega dicionários prontos para exibir: datas no fuso local,
rótulos em português, âncoras e listas já ordenadas. Os modelos só exibem; nenhuma
conta é feita neles. Todo texto sai com os caracteres invisíveis à mostra
(:func:`~eigan.reports.common.deep_visible`).

Este módulo monta capa, veredito, resumo, cenários e plano; os achados ficam em
:mod:`.view_findings` e os anexos (conformidade, comparação, inventário, linha do
tempo) em :mod:`.view_annex`.
"""

from __future__ import annotations

from typing import Any

from .. import __version__
from ..core import fmt
from ..core.kb import EFFORT_LABEL, FIX_GROUPS
from ..core.models import ScanResult, now_iso
from ..core.settings import PROFILE_LABEL
from ..intel import scoring
from .common import (
    BANDS,
    SEVERITY_ORDER,
    SEVERITY_PLURAL,
    STATUS_LABEL,
    STATUS_NOTE,
    anchor,
    as_dict,
    as_int,
    as_list,
    band_view,
    deep_scrub,
    deep_visible,
    ensure_analysis,
    points,
    severity_view,
    web_link,
)
from .view_annex import compliance, diff, footer, inventory, timeline
from .view_findings import groups, kev, overview, strengths, top_findings

FIXES_OPEN = 2
GRADE_CSS = {"A+": "a", "A": "a", "B": "b", "C": "c", "D": "d", "E": "d", "F": "f"}


def build_view(result: ScanResult) -> dict[str, Any]:
    """Tudo o que os relatórios exibem, já formatado (calcula a análise se faltar)."""
    analysis = ensure_analysis(result)
    evaluated = bool(analysis.get("evaluated", bool(result.findings or result.passed)))
    narrative = as_dict(analysis.get("narrative"))
    scenarios = _scenarios(as_list(analysis.get("scenarios")))
    plan = _plan(as_list(analysis.get("plan")))
    kev_items = kev(as_list(analysis.get("kev")))
    action_of = {fp: action for action in plan for fp in action["findings"]}
    scenario_titles = {s["id"]: s["title"] for s in scenarios}
    kev_pairs = {(item["finding"], item["cve"]) for item in kev_items}
    view: dict[str, Any] = {
        "meta": _meta(result, analysis),
        "verdict": _verdict(result, analysis, narrative, evaluated),
        "summary": _summary(narrative),
        "scenarios": scenarios,
        "plan": plan,
        "quick_wins": sum(1 for action in plan if action["quick_win"]),
        "groups": groups(result, action_of, scenario_titles, kev_pairs),
        "overview": overview(result),
        "top_findings": top_findings(result),
        "kev": kev_items,
        "strengths": strengths(result, narrative),
        "compliance": compliance(as_dict(analysis.get("compliance"))),
        "diff": diff(result, analysis.get("diff")),
        "inventory": inventory(as_dict(analysis.get("inventory"))),
        "timeline": timeline(result),
        "footer": footer(as_dict(analysis.get("kev_catalog")), as_dict(analysis.get("catalogos"))),
    }
    view["toc"] = _toc(view)
    _drop_dead_links(view)
    cleaned: dict[str, Any] = deep_visible(deep_scrub(view))
    return cleaned


# -- capa e veredito ------------------------------------------------------------------


def _meta(result: ScanResult, analysis: dict[str, Any]) -> dict[str, Any]:
    stats = as_dict(analysis.get("stats"))
    checks = as_int(stats.get("checks"), len(result.runs))
    unfinished = sum(as_int(stats.get(key)) for key in ("errors", "timeouts", "cancelled"))
    checks_text = str(checks)
    if unfinished:
        checks_text += f" ({fmt.plural(unfinished, 'não terminou', 'não terminaram')})"
    return {
        "target": result.target,
        "kind": result.kind.label,
        "profile": PROFILE_LABEL.get(result.profile, result.profile),
        "started": fmt.date_time(result.started_at),
        "finished": fmt.date_time(result.finished_at),
        "duration": fmt.duration(result.duration) if result.finished_at else "",
        "status": result.status,
        "status_label": STATUS_LABEL.get(result.status, result.status),
        "status_note": STATUS_NOTE.get(result.status, ""),
        "version": result.app_version or __version__,
        "generator": __version__,
        "scan_id": result.id,
        "generated": fmt.date_time(now_iso()),
        "checks": checks,
        "checks_text": checks_text,
        "facts": as_int(stats.get("facts"), len(result.facts)),
        "passed": as_int(stats.get("passed"), len(result.passed)),
    }


def _verdict(
    result: ScanResult,
    analysis: dict[str, Any],
    narrative: dict[str, Any],
    evaluated: bool,
) -> dict[str, Any]:
    posture = as_dict(analysis.get("posture"))
    grade = str(posture.get("grade") or "—") if evaluated else "—"
    score = as_int(posture.get("score"))
    counts = as_dict(analysis.get("counts"))
    priorities = as_dict(analysis.get("priorities"))
    headline = str(narrative.get("headline") or "")
    if not evaluated and not headline:
        headline = "Não foi possível avaliar o alvo: nenhuma verificação obteve resposta."
    return {
        "evaluated": evaluated,
        "grade": grade,
        "grade_css": GRADE_CSS.get(grade, "none"),
        "score": score,
        "label": str(posture.get("label") or scoring.GRADE_LABEL.get(grade, "")),
        "cap_reason": str(posture.get("cap_reason") or "") if evaluated else "",
        "headline": headline,
        "counts": [
            {"key": sev.value, "label": SEVERITY_PLURAL[sev], "n": as_int(counts.get(sev.value))}
            for sev in SEVERITY_ORDER
        ],
        "open": as_int(counts.get("open")),
        "triaged": as_int(counts.get("triaged")),
        "total": as_int(counts.get("total"), len(result.findings)),
        "priorities": [
            {"band": band_view(band), "n": as_int(priorities.get(band))} for band in BANDS
        ],
        "what_if": _what_if_text(as_dict(analysis.get("what_if")), score) if evaluated else "",
    }


def _what_if_text(what_if: dict[str, Any], score: int) -> str:
    actions = as_int(what_if.get("actions"))
    after = as_int(what_if.get("score"), score)
    if actions <= 0 or after <= score:
        return ""
    first = "a primeira ação" if actions == 1 else f"as {actions} primeiras ações"
    grade = str(what_if.get("grade") or "")
    text = f"Corrigindo {first} do plano, a nota estimada sobe de {score} para {after}"
    return text + (f" ({grade})." if grade else ".")


def _summary(narrative: dict[str, Any]) -> dict[str, Any]:
    risks = []
    for raw in as_list(narrative.get("top_risks")):
        item = as_dict(raw)
        if not item:
            continue
        risks.append(
            {
                "title": str(item.get("title") or ""),
                "asset": str(item.get("asset") or ""),
                "severity": severity_view(item.get("severity")),
                "band": band_view(item.get("band")),
                "priority": as_int(item.get("priority")),
                "risk": str(item.get("risk") or ""),
                "anchor": anchor("f", str(item.get("fingerprint") or "")),
            }
        )
    return {
        "paragraphs": [str(p) for p in as_list(narrative.get("paragraphs")) if p],
        "top_risks": risks,
    }


# -- cenários e plano -------------------------------------------------------------------


def _scenarios(raw_list: list[Any]) -> list[dict[str, Any]]:
    scenarios = []
    for raw in raw_list:
        item = as_dict(raw)
        if not item:
            continue
        host = str(item.get("host") or "")
        scenarios.append(
            {
                "id": str(item.get("id") or ""),
                "title": str(item.get("title") or ""),
                "severity": severity_view(item.get("severity")),
                "narrative": str(item.get("narrative") or ""),
                "breaker": str(item.get("breaker") or ""),
                "where": host or "todo o alvo",
                "titles": [str(t) for t in as_list(item.get("titles"))],
                "assets": [str(a) for a in as_list(item.get("assets"))],
                "findings": [str(fp) for fp in as_list(item.get("findings"))],
            }
        )
    return scenarios


def _plan(raw_actions: list[Any]) -> list[dict[str, Any]]:
    actions = []
    for index, raw in enumerate(raw_actions, 1):
        item = as_dict(raw)
        group = str(item.get("group") or "")
        effort = str(item.get("effort") or "")
        gain = as_int(item.get("score_gain"))
        fixes = [as_dict(f) for f in as_list(item.get("fixes"))]
        actions.append(
            {
                "index": index,
                "group": group,
                "anchor": f"acao-{index}",
                "title": str(item.get("title") or FIX_GROUPS.get(group, {}).get("title") or group),
                "area": str(item.get("area") or ""),
                "band": band_view(item.get("band"), str(item.get("band_text") or "")),
                "priority": as_int(item.get("priority")),
                "effort": str(item.get("effort_label") or EFFORT_LABEL.get(effort, effort)),
                "gain": gain,
                "gain_text": f"+{points(gain)}" if gain > 0 else "",
                "quick_win": bool(item.get("quick_win")),
                "kev": bool(item.get("kev")),
                "count": as_int(item.get("count")),
                "worst": severity_view(item.get("worst")),
                "assets": [str(a) for a in as_list(item.get("assets"))],
                "more_assets": as_int(item.get("more_assets")),
                "problems": [_problem(as_dict(p)) for p in as_list(item.get("problems"))],
                "fixes": [
                    {
                        "tech": str(fx.get("tech") or ""),
                        "label": str(fx.get("label") or fx.get("tech") or ""),
                        "lang": str(fx.get("lang") or ""),
                        "code": str(fx.get("code") or ""),
                        "open": position < FIXES_OPEN,
                    }
                    for position, fx in enumerate(fixes)
                    if fx.get("code")
                ],
                "findings": [str(fp) for fp in as_list(item.get("findings"))],
            }
        )
    return actions


def _problem(item: dict[str, Any]) -> dict[str, Any]:
    problem_id = str(item.get("id") or "")
    return {
        "id": problem_id,
        "anchor": anchor("tipo", problem_id),
        "title": str(item.get("title") or problem_id),
        "summary": str(item.get("summary") or ""),
        "severity": severity_view(item.get("severity")),
        "count": as_int(item.get("count")),
        "assets": [str(a) for a in as_list(item.get("assets"))],
        "more_assets": as_int(item.get("more_assets")),
        "steps": [str(s) for s in as_list(item.get("steps")) if s],
        "verify": str(item.get("verify") or ""),
        "references": [web_link(str(u)) for u in as_list(item.get("references")) if u],
    }


# -- navegação --------------------------------------------------------------------------


def _drop_dead_links(view: dict[str, Any]) -> None:
    """Tira o link de quem aponta para uma ocorrência além do limite exibido por bloco."""
    shown = {o["anchor"] for group in view["groups"] for o in group["occurrences"]}
    linked = [*view["summary"]["top_risks"], *view["top_findings"], *view["kev"]]
    if view["diff"]:
        for key in ("fixed", "new", "persisting", "unverified"):
            linked += view["diff"][key]
    for item in linked:
        if item["anchor"] not in shown:
            item["anchor"] = ""


def _toc(view: dict[str, Any]) -> list[dict[str, str]]:
    evaluated = view["verdict"]["evaluated"]
    sections = (
        ("resumo", "Resumo", bool(view["summary"]["paragraphs"] or view["summary"]["top_risks"])),
        ("cenarios", "Cenários de risco", bool(view["scenarios"])),
        ("plano", "Plano de correção", bool(view["plan"])),
        ("achados", "Achados", bool(view["groups"])),
        ("kev", "Exploração conhecida", bool(view["kev"])),
        ("pontos-fortes", "Pontos fortes", evaluated or bool(view["strengths"])),
        ("conformidade", "Conformidade", evaluated),
        ("comparacao", "Comparação", view["diff"] is not None),
        ("inventario", "Inventário", bool(view["inventory"])),
        ("linha-do-tempo", "Linha do tempo", not view["timeline"]["empty"]),
    )
    return [{"anchor": key, "title": title} for key, title, shown in sections if shown]
