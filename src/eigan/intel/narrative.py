"""Resumo em português gerado por modelos de texto (sem IA).

Cada frase vem de um modelo fixo preenchido com números e nomes da auditoria. Assim o
texto é previsível, verificável e igual para o mesmo resultado.
"""

from __future__ import annotations

from typing import Any

from ..core import fmt
from ..core.models import Finding, ScanResult, Severity, TargetKind
from ..core.settings import PROFILE_LABEL
from . import scoring
from .correlation import ScenarioMatch
from .remediation import Action, entry_for

NOT_EVALUATED = {
    TargetKind.URL: (
        "Não foi possível avaliar o alvo: nenhuma verificação obteve resposta. Confira o "
        "endereço, a conexão e se o site está no ar."
    ),
    TargetKind.HOST: (
        "Não foi possível avaliar o alvo: nenhum serviço respondeu. Confira o endereço, a "
        "conexão e se um firewall bloqueia o acesso."
    ),
    TargetKind.LOCAL: "Não foi possível avaliar esta máquina: nenhuma verificação se aplicou.",
    TargetKind.PROJECT: (
        "Nenhum arquivo analisável foi encontrado nesta pasta. Confira o caminho do projeto."
    ),
    TargetKind.LOGS: (
        "Nenhum registro de log reconhecido foi encontrado. Confira o caminho e o formato do log."
    ),
}

RISK_WORD = {
    Severity.CRITICAL: "crítico",
    Severity.HIGH: "alto",
    Severity.MEDIUM: "médio",
    Severity.LOW: "baixo",
}


def severity_phrase(findings: list[Finding]) -> str:
    """``"1 de risco crítico, 2 de risco alto e 3 de risco médio"``."""
    parts = []
    for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        n = sum(1 for f in findings if f.severity is severity)
        if n:
            parts.append(f"{n} de risco {RISK_WORD[severity]}")
    return fmt.join_pt(parts)


def _headline(
    result: ScanResult,
    active: list[Finding],
    evaluated: bool,
) -> str:
    if not evaluated:
        return NOT_EVALUATED.get(result.kind, NOT_EVALUATED[TargetKind.URL])
    if not active:
        return "Nenhum problema encontrado nas verificações realizadas."
    urgent = sum(1 for f in active if f.priority >= 75)
    if urgent == 1:
        return "1 problema exige correção imediata."
    if urgent > 1:
        return f"{urgent} problemas exigem correção imediata."
    if len(active) == 1:
        return "1 problema para corrigir, nenhum urgente."
    return f"{len(active)} problemas para corrigir, nenhum urgente."


def build(
    result: ScanResult,
    *,
    posture: scoring.Posture,
    plan: list[Action],
    scenarios: list[ScenarioMatch],
    what_if: dict[str, Any] | None,
    diff: dict[str, Any] | None,
    evaluated: bool,
) -> dict[str, Any]:
    active = sorted(
        (f for f in result.findings if scoring.counts_toward_score(f)),
        key=lambda f: (-f.priority, -f.severity.rank),
    )
    paragraphs: list[str] = []

    kind_label = result.kind.label.lower()
    profile = PROFILE_LABEL.get(result.profile, result.profile).lower()
    ran = len(result.runs)
    scope = (
        f"A auditoria de {result.target} ({kind_label}, perfil {profile}) executou "
        f"{fmt.plural(ran, 'verificação', 'verificações')} em {fmt.duration(result.duration)}."
    )
    if result.status == "cancelada":
        scope += " Ela foi cancelada antes do fim, então o resultado é parcial."
    paragraphs.append(scope)

    if evaluated:
        if active:
            paragraphs.append(
                f"Foram encontrados {fmt.plural(len(active), 'problema', 'problemas')}: "
                f"{severity_phrase(active)}. A nota de postura é {posture.grade} "
                f"({posture.score}/100, {posture.label.lower()})."
                + (f" {posture.cap_reason}" if posture.cap_reason else "")
            )
            top = active[0]
            entry = entry_for(top)
            risk = f" {entry.risk}" if entry.risk else ""
            paragraphs.append(f"O ponto mais urgente é “{top.title}” em {top.asset}.{risk}")
        else:
            paragraphs.append(
                f"Nenhum problema foi encontrado e a nota de postura é {posture.grade} "
                f"({posture.score}/100). Isso vale para o que foi verificado; mantenha as "
                "auditorias periódicas."
            )

    if scenarios:
        first = scenarios[0]
        count = len(scenarios)
        intro = (
            "Há 1 combinação perigosa de problemas"
            if count == 1
            else f"Há {count} combinações perigosas de problemas"
        )
        paragraphs.append(
            f"{intro}. A mais grave: {first.scenario.title.lower()}. "
            f"{first.scenario.narrative} {first.scenario.breaker}"
        )

    kev = [f for f in active if f.kev]
    if kev:
        cves = sorted({c for f in kev for c in f.cves})
        verb = "consta" if len(cves) == 1 else "constam"
        paragraphs.append(
            f"{fmt.join_pt(cves)} {verb} do catálogo CISA KEV: são falhas já exploradas por "
            "atacantes reais. Trate como prioridade máxima."
        )

    if plan:
        quick = sum(1 for a in plan if a.quick_win)
        text = f"O plano de correção tem {fmt.plural(len(plan), 'ação', 'ações')}"
        text += f", {quick} de esforço baixo." if quick else "."
        if what_if and what_if.get("actions"):
            n = int(what_if["actions"])
            first_n = "a primeira" if n == 1 else f"as {n} primeiras"
            text += (
                f" Fazendo {first_n}, a nota estimada vai de {posture.score} "
                f"para {what_if['score']} ({what_if['grade']})."
            )
        paragraphs.append(text)

    if diff:
        fixed, new, still = len(diff["fixed"]), len(diff["new"]), len(diff["persisting"])
        paragraphs.append(
            f"Em relação à auditoria de {fmt.date_time(diff['previous_date'])}: "
            f"{fmt.plural(fixed, 'problema corrigido', 'problemas corrigidos')}, "
            f"{fmt.plural(new, 'novo', 'novos')} e {fmt.plural(still, 'ainda aberto', 'ainda abertos')}. "
            f"A nota foi de {diff['score_before']} para {diff['score_after']}."
        )

    if result.errors:
        paragraphs.append(
            f"{fmt.plural(len(result.errors), 'verificação não terminou', 'verificações não terminaram')}"
            " (veja a linha do tempo); o resultado pode estar incompleto."
        )

    strengths: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for control in result.passed:
        key = (control.control, control.text)
        if key in seen:
            continue
        seen.add(key)
        strengths.append({"control": control.control, "text": control.text, "asset": control.asset})

    return {
        "headline": _headline(result, active, evaluated),
        "paragraphs": paragraphs,
        "top_risks": [
            {
                "fingerprint": f.fingerprint,
                "title": f.title,
                "asset": f.asset,
                "severity": f.severity.value,
                "priority": f.priority,
                "band": f.priority_label,
                "risk": entry_for(f).risk,
            }
            for f in active[:5]
        ],
        "strengths": strengths,
        "next_steps": [
            {"group": a.group, "title": a.title, "band": a.band, "band_text": a.band_text}
            for a in plan[:3]
        ],
    }
