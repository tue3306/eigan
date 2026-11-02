"""Plano de correção: agrupa os achados pela ação que os resolve.

Vários achados costumam ter a mesma correção (cinco cabeçalhos ausentes = um bloco
de configuração no servidor). O plano junta esses achados em uma **ação**, escolhe os
exemplos de configuração das tecnologias detectadas e monta um único trecho por
tecnologia, pronto para copiar. A ordem segue prioridade, exploração conhecida,
esforço e ganho de nota.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field

from ..core import kb
from ..core.kb import EFFORT_LABEL, EFFORT_RANK, FIX_GROUPS, Fix, KBEntry
from ..core.models import Category, Finding, Severity
from . import scoring

# Prefixo/sufixo de comentário por linguagem do exemplo (None = sem comentários).
_COMMENT: dict[str, tuple[str, str] | None] = {
    "xml": ("<!-- ", " -->"),
    "html": ("<!-- ", " -->"),
    "javascript": ("// ", ""),
    "js": ("// ", ""),
    "typescript": ("// ", ""),
    "php": ("// ", ""),
    "java": ("// ", ""),
    "csharp": ("// ", ""),
    "go": ("// ", ""),
    "sql": ("-- ", ""),
    "ini": ("; ", ""),
    "dns": ("; ", ""),
    "json": None,
}
_MAX_ASSETS = 25


@dataclass
class Problem:
    entry: KBEntry
    findings: list[Finding]

    @property
    def worst(self) -> Severity:
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def to_dict(self) -> dict[str, object]:
        assets = sorted({f.asset for f in self.findings})
        return {
            "id": self.entry.id,
            "title": self.entry.title,
            "summary": self.entry.summary,
            "severity": self.worst.value,
            "count": len(self.findings),
            "assets": assets[:_MAX_ASSETS],
            "more_assets": max(0, len(assets) - _MAX_ASSETS),
            "steps": list(self.entry.steps),
            "verify": self.entry.verify,
            "references": list(self.entry.references),
            "findings": [f.fingerprint for f in self.findings],
        }


@dataclass
class Action:
    group: str
    title: str
    area: str
    problems: list[Problem]
    priority: int = 0
    band: str = "P4"
    band_text: str = ""
    effort: str = "baixo"
    kev: bool = False
    score_gain: int = 0
    fixes: list[dict[str, str]] = field(default_factory=list)

    @property
    def findings(self) -> list[Finding]:
        return [f for p in self.problems for f in p.findings]

    @property
    def fingerprints(self) -> set[str]:
        return {f.fingerprint for f in self.findings}

    @property
    def quick_win(self) -> bool:
        return self.effort == "baixo" and self.priority >= 25

    def sort_key(self) -> tuple[int, int, int, int, int, int]:
        return (
            scoring.BAND_RANK.get(self.band, 9),
            0 if self.kev else 1,
            EFFORT_RANK.get(self.effort, 1),
            -self.priority,
            -self.score_gain,
            -len(self.findings),
        )

    def to_dict(self) -> dict[str, object]:
        findings = self.findings
        assets = sorted({f.asset for f in findings})
        return {
            "group": self.group,
            "title": self.title,
            "area": self.area,
            "priority": self.priority,
            "band": self.band,
            "band_text": self.band_text,
            "effort": self.effort,
            "effort_label": EFFORT_LABEL.get(self.effort, self.effort),
            "kev": self.kev,
            "score_gain": self.score_gain,
            "quick_win": self.quick_win,
            "count": len(findings),
            "assets": assets[:_MAX_ASSETS],
            "more_assets": max(0, len(assets) - _MAX_ASSETS),
            "worst": max((f.severity for f in findings), key=lambda s: s.rank).value,
            "problems": [p.to_dict() for p in self.problems],
            "fixes": self.fixes,
            "findings": [f.fingerprint for f in findings],
        }


def _fallback_entry(finding: Finding) -> KBEntry:
    """Entrada mínima para achados antigos cujo id saiu da base."""
    return KBEntry(
        id=finding.check_id,
        title=finding.title,
        category=Category.HOST,
        severity=finding.severity,
        summary=finding.title,
        explanation="",
        risk="",
        steps=(),
        verify="",
        fix_group="configuracao",
    )


def entry_for(finding: Finding) -> KBEntry:
    return kb.get(finding.check_id) or _fallback_entry(finding)


def _comment(lang: str, text: str) -> str:
    style = _COMMENT.get(lang.lower(), ("# ", ""))
    if style is None:
        return ""
    prefix, suffix = style
    return f"{prefix}{text}{suffix}"


def _pick_fixes(examples: tuple[Fix, ...], techs: set[str]) -> list[Fix]:
    if not techs:
        return list(examples)
    chosen = [fx for fx in examples if fx.tech.lower() in techs]
    if chosen:
        return chosen
    generic = [fx for fx in examples if fx.tech.lower() == "generico"]
    return generic or list(examples)


@dataclass
class _Snippet:
    tech: str
    label: str
    lang: str
    parts: list[tuple[str, str]] = field(default_factory=list)

    def code(self) -> str:
        if len(self.parts) == 1:
            return self.parts[0][1]
        blocks = []
        for title, snippet in self.parts:
            header = _comment(self.lang, title)
            blocks.append(f"{header}\n{snippet}" if header else snippet)
        return "\n\n".join(blocks)


def merge_fixes(problems: list[Problem]) -> list[dict[str, str]]:
    """Um trecho por tecnologia, juntando os exemplos de todos os problemas da ação."""
    techs = Counter(t for p in problems for f in p.findings for t in f.tech)
    merged: dict[str, _Snippet] = {}
    for problem in problems:
        for fx in _pick_fixes(problem.entry.examples, set(techs)):
            tech = fx.tech.lower()
            snippet = merged.setdefault(tech, _Snippet(tech, fx.label, fx.lang))
            code = fx.code.strip("\n")
            if all(existing != code for _title, existing in snippet.parts):
                snippet.parts.append((problem.entry.title, code))
    ordered = sorted(
        merged.values(),
        key=lambda s: (-techs.get(s.tech, 0), s.tech == "generico", s.label.lower()),
    )
    return [{"tech": s.tech, "label": s.label, "lang": s.lang, "code": s.code()} for s in ordered]


def build_plan(
    findings: list[Finding],
    *,
    gain: Callable[[set[str]], int] | None = None,
) -> list[Action]:
    """Monta as ações a partir dos achados que contam para a nota."""
    groups: dict[str, dict[str, Problem]] = {}
    for finding in findings:
        if not scoring.counts_toward_score(finding):
            continue
        entry = entry_for(finding)
        group = entry.fix_group if entry.fix_group in FIX_GROUPS else "configuracao"
        bucket = groups.setdefault(group, {})
        bucket.setdefault(entry.id, Problem(entry, [])).findings.append(finding)

    actions: list[Action] = []
    for group, problems_by_id in groups.items():
        problems = sorted(
            problems_by_id.values(),
            key=lambda p: (-p.worst.rank, -max(f.priority for f in p.findings), p.entry.id),
        )
        info = FIX_GROUPS.get(group, {"title": group, "area": ""})
        action = Action(group=group, title=info["title"], area=info["area"], problems=problems)
        action.priority = max(f.priority for f in action.findings)
        action.band, action.band_text = scoring.priority_band(action.priority)
        action.effort = max((p.entry.effort for p in problems), key=lambda e: EFFORT_RANK.get(e, 1))
        action.kev = any(f.kev for f in action.findings)
        action.fixes = merge_fixes(problems)
        if gain is not None:
            action.score_gain = gain(action.fingerprints)
        actions.append(action)
    actions.sort(key=Action.sort_key)
    return actions
