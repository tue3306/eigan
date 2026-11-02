"""Prioridade de cada achado e nota de postura (0–100, A+ a F), sem IA.

A prioridade combina, de forma transparente:

- severidade técnica (da base de conhecimento ou da checagem);
- confiança (confirmado pesa mais que indício);
- exposição (Internet pesa mais que rede interna);
- exploração conhecida (CVE no catálogo CISA KEV vira prioridade máxima);
- participação em um cenário de risco (problemas que se combinam).

A nota parte de 100 e desconta penalidades por achado, com retorno decrescente
para o mesmo tipo de problema repetido em vários ativos (dez cookies sem flag não
valem dez vezes um). Achados críticos e altos limitam a nota máxima.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

from ..core.models import Confidence, Finding, Severity, TriageStatus

SEVERITY_WEIGHT = {
    Severity.INFO: 0.0,
    Severity.LOW: 2.5,
    Severity.MEDIUM: 5.0,
    Severity.HIGH: 7.5,
    Severity.CRITICAL: 9.5,
}
SEVERITY_PENALTY = {
    Severity.INFO: 0.0,
    Severity.LOW: 1.5,
    Severity.MEDIUM: 5.0,
    Severity.HIGH: 12.0,
    Severity.CRITICAL: 25.0,
}
#: (piso, rótulo, prazo sugerido)
PRIORITY_BANDS = (
    (75, "P1", "Imediata: corrigir em até 72 horas"),
    (50, "P2", "Alta: corrigir em até 7 dias"),
    (25, "P3", "Média: corrigir em até 30 dias"),
    (1, "P4", "Baixa: planejar na próxima janela de manutenção"),
)
SCENARIO_BOOST = 8
GRADES = ((90, "A"), (80, "B"), (70, "C"), (55, "D"), (40, "E"), (0, "F"))
GRADE_ORDER = ("A+", "A", "B", "C", "D", "E", "F")
GRADE_LABEL = {
    "A+": "Excelente",
    "A": "Muito boa",
    "B": "Boa",
    "C": "Regular",
    "D": "Fraca",
    "E": "Ruim",
    "F": "Crítica",
    "—": "Sem dados",
}

#: Achados que não contam: risco aceito, falso positivo e "marcado como corrigido".
EXCLUDED = (TriageStatus.ACCEPTED, TriageStatus.FALSE_POSITIVE, TriageStatus.FIXED)


def counts_toward_score(finding: Finding) -> bool:
    return finding.severity is not Severity.INFO and finding.status not in EXCLUDED


def priority_of(finding: Finding, *, in_scenario: bool = False) -> int:
    """Prioridade de 0 a 100 (0 = informativo)."""
    if finding.severity is Severity.INFO:
        return 0
    base = SEVERITY_WEIGHT[finding.severity]
    if finding.kev:
        base = 10.0
    elif finding.cves:
        base += 0.3
    score = base * finding.confidence.factor * finding.exposure.factor * 10
    if in_scenario:
        score += SCENARIO_BOOST
    if finding.kev:
        # Exploração ativa conhecida: no mínimo P1 quando a detecção é firme.
        score = max(score, 75 if finding.confidence is not Confidence.TENTATIVE else 50)
    return max(1, min(100, round(score)))


def priority_band(score: int) -> tuple[str, str]:
    for floor, label, text in PRIORITY_BANDS:
        if score >= floor:
            return label, text
    return "Info", "Informativo: sem ação obrigatória"


BAND_RANK = {"P1": 0, "P2": 1, "P3": 2, "P4": 3, "Info": 4}


@dataclass
class Posture:
    score: int
    grade: str
    penalty: float
    cap_reason: str = ""

    @property
    def label(self) -> str:
        return GRADE_LABEL.get(self.grade, "")

    def to_dict(self) -> dict[str, object]:
        return {
            "score": self.score,
            "grade": self.grade,
            "label": self.label,
            "penalty": round(self.penalty, 1),
            "cap_reason": self.cap_reason,
        }


def posture(findings: Iterable[Finding]) -> Posture:
    active = [f for f in findings if counts_toward_score(f)]
    if not active:
        return Posture(score=100, grade="A+", penalty=0.0)
    seen: dict[str, int] = defaultdict(int)
    total = 0.0
    for finding in sorted(active, key=lambda f: (-f.severity.rank, -f.confidence.factor)):
        seen[finding.check_id] += 1
        repeat = 0.5 ** (seen[finding.check_id] - 1)
        total += (
            SEVERITY_PENALTY[finding.severity]
            * finding.confidence.factor
            * max(finding.exposure.factor, 0.8)
            * repeat
        )
    score = max(0, round(100 - total))
    grade = next(letter for floor, letter in GRADES if score >= floor)
    cap = ""
    worst = max(f.severity.rank for f in active)
    if any(f.kev for f in active):
        grade, cap = "F", "Há vulnerabilidade com exploração ativa conhecida (catálogo CISA KEV)."
    elif worst >= Severity.CRITICAL.rank and _better_than(grade, "D"):
        grade, cap = "D", "Achados críticos limitam a nota a D até serem corrigidos."
    elif worst >= Severity.HIGH.rank and _better_than(grade, "C"):
        grade, cap = "C", "Achados de severidade alta limitam a nota a C até serem corrigidos."
    return Posture(score=score, grade=grade, penalty=total, cap_reason=cap)


def _better_than(grade: str, other: str) -> bool:
    return GRADE_ORDER.index(grade) < GRADE_ORDER.index(other)


def without(findings: Iterable[Finding], fingerprints: set[str]) -> list[Finding]:
    return [f for f in findings if f.fingerprint not in fingerprints]
