"""Nota base CVSS v3.x a partir do vetor (para registros OSV sem severidade rotulada).

Fórmulas e pesos da especificação CVSS v3.1 (FIRST):
https://www.first.org/cvss/v3.1/specification-document
"""

from __future__ import annotations

import math

from ...core.models import Severity

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    """Arredondamento para cima com uma casa (Apêndice A da especificação 3.1)."""
    scaled = round(value * 100_000)
    if scaled % 10_000 == 0:
        return scaled / 100_000.0
    return (math.floor(scaled / 10_000) + 1) / 10.0


def base_score(vector: str) -> float | None:
    """Nota base (0.0–10.0) de um vetor ``CVSS:3.x/...``; ``None`` se o vetor for inválido."""
    if not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    metrics: dict[str, str] = {}
    for part in vector.split("/")[1:]:
        name, _, value = part.partition(":")
        metrics[name] = value
    try:
        scope_changed = metrics["S"] == "C"
        pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED
        exploitability = (
            8.22
            * _AV[metrics["AV"]]
            * _AC[metrics["AC"]]
            * pr_table[metrics["PR"]]
            * _UI[metrics["UI"]]
        )
        iss = 1 - ((1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]]))
    except KeyError:
        return None
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    total = impact + exploitability
    if scope_changed:
        total *= 1.08
    return _roundup(min(total, 10.0))


def severity_from_score(score: float) -> Severity:
    """Faixas qualitativas da especificação CVSS."""
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


def severity_from_vector(vector: str) -> Severity | None:
    score = base_score(vector)
    return None if score is None else severity_from_score(score)
