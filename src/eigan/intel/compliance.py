"""Mapeamento dos achados para OWASP Top 10 (2021), CIS Controls v8, CWE e LGPD."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..core.kb import CIS_V8, OWASP_2021
from ..core.models import Finding, Severity
from . import scoring
from .remediation import entry_for

LGPD_TEXT = (
    "A LGPD (Lei 13.709/2018, art. 46) exige medidas técnicas de segurança para proteger "
    "dados pessoais de acessos não autorizados e de vazamentos. Os achados marcados podem "
    "expor dados pessoais e devem entrar no plano de adequação do controlador."
)


def _worst(findings: list[Finding]) -> str:
    if not findings:
        return ""
    return max((f.severity for f in findings), key=lambda s: s.rank).value


def _cwe_number(cwe: str) -> str:
    return cwe.upper().removeprefix("CWE-").strip()


def build(findings: list[Finding]) -> dict[str, Any]:
    active = [f for f in findings if scoring.counts_toward_score(f)]
    owasp: dict[str, list[Finding]] = defaultdict(list)
    cis: dict[str, list[Finding]] = defaultdict(list)
    cwe: dict[str, list[Finding]] = defaultdict(list)
    lgpd: list[Finding] = []
    for finding in active:
        entry = entry_for(finding)
        if entry.owasp:
            owasp[entry.owasp].append(finding)
        for control in entry.cis:
            cis[control].append(finding)
        if entry.cwe:
            cwe[entry.cwe.upper()].append(finding)
        if entry.lgpd:
            lgpd.append(finding)

    def titles(items: list[Finding]) -> list[str]:
        return sorted({f.title for f in items})

    return {
        "owasp": [
            {
                "id": code,
                "label": label,
                "count": len(owasp.get(code, [])),
                "worst": _worst(owasp.get(code, [])),
                "titles": titles(owasp.get(code, [])),
            }
            for code, label in OWASP_2021.items()
        ],
        "cis": [
            {
                "id": control,
                "label": CIS_V8.get(control, ""),
                "count": len(items),
                "worst": _worst(items),
                "titles": titles(items),
            }
            for control, items in sorted(cis.items(), key=lambda kv: _cis_key(kv[0]))
        ],
        "cwe": [
            {
                "id": code,
                "url": f"https://cwe.mitre.org/data/definitions/{_cwe_number(code)}.html",
                "count": len(items),
                "worst": _worst(items),
                "titles": titles(items),
            }
            for code, items in sorted(
                cwe.items(),
                key=lambda kv: (-max(f.severity.rank for f in kv[1]), -len(kv[1]), kv[0]),
            )
        ],
        "lgpd": {
            "count": len(lgpd),
            "worst": _worst(lgpd),
            "findings": [f.fingerprint for f in lgpd],
            "titles": titles(lgpd),
            "text": LGPD_TEXT,
        },
        "severities": [s.value for s in Severity],
    }


def _cis_key(control: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in control.split("."))
    except ValueError:
        return (999,)
