"""Exportações para máquinas e planilhas: JSON (resultado completo) e CSV dos achados.

O SARIF fica em :mod:`.sarif`.
"""

from __future__ import annotations

import csv
import io
import re
from datetime import datetime
from enum import Enum
from pathlib import PurePath
from typing import Any

from ..core import fmt
from ..core.models import Finding, ScanResult
from ..core.redact import redact
from ..intel import scoring
from .common import deep_redact, deep_scrub, ensure_analysis, json_text, scrub, visible

CSV_COLUMNS = (
    "Prioridade",
    "Faixa",
    "Severidade",
    "Título",
    "Ativo",
    "Identificador",
    "Confiança",
    "Exposição",
    "CVEs",
    "CISA KEV",
    "Situação",
    "Primeira vez",
    "Evidência",
)
CSV_EVIDENCE_LIMIT = 500
CSV_BOM = "\N{ZERO WIDTH NO-BREAK SPACE}"
# Um valor que começa com estes caracteres vira fórmula no Excel/LibreOffice (inclusive as
# versões de largura total, que algumas versões do Excel também aceitam).
FORMULA_START = (
    "=",
    "+",
    "-",
    "@",
    "\t",
    "\r",
    "\n",
    "\N{FULLWIDTH EQUALS SIGN}",
    "\N{FULLWIDTH PLUS SIGN}",
    "\N{FULLWIDTH HYPHEN-MINUS}",
    "\N{FULLWIDTH COMMERCIAL AT}",
)
_LINE_BREAKS = re.compile(r"\s*(?:\r\n|\r|\n)\s*")


# -- JSON ----------------------------------------------------------------------------------


def render_json(result: ScanResult) -> str:
    """O resultado completo (com a análise), legível de volta por ``ScanResult.from_dict``."""
    ensure_analysis(result)
    return json_text(deep_scrub(_masked(result.to_dict())), default=_json_default)


def _masked(data: dict[str, Any]) -> dict[str, Any]:
    """Reaplica o mascaramento: um resultado antigo ou importado não vaza segredo no arquivo."""
    masked = dict(data)
    masked["findings"] = [
        {**item, "evidence": redact(item["evidence"]), "details": deep_redact(item["details"])}
        for item in data["findings"]
    ]
    masked["facts"] = [{**item, "data": deep_redact(item["data"])} for item in data["facts"]]
    masked["errors"] = deep_redact(data["errors"])
    analysis = data["analysis"]
    if isinstance(analysis, dict) and "inventory" in analysis:
        masked["analysis"] = {**analysis, "inventory": deep_redact(analysis["inventory"])}
    return masked


def _json_default(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, set | frozenset):
        return sorted(value, key=str)
    if isinstance(value, PurePath):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


# -- CSV -------------------------------------------------------------------------------------


def render_csv(result: ScanResult) -> str:
    """Planilha dos achados: UTF-8 com BOM e ``;`` (abre direto no Excel em português)."""
    ensure_analysis(result)
    buffer = io.StringIO()
    writer = csv.writer(buffer, delimiter=";", lineterminator="\r\n")
    writer.writerow(CSV_COLUMNS)
    ordered = sorted(
        result.findings, key=lambda f: (-f.priority, -f.severity.rank, f.check_id, f.asset)
    )
    for finding in ordered:
        writer.writerow([csv_cell(value) for value in _csv_row(finding)])
    return CSV_BOM + buffer.getvalue()


def _csv_row(finding: Finding) -> list[str]:
    evidence = redact(finding.evidence.strip())[:CSV_EVIDENCE_LIMIT]
    status = finding.status.label
    if finding.status_note:
        status += f": {scrub(finding.status_note)}"
    return [
        str(finding.priority),
        finding.priority_label or scoring.priority_band(finding.priority)[0],
        finding.severity.label,
        scrub(finding.title),
        scrub(finding.asset),
        finding.check_id,
        finding.confidence.label,
        finding.exposure.label,
        ", ".join(finding.cves),
        "Sim" if finding.kev else "Não",
        status,
        fmt.date_time(finding.first_seen),
        _LINE_BREAKS.sub(" | ", evidence),
    ]


def csv_cell(value: str) -> str:
    """Célula segura: invisíveis à mostra e fórmula neutralizada (``=SOMA()`` vira ``'=SOMA()``)."""
    text = visible(value)
    return "'" + text if text.startswith(FORMULA_START) else text
