"""Anexos do relatório: conformidade, comparação, inventário, linha do tempo e rodapé."""

from __future__ import annotations

from typing import Any

from .. import __version__
from ..core import fmt, kb
from ..core.kb import CIS_V8, OWASP_2021
from ..core.models import ScanResult
from ..core.redact import redact
from ..core.settings import PROFILE_LABEL
from ..intel.compliance import LGPD_TEXT
from .common import anchor, as_dict, as_int, as_list, cwe_url, points, severity_view, time_of_day

MAX_DECISIONS = 500
RUN_STATUS = {
    "ok": "Concluída",
    "erro": "Erro",
    "tempo_esgotado": "Tempo esgotado",
    "cancelada": "Cancelada",
}
#: nomes amigáveis das colunas do inventário (os dados dos fatos usam chaves técnicas)
COLUMN_LABEL = {
    "url": "URL",
    "host": "Host",
    "port": "Porta",
    "scheme": "Protocolo",
    "sni": "SNI",
    "service": "Serviço",
    "product": "Produto",
    "version": "Versão",
    "banner": "Banner",
    "tls": "TLS",
    "name": "Nome",
    "kind": "Tipo",
    "evidence": "Evidência",
    "subject": "Titular",
    "issuer": "Emissor",
    "not_before": "Válido desde",
    "not_after": "Válido até",
    "san": "Nomes alternativos",
    "domain": "Domínio",
    "a": "A",
    "aaaa": "AAAA",
    "mx": "MX",
    "ns": "NS",
    "txt": "TXT",
    "caa": "CAA",
    "cname": "CNAME",
    "network": "Rede",
    "platform": "Plataforma",
    "os": "Sistema",
    "build": "Build",
    "hostname": "Nome da máquina",
    "path": "Caminho",
    "ecosystem": "Ecossistema",
    "files": "Arquivos",
    "languages": "Linguagens",
    "manifests": "Manifestos",
}


# -- conformidade ---------------------------------------------------------------------------


def _worst(item: dict[str, Any]) -> dict[str, str] | None:
    return severity_view(item["worst"]) if item.get("worst") else None


def _titles(item: dict[str, Any]) -> list[str]:
    return [str(t) for t in as_list(item.get("titles"))]


def compliance(raw: dict[str, Any]) -> dict[str, Any]:
    """OWASP Top 10 (as dez categorias), CIS Controls v8, CWE e o quadro da LGPD."""
    by_code = {
        str(item.get("id")): item for item in (as_dict(i) for i in as_list(raw.get("owasp")))
    }
    covered = {entry.owasp for entry in kb.all_entries() if entry.owasp}
    owasp = []
    for code, label in OWASP_2021.items():
        item = as_dict(by_code.get(code))
        owasp.append(
            {
                "id": code,
                "label": str(item.get("label") or label),
                "count": as_int(item.get("count")),
                "worst": _worst(item),
                "titles": _titles(item),
                # sem nenhuma verificação mapeada para a categoria, "0 achados" enganaria
                "assessed": not covered or code in covered or bool(item.get("count")),
            }
        )
    cis = [
        {
            "id": str(item.get("id") or ""),
            "label": str(item.get("label") or CIS_V8.get(str(item.get("id")), "")),
            "count": as_int(item.get("count")),
            "worst": _worst(item),
            "titles": _titles(item),
        }
        for item in (as_dict(i) for i in as_list(raw.get("cis")))
        if item.get("id")
    ]
    cwe = [
        {
            "id": str(item.get("id") or ""),
            "url": cwe_url(str(item.get("id") or "")),
            "count": as_int(item.get("count")),
            "worst": _worst(item),
            "titles": _titles(item),
        }
        for item in (as_dict(i) for i in as_list(raw.get("cwe")))
        if item.get("id")
    ]
    lgpd = as_dict(raw.get("lgpd"))
    return {
        "owasp": owasp,
        "owasp_hits": sum(1 for item in owasp if item["count"]),
        "cis": cis,
        "cwe": cwe,
        "lgpd": {
            "count": as_int(lgpd.get("count")),
            "worst": _worst(lgpd),
            "titles": _titles(lgpd),
            "text": str(lgpd.get("text") or LGPD_TEXT),
        },
    }


# -- comparação ---------------------------------------------------------------------------------


def diff(result: ScanResult, raw: Any) -> dict[str, Any] | None:
    """O que mudou desde a auditoria anterior do mesmo alvo (``None`` se não houver)."""
    if not isinstance(raw, dict) or not raw:
        return None
    current = {f.fingerprint for f in result.findings}

    def items(key: str) -> list[dict[str, Any]]:
        out = []
        for value in as_list(raw.get(key)):
            item = as_dict(value)
            fp = str(item.get("fingerprint") or "")
            out.append(
                {
                    "title": str(item.get("title") or item.get("check_id") or ""),
                    "asset": str(item.get("asset") or ""),
                    "severity": severity_view(item.get("severity")),
                    "anchor": anchor("f", fp) if fp in current else "",
                }
            )
        return out

    delta = as_int(raw.get("delta"))
    if delta > 0:
        delta_text = f"+{points(delta)}"
    elif delta < 0:
        delta_text = f"−{points(-delta)}"
    else:
        delta_text = "sem mudança"
    profile = str(raw.get("previous_profile") or "")
    return {
        "previous_id": str(raw.get("previous_id") or ""),
        "previous_date": fmt.date_time(str(raw.get("previous_date") or "")),
        "previous_profile": PROFILE_LABEL.get(profile, profile),
        "score_before": as_int(raw.get("score_before")),
        "score_after": as_int(raw.get("score_after")),
        "grade_before": str(raw.get("grade_before") or ""),
        "delta": delta,
        "delta_text": delta_text,
        "fixed": items("fixed"),
        "new": items("new"),
        "persisting": items("persisting"),
        "unverified": items("unverified"),
    }


# -- inventário, linha do tempo e rodapé ----------------------------------------------------------


def inventory(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """Seções do inventário como tabelas (valores com segredos mascarados)."""
    sections = []
    for value in as_list(raw.get("sections")):
        section = as_dict(value)
        columns = [str(c) for c in as_list(section.get("columns"))]
        rows = []
        for row_value in as_list(section.get("rows")):
            row = as_dict(row_value)
            fields = as_dict(row.get("fields"))
            rows.append(
                {
                    "key": redact(str(row.get("key") or "")),
                    "cells": [redact(str(fields.get(column, ""))) for column in columns],
                }
            )
        if not rows:
            continue
        sections.append(
            {
                "title": str(section.get("title") or section.get("kind") or ""),
                "count": as_int(section.get("count"), len(rows)),
                "columns": [
                    COLUMN_LABEL.get(column, column.replace("_", " ").capitalize())
                    for column in columns
                ],
                "rows": rows,
                "truncated": bool(section.get("truncated")),
            }
        )
    return sections


def timeline(result: ScanResult) -> dict[str, Any]:
    """Decisões do motor, verificações que não terminaram e erros."""
    decisions = [
        {"at": time_of_day(d.at), "text": redact(d.text)} for d in result.decisions[:MAX_DECISIONS]
    ]
    problems = [
        {
            "name": run.name or run.check_id,
            "check_id": run.check_id,
            "status": RUN_STATUS.get(run.status, run.status),
            "status_value": run.status,
            "asset": run.fact_key,
            "message": redact(run.message),
            "duration": fmt.duration(run.duration),
        }
        for run in result.runs
        if run.status != "ok"
    ]
    parts = []
    if result.decisions:
        parts.append(fmt.plural(len(result.decisions), "decisão", "decisões"))
    if problems:
        parts.append(
            fmt.plural(len(problems), "verificação com problema", "verificações com problema")
        )
    if result.errors:
        parts.append(fmt.plural(len(result.errors), "erro", "erros"))
    return {
        "decisions": decisions,
        "decisions_hidden": max(0, len(result.decisions) - MAX_DECISIONS),
        "problems": problems,
        "errors": [redact(str(e)) for e in result.errors],
        "summary": fmt.join_pt(parts),
        "empty": not parts,
    }


def footer(catalog: dict[str, Any]) -> dict[str, Any]:
    return {
        "generator": __version__,
        "kev_version": str(catalog.get("versao") or ""),
        "kev_date": fmt.date_only(str(catalog.get("publicado") or "")),
        "kev_total": as_int(catalog.get("total")),
    }
