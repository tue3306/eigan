"""Inventário do ambiente montado a partir dos fatos aprendidos na auditoria."""

from __future__ import annotations

from typing import Any

from ..core import facts
from ..core.models import Fact

SECTIONS: tuple[tuple[str, str], ...] = (
    (facts.HOST_INFO, "Sistema"),
    (facts.NETWORK, "Redes"),
    (facts.HOST, "Hosts"),
    (facts.PORT_OPEN, "Portas abertas"),
    (facts.SERVICE, "Serviços identificados"),
    (facts.HTTP_SERVICE, "Serviços web"),
    (facts.TECH, "Tecnologias"),
    (facts.TLS_SERVICE, "Serviços TLS"),
    (facts.TLS_CERT, "Certificados"),
    (facts.DNS_DOMAIN, "Domínios"),
    (facts.DNS_RECORDS, "Registros DNS"),
    (facts.CODE_INVENTORY, "Código"),
    (facts.CODE_MANIFEST, "Manifestos de dependências"),
    (facts.LOGS_SOURCE, "Fontes de log"),
)
_SKIP_FIELDS = {"label"}
_MAX_ROWS = 500
_MAX_TEXT = 300


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "sim" if value else "não"
    if isinstance(value, list | tuple | set):
        return ", ".join(_text(v) for v in value)
    if isinstance(value, dict):
        return "; ".join(f"{k}: {_text(v)}" for k, v in value.items())
    text = str(value)
    return text if len(text) <= _MAX_TEXT else text[: _MAX_TEXT - 1] + "…"


def build(fact_list: list[Fact]) -> dict[str, Any]:
    by_kind: dict[str, list[Fact]] = {}
    for fact in fact_list:
        by_kind.setdefault(fact.kind, []).append(fact)
    sections = []
    for kind, title in SECTIONS:
        items = sorted(by_kind.get(kind, []), key=lambda f: f.key)
        if not items:
            continue
        columns: list[str] = []
        for fact in items:
            for name in fact.data:
                if name not in _SKIP_FIELDS and name not in columns:
                    columns.append(name)
        rows = [
            {
                "key": fact.label,
                "source": fact.source,
                "fields": {
                    name: _text(fact.data.get(name))
                    for name in columns
                    if fact.data.get(name) not in (None, "", [], {})
                },
            }
            for fact in items[:_MAX_ROWS]
        ]
        sections.append(
            {
                "kind": kind,
                "title": title,
                "count": len(items),
                "columns": columns,
                "rows": rows,
                "truncated": len(items) > _MAX_ROWS,
            }
        )
    return {"sections": sections}
