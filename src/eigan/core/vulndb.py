"""Consulta offline ao catálogo CISA KEV (vulnerabilidades sabidamente exploradas).

O catálogo vai embarcado (``eigan/data/kev.json``); nenhuma consulta de rede é
feita durante a auditoria. Um CVE no KEV é prioridade máxima: existe ataque real
acontecendo com ele.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from ..data import load_json


@dataclass(frozen=True)
class KevEntry:
    cve: str
    vendor: str
    product: str
    name: str
    date_added: str
    ransomware: bool


@lru_cache(maxsize=1)
def _catalog() -> dict[str, Any]:
    try:
        data = load_json("kev.json")
    except (OSError, ValueError):
        return {"itens": {}}
    return data if isinstance(data, dict) else {"itens": {}}


def kev_entry(cve: str) -> KevEntry | None:
    row = _catalog().get("itens", {}).get(cve.strip().upper())
    if not row:
        return None
    vendor, product, name, added, ransomware = (list(row) + ["", "", "", "", 0])[:5]
    return KevEntry(cve.upper(), vendor, product, name, added, bool(ransomware))


def is_kev(cve: str) -> bool:
    return kev_entry(cve) is not None


def any_kev(cves: list[str]) -> bool:
    return any(is_kev(c) for c in cves)


def catalog_info() -> dict[str, Any]:
    data = _catalog()
    return {
        "fonte": data.get("fonte", "CISA KEV"),
        "versao": data.get("versao"),
        "publicado": data.get("publicado"),
        "total": len(data.get("itens", {})),
    }
