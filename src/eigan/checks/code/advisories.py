"""Avisos de segurança de dependências: o catálogo embarcado e o casamento de versões.

O catálogo ``eigan/data/code_advisories.json`` traz avisos de alto impacto
conferidos no GitHub Advisory Database (via OSV.dev), com faixas de versão
copiadas dos registros originais e texto em português. A base completa do OSV,
quando baixada para o cache, entra pelo módulo :mod:`.osv` e usa o mesmo modelo.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from ...core.models import Severity
from ...data import load_json
from . import versioning
from .versioning import VersionRange

ADVISORIES_FILE = "code_advisories.json"

#: nome da pasta/ecossistema do OSV -> chave de tecnologia dos exemplos de correção
ECOSYSTEM_TECH = {
    "npm": "npm",
    "PyPI": "python",
    "Maven": "maven",
    "Packagist": "composer",
    "RubyGems": "bundler",
    "NuGet": "dotnet",
    "Go": "go",
    "crates.io": "cargo",
}


def package_key(ecosystem: str, name: str) -> str:
    """Nome normalizado para casar pacotes (PEP 503 no PyPI, minúsculas onde é seguro)."""
    text = name.strip()
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", text).lower()
    if ecosystem == "crates.io":
        return text.lower().replace("_", "-")
    if ecosystem in ("Go", "RubyGems"):
        return text
    return text.lower()


@dataclass(frozen=True)
class Advisory:
    """Um aviso aplicável a um pacote de um ecossistema."""

    id: str
    ecosystem: str
    package: str
    severity: Severity
    title: str
    summary: str
    reference: str
    cves: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    ranges: tuple[VersionRange, ...] = ()
    versions: frozenset[str] = field(default_factory=frozenset)
    malicious: bool = False
    source: str = "curadoria"
    #: ``False`` quando o registro não traz severidade (fica "média", estimada)
    severity_known: bool = True

    def check(self, version: str) -> tuple[bool, str | None]:
        """``(afetada, versão corrigida)`` para a versão instalada."""
        return versioning.is_affected(self.ecosystem, version, self.ranges, self.versions)

    @property
    def identifiers(self) -> set[str]:
        return {self.id, *self.cves, *self.aliases}


@dataclass(frozen=True)
class Match:
    """Um aviso que se aplica a uma dependência instalada."""

    advisory: Advisory
    fixed: str | None


class Catalog:
    """Índice ``(ecossistema, pacote) -> avisos``."""

    def __init__(self, advisories: list[Advisory]) -> None:
        self._index: dict[tuple[str, str], list[Advisory]] = {}
        for item in advisories:
            key = (item.ecosystem, package_key(item.ecosystem, item.package))
            self._index.setdefault(key, []).append(item)

    def __len__(self) -> int:
        return sum(len(v) for v in self._index.values())

    def for_package(self, ecosystem: str, name: str) -> list[Advisory]:
        return list(self._index.get((ecosystem, package_key(ecosystem, name)), []))

    def match(self, ecosystem: str, name: str, version: str) -> list[Match]:
        found: list[Match] = []
        for advisory in self.for_package(ecosystem, name):
            affected, fixed = advisory.check(version)
            if affected:
                found.append(Match(advisory, fixed))
        return found


def _ranges_from_pairs(pairs: list[dict[str, Any]]) -> tuple[VersionRange, ...]:
    ranges: list[VersionRange] = []
    for pair in pairs:
        events: list[tuple[str, str]] = [("introduced", str(pair.get("introduzida", "0")))]
        if pair.get("corrigida"):
            events.append(("fixed", str(pair["corrigida"])))
        elif pair.get("ultima_afetada"):
            events.append(("last_affected", str(pair["ultima_afetada"])))
        ranges.append(VersionRange(tuple(events)))
    return tuple(ranges)


def _from_curated(row: dict[str, Any]) -> Advisory:
    return Advisory(
        id=str(row["id"]),
        ecosystem=str(row["ecossistema"]),
        package=str(row["pacote"]),
        severity=Severity.parse(str(row.get("severidade", "medium"))),
        title=str(row.get("titulo", row["id"])),
        summary=str(row.get("resumo", "")),
        reference=str(row.get("referencia", "")),
        cves=tuple(str(c) for c in row.get("cves", [])),
        ranges=_ranges_from_pairs(list(row.get("faixas", []))),
        malicious=row.get("tipo") == "malicioso",
        source="curadoria",
    )


@lru_cache(maxsize=1)
def curated_catalog() -> Catalog:
    """Catálogo embarcado (carregado uma vez por processo)."""
    try:
        data = load_json(ADVISORIES_FILE)
    except (OSError, ValueError):
        return Catalog([])
    rows = data.get("avisos", []) if isinstance(data, dict) else []
    return Catalog([_from_curated(row) for row in rows if isinstance(row, dict)])


def catalog_info() -> dict[str, Any]:
    try:
        data = load_json(ADVISORIES_FILE)
    except (OSError, ValueError):
        return {"total": 0}
    return {
        "fonte": data.get("fonte"),
        "versao": data.get("versao"),
        "atualizado": data.get("atualizado"),
        "licenca": data.get("licenca"),
        "total": len(data.get("avisos", [])),
    }
