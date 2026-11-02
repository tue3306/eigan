"""Dependências com vulnerabilidades conhecidas (SCA offline).

Cada manifesto/lockfile encontrado pelo inventário vira um fato ``code.manifest``
e dispara esta checagem. As versões instaladas são comparadas com:

1. o catálogo embarcado de avisos de alto impacto (``code_advisories.json``);
2. a base completa do OSV.dev, **se** ela tiver sido baixada para o cache
   (``osv.download_osv``) — nada é baixado durante a auditoria.

Um pacote com vários avisos vira um único achado (``pacote@versão``) com a maior
severidade; CVE do catálogo CISA KEV ou pacote malicioso elevam o achado a crítico.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ...core import facts, vulndb
from ...core.context import CheckContext
from ...core.models import Category, Confidence, Fact, Severity
from ...core.registry import check
from . import manifests, osv
from .advisories import ECOSYSTEM_TECH, Match, curated_catalog
from .dependencies_kb import MALICIOUS, VULNERABLE
from .files import asset, context_adjust, read_text
from .manifests import Dependency, ManifestSpec
from .versioning import highest

#: lockfiles de monorepos passam fácil de 2 MB: limite próprio para eles
LOCKFILE_MAX_BYTES = 64_000_000


@check(
    id="code.dependencies",
    name="Dependências vulneráveis",
    category=Category.CODE,
    consumes=facts.CODE_MANIFEST,
    description=(
        "Compara as versões dos manifestos e lockfiles (npm, PyPI, Maven, NuGet, Go, Composer, "
        "RubyGems, Cargo) com avisos de segurança publicados, sem acessar a Internet."
    ),
    findings=(VULNERABLE, MALICIOUS),
    order=20,
)
def check_dependencies(ctx: CheckContext, fact: Fact) -> None:
    path = Path(str(fact.data["path"]))
    rel = str(fact.data.get("rel") or path.name)
    spec = manifests.spec_for(path, rel)
    if spec is None:
        ctx.log(f"{rel}: tipo de manifesto não reconhecido.")
        return
    root = Path(str(fact.data["project"])) if fact.data.get("project") else None
    covered = manifests.superseded_by(path, spec.kind, root)
    if covered:
        ctx.log(f"{rel}: versões lidas do {covered}, que é mais preciso.")
        return
    deps = _read_dependencies(ctx, path, rel, spec)
    if not deps:
        return
    ecosystem = spec.ecosystem
    database = ctx.memo(f"code.osv:{ecosystem}", lambda: osv.load_database(ecosystem))
    if database is not None:
        database.prefetch([d.name for d in deps])
    vulnerable = 0
    for dep in deps:
        ctx.check_cancel()
        matches = _matches(ecosystem, dep, database)
        if matches:
            vulnerable += 1
            _report(ctx, rel, spec, dep, matches)
    if not vulnerable and database is not None:
        ctx.passed(
            "code.dependencias",
            f"Nenhuma vulnerabilidade conhecida nas {len(deps)} dependências de {rel} "
            "(catálogo embarcado e base OSV offline)",
            rel,
        )
    elif not vulnerable:
        ctx.log(
            f"{rel}: nenhum aviso no catálogo embarcado (cobertura parcial; "
            "baixe a base OSV para uma checagem completa)."
        )


def _read_dependencies(
    ctx: CheckContext, path: Path, rel: str, spec: ManifestSpec
) -> list[Dependency]:
    limit = ctx.settings.max_file_bytes
    if spec.lockfile:
        limit = max(limit, LOCKFILE_MAX_BYTES)
    text = read_text(path, limit)
    if text is None:
        ctx.log(f"{rel}: arquivo grande demais, binário ou ilegível; dependências não lidas.")
        return []
    parser = manifests.parser_for(spec.kind)
    if parser is None:
        return []
    try:
        deps = parser(text)
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError) as exc:
        ctx.log(f"{rel}: não consegui interpretar o arquivo ({type(exc).__name__}).")
        return []
    ctx.log(f"{rel}: {len(deps)} dependências com versão exata.")
    return deps


def _matches(ecosystem: str, dep: Dependency, database: osv.OsvDatabase | None) -> list[Match]:
    """Avisos que afetam a dependência (catálogo embarcado + OSV, sem repetir o mesmo aviso)."""
    found = curated_catalog().match(ecosystem, dep.name, dep.version)
    if database is None:
        return found
    known: set[str] = set()
    for item in found:
        known |= item.advisory.identifiers
    for advisory in database.advisories(dep.name):
        if advisory.identifiers & known:
            continue
        affected, fixed = advisory.check(dep.version)
        if affected:
            found.append(Match(advisory, fixed))
            known |= advisory.identifiers
    return found


def _report(
    ctx: CheckContext, rel: str, spec: ManifestSpec, dep: Dependency, matches: list[Match]
) -> None:
    ecosystem = spec.ecosystem
    cves = sorted({cve for m in matches for cve in m.advisory.cves})
    kev = vulndb.any_kev(cves)
    malicious = any(m.advisory.malicious for m in matches)
    severity = max((m.advisory.severity for m in matches), key=lambda s: s.rank)
    if kev or malicious:
        severity = Severity.CRITICAL
    confidence = manifests.confidence_for(spec)
    if dep.note.startswith("versão herdada"):
        confidence = Confidence.TENTATIVE
    if _CONDITIONAL.intersection(cves):
        confidence = Confidence.TENTATIVE  # exploração depende de como o aplicativo é empacotado
    severity, confidence, where = context_adjust(rel, severity, confidence)
    fixed = highest(ecosystem, [m.fixed for m in matches if m.fixed])
    unfixed = [m.advisory.id for m in matches if not m.fixed]
    ids = ", ".join(m.advisory.id for m in matches[:6]) + (" ..." if len(matches) > 6 else "")
    evidence = f"{rel}: {dep.name} {dep.version} — {ids}"
    if cves:
        evidence += f" ({', '.join(cves[:6])})"
    ctx.report(
        MALICIOUS if malicious else VULNERABLE,
        asset=asset(rel, dep.line),
        title=f"{'Pacote malicioso' if malicious else 'Dependência vulnerável'}: {dep.name} {dep.version}",
        severity=severity,
        evidence=evidence,
        details=_details(ecosystem, dep, matches, fixed, unfixed, kev, malicious, where),
        confidence=confidence,
        cves=cves,
        kev=kev,
        discriminator=f"{dep.name}@{dep.version}",
        tech=_tech(spec),
    )


#: CVEs que só são exploráveis em certas implantações (a versão sozinha não prova o risco)
_CONDITIONAL = frozenset({"CVE-2022-22965"})  # Spring4Shell: JDK 9+, WAR no Tomcat, Spring MVC


def _tech(spec: ManifestSpec) -> list[str]:
    """Tecnologia usada para escolher o exemplo de correção certo."""
    if spec.kind in ("gradle-lock", "gradle-build"):
        return ["gradle"]
    if spec.kind == "yarn-lock":
        return ["yarn"]
    tech = ECOSYSTEM_TECH.get(spec.ecosystem, "")
    return [tech] if tech else []


def _action(fixed: str | None, unfixed: list[str], malicious: bool) -> str:
    if malicious:
        return (
            f"remova esta versão (a {fixed} ou superior está limpa)" if fixed else "remova o pacote"
        )
    if not fixed:
        return (
            "nenhuma versão corrigida consta no aviso: verifique a versão mais recente do "
            "pacote, aplique a mitigação do aviso ou troque o pacote"
        )
    action = f"atualize para {fixed} ou superior"
    if unfixed:
        action += f" (sem correção para {', '.join(unfixed)}: avalie trocar o pacote)"
    return action


def _details(
    ecosystem: str,
    dep: Dependency,
    matches: list[Match],
    fixed: str | None,
    unfixed: list[str],
    kev: bool,
    malicious: bool,
    where: str,
) -> dict[str, Any]:
    details: dict[str, Any] = {
        "pacote": dep.name,
        "versao": dep.version,
        "ecossistema": ecosystem,
        "versao_corrigida": fixed,
        "acao": _action(fixed, unfixed, malicious),
        "kev": kev,
        "avisos": [
            {
                "id": m.advisory.id,
                "cves": list(m.advisory.cves),
                "severidade": m.advisory.severity.value,
                "titulo": m.advisory.title,
                "resumo": m.advisory.summary,
                "corrigida": m.fixed,
                "referencia": m.advisory.reference,
                "fonte": m.advisory.source,
                "severidade_estimada": not m.advisory.severity_known,
            }
            for m in matches
        ],
    }
    if dep.note:
        details["observacao"] = dep.note
    if where:
        details["contexto"] = f"arquivo de {where}: severidade reduzida"
    return details
