"""Inventário do projeto: linguagens, manifestos de dependências e lockfiles.

É a primeira checagem de código (``order=5``): percorre a pasta uma única vez
(a lista fica em memória para as demais checagens) e publica um fato
``code.manifest`` por manifesto/lockfile reconhecido — é ele que dispara a
análise de dependências — e um fato ``code.inventory`` com o resumo.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from ...core import facts
from ...core.context import CheckContext
from ...core.models import Category, Fact
from ...core.registry import check
from . import manifests
from .files import LANGUAGES, ProjectFiles, SourceFile, project_files

#: manifestos publicados por projeto (monorepos enormes ficam limitados a este número)
MAX_MANIFESTS = 500


@check(
    id="code.inventory",
    name="Inventário do projeto",
    category=Category.CODE,
    consumes=facts.PROJECT,
    description=(
        "Percorre a pasta do projeto (sem seguir links e pulando node_modules, .git...), conta "
        "as linguagens e encontra manifestos e lockfiles de dependências."
    ),
    facts=(facts.CODE_MANIFEST, facts.CODE_INVENTORY),
    order=5,
)
def check_inventory(ctx: CheckContext, fact: Fact) -> None:
    root = Path(str(fact.data.get("path") or fact.key))
    if not root.is_dir():
        ctx.log(f"{root}: não é uma pasta acessível; inventário ignorado.")
        return
    listing = project_files(ctx, root)
    languages: Counter[str] = Counter()
    found: list[tuple[SourceFile, manifests.ManifestSpec]] = []
    for index, item in enumerate(listing.files):
        if index % 512 == 0:
            ctx.check_cancel()
        language = LANGUAGES.get(item.ext)
        if language:
            languages[language] += 1
        spec = manifests.identify(item)
        if spec is not None:
            found.append((item, spec))
    if len(found) > MAX_MANIFESTS:
        ctx.log(
            f"{len(found)} manifestos encontrados: só os primeiros {MAX_MANIFESTS} serão analisados."
        )
        found = found[:MAX_MANIFESTS]
    for item, spec in found:
        ctx.add_fact(
            facts.CODE_MANIFEST,
            str(item.path),
            f"Manifesto de dependências {spec.label} ({spec.ecosystem}) em {item.rel}",
            path=str(item.path),
            rel=item.rel,
            project=str(root),
            ecosystem=spec.ecosystem,
            kind=spec.kind,
            lockfile=spec.lockfile,
            label=item.rel,
        )
    _publish_summary(ctx, root, listing.files, languages, found, listing.truncated)
    _log_limits(ctx, listing)


def _log_limits(ctx: CheckContext, listing: ProjectFiles) -> None:
    """Explica no registro o que a varredura deixou de fora."""
    if listing.truncated:
        ctx.log(
            f"O projeto tem mais de {ctx.settings.max_files} arquivos: a análise ficou limitada "
            "aos primeiros (ajuste 'max_files' nas configurações)."
        )
    if listing.links:
        ctx.log(f"{listing.links} links simbólicos/junções não foram seguidos.")
    if listing.too_deep:
        ctx.log(
            f"{listing.too_deep} pastas aninhadas além do limite de profundidade foram puladas."
        )


def _publish_summary(
    ctx: CheckContext,
    root: Path,
    files: list[SourceFile],
    languages: Counter[str],
    found: list[tuple[SourceFile, manifests.ManifestSpec]],
    truncated: bool,
) -> None:
    top = ", ".join(f"{name} ({count})" for name, count in languages.most_common(4))
    ecosystems = sorted({spec.ecosystem for _, spec in found})
    reason = f"{len(files)} arquivos" + (f"; linguagens: {top}" if top else "")
    if ecosystems:
        reason += f"; dependências: {', '.join(ecosystems)}"
    ctx.add_fact(
        facts.CODE_INVENTORY,
        str(root),
        reason,
        path=str(root),
        files=len(files),
        languages=dict(languages.most_common()),
        manifests=[item.rel for item, _ in found],
        ecosystems=ecosystems,
        truncated=truncated,
        label=f"{root.name or root} — {len(files)} arquivos",
    )
