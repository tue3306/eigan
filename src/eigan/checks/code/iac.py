"""Checagem de infraestrutura como código: Dockerfile, docker-compose, Kubernetes e Terraform.

Usa a lista de arquivos compartilhada (``files.project_files``), escolhe os arquivos
pelo nome, confirma o tipo pelo conteúdo e aplica as regras de cada formato. Cada
problema vira um achado com o arquivo como ativo, a linha nos detalhes e um trecho de
correção pronto para colar. Em testes e exemplos a severidade cai (``context_adjust``)
e os pontos fortes não contam, porque não descrevem a infraestrutura real.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from ...core import facts, kb
from ...core.context import CheckContext
from ...core.models import Category, Fact
from ...core.registry import check
from . import (
    iac_kb_cloud,  # noqa: F401 — registra as entradas da base
    kb_iac,  # noqa: F401 — registra as entradas da base
)
from .files import (
    ProjectFiles,
    SourceFile,
    context_adjust,
    path_context,
    project_files,
    read_text,
)
from .iac_common import (
    COMPOSE,
    DOCKERFILE,
    IAC_FINDINGS,
    KUBERNETES,
    LABEL,
    TECH,
    TERRAFORM,
    IacIssue,
    IacReport,
    candidate,
    classify,
    looks_like_dockerfile,
)
from .iac_compose import check_compose
from .iac_docker import check_dockerfile
from .iac_k8s import check_kubernetes, limit_range_namespaces
from .iac_terraform import check_terraform

#: limite por arquivo: um manifesto gerado com milhares de Pods não vira milhares de achados
MAX_ISSUES_PER_FILE = 200


#: teto de texto mantido em memória entre as duas passadas (evita projetos gigantes)
MAX_RETAINED_CHARS = 64_000_000


@check(
    id="code.iac",
    name="Containers e infraestrutura como código",
    category=Category.CODE,
    consumes=facts.PROJECT,
    description=(
        "Procura configurações inseguras em Dockerfile, docker-compose, manifestos Kubernetes e "
        "Terraform: container como root ou privilegiado, imagem sem versão, downloads sem "
        "verificação, segredos em texto puro, portas de banco abertas, buckets públicos, firewall "
        "aberto para a Internet e criptografia desligada."
    ),
    findings=IAC_FINDINGS,
    order=35,
)
def check_iac(ctx: CheckContext, fact: Fact) -> None:
    root = Path(str(fact.data.get("path") or fact.key))
    if not root.is_dir():
        ctx.log(f"{root}: não é uma pasta acessível; análise de IaC ignorada.")
        return
    listing = project_files(ctx, root)
    sources = _read_sources(ctx, listing)
    counts: dict[str, int] = defaultdict(int)
    limit_ranges = frozenset(
        namespace
        for item, kind, text in sources
        if kind == KUBERNETES
        for namespace in limit_range_namespaces(text)
    )
    modules: dict[str, dict[str, str]] = defaultdict(dict)
    items: dict[str, SourceFile] = {}
    for item, kind, text in sources:
        ctx.check_cancel()
        counts[kind] += 1
        if kind == TERRAFORM:
            modules[item.rel.rpartition("/")[0]][item.rel] = text
            items[item.rel] = item
        else:
            _publish(ctx, item, kind, _analyze(kind, item, text, limit_ranges))
    for files in modules.values():
        ctx.check_cancel()
        for rel, report in check_terraform(files).items():
            _publish(ctx, items[rel], TERRAFORM, report)
    if counts:
        summary = ", ".join(f"{count} {LABEL[kind]}" for kind, count in sorted(counts.items()))
        ctx.log(f"Infraestrutura como código analisada: {summary}.")


def _read_sources(ctx: CheckContext, listing: ProjectFiles) -> list[tuple[SourceFile, str, str]]:
    """Arquivos de IaC reconhecidos: (arquivo, tipo, conteúdo)."""
    sources: list[tuple[SourceFile, str, str]] = []
    limit = ctx.settings.max_file_bytes
    retained = 0
    for index, item in enumerate(listing.files):
        if index % 512 == 0:
            ctx.check_cancel()
        if not candidate(item) or item.size > limit:
            continue
        text = read_text(item.path, limit)
        if text is None:
            continue
        kind = classify(item, text)
        if kind == DOCKERFILE and not looks_like_dockerfile(text):
            continue
        if kind:
            retained += len(text)
            if retained > MAX_RETAINED_CHARS:
                ctx.log("Limite de memória da análise de IaC atingido; demais arquivos ignorados.")
                break
            sources.append((item, kind, text))
    return sources


def _analyze(kind: str, item: SourceFile, text: str, limit_ranges: frozenset[str]) -> IacReport:
    if kind == DOCKERFILE:
        return check_dockerfile(text)
    if kind == COMPOSE:
        return check_compose(text, by_name=classify(item) == COMPOSE)
    return check_kubernetes(text, limit_ranges=limit_ranges)


def _publish(ctx: CheckContext, item: SourceFile, kind: str, report: IacReport) -> None:
    if len(report.issues) > MAX_ISSUES_PER_FILE:
        ctx.log(
            f"{item.rel}: {len(report.issues)} problemas de IaC; só os primeiros "
            f"{MAX_ISSUES_PER_FILE} foram registrados."
        )
    for issue in report.issues[:MAX_ISSUES_PER_FILE]:
        _report_issue(ctx, item, kind, issue)
    if not path_context(item.rel):
        for control, text in report.strengths:
            ctx.passed(control, text, item.rel)


def _report_issue(ctx: CheckContext, item: SourceFile, kind: str, issue: IacIssue) -> None:
    default = issue.severity or kb.require(issue.finding).severity
    severity, confidence, where = context_adjust(item.rel, default, issue.confidence)
    details = {
        **issue.details,
        "arquivo": item.rel,
        "linha": issue.line,
        "tipo": LABEL[kind],
        "correcao": issue.fix,
    }
    if where:
        details["contexto"] = where
    ctx.report(
        issue.finding,
        asset=item.rel,
        title=issue.title,
        severity=severity,
        evidence=f"Linha {issue.line}: {issue.evidence}",
        details=details,
        confidence=confidence,
        discriminator=issue.discriminator or f"linha {issue.line}",
        tech=[TECH[kind]],
    )
