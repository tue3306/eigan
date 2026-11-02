"""Visão de um módulo Terraform: recursos, variáveis, locals e como as regras reportam.

Um módulo é a pasta inteira (todos os ``.tf`` juntos): um bucket pode estar em um
arquivo e a política dele em outro. ``var.x`` e ``local.x`` são resolvidos quando há
valor no próprio módulo. O padrão de uma variável pode ser trocado na hora de aplicar,
por isso o achado que depende dele sai como indício (``indirect``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ...core.models import Confidence, Severity
from .iac_common import IacIssue, IacReport
from .iac_hcl import Block, Ref, parse_hcl

_VARIABLE = re.compile(r"^var\.([\w\-]+)$")
_LOCAL = re.compile(r"^local\.([\w\-]+)$")
_MAX_INDIRECTION = 8


@dataclass(frozen=True)
class Resource:
    """Um bloco ``resource "tipo" "nome"`` e o arquivo onde ele está."""

    rel: str
    block: Block

    @property
    def type(self) -> str:
        return self.block.label(0)

    @property
    def name(self) -> str:
        return self.block.label(1)

    @property
    def address(self) -> str:
        return f"{self.type}.{self.name}"


class Module:
    """Os arquivos ``.tf`` de uma pasta."""

    def __init__(self, files: dict[str, str]) -> None:
        self.resources: list[Resource] = []
        self.variables: dict[str, Any] = {}
        self.locals: dict[str, Any] = {}
        self.policy_documents: dict[str, Block] = {}
        for rel, text in files.items():
            for block in parse_hcl(text):
                self._add(rel, block)

    def _add(self, rel: str, block: Block) -> None:
        if block.type == "resource" and len(block.labels) >= 2:
            if as_int(block.get("count")) == 0:
                return  # ``count = 0``: o Terraform nunca cria o recurso
            self.resources.append(Resource(rel, block))
        elif block.type == "variable" and block.labels and block.has("default"):
            self.variables[block.label(0)] = block.get("default")
        elif block.type == "locals":
            self.locals.update({name: attr.value for name, attr in block.attrs.items()})
        elif block.type == "data" and block.label(0) == "aws_iam_policy_document":
            self.policy_documents[block.label(1)] = block

    def of_type(self, *types: str) -> list[Resource]:
        return [resource for resource in self.resources if resource.type in types]

    def resolve(self, value: Any) -> tuple[Any, bool]:
        """Segue ``var.x``/``local.x``: (valor, depende do padrão de uma variável)."""
        indirect = False
        for _ in range(_MAX_INDIRECTION):
            if not isinstance(value, Ref):
                break
            variable = _VARIABLE.match(value.raw)
            local = _LOCAL.match(value.raw)
            if variable is not None and variable.group(1) in self.variables:
                value = self.variables[variable.group(1)]
                indirect = True
            elif local is not None and local.group(1) in self.locals:
                value = self.locals[local.group(1)]
            else:
                break
        return value, indirect

    def resolved_list(self, *values: Any) -> tuple[list[Any], bool]:
        """Junta valores e listas, já resolvidos: (itens, algum depende de uma variável)."""
        items: list[Any] = []
        indirect = False
        for value in values:
            resolved, via = self.resolve(value)
            for item in resolved if isinstance(resolved, list) else [resolved]:
                final, via_item = self.resolve(item)
                items.append(final)
                indirect = indirect or via or via_item
        return items, indirect

    def flag(self, value: Any) -> tuple[bool | None, bool]:
        resolved, indirect = self.resolve(value)
        return as_bool(resolved), indirect


def as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    return None


def as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def as_text(value: Any) -> str:
    """Texto de um valor simples ("" se for referência, lista, objeto ou nulo)."""
    if isinstance(value, str):
        return value
    if isinstance(value, bool) or value is None:
        return ""
    return str(value) if isinstance(value, (int, float)) else ""


@dataclass
class TfRun:
    """Relatórios por arquivo de uma análise de módulo."""

    module: Module
    reports: dict[str, IacReport]

    def strength(self, resource: Resource, control: str, text: str) -> None:
        self.reports[resource.rel].strength(control, f"{resource.address}: {text}")

    def issue(
        self,
        resource: Resource,
        finding: str,
        line: int,
        title: str,
        evidence: str,
        discriminator: str,
        fix: str,
        *,
        severity: Severity | None = None,
        confidence: Confidence = Confidence.CONFIRMED,
        indirect: bool = False,
        **details: Any,
    ) -> None:
        details["recurso"] = resource.address
        if indirect:
            details["observacao"] = (
                "o valor vem do padrão de uma variável, que pode ser trocado ao aplicar; confira"
            )
        self.reports[resource.rel].add(
            IacIssue(
                finding,
                line or resource.block.line,
                title,
                evidence,
                severity=severity,
                confidence=Confidence.TENTATIVE if indirect else confidence,
                discriminator=f"{resource.address}:{discriminator}",
                details=details,
                fix=fix,
            )
        )
