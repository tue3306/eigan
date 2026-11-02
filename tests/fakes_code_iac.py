"""Apoio aos testes de IaC: monta um projeto sintético e executa ``code.iac``."""

from __future__ import annotations

from pathlib import Path

from fakes_code import project_fact, write_tree
from helpers import CheckOutcome, run_check

from eigan.core.models import Finding


def scan(root: Path, files: dict[str, str]) -> CheckOutcome:
    """Grava os arquivos em ``root`` e roda a checagem de IaC sobre a pasta."""
    write_tree(root, dict(files))
    return run_check("code.iac", project_fact(root))


def ids(out: CheckOutcome) -> set[str]:
    return {f.check_id for f in out.findings}


def of(out: CheckOutcome, check_id: str) -> list[Finding]:
    return [f for f in out.findings if f.check_id == check_id]


def lines_of(out: CheckOutcome, check_id: str) -> list[int]:
    return sorted(int(f.details["linha"]) for f in of(out, check_id))
