"""Apoio aos testes de configuração e SAST: monta um projeto e devolve os achados por id."""

from __future__ import annotations

from pathlib import Path

from fakes_code import project_fact, write_tree
from helpers import CheckOutcome, run_check


def scan(check_id: str, root: Path, files: dict[str, str | bytes]) -> CheckOutcome:
    """Escreve os arquivos em ``root`` e roda a checagem de projeto."""
    write_tree(root, files)
    return run_check(check_id, project_fact(root))


def ids_in(check_id: str, root: Path, files: dict[str, str | bytes]) -> set[str]:
    return scan(check_id, root, files).ids()
