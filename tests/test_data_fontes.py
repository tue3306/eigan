"""Todo dado embarcado precisa dizer de onde veio e sob qual licença."""

from __future__ import annotations

import json
from importlib import resources

import pytest

import eigan.data


def _json_files() -> list[str]:
    root = resources.files(eigan.data)
    return sorted(p.name for p in root.iterdir() if p.name.endswith(".json"))


def test_existem_dados_embarcados() -> None:
    assert len(_json_files()) >= 12


@pytest.mark.parametrize("name", _json_files())
def test_dado_declara_fonte_e_licenca(name: str) -> None:
    data = json.loads(eigan.data.load_text(name))
    assert data.get("fonte"), f"{name} sem campo fonte"
    assert data.get("licenca"), f"{name} sem campo licenca"


@pytest.mark.parametrize("name", _json_files())
def test_dado_aparece_em_fontes_md(name: str) -> None:
    assert f"`{name}`" in eigan.data.load_text("FONTES.md")
