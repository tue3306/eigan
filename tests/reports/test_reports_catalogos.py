"""Idade dos catálogos no resultado da auditoria e nos relatórios HTML e PDF."""

from __future__ import annotations

import json
from datetime import date, timedelta
from typing import Any

import pytest
from fakes_reports import clean_result

from eigan import data
from eigan.core import atualizacao
from eigan.reports import render_html, render_json, render_pdf
from eigan.reports.view import build_view


def embarcado(arquivo: str) -> date:
    campo = "publicado" if arquivo == "kev.json" else "atualizado"
    return date.fromisoformat(data.load_embedded_json(arquivo)[campo][:10])


def br(dia: date) -> str:
    return dia.strftime("%d/%m/%Y")


def estado_de(dia: date) -> Any:
    original = atualizacao.estado

    def fixo(hoje: date | None = None) -> Any:
        return original(dia)

    return fixo


def test_resultado_traz_a_idade_de_cada_catalogo() -> None:
    result = clean_result()
    catalogos = result.analysis["catalogos"]
    nomes = {c["nome"] for c in catalogos["catalogos"]}
    assert {"kev", "retire", "sufixos", "host_eol", "tls_suites"} <= nomes
    kev = next(c for c in catalogos["catalogos"] if c["nome"] == "kev")
    assert kev["origem"] in ("embarcado", "baixado")
    assert kev["data"]
    assert isinstance(kev["idade_dias"], int)
    saida = json.loads(render_json(result))
    assert saida["analysis"]["catalogos"]["limite_dias"] == 30


def test_relatorio_html_tem_uma_linha_com_as_datas(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(atualizacao, "estado", estado_de(embarcado("kev.json")))
    html = render_html(clean_result())
    assert f"Dados desta auditoria: CISA KEV de {br(embarcado('kev.json'))} (embarcado)" in html
    assert f"retire.js de {br(embarcado('web_retire.json'))}" in html
    assert 'class="stale"' not in html


def test_catalogo_com_mais_de_30_dias_gera_aviso_claro(monkeypatch: pytest.MonkeyPatch) -> None:
    kev = embarcado("kev.json")
    hoje = max(kev, embarcado("web_retire.json"), embarcado("dns_sufixos.json")) + timedelta(31)
    monkeypatch.setattr(atualizacao, "estado", estado_de(hoje))
    result = clean_result()
    avisos = result.analysis["catalogos"]["avisos"]
    assert len(avisos) == 3
    assert f"dados de {br(kev)}, há {(hoje - kev).days} dias" in avisos[0]
    view = build_view(result)
    assert view["footer"]["catalog_notices"] == avisos
    html = render_html(result)
    assert 'class="stale"' in html
    assert f"dados de {br(kev)}, há {(hoje - kev).days} dias" in html
    assert "eigan atualizar" in html


def test_pdf_com_aviso_de_catalogo_velho_e_gerado(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(atualizacao, "estado", estado_de(date(2099, 1, 1)))
    pdf = render_pdf(clean_result())
    assert pdf.startswith(b"%PDF")


def test_resultado_antigo_sem_o_campo_continua_gerando_relatorio() -> None:
    result = clean_result()
    del result.analysis["catalogos"]
    html = render_html(result)
    assert "Dados desta auditoria" not in html
    assert render_pdf(result).startswith(b"%PDF")
