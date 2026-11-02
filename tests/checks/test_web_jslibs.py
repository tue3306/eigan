"""Bibliotecas JavaScript vulneráveis (``web.jslibs``, base do retire.js)."""

from __future__ import annotations

import time

import pytest
from fakes_web import fake_scan, run_in
from fakes_web_content import BASE, site

from eigan.checks.web import jslibs
from eigan.core.models import Confidence, Severity
from eigan.core.settings import Settings

CHECK = "web.jslibs"
ID = "web.biblioteca.vulneravel"
JQUERY_162 = "/*! jQuery v1.6.2 | http://jquery.com/ | Copyright 2011 */\nvar a=1;"
JQUERY_371 = (
    "/*! jQuery v3.7.1 | (c) OpenJS Foundation and other contributors | jquery.org/license */"
)


def page(*scripts: str) -> str:
    tags = "".join(f'<script src="{s}"></script>' for s in scripts)
    return f"<!doctype html><html><head><title>Loja</title></head><body>{tags}</body></html>"


def run(routes, *, settings=None, base=BASE):
    scan, fake = fake_scan(site(routes, base), settings=settings, target=base + "/")
    findings = run_in(scan, CHECK, base + "/")
    return findings, scan, fake


# -- a base embarcada ---------------------------------------------------------------------------


def test_base_embarcada_traz_fonte_licenca_e_data():
    data = jslibs.load_json(jslibs.DATA_FILE)
    for key in ("fonte", "url", "licenca", "atualizado"):
        assert data[key]
    assert data["licenca"] == "Apache-2.0"
    assert len(data["bibliotecas"]) > 50


def test_base_compila_quase_toda_e_so_ignora_o_que_o_re_nao_aceita():
    repo = jslibs.repository()
    assert repo.by_name["jquery"].filecontent
    assert len(repo.skipped_patterns) <= 5


# -- versões ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("version", "other", "expected"),
    [
        ("1.12.4", "1.12.4", True),
        ("1.2", "1.10", False),
        ("1.10.0", "1.9.9", True),
        ("1.0.0", "1.0.0-rc", True),  # número vence texto, como no retire.js
        ("1.0.0-rc", "1.0.0", False),
        ("3.5.0", "3.5", True),
    ],
)
def test_comparacao_de_versoes(version, other, expected):
    assert jslibs.is_at_or_above(version, other) is expected


def test_faixas_below_e_at_or_above():
    vuln = jslibs.Vulnerability("3.5.0", "1.2.0", ("2.0.0",), Severity.MEDIUM, (), (), "", "", ())
    assert vuln.affects("1.2.0") and vuln.affects("3.4.9")
    assert not vuln.affects("1.1.9") and not vuln.affects("3.5.0") and not vuln.affects("2.0.0")


def test_jquery_antigo_tem_cve_e_o_novo_nao():
    cves = {c for v in jslibs.vulnerabilities_of("jquery", "1.12.4") for c in v.cves}
    assert "CVE-2015-9251" in cves
    assert jslibs.vulnerabilities_of("jquery", "3.7.1") == []
    assert jslibs.vulnerabilities_of("biblioteca-inexistente", "1.0.0") == []


# -- extratores ---------------------------------------------------------------------------------


def test_extrator_de_endereco_e_de_nome_de_arquivo():
    [by_uri] = jslibs.scan_url("https://cdn.exemplo.test/ajax/libs/angular.js/1.5.8/angular.min.js")
    assert (by_uri.library, by_uri.version, by_uri.method) == ("angularjs", "1.5.8", "uri")
    [by_name] = jslibs.scan_url("https://loja.exemplo.test/static/jquery-1.12.4.min.js")
    assert (by_name.library, by_name.version) == ("jquery", "1.12.4")
    assert jslibs.scan_url("https://loja.exemplo.test/static/app.js") == []


def test_extrator_de_conteudo():
    [found] = jslibs.scan_content(JQUERY_162)
    assert (found.library, found.version, found.method) == ("jquery", "1.6.2", "filecontent")
    assert jslibs.scan_content("function soma(a,b){return a+b} // v1.2.3") == []


def test_hash_so_vale_para_arquivo_inteiro():
    repo = jslibs.repository()
    digest, (name, version) = next(iter(repo.hashes.items()))
    assert name and version and len(digest) == 40
    assert jslibs._scan_hash(b"conteudo qualquer") == []


# -- a checagem ---------------------------------------------------------------------------------


def test_biblioteca_vulneravel_por_endereco_de_cdn():
    routes = {"/": page("https://code.jquery.com/jquery-1.6.2.min.js")}
    findings, scan, fake = run(routes)
    [f] = [f for f in findings if f.check_id == ID]
    assert "jquery 1.6.2" in f.title
    assert "CVE-2015-9251" in f.cves
    assert f.confidence is Confidence.FIRM
    assert not [u for u in fake.urls() if "code.jquery.com" in u]  # CDN não é baixado no padrão


def test_conteudo_da_mesma_origem_confirma_a_versao():
    routes = {"/": page("/static/jquery.min.js"), "/static/jquery.min.js": JQUERY_162}
    findings, _, _ = run(routes)
    [f] = findings
    assert f.confidence is Confidence.CONFIRMED and f.details["identificacao"] == "filecontent"
    assert f.details["versao_corrigida"]


def test_cdn_so_e_baixada_no_perfil_completo():
    routes = {"/": page("https://cdn.exemplo.test/lib.js"), "/lib.js": JQUERY_162}
    _, _, padrao = run(routes)
    assert not [u for u in padrao.urls() if "cdn.exemplo.test" in u]
    _, _, completo = run(routes, settings=Settings(http_timeout=5.0, profile="completo"))
    assert [u for u in completo.urls() if "cdn.exemplo.test" in u]


def test_conteudo_prevalece_sobre_a_versao_do_nome_do_arquivo():
    routes = {
        "/": page("/static/jquery-1.6.2.min.js"),
        "/static/jquery-1.6.2.min.js": JQUERY_371,
    }
    findings, scan, _ = run(routes)
    assert findings == []
    assert any("jquery 3.7.1" in p.text for p in scan.passed)


def test_versao_atual_nao_gera_achado_e_vira_ponto_forte():
    routes = {"/": page("/static/jquery.min.js"), "/static/jquery.min.js": JQUERY_371}
    findings, scan, _ = run(routes)
    assert findings == [] and scan.passed


def test_pagina_sem_scripts_conhecidos_nao_reporta():
    routes = {"/": page("/app.js"), "/app.js": "console.log('oi')"}
    findings, scan, _ = run(routes)
    assert findings == [] and not scan.passed


def test_script_que_responde_html_soft404_e_ignorado():
    routes = {"/": page("/static/jquery.min.js")}
    scan, _ = fake_scan(
        site(routes, fallback=(200, "<html><body>jQuery v1.6.2 na documentação</body></html>")),
        target=BASE + "/",
    )
    assert run_in(scan, CHECK, BASE + "/") == []


def test_kev_eleva_para_critica(monkeypatch):
    monkeypatch.setattr(jslibs.vulndb, "any_kev", lambda cves: True)
    findings, _, _ = run({"/": page("https://code.jquery.com/jquery-1.6.2.min.js")})
    [f] = findings
    assert f.severity is Severity.CRITICAL and f.kev


def test_a_tecnologia_e_registrada():
    _, scan, _ = run({"/": page("https://code.jquery.com/jquery-1.6.2.min.js")})
    assert any(
        fact.data.get("name") == "jquery" and fact.data.get("version") == "1.6.2"
        for fact in scan.facts_of("tech")
    )


# -- regressões da revisão ----------------------------------------------------------------------

LODASH_MIN = (
    'function(){var An={};An.VERSION="4.17.15",r("bind bindKey curry curryRight partial '
    'partialRight".split(" "),function(n){});}'
)


@pytest.mark.parametrize(
    "url",
    [
        "https://code.jquery.com/jquery-3.5.0.slim.min.js",
        "https://x.test/jquery-3.5.0.slim.js",
        "https://x.test/bootstrap-4.3.1.bundle.min.js",
    ],
)
def test_sufixos_de_build_nao_viram_parte_da_versao(url):
    [det] = jslibs.scan_url(url)
    assert det.version in ("3.5.0", "4.3.1")
    assert not jslibs.vulnerabilities_of(det.library, det.version)


def test_marcadores_999_nao_sao_versao_corrigida():
    for below in ("3.999.999", "1.999", "2.999.999", "999.999.999"):
        vuln = jslibs.Vulnerability(below, None, (), Severity.MEDIUM, (), (), "", "", ())
        assert not vuln.has_fix
    real = jslibs.Vulnerability("3.5.0", None, (), Severity.MEDIUM, (), (), "", "", ())
    assert real.has_fix
    vulns = jslibs.vulnerabilities_of("angularjs", "1.5.0")
    fixed, no_fix = jslibs._fixed_version(vulns)
    assert fixed is None or "999" not in fixed
    assert no_fix


def test_lodash_minificado_e_reconhecido_pelo_conteudo():
    [det] = [d for d in jslibs.scan_content(LODASH_MIN) if d.library == "lodash"]
    assert det.version == "4.17.15" and det.method == "filecontent"


def test_cdn_npm_do_jsdelivr_traz_a_versao():
    achados = {
        (d.library, d.version)
        for url in (
            "https://cdn.jsdelivr.net/npm/jquery@3.4.1/dist/jquery.min.js",
            "https://cdn.jsdelivr.net/npm/lodash@4.17.15/lodash.min.js",
        )
        for d in jslibs.scan_url(url)
    }
    assert ("jquery", "3.4.1") in achados and ("lodash", "4.17.15") in achados


def test_entrada_hostil_nao_trava_a_busca_por_conteudo():
    nl = chr(10)
    entradas = (
        " " * 200_000,
        nl * 200_000,
        "/" + "*" * 200_000,
        "/*" + nl + (" *" + nl) * 60_000,
        ("/*" + "*" * 150) * 1_200,
    )
    inicio = time.monotonic()
    for texto in entradas:
        jslibs.scan_content(texto)
    assert time.monotonic() - inicio < 15


def test_script_que_sumiu_nao_e_firme():
    routes = {"/": page("/jquery-1.6.2.min.js")}  # o arquivo responde 404
    findings, _, _ = run(routes)
    [f] = [f for f in findings if f.check_id == ID]
    assert f.confidence is Confidence.TENTATIVE
