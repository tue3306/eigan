from __future__ import annotations

from pathlib import Path

import pytest

from eigan.core import kb
from eigan.core.kb import Fix, KBEntry
from eigan.core.models import (
    Category,
    CheckRun,
    Confidence,
    Exposure,
    Finding,
    PassedControl,
    ScanResult,
    Severity,
    TargetKind,
    TriageStatus,
)
from eigan.core.registry import load_builtin_checks
from eigan.intel import correlation, diff, remediation, scoring
from eigan.intel.analysis import analyze
from eigan.storage import Store

load_builtin_checks()

SITE = "https://exemplo.com.br/"


def make(
    check_id: str,
    asset: str = SITE,
    *,
    severity: Severity | None = None,
    source: str = "web.transport",
    **extra: object,
) -> Finding:
    entry = kb.require(check_id)
    return Finding(
        check_id=check_id,
        title=entry.title,
        severity=severity or entry.severity,
        asset=asset,
        source=source,
        **extra,  # type: ignore[arg-type]
    )


def scan(
    findings: list[Finding],
    *,
    scan_id: str = "s1",
    started: str = "2026-11-01T10:00:00+00:00",
    passed: list[PassedControl] | None = None,
    runs: list[CheckRun] | None = None,
) -> ScanResult:
    return ScanResult(
        id=scan_id,
        target="https://exemplo.com.br",
        kind=TargetKind.URL,
        profile="padrao",
        started_at=started,
        finished_at=started,
        status="concluida",
        findings=findings,
        passed=passed or [],
        runs=runs
        if runs is not None
        else [CheckRun(check_id="web.transport", name="HTTPS e HSTS", fact_key=SITE, status="ok")],
    )


# -- nota e prioridade -----------------------------------------------------------


def test_sem_achados_e_a_mais():
    posture = scoring.posture([])
    assert (posture.score, posture.grade) == (100, "A+")


def test_achado_critico_limita_a_nota():
    finding = make("web.https.ausente", severity=Severity.CRITICAL, confidence=Confidence.CONFIRMED)
    posture = scoring.posture([finding])
    assert posture.score == 75
    assert posture.grade == "D"
    assert "críticos" in posture.cap_reason


def test_kev_derruba_para_f_e_vira_p1():
    finding = make("web.https.ausente", cves=["CVE-2021-44228"], kev=True)
    assert scoring.posture([finding]).grade == "F"
    assert scoring.priority_band(scoring.priority_of(finding))[0] == "P1"


def test_mesmo_problema_repetido_tem_retorno_decrescente():
    one = scoring.posture([make("web.hsts.ausente", confidence=Confidence.CONFIRMED)])
    three = scoring.posture(
        [
            make(
                "web.hsts.ausente", f"https://{n}.exemplo.com.br/", confidence=Confidence.CONFIRMED
            )
            for n in ("a", "b", "c")
        ]
    )
    assert one.penalty == pytest.approx(5.0)
    assert three.penalty == pytest.approx(5.0 + 2.5 + 1.25)


def test_prioridade_considera_confianca_e_exposicao():
    urgent = make("web.https.ausente", confidence=Confidence.CONFIRMED)
    internal = make("web.hsts.ausente", exposure=Exposure.INTERNAL)
    assert scoring.priority_of(urgent) == 75
    assert scoring.priority_band(scoring.priority_of(urgent))[0] == "P1"
    assert scoring.priority_of(internal) == 34
    assert scoring.priority_band(34)[0] == "P3"


def test_triagem_tira_o_achado_da_nota():
    finding = make("web.https.ausente", status=TriageStatus.ACCEPTED)
    assert scoring.posture([finding]).score == 100


# -- correlação --------------------------------------------------------------------


def test_cenario_exige_todos_os_grupos_no_mesmo_host(monkeypatch):
    rule = correlation.Scenario(
        id="cenario.teste",
        title="Teste",
        severity=Severity.HIGH,
        requires=(("web.hsts.ausente",), ("web.https.sem_redirecionamento",)),
        narrative="n",
        breaker="b",
    )
    monkeypatch.setattr(correlation, "SCENARIOS", (rule,))
    same_host = [
        make("web.hsts.ausente"),
        make("web.https.sem_redirecionamento", "http://exemplo.com.br/"),
    ]
    other_host = [
        make("web.hsts.ausente"),
        make("web.https.sem_redirecionamento", "http://outro.com/"),
    ]
    [match] = correlation.correlate(same_host)
    assert match.host == "exemplo.com.br"
    assert len(match.fingerprints) == 2
    assert correlation.correlate(other_host) == []


def test_host_do_ativo():
    assert correlation.asset_host("https://Site.com.br:8443/x") == "site.com.br"
    assert correlation.asset_host("10.0.0.5:22/tcp") == "10.0.0.5"
    assert correlation.asset_host("exemplo.com.br") == "exemplo.com.br"


# -- plano de correção ---------------------------------------------------------------


def _entry(entry_id: str, *examples: Fix) -> KBEntry:
    return KBEntry(
        id=entry_id,
        title=f"Título {entry_id}",
        category=Category.WEB,
        severity=Severity.MEDIUM,
        summary="s",
        explanation="e",
        risk="r",
        steps=("passo",),
        verify="v",
        examples=examples,
        fix_group="cabecalhos",
    )


def test_trechos_sao_juntados_por_tecnologia_detectada():
    a = _entry(
        "t.a",
        Fix("nginx", "nginx", "add_header A 1;", "nginx"),
        Fix("apache", "Apache", "Header set A 1", "apache"),
    )
    b = _entry(
        "t.b", Fix("nginx", "nginx", "add_header B 1;", "nginx"), Fix("iis", "IIS", "<b/>", "xml")
    )
    fa = make("web.hsts.ausente", tech=["nginx"])
    fb = make("web.hsts.fraco", tech=["nginx"])
    fixes = remediation.merge_fixes([remediation.Problem(a, [fa]), remediation.Problem(b, [fb])])
    assert [fx["tech"] for fx in fixes] == ["nginx"]
    code = fixes[0]["code"]
    assert "# Título t.a" in code and "add_header A 1;" in code and "add_header B 1;" in code


def test_sem_tecnologia_detectada_mostra_todos_os_exemplos():
    a = _entry("t.a", Fix("nginx", "nginx", "x", "nginx"), Fix("iis", "IIS", "<x/>", "xml"))
    fixes = remediation.merge_fixes([remediation.Problem(a, [make("web.hsts.ausente")])])
    assert {fx["tech"] for fx in fixes} == {"nginx", "iis"}


# -- análise completa ------------------------------------------------------------------


def test_analise_completa_tem_plano_resumo_e_simulacao():
    findings = [
        make("web.https.ausente", confidence=Confidence.CONFIRMED),
        make("web.hsts.ausente"),
        make("web.hsts.fraco", "https://www.exemplo.com.br/"),
    ]
    result = scan(findings, passed=[PassedControl("web.https.forcado", "HTTPS forçado", SITE)])
    data = analyze(result)
    assert data["evaluated"] is True
    assert data["posture"]["grade"] == "C"
    assert data["counts"]["high"] == 1 and data["counts"]["open"] == 3
    assert data["priorities"]["P1"] == 1
    groups = [a["group"] for a in data["plan"]]
    assert groups[0] == "https"
    assert data["what_if"]["score"] == 100
    assert data["narrative"]["headline"] == "1 problema exige correção imediata."
    assert data["narrative"]["strengths"][0]["text"] == "HTTPS forçado"
    assert result.findings[0].priority_label == "P1"
    assert {c["id"] for c in data["categories"]} == {"web"}
    assert any(item["count"] for item in data["compliance"]["owasp"])


def test_alvo_sem_resposta_nao_ganha_nota():
    data = analyze(scan([]))
    assert data["evaluated"] is False
    assert data["posture"]["grade"] == "—"
    assert data["narrative"]["headline"].startswith("Não foi possível avaliar")


def test_comparacao_so_conta_corrigido_quando_a_checagem_rodou():
    a = make("web.https.ausente")
    b = make("web.hsts.ausente")
    deep = make("web.hsts.fraco", source="checagem.profunda")
    previous = scan([a, b, deep], scan_id="s0", started="2026-10-01T10:00:00+00:00")
    analyze(previous)
    c = make("web.https.sem_redirecionamento", "http://exemplo.com.br/")
    current = scan([make("web.hsts.ausente"), c])
    result = diff.compare(current, previous)
    assert [x["check_id"] for x in result["fixed"]] == ["web.https.ausente"]
    assert [x["check_id"] for x in result["new"]] == ["web.https.sem_redirecionamento"]
    assert [x["check_id"] for x in result["persisting"]] == ["web.hsts.ausente"]
    assert [x["check_id"] for x in result["unverified"]] == ["web.hsts.fraco"]


# -- histórico ------------------------------------------------------------------------


def test_historico_salva_compara_e_aplica_triagem(tmp_path: Path):
    store = Store(tmp_path / "eigan.db")
    first = scan(
        [make("web.https.ausente"), make("web.hsts.ausente")],
        scan_id="a1",
        started="2026-10-01T10:00:00+00:00",
    )
    store.mark_first_seen(first)
    analyze(first)
    store.save(first)

    loaded = store.get("a1")
    assert loaded is not None and len(loaded.findings) == 2
    assert loaded.analysis["posture"]["score"] == first.analysis["posture"]["score"]

    by_check = {f.check_id: f.fingerprint for f in first.findings}
    store.set_triage(
        "url", "https://exemplo.com.br", by_check["web.hsts.ausente"], TriageStatus.ACCEPTED, "CDN"
    )
    # A barra final não muda o alvo.
    store.set_triage(
        "url", "https://exemplo.com.br/", by_check["web.https.ausente"], TriageStatus.FIXED
    )

    second = scan([make("web.https.ausente"), make("web.hsts.ausente")], scan_id="a2")
    store.apply_triage(second)
    store.mark_first_seen(second)
    by_id = {f.check_id: f for f in second.findings}
    assert by_id["web.hsts.ausente"].status is TriageStatus.ACCEPTED
    # "Corrigido" que reaparece volta a ficar aberto.
    assert by_id["web.https.ausente"].status is TriageStatus.OPEN
    assert "reapareceu" in by_id["web.https.ausente"].status_note
    assert by_id["web.hsts.ausente"].first_seen == "2026-10-01T10:00:00+00:00"

    previous = store.previous(second)
    assert previous is not None and previous.id == "a1"
    analyze(second, previous)
    store.save(second)
    assert [row["id"] for row in store.scans()] == ["a2", "a1"]
    [target] = store.targets()
    assert target["total"] == 2
    assert store.delete("a1") is True
    assert store.get("a1") is None
