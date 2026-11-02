"""JSON (ida e volta), CSV (planilha segura) e SARIF 2.1.0 (estrutura do esquema oficial)."""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import pytest
from fakes_reports import (
    IMG,
    JS_URL,
    SCRIPT,
    SECRET,
    SITE,
    analyzed,
    clean_result,
    make,
    many_findings,
    not_evaluated,
    sample_result,
    sample_with_diff,
    scan,
)

from eigan import __version__
from eigan.core import kb
from eigan.core.kb import Fix, KBEntry
from eigan.core.models import (
    Category,
    CheckRun,
    Confidence,
    Exposure,
    Fact,
    ScanResult,
    Severity,
    TargetKind,
    TriageStatus,
)
from eigan.reports import render_csv, render_json, render_sarif
from eigan.reports.exports import CSV_COLUMNS, csv_cell
from eigan.reports.sarif import safe_url

# -- JSON ------------------------------------------------------------------------------------


def test_json_ida_e_volta_preserva_o_resultado() -> None:
    result = sample_with_diff()
    text = render_json(result)
    back = ScanResult.from_dict(json.loads(text))
    assert back.to_dict() == result.to_dict()
    assert back.kind is TargetKind.URL
    assert [f.fingerprint for f in back.findings] == [f.fingerprint for f in result.findings]
    assert isinstance(back.findings[0].severity, Severity)
    assert back.analysis["posture"] == result.analysis["posture"]


def test_json_ida_e_volta_gera_os_mesmos_relatorios() -> None:
    result = sample_result()
    back = ScanResult.from_dict(json.loads(render_json(result)))
    assert render_csv(back) == render_csv(result)
    assert render_sarif(back) == render_sarif(result)


def test_json_mantem_acentos_legiveis() -> None:
    text = render_json(analyzed(scan([make(title="Coração São João")])))
    assert "Coração São João" in text
    assert "\\u00e7" not in text
    assert text.endswith("\n")


def test_json_com_valores_nao_serializaveis_nos_detalhes() -> None:
    details: dict[str, Any] = {
        "conjunto": {"b", "a"},
        "caminho": PurePosixPath("/etc/passwd"),
        "momento": datetime(2026, 11, 1, tzinfo=UTC),
        "severidade": Severity.HIGH,
        "objeto": object,
    }
    data = json.loads(render_json(analyzed(scan([make(details=details)]))))
    saved = data["findings"][0]["details"]
    assert saved["conjunto"] == ["a", "b"]
    assert saved["caminho"] == "/etc/passwd"
    assert saved["momento"].startswith("2026-11-01")
    assert saved["severidade"] == "high"
    assert isinstance(saved["objeto"], str)


def test_json_com_substituto_solto_continua_gravavel_e_volta_igual() -> None:
    hostile = "banner \udce9 fim"
    text = render_json(analyzed(scan([make(evidence=hostile)])))
    assert text.encode("utf-8")
    assert "\\udce9" in text
    assert json.loads(text)["findings"][0]["evidence"] == hostile


def test_json_nao_esconde_caracteres_invisiveis_e_volta_igual() -> None:
    hostile = "a\u202eb\u2066c\x7fd\ufeffe"
    text = render_json(analyzed(scan([make(title=hostile, evidence=hostile)])))
    for char in ("\u202e", "\u2066", "\x7f", "\ufeff"):
        assert char not in text
    assert "\\u202e" in text
    data = json.loads(text)
    assert data["findings"][0]["title"] == hostile
    assert data["findings"][0]["evidence"] == hostile


def test_json_com_chaves_e_conjuntos_incomuns_nos_detalhes() -> None:
    details = {("a", "b"): 1, 2: "dois", "conjunto": {f"aws={SECRET}"}}
    saved = json.loads(render_json(analyzed(scan([make(details=details)]))))["findings"][0]
    assert saved["details"]["('a', 'b')"] == 1
    assert saved["details"]["2"] == "dois"
    assert SECRET not in saved["details"]["conjunto"][0]


def test_json_nao_vaza_segredo_de_resultado_antigo() -> None:
    result = analyzed(
        scan(
            [make(evidence=f"chave {SECRET}", details={"x": [f"aws={SECRET}"]})],
            facts=[Fact("tech", "t", {"name": "n", "evidence": f"banner {SECRET}"}, source="web")],
            errors=[f"falha {SECRET}"],
        )
    )
    text = render_json(result)
    assert SECRET not in text
    assert "AKIA…(20 caracteres)" in text
    # o objeto em memória continua como estava (o mascaramento é só na saída)
    assert result.findings[0].evidence == f"chave {SECRET}"


def test_json_de_nao_avaliado_e_sem_problemas() -> None:
    for result in (not_evaluated(), clean_result()):
        back = ScanResult.from_dict(json.loads(render_json(result)))
        assert back.analysis["evaluated"] is result.analysis["evaluated"]


# -- CSV -------------------------------------------------------------------------------------


def read_csv(text: str) -> list[dict[str, str]]:
    assert text.startswith("\ufeff")
    return list(csv.DictReader(io.StringIO(text[1:], newline=""), delimiter=";"))


def test_csv_abre_no_excel_em_portugues() -> None:
    text = render_csv(sample_result())
    assert text.startswith("\ufeff")
    assert text.encode("utf-8").startswith(b"\xef\xbb\xbf")
    first_line = text[1:].split("\r\n")[0]
    assert first_line == ";".join(CSV_COLUMNS)
    assert list(CSV_COLUMNS) == [
        "Prioridade",
        "Faixa",
        "Severidade",
        "Título",
        "Ativo",
        "Identificador",
        "Confiança",
        "Exposição",
        "CVEs",
        "CISA KEV",
        "Situação",
        "Primeira vez",
        "Evidência",
    ]


def test_csv_tem_uma_linha_por_achado_ordenada_por_prioridade() -> None:
    result = sample_result()
    rows = read_csv(render_csv(result))
    assert len(rows) == len(result.findings)
    priorities = [int(row["Prioridade"]) for row in rows]
    assert priorities == sorted(priorities, reverse=True)
    top = rows[0]
    assert top["Faixa"] == "P1"
    assert top["Severidade"] == "Crítica"
    assert top["CVEs"] == "CVE-2021-44228, CVE-2021-45046"
    assert top["CISA KEV"] == "Sim"
    assert {row["CISA KEV"] for row in rows[1:]} == {"Não"}
    assert top["Ativo"] == "loja.exemplo.com.br:8443/tcp"
    assert top["Identificador"] == "net.servico.vulneravel"
    assert top["Confiança"] == Confidence.FIRM.label
    assert top["Exposição"] == Exposure.INTERNET.label
    assert top["Primeira vez"] == "01/11/2026 07:00" or top["Primeira vez"]


def test_csv_situacao_mostra_a_nota_da_triagem() -> None:
    rows = read_csv(render_csv(sample_result()))
    accepted = next(row for row in rows if "legado" in row["Ativo"])
    assert accepted["Situação"].startswith(TriageStatus.ACCEPTED.label)
    assert "desligamento previsto" in accepted["Situação"]


@pytest.mark.parametrize(
    "prefix",
    ["=", "+", "-", "@", "\t", "\r", "\n", "＝", "＋", "－", "＠"],
)
def test_celula_que_comeca_com_formula_ganha_apostrofo(prefix: str) -> None:
    assert csv_cell(f"{prefix}1+1") == f"'{prefix}1+1"


@pytest.mark.parametrize(
    "value",
    ["texto", "CVE-2021-44228", "1=1", "a-b", "user@host", "https://x/?a=1", "", "'já tem", "12"],
)
def test_celula_comum_nao_muda(value: str) -> None:
    assert csv_cell(value) == value


@pytest.mark.parametrize(
    "payload",
    [
        '=HYPERLINK("http://mal.example";"clique")',
        "=cmd|'/C calc'!A0",
        "+1+1",
        "-2+3",
        "@SOMA(1;1)",
        "\t=1+1",
        "\r=1+1",
    ],
)
@pytest.mark.parametrize("column", ["title", "asset", "note", "evidence"])
def test_nenhuma_coluna_vira_formula(column: str, payload: str) -> None:
    fields: dict[str, Any] = {"title": "Título", "asset": "ativo"}
    if column == "note":
        fields.update(status=TriageStatus.ACCEPTED, status_note=payload)
    else:
        fields[column] = payload
    rows = read_csv(render_csv(analyzed(scan([make(**fields)]))))
    for name, cell in rows[0].items():
        assert not cell.startswith(("=", "+", "-", "@", "\t", "\r", "\n")), (name, cell)
    target = {"title": "Título", "asset": "Ativo", "evidence": "Evidência"}.get(column)
    if target:
        assert rows[0][target].startswith("'") or rows[0][target].startswith("'".strip())


def test_csv_quebras_de_linha_da_evidencia_viram_separador_e_limite() -> None:
    rows = read_csv(render_csv(analyzed(scan([make(evidence="a\n  b\r\nc")]))))
    assert rows[0]["Evidência"] == "a | b | c"
    rows = read_csv(render_csv(analyzed(scan([make(evidence="E" * 2000)]))))
    assert len(rows[0]["Evidência"]) == 500


def test_csv_separador_seguido_de_formula_nao_abre_outra_celula() -> None:
    title = 'x;=1+1;"=2+2"'
    rows = read_csv(render_csv(analyzed(scan([make(title=title)]))))
    assert rows[0]["Título"] == title
    assert rows[0]["Ativo"] == SITE


def test_csv_ponto_e_virgula_e_aspas_ficam_na_mesma_celula() -> None:
    title = 'a;b "c"\nd'
    rows = read_csv(render_csv(analyzed(scan([make(title=title)]))))
    assert rows[0]["Título"] == title
    assert len(rows) == 1


def test_csv_caracteres_invisiveis_e_segredos() -> None:
    rows = read_csv(
        render_csv(analyzed(scan([make(title="a\u202eb", evidence=f"chave {SECRET}\x00")])))
    )
    assert rows[0]["Título"] == "a<U+202E>b"
    assert SECRET not in rows[0]["Evidência"]
    assert "AKIA…(20 caracteres)" in rows[0]["Evidência"]
    assert "<U+0000>" in rows[0]["Evidência"]


def test_csv_vazio_tem_so_o_cabecalho() -> None:
    assert read_csv(render_csv(clean_result())) == []
    assert read_csv(render_csv(not_evaluated())) == []


def test_csv_com_centenas_de_achados_nao_corta_nenhum() -> None:
    assert len(read_csv(render_csv(many_findings(700)))) == 700


# -- SARIF: validador das regras do esquema oficial 2.1.0 --------------------------------------

LEVELS = {"none", "note", "warning", "error"}
SUPPRESSION_KINDS = {"inSource", "external"}
SUPPRESSION_STATUS = {"accepted", "underReview", "rejected"}
BASELINE = {"new", "unchanged", "updated", "absent"}
DATE_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
FORBIDDEN_IN_URI = re.compile(r"[\s\"<>\\^`{|}\x00-\x1f\x7f]")


def check_uri(uri: str, *, absolute: bool) -> None:
    """``format: uri`` / ``uri-reference`` da RFC 3986: só caracteres válidos, ASCII."""
    assert uri.isascii(), uri
    assert not FORBIDDEN_IN_URI.search(uri), uri
    assert not re.search(r"%(?![0-9A-Fa-f]{2})", uri), uri
    if absolute:
        assert urlsplit(uri).scheme, uri


def check_message(message: dict[str, Any]) -> None:
    assert message.get("text") or message.get("id")


def check_multiformat(item: dict[str, Any]) -> None:
    assert isinstance(item["text"], str)
    assert item["text"]


def check_tags(properties: dict[str, Any]) -> None:
    tags = properties.get("tags", [])
    assert len(tags) == len(set(tags))
    assert all(isinstance(tag, str) for tag in tags)


def check_location(location: dict[str, Any]) -> None:
    assert set(location) <= {"physicalLocation", "logicalLocations", "message", "id"}
    physical = location.get("physicalLocation")
    if physical:
        artifact = physical["artifactLocation"]
        assert artifact.get("uri")
        has_base = "uriBaseId" in artifact
        check_uri(artifact["uri"], absolute=False)
        if has_base:
            assert not urlsplit(artifact["uri"]).scheme  # relativa + uriBaseId
            assert not artifact["uri"].startswith("/")
        region = physical.get("region")
        if region:
            assert isinstance(region["startLine"], int)
            assert region["startLine"] >= 1
    for logical in location.get("logicalLocations", []):
        assert isinstance(logical["name"], str)
        assert logical["name"]
        assert logical["kind"] == "resource"
    assert physical or location.get("logicalLocations")


def validate_sarif(text: str) -> dict[str, Any]:
    """As regras do esquema que o relatório usa (obrigatórios, enums, formatos e índices)."""
    log = json.loads(text)
    assert log["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert log["version"] == "2.1.0"
    assert len(log["runs"]) == 1
    run = log["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "EIGAN"
    assert driver["version"] == __version__
    assert driver["semanticVersion"] == __version__
    assert re.fullmatch(r"[a-zA-Z]{2}(-[a-zA-Z]{2})?", driver["language"])
    check_uri(driver["informationUri"], absolute=True)
    rules = driver["rules"]
    ids = [rule["id"] for rule in rules]
    assert len(ids) == len(set(ids))
    for rule in rules:
        assert rule["id"]
        check_multiformat(rule["shortDescription"])
        check_multiformat(rule["fullDescription"])
        check_multiformat(rule["help"])
        assert isinstance(rule["help"]["markdown"], str)
        assert rule["defaultConfiguration"]["level"] in LEVELS
        props = rule["properties"]
        check_tags(props)
        assert "security" in props["tags"]
        assert props["security-severity"] in {"9.5", "7.5", "5.0", "2.5", "0.0"}
        assert props["precision"] in {"very-high", "high", "medium"}
        if "helpUri" in rule:
            check_uri(rule["helpUri"], absolute=True)
    for invocation in run["invocations"]:
        assert isinstance(invocation["executionSuccessful"], bool)
        for key in ("startTimeUtc", "endTimeUtc"):
            if key in invocation:
                assert DATE_TIME.match(invocation[key]), invocation[key]
        for note in invocation.get("toolExecutionNotifications", []):
            check_message(note["message"])
            assert note["level"] in LEVELS
    for base in run.get("originalUriBaseIds", {}).values():
        check_uri(base["uri"], absolute=True)
        assert base["uri"].endswith("/")
    assert run["automationDetails"]["id"]
    for result in run["results"]:
        assert result["ruleId"] in ids
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]
        assert result["level"] in LEVELS
        check_message(result["message"])
        for location in result["locations"]:
            check_location(location)
        assert list(result["partialFingerprints"]) == ["eiganFingerprint/v1"]
        if "baselineState" in result:
            assert result["baselineState"] in BASELINE
        for suppression in result.get("suppressions", []):
            assert suppression["kind"] in SUPPRESSION_KINDS
            assert suppression["status"] in SUPPRESSION_STATUS
    return log


def run_of(text: str) -> dict[str, Any]:
    return validate_sarif(text)["runs"][0]


# -- SARIF: conteúdo ---------------------------------------------------------------------------


def test_sarif_de_exemplo_segue_o_esquema() -> None:
    result = sample_with_diff()
    run = run_of(render_sarif(result))
    assert len(run["results"]) == len(result.findings)
    assert len(run["tool"]["driver"]["rules"]) == len({f.check_id for f in result.findings})
    assert run["properties"]["grade"] == result.analysis["posture"]["grade"]
    assert run["properties"]["score"] == result.analysis["posture"]["score"]
    assert run["properties"]["evaluated"] is True


def test_sarif_regra_tem_ajuda_com_os_passos_da_base() -> None:
    run = run_of(render_sarif(analyzed(scan([make("web.hsts.ausente")]))))
    rule = run["tool"]["driver"]["rules"][0]
    entry = kb.require("web.hsts.ausente")
    assert rule["id"] == "web.hsts.ausente"
    assert rule["name"] == "WebHstsAusente"
    assert rule["shortDescription"]["text"] == entry.title
    assert rule["fullDescription"]["text"] == entry.summary
    assert entry.steps[0] in rule["help"]["text"]
    assert rule["help"]["text"].startswith("1. ")
    assert "Como verificar:" in rule["help"]["text"]
    assert "**Como corrigir**" in rule["help"]["markdown"]
    assert rule["helpUri"] == safe_url(entry.references[0])
    assert rule["defaultConfiguration"]["level"] == "warning"
    tags = rule["properties"]["tags"]
    assert entry.category.value in tags
    if entry.cwe:
        assert entry.cwe in tags


@pytest.mark.parametrize(
    ("severity", "level", "score"),
    [
        (Severity.CRITICAL, "error", "9.5"),
        (Severity.HIGH, "error", "7.5"),
        (Severity.MEDIUM, "warning", "5.0"),
        (Severity.LOW, "note", "2.5"),
        (Severity.INFO, "note", "0.0"),
    ],
)
def test_sarif_mapeia_severidade(severity: Severity, level: str, score: str) -> None:
    run = run_of(render_sarif(analyzed(scan([make("id.qualquer", severity=severity)]))))
    assert run["results"][0]["level"] == level
    assert run["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == score


def test_sarif_uma_regra_por_tipo_com_indice_consistente() -> None:
    findings = [make("web.hsts.fraco", f"https://h{n}.exemplo.com/") for n in range(3)]
    findings += [make("web.hsts.ausente"), make("id.sem.base", severity=Severity.LOW)]
    run = run_of(render_sarif(analyzed(scan(findings))))
    assert len(run["tool"]["driver"]["rules"]) == 3
    assert len(run["results"]) == 5
    for item in run["results"]:
        assert run["tool"]["driver"]["rules"][item["ruleIndex"]]["id"] == item["ruleId"]


def test_sarif_mensagem_com_titulo_e_ativo() -> None:
    run = run_of(render_sarif(analyzed(scan([make(title="Título", asset="ativo")]))))
    assert run["results"][0]["message"]["text"] == "Título — ativo"
    run = run_of(render_sarif(analyzed(scan([make(title="Título", asset="")]))))
    assert run["results"][0]["message"]["text"] == "Título"
    assert run["results"][0]["locations"][0]["logicalLocations"][0]["name"]


def test_sarif_propriedades_do_resultado() -> None:
    finding = make(
        cves=["CVE-2021-44228"],
        kev=True,
        confidence=Confidence.CONFIRMED,
        exposure=Exposure.INTERNET,
    )
    run = run_of(render_sarif(analyzed(scan([finding]))))
    props = run["results"][0]["properties"]
    assert props["band"] == "P1"
    assert props["priority"] == finding.priority
    assert props["confidence"] == Confidence.CONFIRMED.value
    assert props["exposure"] == finding.exposure.value
    assert props["cves"] == ["CVE-2021-44228"]
    assert props["kev"] is True
    assert props["status"] == "aberto"
    assert run["results"][0]["partialFingerprints"]["eiganFingerprint/v1"] == finding.fingerprint


# -- SARIF: locais --------------------------------------------------------------------------------


def project_location(asset: str, target: str = "/projeto", **extra: Any) -> dict[str, Any]:
    result = analyzed(
        scan(
            [make("code.segredo.exposto", asset, exposure=Exposure.CODE, **extra)],
            kind=TargetKind.PROJECT,
            target=target,
        )
    )
    location: dict[str, Any] = run_of(render_sarif(result))["results"][0]["locations"][0]
    return location


def test_achado_de_codigo_aponta_arquivo_relativo_e_linha() -> None:
    physical = project_location("src/app.py:12")["physicalLocation"]
    assert physical["artifactLocation"] == {"uri": "src/app.py", "uriBaseId": "SRCROOT"}
    assert physical["region"] == {"startLine": 12}


@pytest.mark.parametrize(
    ("asset", "uri", "line"),
    [
        ("requirements.txt", "requirements.txt", None),
        ("./src/a.py:3", "src/a.py", 3),
        ("src\\sub\\a.py:7", "src/sub/a.py", 7),
        ("src/a.py:3:9", "src/a.py", 3),
        ("src/a.py:0", "src/a.py", None),
        ("pasta com espaço/ação.py:2", "pasta%20com%20espa%C3%A7o/a%C3%A7%C3%A3o.py", 2),
        ('a"b<c>.py:1', "a%22b%3Cc%3E.py", 1),
        ("100%.py:1", "100%25.py", 1),
        ("/projeto/src/a.py:5", "src/a.py", 5),
    ],
)
def test_caminhos_de_codigo_viram_uri_relativa(asset: str, uri: str, line: int | None) -> None:
    physical = project_location(asset)["physicalLocation"]
    assert physical["artifactLocation"] == {"uri": uri, "uriBaseId": "SRCROOT"}
    if line is None:
        assert "region" not in physical
    else:
        assert physical["region"]["startLine"] == line


def test_caminho_absoluto_no_windows_vira_relativo_sem_diferenciar_maiusculas() -> None:
    physical = project_location("c:\\Projetos\\App\\src\\a.py:4", target="C:\\Projetos\\App\\")[
        "physicalLocation"
    ]
    assert physical["artifactLocation"]["uri"] == "src/a.py"
    assert physical["region"]["startLine"] == 4


def test_caminho_fora_do_projeto_continua_absoluto() -> None:
    physical = project_location("C:\\Outro\\a.py:4", target="C:\\Projetos\\App")["physicalLocation"]
    assert physical["artifactLocation"] == {"uri": "file:///C:/Outro/a.py"}
    assert physical["region"]["startLine"] == 4
    physical = project_location("/etc/nginx/nginx.conf:9")["physicalLocation"]
    assert physical["artifactLocation"] == {"uri": "file:///etc/nginx/nginx.conf"}


def test_achado_sobre_a_propria_pasta_do_projeto_fica_como_local_logico() -> None:
    location = project_location("/projeto")
    assert "physicalLocation" not in location
    assert location["logicalLocations"][0]["name"] == "/projeto"


def test_projeto_define_a_raiz_dos_caminhos_relativos() -> None:
    result = analyzed(scan([make()], kind=TargetKind.PROJECT, target="C:\\Meu Projeto\\App"))
    run = run_of(render_sarif(result))
    assert run["originalUriBaseIds"]["SRCROOT"]["uri"] == "file:///C:/Meu%20Projeto/App/"
    result = analyzed(scan([make()], kind=TargetKind.PROJECT, target="/srv/app/"))
    assert (
        run_of(render_sarif(result))["originalUriBaseIds"]["SRCROOT"]["uri"] == "file:///srv/app/"
    )
    result = analyzed(scan([make()], kind=TargetKind.PROJECT, target="projeto-relativo"))
    assert "originalUriBaseIds" not in run_of(render_sarif(result))


def test_auditoria_web_nao_define_raiz_de_codigo() -> None:
    assert "originalUriBaseIds" not in run_of(render_sarif(sample_result()))


def test_achado_web_aponta_a_url_e_um_local_logico() -> None:
    location = run_of(render_sarif(analyzed(scan([make(asset=SITE)]))))["results"][0]["locations"][
        0
    ]
    assert location["physicalLocation"]["artifactLocation"]["uri"] == SITE
    assert "uriBaseId" not in location["physicalLocation"]["artifactLocation"]
    assert location["logicalLocations"] == [{"name": SITE, "kind": "resource"}]


@pytest.mark.parametrize(
    "asset",
    [
        "exemplo.com.br:443/tcp",
        "10.0.0.1",
        "serviço Redis em 10.0.0.1:6379",
        "HKLM\\SOFTWARE\\Policies\\X",
        JS_URL,
        "data:text/html,<script>",
    ],
)
def test_achado_de_rede_e_host_fica_como_local_logico(asset: str) -> None:
    location = run_of(render_sarif(analyzed(scan([make(asset=asset)]))))["results"][0]["locations"][
        0
    ]
    assert "physicalLocation" not in location
    assert location["logicalLocations"] == [{"name": asset, "kind": "resource"}]


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://exemplo.com/a b", "https://exemplo.com/a%20b"),
        ('https://exemplo.com/?q="<x>"', "https://exemplo.com/?q=%22%3Cx%3E%22"),
        ("HTTPS://exemplo.com/ação", "https://exemplo.com/a%C3%A7%C3%A3o"),
        ("https://exemplo.com/100%", "https://exemplo.com/100%25"),
        ("https://exemplo.com/%41", "https://exemplo.com/%41"),
        ("http://[::1]:8080/x", "http://[::1]:8080/x"),
        ("https://exemplo.com/a?b=c&d=e#f", "https://exemplo.com/a?b=c&d=e#f"),
    ],
)
def test_url_segura_para_o_esquema(url: str, expected: str) -> None:
    assert safe_url(url) == expected
    check_uri(expected, absolute=True)


def test_url_hostil_vira_uri_valida() -> None:
    asset = 'https://exemplo.com/"><script>alert(1)</script>?a=1&b=<x>#"'
    run = run_of(render_sarif(analyzed(scan([make(asset=asset)]))))
    uri = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert "<" not in uri
    assert '"' not in uri


# -- SARIF: triagem, comparação e execução --------------------------------------------------------


@pytest.mark.parametrize(
    "status",
    [TriageStatus.ACCEPTED, TriageStatus.FALSE_POSITIVE],
)
def test_triado_vira_supressao(status: TriageStatus) -> None:
    finding = make(status=status, status_note="Motivo da triagem")
    item = run_of(render_sarif(analyzed(scan([finding]))))["results"][0]
    assert item["suppressions"] == [
        {"kind": "external", "status": "accepted", "justification": "Motivo da triagem"}
    ]


def test_triado_sem_nota_usa_o_nome_da_situacao() -> None:
    finding = make(status=TriageStatus.FALSE_POSITIVE)
    item = run_of(render_sarif(analyzed(scan([finding]))))["results"][0]
    assert item["suppressions"][0]["justification"] == TriageStatus.FALSE_POSITIVE.label


def test_aberto_nao_tem_supressao() -> None:
    item = run_of(render_sarif(analyzed(scan([make(status=TriageStatus.OPEN)]))))["results"][0]
    assert "suppressions" not in item
    assert item["properties"]["status"] == "aberto"


def test_corrigido_vira_supressao_com_justificativa() -> None:
    item = run_of(render_sarif(analyzed(scan([make(status=TriageStatus.FIXED)]))))["results"][0]
    assert "corrigido" in item["suppressions"][0]["justification"]


def test_comparacao_vira_baseline_state() -> None:
    result = sample_with_diff()
    run = run_of(render_sarif(result))
    states = {item["baselineState"] for item in run["results"] if "baselineState" in item}
    assert states == {"new", "unchanged"}
    by_fingerprint = {
        item["partialFingerprints"]["eiganFingerprint/v1"]: item for item in run["results"]
    }
    persisting = result.analysis["diff"]["persisting"][0]["fingerprint"]
    assert by_fingerprint[persisting]["baselineState"] == "unchanged"


def test_sem_comparacao_nao_tem_baseline_state() -> None:
    run = run_of(render_sarif(sample_result()))
    assert not [item for item in run["results"] if "baselineState" in item]


def test_invocacao_registra_horario_erros_e_verificacoes_incompletas() -> None:
    run = run_of(render_sarif(sample_result()))
    invocation = run["invocations"][0]
    assert invocation["executionSuccessful"] is True
    assert invocation["startTimeUtc"] == "2026-11-01T10:00:00Z"
    assert invocation["endTimeUtc"] == "2026-11-01T10:04:12Z"
    notes = [note["message"]["text"] for note in invocation["toolExecutionNotifications"]]
    assert any("tempo esgotado após 30 s" in note for note in notes)
    assert any(note.startswith("Cookies: Tempo esgotado") for note in notes)
    assert any(note.startswith("Portas: Erro") for note in notes)


def test_invocacao_cancelada_nao_foi_bem_sucedida() -> None:
    run = run_of(render_sarif(analyzed(scan([make()], status="cancelada"))))
    assert run["invocations"][0]["executionSuccessful"] is False
    assert "toolExecutionNotifications" not in run["invocations"][0]


def test_nao_avaliado_e_sem_problemas_seguem_o_esquema() -> None:
    run = run_of(render_sarif(not_evaluated()))
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []
    assert run["properties"]["evaluated"] is False
    run = run_of(render_sarif(clean_result()))
    assert run["results"] == []
    assert run["properties"]["score"] == 100


def test_centenas_de_achados_seguem_o_esquema_sem_cortar() -> None:
    run = run_of(render_sarif(many_findings(600)))
    assert len(run["results"]) == 600
    assert len({i["partialFingerprints"]["eiganFingerprint/v1"] for i in run["results"]}) == 600


# -- SARIF: texto hostil --------------------------------------------------------------------------


def test_texto_hostil_sai_como_texto_e_controles_a_mostra() -> None:
    finding = make(
        title=f"{SCRIPT}\u202e",
        asset=f"{IMG}\x00",
        evidence=f"{SCRIPT}\x1b[31m",
        status=TriageStatus.ACCEPTED,
        status_note="nota\u2066",
    )
    text = render_sarif(analyzed(scan([finding], target="alvo\u202e", errors=["erro\x07"])))
    run = run_of(text)
    item = run["results"][0]
    assert SCRIPT in item["message"]["text"]
    assert "<U+202E>" in item["message"]["text"]
    assert "<U+0000>" in item["message"]["text"]
    assert "<U+001B>" in item["properties"]["evidence"]
    assert item["suppressions"][0]["justification"] == "nota<U+2066>"
    assert run["properties"]["target"] == "alvo<U+202E>"
    assert "<U+0007>" in run["invocations"][0]["toolExecutionNotifications"][0]["message"]["text"]
    assert "\u202e" not in text
    assert "\\u0000" not in text


def test_evidencia_e_erros_nao_vazam_segredo_e_tem_limite() -> None:
    finding = make(evidence=f"chave {SECRET} " + "E" * 5000)
    run_text = render_sarif(analyzed(scan([finding], errors=[f"falha {SECRET}"])))
    assert SECRET not in run_text
    evidence = run_of(run_text)["results"][0]["properties"]["evidence"]
    assert "AKIA…(20 caracteres)" in evidence
    assert len(evidence) <= 1000


def _entry(**fields: Any) -> KBEntry:
    base: dict[str, Any] = {
        "id": "teste.sarif.hostil",
        "title": "Entrada",
        "category": Category.WEB,
        "severity": Severity.HIGH,
        "summary": "Resumo",
        "explanation": "Explicação",
        "risk": "Risco",
        "steps": ("Passo",),
        "verify": "Verifique",
        "fix_group": "configuracao",
    }
    base.update(fields)
    return KBEntry(**base)


def _sarif_with(entry: KBEntry) -> dict[str, Any]:
    previous = dict(kb._KB)
    kb._KB[entry.id] = entry
    try:
        run = run_of(render_sarif(analyzed(scan([make(entry.id, title="T")]))))
    finally:
        kb._KB.clear()
        kb._KB.update(previous)
    rule: dict[str, Any] = run["tool"]["driver"]["rules"][0]
    return rule


def test_markdown_da_ajuda_nao_vira_html_nem_link() -> None:
    rule = _sarif_with(
        _entry(
            title=SCRIPT,
            summary="[clique](javascript:alert(1))",
            risk="<img src=x onerror=alert(1)>",
            steps=("`código` & *ênfase*",),
            verify="<b>x</b>",
            references=(JS_URL, "https://exemplo.org/ok"),
        )
    )
    markdown = rule["help"]["markdown"]
    assert "<script" not in markdown
    assert "<img" not in markdown
    assert "<b>" not in markdown
    # Colchetes escapados: o Markdown mostra o texto em vez de criar um link.
    assert "\\[clique\\](javascript:alert(1))" in markdown
    assert not re.search(r"(?<!\\)\]\(", markdown)
    assert f"<{JS_URL}>" not in markdown
    assert "<https://exemplo.org/ok>" in markdown
    assert rule["helpUri"] == "https://exemplo.org/ok"


def test_referencia_que_nao_e_http_nao_vira_help_uri() -> None:
    rule = _sarif_with(_entry(references=(JS_URL, "/relativo", "file:///etc/passwd")))
    assert "helpUri" not in rule


def test_markdown_inclui_exemplos_de_correcao_em_bloco_de_codigo() -> None:
    rule = _sarif_with(
        _entry(
            examples=(
                Fix("nginx", "nginx", 'add_header X "y" always;', "nginx"),
                Fix("generico", "Com crases", "```\ncódigo\n```", 'lang"><x'),
            )
        )
    )
    markdown = rule["help"]["markdown"]
    assert '**Exemplo de correção: nginx**\n\n```nginx\nadd_header X "y" always;\n```' in markdown
    assert "````langx\n```\ncódigo\n```\n````" in markdown


def test_regra_sem_entrada_na_base_tem_ajuda_minima() -> None:
    run = run_of(render_sarif(analyzed(scan([make("id.fora.da.base", title="Título antigo")]))))
    rule = run["tool"]["driver"]["rules"][0]
    assert rule["shortDescription"]["text"] == "Título antigo"
    assert rule["help"]["text"]
    assert "helpUri" not in rule


def test_nomes_de_regra_em_camel_case() -> None:
    run = run_of(render_sarif(analyzed(scan([make("web.https.sem_redirecionamento")]))))
    assert run["tool"]["driver"]["rules"][0]["name"] == "WebHttpsSemRedirecionamento"


def test_execucao_com_mensagem_hostil_no_nome() -> None:
    run = run_of(
        render_sarif(
            analyzed(scan([make()], runs=[CheckRun("x", SCRIPT, "a", "erro", 0.1, f"m {SECRET}")]))
        )
    )
    note = run["invocations"][0]["toolExecutionNotifications"][0]["message"]["text"]
    assert SCRIPT in note
    assert SECRET not in note


# -- segredos em título, ativo e alvo; JSON válido; caminhos do SARIF ---------------------


CRED_URL = "https://admin:SuperSegredo123xyz@exemplo.com/p?token=AKIAABCDEFGHIJKLMNOP"


def _credentialed() -> ScanResult:
    finding = make(
        "web.hsts.ausente",
        CRED_URL,
        title=f"Falha em {CRED_URL}",
        status_note="Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789",
    )
    return analyzed(scan([finding], target=CRED_URL))


def test_segredos_no_titulo_ativo_e_alvo_nao_vazam_em_nenhum_formato() -> None:
    from eigan.reports import render_html, render_pdf

    result = _credentialed()
    outputs = [
        render_json(result),
        render_csv(result),
        render_sarif(result),
        render_html(result),
        render_pdf(result).decode("latin-1"),
    ]
    for text in outputs:
        assert "SuperSegredo123xyz" not in text
        assert "AKIAABCDEFGHIJKLMNOP" not in text
        assert "abcdefghijklmnopqrstuvwxyz0123456789" not in text


def test_pasta_padrao_nao_usa_a_senha_do_alvo() -> None:
    from eigan.reports import default_outdir

    assert "supersegredo" not in default_outdir(_credentialed()).name


def test_json_com_numero_nao_finito_e_valido() -> None:
    finding = make(details={"x": float("nan"), "y": float("inf"), "z": 1.5})
    text = render_json(analyzed(scan([finding])))
    assert "NaN" not in text
    assert "Infinity" not in text
    json.loads(text, parse_constant=lambda name: pytest.fail(name))


def test_sarif_caminho_que_sai_do_projeto_nao_usa_srcroot() -> None:
    from eigan.core.models import TargetKind

    finding = make("code.secrets.chave", "src/../../etc/passwd:3", exposure=Exposure.CODE)
    run = run_of(render_sarif(analyzed(scan([finding], target="/proj", kind=TargetKind.PROJECT))))
    artifact = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    assert "uriBaseId" not in artifact


def test_sarif_caminho_com_ponto_ponto_interno_e_normalizado() -> None:
    from eigan.core.models import TargetKind

    finding = make("code.secrets.chave", "src/a/../app.py:3", exposure=Exposure.CODE)
    run = run_of(render_sarif(analyzed(scan([finding], target="/proj", kind=TargetKind.PROJECT))))
    artifact = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    assert artifact == {"uri": "src/app.py", "uriBaseId": "SRCROOT"}
