"""Dependências vulneráveis: catálogo embarcado, severidade, KEV e proteção contra falso positivo."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from fakes_code import manifest_fact, write_tree
from helpers import CheckOutcome, run_check

from eigan.checks.code import advisories, dependencies, osv
from eigan.checks.code.advisories import (
    Advisory,
    Catalog,
    curated_catalog,
    package_key,
)
from eigan.checks.code.dependencies_kb import MALICIOUS, VULNERABLE
from eigan.checks.code.versioning import in_range, is_affected
from eigan.core import kb
from eigan.core.context import Cancelled, CheckContext, ScanContext
from eigan.core.models import Confidence, Severity
from eigan.core.registry import get_check, load_builtin_checks
from eigan.core.settings import Settings
from eigan.core.target import parse_target
from eigan.data import load_json


@pytest.fixture(autouse=True)
def sem_base_osv(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> None:
    """Os testes daqui usam só o catálogo embarcado (a base OSV é testada em test_code_osv)."""
    monkeypatch.setattr(osv, "osv_root", lambda: tmp_path_factory.mktemp("osv-vazio"))


def package_lock(*packages: tuple[str, str]) -> str:
    entries = {f"node_modules/{name}": {"version": version} for name, version in packages}
    return json.dumps(
        {"lockfileVersion": 3, "packages": {"": {"name": "app"}, **entries}},
        indent=2,
    )


def scan_manifest(
    root: Path, rel: str, content: str | None = None, **settings: object
) -> CheckOutcome:
    if content is not None:
        write_tree(root, {rel: content})
    return run_check(
        "code.dependencies",
        manifest_fact(root, rel),
        settings=Settings(**settings) if settings else None,
    )


# -- achados --------------------------------------------------------------------------


def test_lockfile_com_versao_vulneravel(tmp_path: Path) -> None:
    out = scan_manifest(
        tmp_path, "web/package-lock.json", package_lock(("lodash", "4.17.20"), ("qs", "6.11.0"))
    )
    [finding] = out.findings
    assert finding.check_id == VULNERABLE
    assert finding.title == "Dependência vulnerável: lodash 4.17.20"
    assert finding.severity is Severity.HIGH
    assert finding.confidence is Confidence.CONFIRMED
    assert finding.discriminator == "lodash@4.17.20"
    assert finding.asset == "web/package-lock.json:7"
    assert finding.cves == ["CVE-2021-23337"]
    assert "lodash 4.17.20" in finding.evidence
    assert "CVE-2021-23337" in finding.evidence
    details = finding.details
    assert details["pacote"] == "lodash"
    assert details["versao"] == "4.17.20"
    assert details["ecossistema"] == "npm"
    assert details["versao_corrigida"] == "4.17.21"
    assert details["acao"] == "atualize para 4.17.21 ou superior"
    assert details["kev"] is False
    [aviso] = details["avisos"]
    assert aviso["id"] == "GHSA-35jh-r3h4-6jhm"
    assert aviso["referencia"].startswith("https://")
    assert aviso["corrigida"] == "4.17.21"
    assert aviso["resumo"]
    assert aviso["titulo"]
    assert aviso["fonte"] == "curadoria"
    assert finding.tech == ["npm"]


def test_catalogo_embarcado_sozinho_nao_vira_ponto_forte(tmp_path: Path) -> None:
    """Sem a base OSV a cobertura é parcial: ausência de aviso não é garantia."""
    out = scan_manifest(tmp_path, "package-lock.json", package_lock(("lodash", "4.17.21")))
    assert out.findings == []
    assert out.passed == []


def test_manifesto_sem_dependencias_nao_vira_ponto_forte(tmp_path: Path) -> None:
    out = scan_manifest(tmp_path, "package-lock.json", package_lock())
    assert out.findings == []
    assert out.passed == []


def test_varios_avisos_viram_um_achado_com_a_maior_correcao(tmp_path: Path) -> None:
    pom = """\
<project><dependencies><dependency>
  <groupId>org.apache.logging.log4j</groupId>
  <artifactId>log4j-core</artifactId>
  <version>2.14.1</version>
</dependency></dependencies></project>
"""
    out = scan_manifest(tmp_path, "pom.xml", pom)
    [finding] = out.findings
    assert finding.discriminator == "org.apache.logging.log4j:log4j-core@2.14.1"
    assert set(finding.cves) >= {
        "CVE-2021-44228",
        "CVE-2021-45046",
        "CVE-2021-45105",
        "CVE-2021-44832",
    }
    assert finding.details["versao_corrigida"] == "2.17.1"
    assert finding.details["acao"] == "atualize para 2.17.1 ou superior"
    corrigidas = {a["id"]: a["corrigida"] for a in finding.details["avisos"]}
    assert corrigidas["GHSA-jfh8-c2jp-5v3q"] == "2.15.0"
    assert corrigidas["GHSA-8489-44mv-ggj8"] == "2.17.1"
    assert finding.tech == ["maven"]


def test_kev_eleva_para_critico(tmp_path: Path) -> None:
    pom = """\
<project><dependency>
  <groupId>org.apache.logging.log4j</groupId>
  <artifactId>log4j-core</artifactId>
  <version>2.14.1</version>
</dependency></project>
"""
    out = scan_manifest(tmp_path, "pom.xml", pom)
    [finding] = out.findings
    assert finding.kev is True  # CVE-2021-44228 está no catálogo CISA KEV embarcado
    assert finding.details["kev"] is True
    assert finding.severity is Severity.CRITICAL


def test_kev_eleva_aviso_de_severidade_menor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(dependencies.vulndb, "any_kev", lambda cves: "CVE-2021-23337" in cves)
    out = scan_manifest(tmp_path, "package-lock.json", package_lock(("lodash", "4.17.20")))
    [finding] = out.findings
    assert finding.kev is True
    assert finding.severity is Severity.CRITICAL


def test_sem_kev_mantem_a_severidade_do_aviso(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(dependencies.vulndb, "any_kev", lambda cves: False)
    out = scan_manifest(tmp_path, "package-lock.json", package_lock(("axios", "0.21.1")))
    [finding] = out.findings
    assert finding.kev is False
    assert finding.severity is Severity.HIGH  # maior entre os avisos que afetam 0.21.1


@pytest.mark.parametrize(
    ("package", "version", "clean_version"),
    [
        ("event-stream", "3.3.6", "3.3.5"),
        ("flatmap-stream", "0.1.1", None),
        ("node-ipc", "10.1.1", "10.1.3"),
        ("ua-parser-js", "0.7.29", "0.7.30"),
    ],
)
def test_pacote_malicioso(
    tmp_path: Path, package: str, version: str, clean_version: str | None
) -> None:
    out = scan_manifest(tmp_path, "package-lock.json", package_lock((package, version)))
    [finding] = out.findings
    assert finding.check_id == MALICIOUS
    assert finding.severity is Severity.CRITICAL
    assert finding.title == f"Pacote malicioso: {package} {version}"
    assert finding.details["acao"].startswith("remova")
    if clean_version is not None:
        limpo = scan_manifest(tmp_path, "package-lock.json", package_lock((package, clean_version)))
        assert limpo.findings == []


def test_sem_versao_corrigida_orienta_trocar_o_pacote(tmp_path: Path) -> None:
    pom = """\
<project><dependency>
  <groupId>log4j</groupId>
  <artifactId>log4j</artifactId>
  <version>1.2.17</version>
</dependency></project>
"""
    [finding] = scan_manifest(tmp_path, "pom.xml", pom).findings
    assert finding.details["versao_corrigida"] is None
    assert "nenhuma versão corrigida" in finding.details["acao"]


# -- um caso real por ecossistema: versão afetada e versão corrigida ------------------


CASES = [
    # (arquivo, conteúdo com {v}, CVE esperado, versão vulnerável, versão corrigida)
    (
        "requirements.txt",
        "PyYAML=={v}\n",
        "CVE-2020-14343",
        "5.3.1",
        "5.4",
    ),
    (
        "Pipfile.lock",
        '{{"default": {{"requests": {{"version": "=={v}"}}}}, "develop": {{}}}}',
        "CVE-2023-32681",
        "2.30.0",
        "2.32.0",
    ),
    (
        "poetry.lock",
        '[[package]]\nname = "Jinja2"\nversion = "{v}"\n',
        "CVE-2024-22195",
        "3.1.2",
        "3.1.6",
    ),
    (
        "package-lock.json",
        '{{"lockfileVersion": 3, "packages": {{"node_modules/minimist": {{"version": "{v}"}}}}}}',
        "CVE-2021-44906",
        "1.2.5",
        "1.2.6",
    ),
    (
        "yarn.lock",
        'jsonwebtoken@^8.0.0:\n  version "{v}"\n',
        "CVE-2022-23539",
        "8.5.1",
        "9.0.0",
    ),
    (
        "pnpm-lock.yaml",
        "packages:\n\n  axios@{v}:\n    resolution: {{integrity: x}}\n",
        "CVE-2023-45857",
        "1.5.0",
        "1.8.2",
    ),
    (
        "composer.lock",
        '{{"packages": [{{"name": "guzzlehttp/guzzle", "version": "{v}"}}]}}',
        "CVE-2022-31090",
        "v7.4.4",
        "v7.4.5",
    ),
    (
        "Gemfile.lock",
        "GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri ({v}-x86_64-linux)\n",
        "CVE-2022-24836",
        "1.13.3",
        "1.13.4",
    ),
    (
        "go.mod",
        "module x\n\nrequire golang.org/x/net v{v}\n",
        "CVE-2022-41723",
        "0.6.0",
        "0.17.0",
    ),
    (
        "go.mod",
        "module x\n\nrequire golang.org/x/crypto {v}\n",
        "CVE-2020-29652",
        "v0.0.0-20200622213623-75b288015ac9",
        "v0.31.0",
    ),
    (
        "Cargo.lock",
        '[[package]]\nname = "smallvec"\nversion = "{v}"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n',
        "CVE-2021-25900",
        "1.6.0",
        "1.6.1",
    ),
    (
        "packages.lock.json",
        '{{"dependencies": {{"net6.0": {{"Newtonsoft.Json": {{"resolved": "{v}"}}}}}}}}',
        "CVE-2024-21907",
        "12.0.3",
        "13.0.1",
    ),
    (
        "App.csproj",
        '<Project><PackageReference Include="newtonsoft.json" Version="{v}" /></Project>',
        "CVE-2024-21907",
        "12.0.3",
        "13.0.1",
    ),
    (
        "pom.xml",
        "<project><dependency><groupId>org.springframework</groupId>"
        "<artifactId>spring-beans</artifactId><version>{v}</version></dependency></project>",
        "CVE-2022-22965",
        "5.3.17",
        "5.3.18",
    ),
    (
        "pom.xml",
        "<project><dependency><groupId>org.springframework</groupId>"
        "<artifactId>spring-beans</artifactId><version>{v}</version></dependency></project>",
        "CVE-2022-22965",
        "5.2.19.RELEASE",
        "5.2.20.RELEASE",
    ),
    (
        "gradle.lockfile",
        "com.fasterxml.jackson.core:jackson-databind:{v}=runtimeClasspath\n",
        "CVE-2020-36518",
        "2.13.1",
        "2.15.0",
    ),
]


@pytest.mark.parametrize(
    ("rel", "template", "cve", "vulnerable", "fixed"),
    CASES,
    ids=[f"{c[0]}-{c[2]}" for c in CASES],
)
def test_ecossistemas(
    tmp_path: Path, rel: str, template: str, cve: str, vulnerable: str, fixed: str
) -> None:
    out = scan_manifest(tmp_path, rel, template.format(v=vulnerable))
    found = {c for f in out.findings for c in f.cves}
    assert cve in found, f"{rel} {vulnerable}: {found}"
    limpo = scan_manifest(tmp_path, rel, template.format(v=fixed))
    assert cve not in {c for f in limpo.findings for c in f.cves}


def test_nomes_sao_normalizados_por_ecossistema() -> None:
    assert package_key("PyPI", "PyYAML") == "pyyaml"
    assert package_key("PyPI", "zope.interface") == package_key("PyPI", "zope_interface")
    assert package_key("PyPI", "Foo__Bar") == "foo-bar"
    assert package_key("crates.io", "serde_json") == "serde-json"
    assert package_key("NuGet", "Newtonsoft.Json") == "newtonsoft.json"
    assert package_key("Maven", "Org.Apache:Foo") == "org.apache:foo"
    assert package_key("Go", "github.com/Foo/Bar") == "github.com/Foo/Bar"
    assert package_key("RubyGems", "Rack") == "Rack"


# -- confiança e contexto ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("rel", "content", "expected"),
    [
        ("requirements.txt", "PyYAML==5.3.1\n", Confidence.FIRM),
        (
            "App.csproj",
            '<Project><PackageReference Include="Newtonsoft.Json" Version="12.0.3" /></Project>',
            Confidence.FIRM,
        ),
        ("go.sum", "golang.org/x/net v0.6.0 h1:abc=\n", Confidence.TENTATIVE),
        ("package-lock.json", package_lock(("lodash", "4.17.20")), Confidence.CONFIRMED),
    ],
)
def test_confianca_conforme_o_tipo_de_manifesto(
    tmp_path: Path, rel: str, content: str, expected: Confidence
) -> None:
    [finding] = scan_manifest(tmp_path, rel, content).findings
    assert finding.confidence is expected


def test_versao_herdada_do_parent_e_indicio(tmp_path: Path) -> None:
    pom = """\
<project>
  <parent>
    <groupId>org.springframework</groupId>
    <artifactId>spring-parent</artifactId>
    <version>5.3.17</version>
  </parent>
  <dependencies><dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-beans</artifactId>
  </dependency></dependencies>
</project>
"""
    [finding] = scan_manifest(tmp_path, "pom.xml", pom).findings
    assert finding.confidence is Confidence.TENTATIVE
    assert "herdada" in finding.details["observacao"]


def test_manifesto_em_pasta_de_teste_tem_severidade_baixa(tmp_path: Path) -> None:
    [finding] = scan_manifest(
        tmp_path, "tests/fixtures/package-lock.json", package_lock(("lodash", "4.17.20"))
    ).findings
    assert finding.severity is Severity.LOW
    assert finding.confidence is Confidence.TENTATIVE
    assert "severidade reduzida" in finding.details["contexto"]


def test_manifesto_de_exemplo_perde_um_nivel(tmp_path: Path) -> None:
    [finding] = scan_manifest(
        tmp_path, "examples/package-lock.json", package_lock(("lodash", "4.17.20"))
    ).findings
    assert finding.severity is Severity.MEDIUM
    assert finding.confidence is Confidence.TENTATIVE


# -- falsos positivos -------------------------------------------------------------------


def test_faixas_em_package_json_sem_lockfile_nao_viram_achado(tmp_path: Path) -> None:
    content = json.dumps({"dependencies": {"lodash": "^4.17.0", "axios": ">=0.1 <0.2", "qs": "*"}})
    out = scan_manifest(tmp_path, "package.json", content)
    assert out.findings == []
    assert out.passed == []  # nada foi avaliado: não é ponto forte


def test_package_json_com_lockfile_nao_e_lido_duas_vezes(tmp_path: Path) -> None:
    write_tree(tmp_path, {"package-lock.json": package_lock(("lodash", "4.17.21"))})
    out = scan_manifest(
        tmp_path, "package.json", json.dumps({"dependencies": {"lodash": "4.17.20"}})
    )
    assert out.findings == []
    assert any("mais preciso" in line for line in out.logs)


def test_package_json_em_subpasta_usa_lockfile_da_raiz(tmp_path: Path) -> None:
    write_tree(tmp_path, {"yarn.lock": ""})
    out = scan_manifest(
        tmp_path, "packages/a/package.json", json.dumps({"dependencies": {"lodash": "4.17.20"}})
    )
    assert out.findings == []


def test_pacote_homonimo_em_outro_ecossistema_nao_casa(tmp_path: Path) -> None:
    # "lodash" no PyPI não é o lodash do npm.
    assert scan_manifest(tmp_path, "requirements.txt", "lodash==4.17.20\n").findings == []


def test_versao_anterior_ao_inicio_da_faixa_nao_e_afetada(tmp_path: Path) -> None:
    # CVE-2021-44906: a faixa do minimist 1.x começa em 1.0.0 e a 0.x termina em 0.2.4.
    out = scan_manifest(tmp_path, "package-lock.json", package_lock(("minimist", "0.2.4")))
    assert "CVE-2021-44906" not in {c for f in out.findings for c in f.cves}


def test_pre_lancamento_da_versao_corrigida_continua_afetado(tmp_path: Path) -> None:
    # 2.15.0-rc1 vem antes da 2.15.0 (a primeira corrigida do Log4Shell).
    pom = (
        "<project><dependency><groupId>org.apache.logging.log4j</groupId>"
        "<artifactId>log4j-core</artifactId><version>2.15.0-rc1</version></dependency></project>"
    )
    [finding] = scan_manifest(tmp_path, "pom.xml", pom).findings
    assert "CVE-2021-44228" in finding.cves


@pytest.mark.parametrize(
    ("rel", "content"),
    [
        ("package-lock.json", "{ json quebrado"),
        ("poetry.lock", "isto = não é = toml"),
        ("Cargo.lock", "[[package"),
        ("composer.lock", "[1, 2, 3]"),
    ],
)
def test_arquivo_invalido_nao_derruba_a_checagem(tmp_path: Path, rel: str, content: str) -> None:
    out = scan_manifest(tmp_path, rel, content)
    assert out.findings == []
    assert out.passed == []


def test_manifesto_grande_demais_e_ignorado_com_aviso(tmp_path: Path) -> None:
    content = "PyYAML==5.3.1\n" + "# comentário\n" * 1000
    out = scan_manifest(tmp_path, "requirements.txt", content, max_file_bytes=100)
    assert out.findings == []
    assert any("grande demais" in line for line in out.logs)


def test_lockfile_tem_limite_proprio_maior(tmp_path: Path) -> None:
    content = package_lock(("lodash", "4.17.20")) + " " * 1000
    out = scan_manifest(tmp_path, "package-lock.json", content, max_file_bytes=100)
    assert len(out.findings) == 1


def test_arquivo_apagado_durante_a_varredura(tmp_path: Path) -> None:
    out = run_check("code.dependencies", manifest_fact(tmp_path, "package-lock.json"))
    assert out.findings == []
    assert any("ilegível" in line for line in out.logs)


def test_tipo_de_manifesto_desconhecido(tmp_path: Path) -> None:
    write_tree(tmp_path, {"notas.txt": "x"})
    out = run_check("code.dependencies", manifest_fact(tmp_path, "notas.txt"))
    assert out.findings == []
    assert any("não reconhecido" in line for line in out.logs)


def test_cancelamento_e_respeitado(tmp_path: Path) -> None:
    write_tree(tmp_path, {"package-lock.json": package_lock(("lodash", "4.17.21"))})
    load_builtin_checks()
    item = get_check("code.dependencies")
    assert item is not None
    fact = manifest_fact(tmp_path, "package-lock.json")
    scan = ScanContext(parse_target("https://127.0.0.1/"), Settings())
    scan.cancel.set()
    with pytest.raises(Cancelled):
        item.func(CheckContext(scan, item, fact), fact)


# -- catálogo embarcado -----------------------------------------------------------------


def _rows() -> list[dict]:
    return list(load_json("code_advisories.json")["avisos"])


def test_catalogo_registra_origem_e_licenca() -> None:
    data = load_json("code_advisories.json")
    for key in ("fonte", "licenca", "url", "atualizado", "versao"):
        assert data[key], key
    assert data["url"].startswith("https://")
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", data["atualizado"])
    info = advisories.catalog_info()
    assert info["total"] == len(data["avisos"]) >= 100
    assert info["atualizado"] == data["atualizado"]


def test_catalogo_cada_aviso_esta_completo() -> None:
    for row in _rows():
        label = f"{row['id']}/{row['pacote']}"
        assert re.fullmatch(r"GHSA(-[23456789cfghjmpqrvwx]{4}){3}", row["id"]), label
        assert row["ecossistema"] in osv.ECOSYSTEMS, label
        assert row["pacote"].strip(), label
        assert row["titulo"].strip() and row["resumo"].strip(), label
        assert row["referencia"].startswith("https://"), label
        assert Severity.parse(row["severidade"]) in Severity, label
        for cve in row["cves"]:
            assert re.fullmatch(r"CVE-\d{4}-\d{4,}", cve), label
        assert row["faixas"], label
        for faixa in row["faixas"]:
            assert faixa["introduzida"], label
            assert not ("corrigida" in faixa and "ultima_afetada" in faixa), label


def test_catalogo_faixas_sao_coerentes_com_o_comparador() -> None:
    # A primeira versão da faixa é afetada, e a corrigida não: pega comparadores errados.
    catalog = curated_catalog()
    assert len(catalog) == len(_rows())
    for row in _rows():
        advisory = catalog.for_package(row["ecossistema"], row["pacote"])
        same = [a for a in advisory if a.id == row["id"]]
        assert same, row["id"]
        for rng in same[0].ranges:
            events = dict(rng.events)
            introduced = events["introduced"]
            if introduced != "0":
                assert in_range(row["ecossistema"], introduced, rng), (row["id"], rng)
            if "fixed" in events:
                assert not in_range(row["ecossistema"], events["fixed"], rng), (row["id"], rng)
            if "last_affected" in events:
                assert in_range(row["ecossistema"], events["last_affected"], rng), (row["id"], rng)


def test_catalogo_ids_conhecidos() -> None:
    catalog = curated_catalog()
    ids = {a.id for a in catalog.for_package("Maven", "org.apache.logging.log4j:log4j-core")}
    assert "GHSA-jfh8-c2jp-5v3q" in ids
    assert catalog.for_package("npm", "pacote-que-nao-existe-no-catalogo") == []
    assert catalog.match("npm", "pacote-que-nao-existe-no-catalogo", "1.0.0") == []


def test_catalog_match_devolve_a_correcao_do_ramo_instalado() -> None:
    catalog = curated_catalog()
    matches = catalog.match("Maven", "org.apache.logging.log4j:log4j-core", "2.12.1")
    fixed = {m.advisory.id: m.fixed for m in matches}
    assert fixed["GHSA-jfh8-c2jp-5v3q"] == "2.12.2"
    assert fixed["GHSA-8489-44mv-ggj8"] == "2.12.4"


def test_catalogo_ausente_nao_quebra(monkeypatch: pytest.MonkeyPatch) -> None:
    def falha(name: str) -> object:
        raise OSError(name)

    monkeypatch.setattr(advisories, "load_json", falha)
    advisories.curated_catalog.cache_clear()
    try:
        assert len(advisories.curated_catalog()) == 0
        assert advisories.catalog_info() == {"total": 0}
    finally:
        monkeypatch.undo()
        advisories.curated_catalog.cache_clear()


def test_advisory_identificadores_incluem_cves_e_apelidos() -> None:
    advisory = Advisory(
        id="GHSA-x",
        ecosystem="npm",
        package="p",
        severity=Severity.LOW,
        title="t",
        summary="s",
        reference="https://example.org/",
        cves=("CVE-1",),
        aliases=("GO-1",),
    )
    assert advisory.identifiers == {"GHSA-x", "CVE-1", "GO-1"}
    assert Catalog([advisory]).for_package("npm", "P") == [advisory]


def test_is_affected_com_versao_absurda_nao_quebra() -> None:
    from eigan.checks.code.versioning import VersionRange

    enorme = "1-" * 5000 + "1"
    rng = VersionRange((("introduced", "0"),))
    assert is_affected("Maven", enorme, (rng,)) == (False, None)


# -- base de conhecimento ---------------------------------------------------------------


@pytest.mark.parametrize("entry_id", [VULNERABLE, MALICIOUS])
def test_entradas_da_base_estao_completas(entry_id: str) -> None:
    entry = kb.require(entry_id)
    assert entry.title and entry.summary and entry.explanation and entry.risk
    assert entry.steps and entry.verify
    assert entry.fix_group == "dependencias"
    assert entry.references and all(r.startswith("https://") for r in entry.references)
    assert entry.cwe and entry.cwe.startswith("CWE-")
    assert entry.owasp in kb.OWASP_2021
    assert all(c in kb.CIS_V8 for c in entry.cis)
    assert entry.effort in ("baixo", "medio", "alto")


def test_todo_ecossistema_tem_exemplo_de_correcao() -> None:
    entry = kb.require(VULNERABLE)
    techs = {fix.tech for fix in entry.examples}
    assert set(advisories.ECOSYSTEM_TECH.values()) <= techs
    assert {"gradle", "yarn"} <= techs


@pytest.mark.parametrize(
    ("rel", "content", "tech"),
    [
        ("gradle.lockfile", "com.fasterxml.jackson.core:jackson-databind:2.13.1=x\n", "gradle"),
        ("yarn.lock", 'lodash@^4.0.0:\n  version "4.17.20"\n', "yarn"),
        ("requirements.txt", "PyYAML==5.3.1\n", "python"),
    ],
)
def test_tecnologia_escolhe_o_exemplo_certo(
    tmp_path: Path, rel: str, content: str, tech: str
) -> None:
    [finding] = scan_manifest(tmp_path, rel, content).findings
    assert finding.tech == [tech]


def test_spring4shell_so_pela_versao_fica_tentativo(tmp_path: Path) -> None:
    pom = """<project><dependencies><dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-web</artifactId>
  <version>2.5.5</version>
</dependency></dependencies></project>
"""
    out = scan_manifest(tmp_path, "pom.xml", pom)
    spring = [f for f in out.findings if "CVE-2022-22965" in f.cves]
    assert spring
    assert spring[0].confidence is Confidence.TENTATIVE
