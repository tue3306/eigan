"""Base offline do OSV: índice, casamento de registros, download seguro e nota CVSS."""

from __future__ import annotations

import io
import json
import socket
import urllib.error
import urllib.request
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from fakes_code import manifest_fact, write_tree
from helpers import Route, run_check

from eigan.checks.code import cvss, dependencies, osv
from eigan.checks.code.dependencies_kb import MALICIOUS, VULNERABLE
from eigan.core import baixar, paths
from eigan.core.models import Severity


def record(rec_id: str, package: str = "pacote", ecosystem: str = "npm", **extra: Any) -> dict:
    """Registro OSV mínimo: por padrão afeta tudo antes da 2.0.0."""
    affected: dict[str, Any] = {
        "package": {"ecosystem": ecosystem, "name": package},
        "ranges": extra.pop(
            "ranges",
            [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
        ),
    }
    if "versions" in extra:
        affected["versions"] = extra.pop("versions")
    if "affected_extra" in extra:
        affected.update(extra.pop("affected_extra"))
    base = {
        "id": rec_id,
        "summary": f"Resumo de {rec_id}",
        "affected": [affected],
    }
    base.update(extra)
    return base


def zip_bytes(records: list[dict], *, extra: dict[str, bytes] | None = None) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for item in records:
            archive.writestr(f"{item['id']}.json", json.dumps(item))
        for name, content in (extra or {}).items():
            archive.writestr(name, content)
    return buffer.getvalue()


def write_cache(root: Path, ecosystem: str, records: list[dict]) -> Path:
    folder = root / ecosystem
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "all.zip").write_bytes(zip_bytes(records))
    return folder


@pytest.fixture
def cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "cache-osv"
    root.mkdir()
    monkeypatch.setattr(osv, "osv_root", lambda: root)
    return root


# -- pasta do cache ---------------------------------------------------------------------


def test_cache_fica_na_pasta_do_eigan() -> None:
    assert osv.osv_root() == paths.cache_dir() / "osv"


def test_sem_base_baixada_nada_e_carregado(tmp_path: Path) -> None:
    assert osv.load_database("npm", tmp_path) is None
    (tmp_path / "npm").mkdir()
    assert osv.load_database("npm", tmp_path) is None


def test_ecossistema_desconhecido_nao_e_carregado(tmp_path: Path) -> None:
    (tmp_path / "Debian").mkdir()
    assert osv.load_database("Debian", tmp_path) is None
    (tmp_path / "Chainguard").mkdir()
    (tmp_path / "Chainguard" / "all.zip").write_bytes(
        zip_bytes([record("CGA-1", ecosystem="Chainguard")])
    )
    assert osv.load_database("Chainguard", tmp_path) is None


# -- índice e leitura -------------------------------------------------------------------


def test_le_registros_do_zip(tmp_path: Path) -> None:
    write_cache(tmp_path, "npm", [record("GHSA-a"), record("GHSA-b", package="outro")])
    database = osv.load_database("npm", tmp_path)
    assert database is not None
    assert database.packages == 2
    assert [a.id for a in database.advisories("pacote")] == ["GHSA-a"]
    assert [a.id for a in database.advisories("outro")] == ["GHSA-b"]
    assert database.advisories("nao-existe") == []


def test_le_registros_json_extraidos(tmp_path: Path) -> None:
    folder = tmp_path / "PyPI"
    folder.mkdir()
    rec = record("PYSEC-1", package="Foo_Bar", ecosystem="PyPI")
    (folder / "PYSEC-1.json").write_text(json.dumps(rec), encoding="utf-8")
    database = osv.load_database("PyPI", tmp_path)
    assert database is not None
    assert [a.id for a in database.advisories("foo-bar")] == ["PYSEC-1"]


def test_indice_e_salvo_e_reaproveitado(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    folder = write_cache(tmp_path, "npm", [record("GHSA-a")])
    assert osv.load_database("npm", tmp_path) is not None
    assert (folder / osv.INDEX_FILE).is_file()

    def nao_chame(*args: object) -> dict:
        raise AssertionError("o índice salvo deveria ter sido reaproveitado")

    monkeypatch.setattr(osv, "build_index", nao_chame)
    database = osv.load_database("npm", tmp_path)
    assert database is not None
    assert [a.id for a in database.advisories("pacote")] == ["GHSA-a"]


def test_indice_e_refeito_quando_a_base_muda(tmp_path: Path) -> None:
    write_cache(tmp_path, "npm", [record("GHSA-a")])
    assert osv.load_database("npm", tmp_path) is not None
    write_cache(tmp_path, "npm", [record("GHSA-a"), record("GHSA-novo", package="novo")])
    database = osv.load_database("npm", tmp_path)
    assert database is not None
    assert [a.id for a in database.advisories("novo")] == ["GHSA-novo"]


def test_indice_corrompido_e_refeito(tmp_path: Path) -> None:
    folder = write_cache(tmp_path, "npm", [record("GHSA-a")])
    (folder / osv.INDEX_FILE).write_text("{ quebrado", encoding="utf-8")
    database = osv.load_database("npm", tmp_path)
    assert database is not None
    assert database.packages == 1


def test_zip_corrompido_nao_quebra(tmp_path: Path) -> None:
    folder = tmp_path / "npm"
    folder.mkdir()
    (folder / "all.zip").write_bytes(b"isto nao e um zip")
    database = osv.load_database("npm", tmp_path)
    assert database is not None
    assert database.packages == 0
    assert database.advisories("pacote") == []


def test_registro_invalido_e_ignorado(tmp_path: Path) -> None:
    folder = tmp_path / "npm"
    folder.mkdir()
    extra = {"lixo.json": b"{ quebrado", "lista.json": b"[1, 2]", "leia.txt": b"nao e json"}
    (folder / "all.zip").write_bytes(zip_bytes([record("GHSA-a")], extra=extra))
    database = osv.load_database("npm", tmp_path)
    assert database is not None
    assert database.packages == 1


def test_registro_grande_demais_e_ignorado(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write_cache(tmp_path, "npm", [record("GHSA-a", details="x" * 5000)])
    monkeypatch.setattr(osv, "MAX_RECORD_BYTES", 100)
    database = osv.load_database("npm", tmp_path)
    assert database is not None
    assert database.packages == 0


def test_zip_que_descompacta_demais_e_recusado(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_cache(tmp_path, "npm", [record("GHSA-a", details="x" * 5000)])
    monkeypatch.setattr(osv, "MAX_UNCOMPRESSED_BYTES", 100)
    database = osv.load_database("npm", tmp_path)
    assert database is not None
    assert database.packages == 0


def test_nome_de_membro_nao_sai_da_pasta_em_json_extraido(tmp_path: Path) -> None:
    folder = tmp_path / "npm"
    folder.mkdir()
    (tmp_path / "fora.json").write_text(json.dumps(record("GHSA-fora")), encoding="utf-8")
    database = osv.OsvDatabase("npm", folder, {"pacote": ["../fora.json"]})
    assert database.advisories("pacote") == []


# -- conversão de registros -------------------------------------------------------------


def convert(rec: dict, ecosystem: str = "npm", key: str = "pacote") -> list:
    return osv.advisories_from_record(rec, ecosystem, key)


def test_registro_retirado_e_ignorado(tmp_path: Path) -> None:
    rec = record("GHSA-velho", withdrawn="2023-01-01T00:00:00Z")
    assert convert(rec) == []
    write_cache(tmp_path, "npm", [rec])
    database = osv.load_database("npm", tmp_path)
    assert database is not None
    assert database.packages == 0


def test_registro_de_licenca_nao_comercial_e_ignorado() -> None:
    assert convert(record("CGA-abcd-1234")) == []


def test_faixa_git_nao_conta_e_faixa_semver_conta() -> None:
    git = record("GHSA-g", ranges=[{"type": "GIT", "repo": "x", "events": [{"introduced": "0"}]}])
    assert convert(git) == []
    semver = record("GHSA-s", ranges=[{"type": "SEMVER", "events": [{"introduced": "1.0.0"}]}])
    [advisory] = convert(semver)
    assert advisory.check("1.5.0") == (True, None)
    assert advisory.check("0.9.0") == (False, None)


def test_lista_de_versoes_e_last_affected() -> None:
    listed = record("GHSA-l", ranges=[], versions=["1.0.0", "1.0.1"])
    [advisory] = convert(listed)
    assert advisory.check("1.0.1")[0] is True
    assert advisory.check("1.0.2")[0] is False
    last = record(
        "GHSA-u",
        ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": "1.2"}]}],
    )
    [advisory] = convert(last)
    assert advisory.check("1.2.0")[0] is True
    assert advisory.check("1.2.1")[0] is False


def test_identificadores_e_referencia() -> None:
    rec = record("GHSA-x", aliases=["CVE-2020-1", "PYSEC-2020-1", "CVE-2020-2"])
    [advisory] = convert(rec)
    assert advisory.cves == ("CVE-2020-1", "CVE-2020-2")
    assert "PYSEC-2020-1" in advisory.identifiers
    assert advisory.reference == "https://osv.dev/vulnerability/GHSA-x"
    assert advisory.source == "osv"
    assert advisory.title == "Resumo de GHSA-x"


def test_titulo_vem_dos_detalhes_quando_nao_ha_resumo() -> None:
    rec = record("GO-1", details="\n# Primeira linha\nresto")
    del rec["summary"]
    [advisory] = convert(rec)
    assert advisory.title == "Primeira linha"


def test_titulo_cai_no_id_quando_nao_ha_texto() -> None:
    rec = record("GO-2")
    del rec["summary"]
    [advisory] = convert(rec)
    assert advisory.title == "GO-2"


def test_so_o_pacote_e_o_ecossistema_certos_valem() -> None:
    rec = {
        "id": "GHSA-m",
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "pacote"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
            },
            {
                "package": {"ecosystem": "npm", "name": "outro"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
            },
            {
                "package": {"ecosystem": "npm", "name": "pacote"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "3.0.0"}]}],
            },
        ],
    }
    [advisory] = convert(rec)
    assert advisory.check("3.1.0")[0] is True
    assert advisory.check("1.0.0")[0] is False


def test_ecossistema_com_sufixo_e_reconhecido() -> None:
    rec = record("X-1", ecosystem="npm:algo")
    assert len(convert(rec)) == 1
    assert convert(record("X-2", ecosystem="npmish")) == []


def test_campos_estranhos_nao_quebram() -> None:
    assert osv.advisories_from_record({"id": "X"}, "npm", "pacote") == []
    assert osv.advisories_from_record({"id": "X", "affected": [None]}, "npm", "pacote") == []
    rec = record("X", ranges=[{"type": "SEMVER", "events": ["nao e objeto", {"introduced": "0"}]}])
    [advisory] = convert(rec)
    assert advisory.check("1.0.0")[0] is True


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("CRITICAL", Severity.CRITICAL),
        ("HIGH", Severity.HIGH),
        ("MODERATE", Severity.MEDIUM),
        ("LOW", Severity.LOW),
    ],
)
def test_severidade_do_ghsa(label: str, expected: Severity) -> None:
    [advisory] = convert(record("GHSA-1", database_specific={"severity": label}))
    assert advisory.severity is expected
    assert advisory.severity_known is True


def test_severidade_pela_nota_cvss_do_registro_e_do_pacote() -> None:
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    [advisory] = convert(record("X-1", severity=[{"type": "CVSS_V3", "score": vector}]))
    assert advisory.severity is Severity.CRITICAL
    [advisory] = convert(
        record("X-2", affected_extra={"severity": [{"type": "CVSS_V3", "score": vector}]})
    )
    assert advisory.severity is Severity.CRITICAL


def test_sem_severidade_fica_media_estimada() -> None:
    [advisory] = convert(record("PYSEC-1"))
    assert advisory.severity is Severity.MEDIUM
    assert advisory.severity_known is False
    [advisory] = convert(record("X", severity=[{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N"}]))
    assert advisory.severity_known is False


def test_pacote_malicioso_mal() -> None:
    [advisory] = convert(record("MAL-2024-1"))
    assert advisory.malicious is True
    assert advisory.severity is Severity.CRITICAL


# -- integração com a checagem ----------------------------------------------------------


def test_checagem_usa_a_base_quando_existe(cache: Path, tmp_path: Path) -> None:
    write_cache(
        cache,
        "npm",
        [
            record(
                "GHSA-so-na-base",
                package="biblioteca-rara",
                aliases=["CVE-2099-1"],
                database_specific={"severity": "HIGH"},
            )
        ],
    )
    lock = {
        "lockfileVersion": 3,
        "packages": {"node_modules/biblioteca-rara": {"version": "1.0.0"}},
    }
    write_tree(tmp_path, {"proj/package-lock.json": json.dumps(lock)})
    out = run_check("code.dependencies", manifest_fact(tmp_path / "proj", "package-lock.json"))
    [finding] = out.findings
    assert finding.check_id == VULNERABLE
    assert finding.cves == ["CVE-2099-1"]
    assert finding.severity is Severity.HIGH
    assert finding.details["versao_corrigida"] == "2.0.0"
    [aviso] = finding.details["avisos"]
    assert aviso["fonte"] == "osv"
    assert aviso["referencia"] == "https://osv.dev/vulnerability/GHSA-so-na-base"
    assert aviso["severidade_estimada"] is False


def test_versao_fora_da_faixa_da_base_nao_gera_achado(cache: Path, tmp_path: Path) -> None:
    write_cache(cache, "npm", [record("GHSA-x", package="biblioteca-rara")])
    lock = {
        "lockfileVersion": 3,
        "packages": {"node_modules/biblioteca-rara": {"version": "2.0.0"}},
    }
    write_tree(tmp_path, {"proj/package-lock.json": json.dumps(lock)})
    out = run_check("code.dependencies", manifest_fact(tmp_path / "proj", "package-lock.json"))
    assert out.findings == []
    assert "base OSV offline" in out.passed[0].text


def test_mesmo_aviso_no_catalogo_e_na_base_nao_duplica(cache: Path, tmp_path: Path) -> None:
    write_cache(
        cache,
        "PyPI",
        [
            # Mesmo problema do catálogo (PyYAML CVE-2020-14343) com outro identificador.
            record(
                "PYSEC-2021-142",
                package="PyYAML",
                ecosystem="PyPI",
                aliases=["CVE-2020-14343"],
                ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.4"}]}],
            ),
            # Um aviso que só a base conhece.
            record(
                "PYSEC-NOVO",
                package="pyyaml",
                ecosystem="PyPI",
                aliases=["CVE-2099-2"],
                ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "6.1"}]}],
            ),
        ],
    )
    write_tree(tmp_path, {"proj/requirements.txt": "PyYAML==5.3.1\n"})
    out = run_check("code.dependencies", manifest_fact(tmp_path / "proj", "requirements.txt"))
    [finding] = out.findings
    ids = [a["id"] for a in finding.details["avisos"]]
    assert "GHSA-8q59-q68h-6hv4" in ids
    assert "PYSEC-2021-142" not in ids
    assert "PYSEC-NOVO" in ids
    assert finding.details["versao_corrigida"] == "6.1"
    assert ids.count("GHSA-8q59-q68h-6hv4") == 1


def test_pacote_malicioso_da_base(cache: Path, tmp_path: Path) -> None:
    write_cache(cache, "npm", [record("MAL-2024-99", package="pacote-do-mal")])
    lock = {"lockfileVersion": 3, "packages": {"node_modules/pacote-do-mal": {"version": "1.0.0"}}}
    write_tree(tmp_path, {"proj/package-lock.json": json.dumps(lock)})
    out = run_check("code.dependencies", manifest_fact(tmp_path / "proj", "package-lock.json"))
    [finding] = out.findings
    assert finding.check_id == MALICIOUS
    assert finding.severity is Severity.CRITICAL


def test_varredura_nao_acessa_a_rede_nem_baixa_nada(
    cache: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def proibido(*args: object, **kwargs: object) -> None:
        raise AssertionError("a auditoria não pode acessar a rede")

    monkeypatch.setattr(osv, "download_osv", proibido)
    monkeypatch.setattr(osv, "_download_one", proibido)
    monkeypatch.setattr(osv, "_https_opener", proibido)
    monkeypatch.setattr(urllib.request, "urlopen", proibido)
    monkeypatch.setattr(socket.socket, "connect", proibido)
    write_cache(cache, "npm", [record("GHSA-x", package="biblioteca-rara")])
    lock = {
        "lockfileVersion": 3,
        "packages": {"node_modules/biblioteca-rara": {"version": "1.0.0"}},
    }
    write_tree(tmp_path, {"proj/package-lock.json": json.dumps(lock)})
    out = run_check("code.dependencies", manifest_fact(tmp_path / "proj", "package-lock.json"))
    assert len(out.findings) == 1


def test_dependencies_nao_referencia_o_download() -> None:
    source = Path(dependencies.__file__).read_text(encoding="utf-8")
    assert "download_osv(" not in source.replace("``osv.download_osv``", "")


# -- download ---------------------------------------------------------------------------


class FakeResponse:
    def __init__(self, body: bytes, url: str, headers: dict[str, str] | None = None) -> None:
        self._body = io.BytesIO(body)
        self._url = url
        self.headers = headers or {}

    def geturl(self) -> str:
        return self._url

    def read(self, size: int = -1) -> bytes:
        return self._body.read(size)

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def opener_for(bodies: dict[str, bytes], calls: list[str] | None = None) -> Callable[..., Any]:
    def fetch(url: str, timeout: float = 0.0) -> FakeResponse:
        if calls is not None:
            calls.append(url)
        for ecosystem, body in bodies.items():
            if f"/{ecosystem}/all.zip" in url:
                return FakeResponse(body, url)
        raise urllib.error.HTTPError(url, 404, "Not Found", None, None)  # type: ignore[arg-type]

    return fetch


def test_download_grava_zip_indice_e_origem(tmp_path: Path) -> None:
    calls: list[str] = []
    body = zip_bytes([record("GHSA-a"), record("GHSA-b", package="outro")])
    result = osv.download_osv(["npm"], root=tmp_path, opener=opener_for({"npm": body}, calls))
    assert calls == ["https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip"]
    info = result["npm"]
    assert info["ok"] is True
    assert info["pacotes"] == 2
    assert info["registros"] == 2
    assert info["bytes"] == len(body)
    folder = tmp_path / "npm"
    assert Path(info["arquivo"]) == folder / "all.zip"
    assert (folder / "all.zip").read_bytes() == body
    assert not (folder / "all.zip.part").exists()
    source = osv.database_info("npm", tmp_path)
    assert source is not None
    assert source["url"] == calls[0]
    assert "CC-BY-4.0" in source["licencas"]
    assert source["baixado_em"]
    database = osv.load_database("npm", tmp_path)
    assert database is not None
    assert [a.id for a in database.advisories("outro")] == ["GHSA-b"]


def test_download_usa_o_cache_por_padrao(cache: Path) -> None:
    body = zip_bytes([record("GHSA-a")])
    result = osv.download_osv(["npm"], opener=opener_for({"npm": body}))
    assert result["npm"]["ok"] is True
    assert (cache / "npm" / "all.zip").is_file()


def test_download_url_de_cada_ecossistema(tmp_path: Path) -> None:
    calls: list[str] = []
    bodies = {eco: zip_bytes([record(f"X-{eco}", ecosystem=eco)]) for eco in osv.ECOSYSTEMS}
    result = osv.download_osv(list(osv.ECOSYSTEMS), root=tmp_path, opener=opener_for(bodies, calls))
    assert all(item["ok"] for item in result.values())
    assert "https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip" in calls
    assert "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip" in calls
    assert (tmp_path / "crates.io" / "all.zip").is_file()


@pytest.mark.parametrize("ecosystem", ["Chainguard", "Wolfi"])
def test_download_recusa_licenca_nao_comercial(tmp_path: Path, ecosystem: str) -> None:
    calls: list[str] = []
    result = osv.download_osv([ecosystem], root=tmp_path, opener=opener_for({}, calls))
    assert result[ecosystem]["ok"] is False
    assert "licença não comercial" in result[ecosystem]["erro"]
    assert calls == []
    assert not (tmp_path / ecosystem).exists()


def test_download_recusa_ecossistema_nao_suportado(tmp_path: Path) -> None:
    calls: list[str] = []
    result = osv.download_osv(
        ["Debian:11", "../../fora"], root=tmp_path, opener=opener_for({}, calls)
    )
    assert result["Debian:11"]["ok"] is False
    assert result["../../fora"]["ok"] is False
    assert calls == []
    assert list(tmp_path.iterdir()) == []


def test_download_falha_em_um_nao_impede_o_outro(tmp_path: Path) -> None:
    result = osv.download_osv(
        ["PyPI", "npm"],
        root=tmp_path,
        opener=opener_for({"npm": zip_bytes([record("GHSA-a")])}),
    )
    assert result["PyPI"]["ok"] is False
    assert "HTTPError" in result["PyPI"]["erro"]
    assert result["npm"]["ok"] is True


def test_download_falha_de_rede_nao_apaga_a_base_anterior(tmp_path: Path) -> None:
    good = zip_bytes([record("GHSA-velho")])
    assert osv.download_osv(["npm"], root=tmp_path, opener=opener_for({"npm": good}))["npm"]["ok"]

    result = osv.download_osv(["npm"], root=tmp_path, opener=opener_for({"npm": b"nao e zip"}))
    assert result["npm"]["ok"] is False
    assert "zip" in result["npm"]["erro"]
    assert (tmp_path / "npm" / "all.zip").read_bytes() == good
    assert not (tmp_path / "npm" / "all.zip.part").exists()
    database = osv.load_database("npm", tmp_path)
    assert database is not None
    assert [a.id for a in database.advisories("pacote")] == ["GHSA-velho"]


def test_download_zip_sem_registros_e_recusado(tmp_path: Path) -> None:
    result = osv.download_osv(["npm"], root=tmp_path, opener=opener_for({"npm": zip_bytes([])}))
    assert result["npm"]["ok"] is False
    assert not (tmp_path / "npm" / "all.zip").exists()


def test_download_limite_pelo_cabecalho(tmp_path: Path) -> None:
    def fetch(url: str, timeout: float = 0.0) -> FakeResponse:
        return FakeResponse(b"x", url, {"Content-Length": "1000000"})

    result = osv.download_osv(["npm"], root=tmp_path, opener=fetch, max_bytes=100)
    assert result["npm"]["ok"] is False
    assert "limite" in result["npm"]["erro"]
    assert not (tmp_path / "npm" / "all.zip").exists()


def test_download_limite_durante_a_leitura(tmp_path: Path) -> None:
    def fetch(url: str, timeout: float = 0.0) -> FakeResponse:
        return FakeResponse(b"x" * 5000, url)

    result = osv.download_osv(["npm"], root=tmp_path, opener=fetch, max_bytes=100)
    assert result["npm"]["ok"] is False
    assert "limite" in result["npm"]["erro"]
    assert not (tmp_path / "npm" / "all.zip.part").exists()


def test_download_recusa_resposta_de_endereco_http(tmp_path: Path) -> None:
    def fetch(url: str, timeout: float = 0.0) -> FakeResponse:
        return FakeResponse(zip_bytes([record("GHSA-a")]), "http://mirror.exemplo/all.zip")

    result = osv.download_osv(["npm"], root=tmp_path, opener=fetch)
    assert result["npm"]["ok"] is False
    assert "https" in result["npm"]["erro"]
    assert not (tmp_path / "npm" / "all.zip").exists()


def test_download_so_aceita_https(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(osv, "OSV_URL", "http://127.0.0.1:9/{ecosystem}/all.zip")
    result = osv.download_osv(["npm"], root=tmp_path, opener=opener_for({}, calls))
    assert result["npm"]["ok"] is False
    assert "https" in result["npm"]["erro"]
    assert calls == []


def test_redirecionamento_para_http_e_recusado() -> None:
    handler = osv._HttpsOnlyRedirect()
    request = urllib.request.Request("https://exemplo.invalid/all.zip")
    with pytest.raises(urllib.error.URLError):
        handler.redirect_request(request, None, 302, "Found", {}, "http://exemplo.invalid/all.zip")
    novo = handler.redirect_request(
        request, None, 302, "Found", {}, "https://outro.invalid/all.zip"
    )
    assert novo is not None
    assert novo.full_url == "https://outro.invalid/all.zip"


def test_download_valida_o_certificado(
    tmp_path: Path, serve: Callable[..., Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Servidor local com certificado autoassinado: o download precisa recusar.
    body = zip_bytes([record("GHSA-a")])
    srv = serve({"/npm/all.zip": Route(200, body, content_type="application/zip")}, tls=True)
    monkeypatch.setattr(osv, "OSV_URL", f"https://127.0.0.1:{srv.port}/{{ecosystem}}/all.zip")
    result = osv.download_osv(["npm"], root=tmp_path, timeout=5.0)
    assert result["npm"]["ok"] is False
    assert not (tmp_path / "npm" / "all.zip").exists()
    assert srv.requests == []


def test_download_baixa_de_verdade_com_certificado_confiavel(
    tmp_path: Path, serve: Callable[..., Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Mesmo caminho do download real (abridor, TLS e fluxo), confiando só no certificado do teste.
    import ssl

    from helpers import FIXTURES

    body = zip_bytes([record("GHSA-a")])
    srv = serve({"/npm/all.zip": Route(200, body, content_type="application/zip")}, tls=True)
    monkeypatch.setattr(osv, "OSV_URL", f"https://127.0.0.1:{srv.port}/{{ecosystem}}/all.zip")
    context = ssl.create_default_context(cafile=str(FIXTURES / "tls" / "localhost.crt"))
    context.check_hostname = False
    monkeypatch.setattr(baixar.ssl, "create_default_context", lambda: context)
    result = osv.download_osv(["npm"], root=tmp_path, timeout=5.0)
    assert result["npm"]["ok"] is True, result
    assert (tmp_path / "npm" / "all.zip").read_bytes() == body


# -- nota CVSS --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        # Notas publicadas no NVD para estes vetores.
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_cvss_nota_base(vector: str, score: float) -> None:
    assert cvss.base_score(vector) == score


@pytest.mark.parametrize(
    ("score", "severity"),
    [
        (10.0, Severity.CRITICAL),
        (9.0, Severity.CRITICAL),
        (8.9, Severity.HIGH),
        (7.0, Severity.HIGH),
        (6.9, Severity.MEDIUM),
        (4.0, Severity.MEDIUM),
        (3.9, Severity.LOW),
        (0.1, Severity.LOW),
        (0.0, Severity.INFO),
    ],
)
def test_cvss_faixas_qualitativas(score: float, severity: Severity) -> None:
    assert cvss.severity_from_score(score) is severity


@pytest.mark.parametrize(
    "vector",
    [
        "",
        "AV:N/AC:L",
        "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",
        "CVSS:3.1/AV:N/AC:L",
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    ],
)
def test_cvss_vetor_invalido(vector: str) -> None:
    assert cvss.base_score(vector) is None
    assert cvss.severity_from_vector(vector) is None
