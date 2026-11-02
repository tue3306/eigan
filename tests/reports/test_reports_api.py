"""API pública dos relatórios: formatos, nomes de arquivo, pasta padrão e gravação atômica."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest
from fakes_reports import SITE, analyzed, make, not_evaluated, sample_result, scan

import eigan.reports as reports
from eigan.core import paths
from eigan.core.models import ScanResult, TargetKind
from eigan.reports import FILENAMES, FORMATS, default_outdir, write_reports
from eigan.reports.common import anchor, slugify


def test_formatos_publicos() -> None:
    assert FORMATS == ("html", "pdf", "json", "sarif", "csv")
    assert set(FILENAMES) == set(FORMATS)
    for name in ("render_html", "render_pdf", "render_json", "render_sarif", "render_csv"):
        assert name in reports.__all__
        assert callable(getattr(reports, name))


def test_grava_os_cinco_arquivos_com_os_nomes_certos(tmp_path: Path) -> None:
    written = write_reports(sample_result(), outdir=tmp_path)
    assert set(written) == set(FORMATS)
    names = sorted(p.name for p in tmp_path.iterdir())
    assert names == sorted(
        [
            "eigan-relatorio.html",
            "eigan-relatorio.pdf",
            "eigan-resultado.json",
            "eigan-resultado.sarif",
            "eigan-achados.csv",
        ]
    )
    for path in written.values():
        assert path.parent == tmp_path
        assert path.stat().st_size > 200
    assert written["pdf"].read_bytes().startswith(b"%PDF")
    assert written["html"].read_text(encoding="utf-8").startswith("<!doctype html>")
    assert written["csv"].read_bytes().startswith(b"\xef\xbb\xbf")
    assert json.loads(written["json"].read_text(encoding="utf-8"))["id"] == "abc123"
    assert json.loads(written["sarif"].read_text(encoding="utf-8"))["version"] == "2.1.0"


def test_nao_deixa_arquivo_temporario(tmp_path: Path) -> None:
    write_reports(sample_result(), outdir=tmp_path)
    assert not [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")]


def test_formatos_como_lista_ou_texto_sem_repetir(tmp_path: Path) -> None:
    result = sample_result()
    only = write_reports(result, ["html", "HTML", " pdf "], tmp_path / "a")
    assert list(only) == ["html", "pdf"]
    assert sorted(p.name for p in (tmp_path / "a").iterdir()) == [
        "eigan-relatorio.html",
        "eigan-relatorio.pdf",
    ]
    text = write_reports(result, "csv, json,", tmp_path / "b")
    assert list(text) == ["csv", "json"]


@pytest.mark.parametrize("bad", [["docx"], ["html", "exe"], "pdf,txt"])
def test_formato_desconhecido_gera_erro_em_portugues_sem_gravar(
    tmp_path: Path, bad: object
) -> None:
    pasta = tmp_path / "saida"
    with pytest.raises(ValueError, match="Formato de relatório desconhecido"):
        write_reports(sample_result(), bad, pasta)  # type: ignore[arg-type]
    assert not pasta.exists()


@pytest.mark.parametrize("empty", [[], "", " , "])
def test_lista_vazia_gera_erro_em_portugues(tmp_path: Path, empty: object) -> None:
    with pytest.raises(ValueError, match="Nenhum formato"):
        write_reports(sample_result(), empty, tmp_path)  # type: ignore[arg-type]


def test_aceita_pasta_como_texto_e_cria_subpastas(tmp_path: Path) -> None:
    alvo = tmp_path / "x" / "y"
    written = write_reports(sample_result(), ["json"], str(alvo))
    assert written["json"] == alvo / "eigan-resultado.json"
    assert written["json"].exists()


def test_sobrescreve_relatorio_anterior(tmp_path: Path) -> None:
    (tmp_path / "eigan-resultado.json").write_text("velho", encoding="utf-8")
    write_reports(sample_result(), ["json"], tmp_path)
    assert (tmp_path / "eigan-resultado.json").read_text(encoding="utf-8") != "velho"


def test_falha_na_gravacao_preserva_o_arquivo_anterior(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    alvo = tmp_path / "eigan-resultado.json"
    alvo.write_text("velho", encoding="utf-8")

    def falha(_src: object, _dst: object) -> None:
        raise OSError("disco cheio")

    monkeypatch.setattr(os, "replace", falha)
    with pytest.raises(OSError, match="disco cheio"):
        write_reports(sample_result(), ["json"], tmp_path)
    assert alvo.read_text(encoding="utf-8") == "velho"
    assert not [p for p in tmp_path.iterdir() if p.name.endswith(".tmp")]


def test_calcula_a_analise_quando_falta(tmp_path: Path) -> None:
    result = scan([make()])
    assert not result.analysis
    written = write_reports(result, ["json"], tmp_path)
    assert result.analysis["evaluated"] is True
    saved = json.loads(written["json"].read_text(encoding="utf-8"))
    assert saved["analysis"]["posture"]["score"] == result.analysis["posture"]["score"]


@pytest.mark.parametrize(
    "render",
    [
        reports.render_html,
        reports.render_pdf,
        reports.render_json,
        reports.render_sarif,
        reports.render_csv,
    ],
)
def test_render_calcula_a_analise_quando_falta(render) -> None:  # type: ignore[no-untyped-def]
    result = scan([make()])
    assert render(result)
    assert result.analysis


def test_nao_recalcula_analise_existente() -> None:
    result = analyzed(scan([make()]))
    result.analysis["narrative"]["headline"] = "Manchete preservada"
    assert "Manchete preservada" in reports.render_html(result)


def test_pasta_padrao_tem_data_alvo_e_id(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(reports, "reports_dir", lambda: tmp_path)
    result = scan(target="https://Exemplo.com.br/Caminho", id="abc123")
    folder = default_outdir(result)
    assert folder.parent == tmp_path
    assert re.fullmatch(
        r"\d{4}-\d{2}-\d{2}_\d{4}-exemplo-com-br-abc123",
        folder.name,
    )
    written = write_reports(analyzed(result), ["json"])
    assert written["json"].parent == folder


@pytest.mark.parametrize(
    "target",
    [
        "../../../etc/passwd",
        "..\\..\\Windows\\System32",
        "C:\\Users\\alguém\\projeto",
        "https://exemplo.com/<script>alert(1)</script>",
        "CON",
        "alvo com espaços e acentuação",
        "x" * 500,
        "",
        "🔥🔥🔥",
    ],
)
def test_pasta_padrao_nunca_escapa_nem_tem_nome_invalido(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, target: str
) -> None:
    monkeypatch.setattr(reports, "reports_dir", lambda: tmp_path)
    folder = default_outdir(scan(target=target, id='../../id<>:"|?*'))
    assert folder.parent == tmp_path
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}_\d{4}-[a-z0-9-]+-[a-z0-9-]+", folder.name)
    written = write_reports(analyzed(scan(target=target, id='../../id<>:"|?*')), ["json"])
    assert tmp_path in written["json"].parents


def test_pasta_padrao_sem_data_valida_usa_o_momento_atual(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(reports, "reports_dir", lambda: tmp_path)
    folder = default_outdir(scan(started_at="data inválida"))
    assert re.match(r"\d{4}-\d{2}-\d{2}_\d{4}-", folder.name)


def test_pasta_padrao_real_fica_na_pasta_de_relatorios() -> None:
    assert default_outdir(scan()).parent == paths.reports_dir()


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("https://Exemplo.COM.br:8443/a/b?x=1", "exemplo-com-br-8443-a-b-x-1"),
        ("São Paulo — Coração", "sao-paulo-coracao"),
        ("---", "alvo"),
        ("", "alvo"),
        ("a" * 80, "a" * 50),
    ],
)
def test_slug(text: str, expected: str) -> None:
    assert slugify(text) == expected
    assert re.fullmatch(r"[a-z0-9-]{1,50}", slugify(text))


def test_ancora_estavel_e_segura() -> None:
    assert anchor("tipo", "web.hsts.ausente") == "tipo-web.hsts.ausente"
    hostile = anchor("tipo", '"><script>alert(1)</script>')
    assert re.fullmatch(r"tipo-[a-z0-9-]+-[0-9a-f]{8}", hostile)
    assert anchor("f", "a b") != anchor("f", "a-b")


def test_nao_avaliado_grava_todos_os_formatos(tmp_path: Path) -> None:
    written = write_reports(not_evaluated(), outdir=tmp_path)
    assert all(path.stat().st_size > 100 for path in written.values())


def test_caracteres_que_o_utf8_nao_representa_nao_impedem_a_gravacao(tmp_path: Path) -> None:
    # Nome de arquivo inválido no Linux chega como substituto solto (surrogateescape).
    hostile = "arquivo-\udce9.py"
    result = analyzed(
        scan(
            [make("code.segredo.exposto", "src/a.py:3", title=hostile, evidence=hostile)],
            kind=TargetKind.PROJECT,
            target=f"/projeto/{hostile}",
            errors=[hostile],
        )
    )
    written = write_reports(result, outdir=tmp_path)
    for name in ("html", "json", "sarif", "csv"):
        written[name].read_text(encoding="utf-8")  # sempre UTF-8 válido
    assert written["pdf"].read_bytes().startswith(b"%PDF")
    assert "&lt;U+DCE9&gt;" in written["html"].read_text(encoding="utf-8")
    assert "<U+DCE9>" in written["csv"].read_text(encoding="utf-8")
    loaded = json.loads(written["json"].read_text(encoding="utf-8"))
    assert ScanResult.from_dict(loaded).findings[0].title == hostile
    sarif = json.loads(written["sarif"].read_text(encoding="utf-8"))
    base = sarif["runs"][0]["originalUriBaseIds"]["SRCROOT"]["uri"]
    assert base.isascii()
    assert base.startswith("file:///projeto/arquivo-%")


def test_sem_achados_nem_analise_tambem_funciona(tmp_path: Path) -> None:
    written = write_reports(scan(), outdir=tmp_path)
    assert set(written) == set(FORMATS)


def test_painel_e_linha_de_comando_usam_a_mesma_api() -> None:
    # Contrato que src/eigan/panel/server.py e src/eigan/cli/main.py usam.
    result = analyzed(scan([make("web.hsts.ausente", SITE)]))
    for fmt in FORMATS:
        renderer = getattr(reports, f"render_{fmt}")
        body = renderer(result)
        assert isinstance(body, bytes if fmt == "pdf" else str)
        if isinstance(body, str):
            assert body.encode("utf-8")
