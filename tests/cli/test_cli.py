"""Linha de comando: auditoria de pasta, relatórios, histórico, comparação e códigos de saída."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from eigan import __version__
from eigan.cli import main as cli
from eigan.core import logs


@pytest.fixture(autouse=True)
def isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "dados"
    monkeypatch.setenv("EIGAN_HOME", str(home))
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setattr(logs, "_configured", True)  # sem arquivo de log aberto no tmp
    return home


@pytest.fixture
def project(tmp_path: Path) -> Path:
    folder = tmp_path / "projeto"
    folder.mkdir()
    (folder / "app.py").write_text("print('ola')\n", encoding="utf-8")
    return folder


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = cli.main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_versao(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "versao")
    assert code == cli.EXIT_OK
    assert f"EIGAN {__version__}" in out
    with pytest.raises(SystemExit) as exc:
        cli.main(["--versao"])
    assert exc.value.code == 0
    assert f"EIGAN {__version__}" in capsys.readouterr().out


def test_ajuda_em_portugues(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        cli.main(["--ajuda"])
    out = capsys.readouterr().out
    assert out.startswith("uso: eigan")
    assert "auditar" in out and "Sem IA" in out


def test_argumento_invalido_sai_com_erro(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["auditar", "x", "--perfil", "turbo"])
    assert exc.value.code == cli.EXIT_ERROR
    assert "erro:" in capsys.readouterr().err


def test_auditar_pasta_com_json_e_relatorios(
    capsys: pytest.CaptureFixture[str], project: Path, tmp_path: Path
) -> None:
    out_dir = tmp_path / "relatorios"
    code, out, _ = run(
        capsys,
        "auditar",
        str(project),
        "--tipo",
        "projeto",
        "--json",
        "--formatos",
        "json,csv,sarif",
        "--saida",
        str(out_dir),
    )
    assert code == cli.EXIT_OK
    data = json.loads(out)
    assert data["status"] == "concluida"
    assert data["kind"] == "projeto"
    assert data["analysis"]["posture"]["grade"]
    assert sorted(p.name for p in out_dir.iterdir()) == [
        "eigan-achados.csv",
        "eigan-resultado.json",
        "eigan-resultado.sarif",
    ]
    sarif = json.loads((out_dir / "eigan-resultado.sarif").read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"


def test_resumo_no_terminal(capsys: pytest.CaptureFixture[str], project: Path) -> None:
    code, out, _ = run(
        capsys, "auditar", str(project), "--tipo", "projeto", "--sem-relatorio", "-q"
    )
    assert code == cli.EXIT_OK
    assert "Nota" in out


def test_formato_desconhecido(capsys: pytest.CaptureFixture[str], project: Path) -> None:
    code, out, _ = run(capsys, "auditar", str(project), "--formatos", "docx")
    assert code == cli.EXIT_ERROR
    assert "docx" in out


def test_url_sem_confirmacao_fora_do_terminal(capsys: pytest.CaptureFixture[str]) -> None:
    # Sem terminal interativo e sem --sim, a auditoria de rede não começa.
    code, out, _ = run(capsys, "auditar", "https://127.0.0.1:9", "--sem-relatorio")
    assert code == cli.EXIT_ERROR
    assert "--sim" in out


def test_historico_relatorio_e_comparar(
    capsys: pytest.CaptureFixture[str], project: Path, tmp_path: Path
) -> None:
    code, _, _ = run(capsys, "historico")
    assert code == cli.EXIT_OK

    ids = []
    for _ in range(2):
        code, out, _ = run(
            capsys, "auditar", str(project), "--tipo", "projeto", "--json", "--sem-relatorio"
        )
        assert code == cli.EXIT_OK
        ids.append(json.loads(out)["id"])

    code, out, _ = run(capsys, "historico")
    assert code == cli.EXIT_OK
    assert all(scan_id in out for scan_id in ids)

    out_dir = tmp_path / "regerado"
    code, out, _ = run(capsys, "relatorio", ids[0], "--formatos", "html", "--saida", str(out_dir))
    assert code == cli.EXIT_OK
    html = (out_dir / "eigan-relatorio.html").read_text(encoding="utf-8")
    assert "<html" in html.lower() and "<script" not in html.lower()

    code, out, _ = run(capsys, "comparar", ids[0], ids[1])
    assert code == cli.EXIT_OK
    assert "Nota" in out

    code, out, _ = run(capsys, "relatorio", "nao-existe")
    assert code == cli.EXIT_ERROR


def test_comparar_alvos_diferentes(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    ids = []
    for name in ("a", "b"):
        folder = tmp_path / name
        folder.mkdir()
        code, out, _ = run(
            capsys, "auditar", str(folder), "--tipo", "projeto", "--json", "--sem-relatorio"
        )
        ids.append(json.loads(out)["id"])
    code, out, _ = run(capsys, "comparar", *ids)
    assert code == cli.EXIT_ERROR
    assert "mesmo alvo" in out


def test_explicar(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "explicar", "web.hsts.ausente")
    assert code == cli.EXIT_OK
    for section in ("O que é", "Risco", "Como corrigir", "Como verificar"):
        assert section in out

    code, out, _ = run(capsys, "explicar", "web.hsts.ausnte")
    assert code == cli.EXIT_ERROR
    assert "web.hsts.ausente" in out


def test_checagens_por_categoria(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "checagens", "--categoria", "web")
    assert code == cli.EXIT_OK
    assert "web.transport" in out
    assert "tipos de achado na base de conhecimento" in out
