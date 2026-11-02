"""eigan atualizar: fontes, --estado, --saida, --osv, --json e códigos de saída."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fakes_atualizacao import ok_routes, opener_for

from eigan import data
from eigan.checks.code import osv
from eigan.cli import main as cli
from eigan.core import atualizacao, baixar, logs


@pytest.fixture(autouse=True)
def isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    home = tmp_path / "dados"
    monkeypatch.setenv("EIGAN_HOME", str(home))
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setattr(logs, "_configured", True)
    atualizacao._limpar_derivados()
    yield home
    monkeypatch.undo()
    atualizacao._limpar_derivados()


def com_rede_falsa(
    monkeypatch: pytest.MonkeyPatch, routes: dict[str, bytes | Exception] | None = None
) -> list[str]:
    chamadas: list[str] = []
    abridor = opener_for(routes if routes is not None else ok_routes(), chamadas)
    monkeypatch.setattr(baixar, "https_opener", lambda: abridor)
    return chamadas


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = cli.main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_ajuda_do_comando_em_portugues(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as saida:
        cli.main(["atualizar", "--ajuda"])
    assert saida.value.code == 0
    out = capsys.readouterr().out
    assert "eigan atualizar [-h" in out
    for trecho in ("--fontes", "--osv", "--estado", "--saida", "--json", "nunca acessa a Internet"):
        assert trecho in out
    with pytest.raises(SystemExit):
        cli.main(["--ajuda"])
    listagem = capsys.readouterr().out
    assert "atualizar" in listagem
    assert "baixa os catálogos" in listagem


def test_estado_mostra_cada_catalogo_sem_rede(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    chamadas = com_rede_falsa(monkeypatch)
    code, out, _ = run(capsys, "atualizar", "--estado")
    assert code == 0
    assert chamadas == []
    for nome in ("kev", "retire", "sufixos"):
        assert nome in out
    assert "embarcado" in out
    assert "dias" in out
    assert "Curadoria manual" in out
    for manual in ("host_eol", "net_vulns", "net_ports", "web_cms", "dns_takeover", "tls_suites"):
        assert manual in out


def test_estado_em_json(capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(capsys, "atualizar", "--estado", "--json")
    assert code == 0
    linhas = json.loads(out)
    kev = next(linha for linha in linhas if linha["nome"] == "kev")
    assert kev["origem"] == "embarcado"
    assert isinstance(kev["idade_dias"], int)
    assert any(not linha["atualizavel"] for linha in linhas)


def test_atualizar_tudo_baixa_grava_e_sai_com_zero(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, isolated_home: Path
) -> None:
    chamadas = com_rede_falsa(monkeypatch)
    code, out, _ = run(capsys, "atualizar")
    assert code == cli.EXIT_OK
    assert sorted(chamadas) == sorted(
        [atualizacao.KEV_URL, atualizacao.RETIRE_URL, atualizacao.SUFIXOS_URL]
    )
    assert "kev" in out and "1200 itens" in out
    assert (isolated_home / "dados" / "kev.json").is_file()
    assert data.origem("kev.json") == "baixado"
    code, estado, _ = run(capsys, "atualizar", "--estado")
    assert "baixado" in estado


def test_alias_update(capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    com_rede_falsa(monkeypatch)
    code, out, _ = run(capsys, "update", "--fontes", "sufixos")
    assert code == 0
    assert "sufixos" in out


def test_fontes_limita_o_que_e_baixado(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    chamadas = com_rede_falsa(monkeypatch)
    code, _, _ = run(capsys, "atualizar", "--fontes", "kev, retire")
    assert code == 0
    assert sorted(chamadas) == sorted([atualizacao.KEV_URL, atualizacao.RETIRE_URL])


def test_falha_parcial_sai_com_1_e_mantem_as_outras(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, isolated_home: Path
) -> None:
    routes = ok_routes()
    del routes[atualizacao.RETIRE_URL]
    com_rede_falsa(monkeypatch, routes)
    code, out, _ = run(capsys, "atualizar")
    assert code == cli.EXIT_FAIL_ON == 1
    assert "retire" in out and "404" in out
    assert "1 de 3 fontes falharam" in out
    assert (isolated_home / "dados" / "kev.json").is_file()
    assert (isolated_home / "dados" / "dns_sufixos.json").is_file()
    assert not (isolated_home / "dados" / "web_retire.json").exists()


def test_todas_as_fontes_falhando_sai_com_1(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    com_rede_falsa(monkeypatch, {})
    code, out, _ = run(capsys, "atualizar")
    assert code == 1
    assert "3 de 3" in out


def test_fonte_desconhecida_e_erro_de_uso(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    chamadas = com_rede_falsa(monkeypatch)
    code, out, _ = run(capsys, "atualizar", "--fontes", "kev,nada")
    assert code == cli.EXIT_ERROR == 2
    assert "nada" in out
    assert chamadas == []


def test_opcao_inexistente_e_erro_de_uso(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as saida:
        cli.main(["atualizar", "--tudo"])
    assert saida.value.code == 2
    capsys.readouterr()


def test_saida_escreve_em_outra_pasta_e_nao_altera_os_dados_em_uso(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    isolated_home: Path,
) -> None:
    com_rede_falsa(monkeypatch)
    pasta = tmp_path / "novos"
    code, out, _ = run(capsys, "atualizar", "--saida", str(pasta))
    assert code == 0
    assert sorted(p.name for p in pasta.iterdir()) == [
        "dns_sufixos.json",
        "kev.json",
        "web_retire.json",
    ]
    assert str(pasta / "kev.json") in out
    assert not (isolated_home / "dados").exists()
    assert data.origem("kev.json") == "embarcado"


def test_json_traz_resultado_por_fonte_e_estado(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    routes = ok_routes()
    del routes[atualizacao.KEV_URL]
    com_rede_falsa(monkeypatch, routes)
    code, out, _ = run(capsys, "atualizar", "--json")
    assert code == 1
    payload = json.loads(out)
    assert payload["ok"] is False
    por_nome = {f["nome"]: f for f in payload["fontes"]}
    assert por_nome["kev"]["ok"] is False
    assert por_nome["retire"]["ok"] is True
    assert {c["nome"] for c in payload["catalogos"]} >= {"kev", "retire", "sufixos"}


def test_osv_so_baixa_quando_o_usuario_nomeia_ecossistemas(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    com_rede_falsa(monkeypatch)
    pedidos: list[list[str]] = []

    def falso(ecosystems: list[str], **kwargs: Any) -> dict[str, dict[str, Any]]:
        pedidos.append(ecosystems)
        return {
            "npm": {"ok": True, "arquivo": "x/all.zip", "bytes": 10, "pacotes": 2, "registros": 3},
            "PyPI": {"ok": False, "erro": "licença"},
        }

    monkeypatch.setattr(osv, "download_osv", falso)
    code, _, _ = run(capsys, "atualizar")
    assert code == 0
    assert pedidos == []
    code, out, _ = run(capsys, "atualizar", "--osv", "NPM,pypi")
    assert pedidos == [["npm", "PyPI"]]
    assert code == 1
    assert "osv:npm" in out and "osv:PyPI" in out


def test_osv_com_ecossistema_desconhecido_ou_com_saida_e_erro_de_uso(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    chamadas = com_rede_falsa(monkeypatch)
    code, out, _ = run(capsys, "atualizar", "--osv", "cobol")
    assert code == 2
    assert "cobol" in out
    code, out, _ = run(capsys, "atualizar", "--osv", "npm", "--saida", str(tmp_path / "x"))
    assert code == 2
    assert "--saida" in out
    assert chamadas == []


def test_atualizacao_em_andamento_e_erro_de_uso(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    com_rede_falsa(monkeypatch)

    def ocupado(*args: object, **kwargs: object) -> None:
        raise RuntimeError("Já há uma atualização em andamento.")

    monkeypatch.setattr(atualizacao, "atualizar", ocupado)
    code, out, _ = run(capsys, "atualizar")
    assert code == 2
    assert "andamento" in out


@pytest.mark.parametrize("fontes", [",", " , ,", ""])
def test_fontes_vazio_e_erro_de_uso_e_nao_baixa_nada(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, fontes: str
) -> None:
    chamadas = com_rede_falsa(monkeypatch)
    code, out, _ = run(capsys, "atualizar", "--fontes", fontes)
    assert code == cli.EXIT_ERROR == 2
    assert "--fontes" in out
    assert chamadas == []


@pytest.mark.parametrize(
    "extra", [["--fontes", "foo"], ["--osv", "npm"], ["--saida", "x"], ["--fontes", "kev"]]
)
def test_estado_nao_ignora_em_silencio_as_outras_opcoes(
    capsys: pytest.CaptureFixture[str], extra: list[str]
) -> None:
    code, out, _ = run(capsys, "atualizar", "--estado", *extra)
    assert code == cli.EXIT_ERROR
    assert "--estado" in out


def test_versao_nao_e_cortada_no_meio_do_parentese(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    com_rede_falsa(monkeypatch)
    code, out, _ = run(capsys, "atualizar", "--fontes", "sufixos")
    assert code == 0
    linha = next(x for x in out.splitlines() if "sufixos" in x)
    assert "2027-01-14_10-00-00_UTC" in linha
    assert "(commit" not in linha
