"""Painel: estado dos catálogos e o botão que os atualiza (token, origem e nada de rede sozinho)."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from pathlib import Path

import pytest
from fakes_atualizacao import FakeResponse, kev_feed, ok_routes, opener_for
from test_server import as_json, call

from eigan import data
from eigan.core import atualizacao, baixar
from eigan.panel.server import PanelApp, PanelServer, create_server
from eigan.storage import Store

UPDATE = "/api/catalogos/atualizar"


@pytest.fixture(autouse=True)
def isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    monkeypatch.setenv("EIGAN_HOME", str(tmp_path / "home"))
    atualizacao._limpar_derivados()
    yield tmp_path / "home"
    monkeypatch.undo()
    atualizacao._limpar_derivados()


@pytest.fixture
def panel(tmp_path: Path) -> Iterator[PanelServer]:
    app = PanelApp(Store(tmp_path / "eigan.db"), token="token-de-teste")
    server = create_server(port=0, app=app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


def rede_falsa(
    monkeypatch: pytest.MonkeyPatch, routes: dict[str, bytes | Exception] | None = None
) -> list[str]:
    chamadas: list[str] = []
    abridor = opener_for(routes if routes is not None else ok_routes(), chamadas)
    monkeypatch.setattr(baixar, "https_opener", lambda: abridor)
    return chamadas


def test_leitura_do_estado_nao_baixa_nada(
    panel: PanelServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    chamadas = rede_falsa(monkeypatch)
    status, _, body = call(panel, "GET", "/api/catalogos")
    assert status == 200
    dados = as_json(body)
    assert dados["limite_dias"] == 30
    assert dados["atualizando"] is False
    assert {c["nome"] for c in dados["catalogos"]} >= {"kev", "retire", "sufixos", "host_eol"}
    assert isinstance(dados["avisos"], list)
    status, _, body = call(panel, "GET", "/api/info")
    assert as_json(body)["catalogos"]["catalogos"]
    assert chamadas == []


def test_atualizar_exige_o_token(panel: PanelServer, monkeypatch: pytest.MonkeyPatch) -> None:
    chamadas = rede_falsa(monkeypatch)
    for token in (None, "errado"):
        status, _, _ = call(panel, "POST", UPDATE, {}, token=token)
        assert status == 401
    status, _, _ = call(panel, "GET", "/api/catalogos", token=None)
    assert status == 401
    assert chamadas == []
    assert data.origem("kev.json") == "embarcado"


def test_atualizar_confere_a_origem(panel: PanelServer, monkeypatch: pytest.MonkeyPatch) -> None:
    chamadas = rede_falsa(monkeypatch)
    status, _, _ = call(panel, "POST", UPDATE, {}, origin="https://site-malicioso.invalid")
    assert status == 403
    status, _, _ = call(panel, "POST", UPDATE, {}, host="exemplo.invalid")
    assert status == 421
    assert chamadas == []


def test_atualizar_so_aceita_post(panel: PanelServer) -> None:
    status, _, _ = call(panel, "GET", UPDATE)
    assert status == 405


def test_botao_atualiza_e_devolve_o_novo_estado(
    panel: PanelServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    chamadas = rede_falsa(monkeypatch)
    origem = f"http://127.0.0.1:{panel.app.port}"
    status, _, body = call(panel, "POST", UPDATE, {}, origin=origem)
    assert status == 200
    dados = as_json(body)
    assert dados["ok"] is True
    assert {r["nome"] for r in dados["resultados"]} == {"kev", "retire", "sufixos"}
    por_nome = {c["nome"]: c for c in dados["catalogos"]}
    assert por_nome["kev"]["origem"] == "baixado"
    assert por_nome["kev"]["itens"] == 1200
    assert sorted(chamadas) == sorted(
        [atualizacao.KEV_URL, atualizacao.RETIRE_URL, atualizacao.SUFIXOS_URL]
    )
    status, _, body = call(panel, "GET", "/api/catalogos")
    assert {c["nome"]: c for c in as_json(body)["catalogos"]}["kev"]["origem"] == "baixado"


def test_falha_de_uma_fonte_aparece_no_resultado(
    panel: PanelServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    routes = ok_routes()
    del routes[atualizacao.KEV_URL]
    rede_falsa(monkeypatch, routes)
    status, _, body = call(panel, "POST", UPDATE, {})
    assert status == 200
    dados = as_json(body)
    assert dados["ok"] is False
    por_nome = {r["nome"]: r for r in dados["resultados"]}
    assert por_nome["kev"]["ok"] is False
    assert por_nome["retire"]["ok"] is True


def test_fonte_desconhecida_e_recusada(panel: PanelServer, monkeypatch: pytest.MonkeyPatch) -> None:
    chamadas = rede_falsa(monkeypatch)
    status, _, _ = call(panel, "POST", UPDATE, {"fontes": ["kev", "../../etc"]})
    assert status == 400
    status, _, _ = call(panel, "POST", UPDATE, {"fontes": "kev"})
    assert status == 400
    assert chamadas == []


def test_so_as_fontes_pedidas_sao_baixadas(
    panel: PanelServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    chamadas = rede_falsa(monkeypatch)
    status, _, _ = call(panel, "POST", UPDATE, {"fontes": ["kev"]})
    assert status == 200
    assert chamadas == [atualizacao.KEV_URL]


def test_atualizacao_em_andamento_responde_409(
    panel: PanelServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    entrou, solto = threading.Event(), threading.Event()

    def lento(url: str, timeout: float = 0.0) -> FakeResponse:
        entrou.set()
        solto.wait(10)
        return FakeResponse(kev_feed(), url)

    monkeypatch.setattr(baixar, "https_opener", lambda: lento)
    primeira = threading.Thread(
        target=lambda: call(panel, "POST", UPDATE, {"fontes": ["kev"]}), daemon=True
    )
    primeira.start()
    assert entrou.wait(5)
    status, _, body = call(panel, "POST", UPDATE, {})
    assert status == 409
    assert "andamento" in as_json(body)["erro"]
    _, _, body = call(panel, "GET", "/api/catalogos")
    assert as_json(body)["atualizando"] is True
    solto.set()
    primeira.join(10)


def test_o_codigo_do_painel_nao_usa_innerhtml() -> None:
    static = Path(__file__).resolve().parents[2] / "src" / "eigan" / "panel" / "static" / "js"
    texto = (static / "views" / "sobre.js").read_text(encoding="utf-8")
    assert "innerHTML" not in texto
    assert "/api/catalogos/atualizar" in texto
    assert '"POST"' in texto


@pytest.mark.parametrize("fontes", [[["kev"]], [{"a": 1}], [None], [1], [["kev"], "retire"]])
def test_fonte_de_tipo_errado_e_400_e_nao_500(
    panel: PanelServer, monkeypatch: pytest.MonkeyPatch, fontes: list[object]
) -> None:
    chamadas = rede_falsa(monkeypatch)
    status, _, _ = call(panel, "POST", UPDATE, {"fontes": fontes})
    assert status == 400
    assert chamadas == []
