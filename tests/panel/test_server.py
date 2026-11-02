from __future__ import annotations

import http.client
import json
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from eigan.core import kb
from eigan.core.models import Finding, ScanResult, TargetKind
from eigan.core.registry import load_builtin_checks
from eigan.intel.analysis import analyze
from eigan.panel.server import PanelApp, PanelServer, create_server
from eigan.storage import Store


@pytest.fixture
def panel(tmp_path: Path) -> Iterator[PanelServer]:
    app = PanelApp(Store(tmp_path / "eigan.db"), token="token-de-teste")
    server = create_server(port=0, app=app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


def call(
    server: PanelServer,
    method: str,
    path: str,
    body: Any = None,
    *,
    token: str | None = "token-de-teste",
    host: str | None = None,
    origin: str | None = None,
) -> tuple[int, dict[str, str], bytes]:
    port = server.app.port
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Host": host or f"127.0.0.1:{port}"}
    if token:
        headers["X-EIGAN-Token"] = token
    if origin:
        headers["Origin"] = origin
    payload = None
    if body is not None:
        payload = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    conn.request(method, path, body=payload, headers=headers)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, {k.lower(): v for k, v in resp.getheaders()}, data


def as_json(data: bytes) -> Any:
    return json.loads(data.decode("utf-8"))


def test_pagina_inicial_tem_token_e_csp(panel):
    status, headers, body = call(panel, "GET", "/", token=None)
    assert status == 200
    assert b"token-de-teste" in body
    assert "default-src 'self'" in headers["content-security-policy"]
    assert headers["x-frame-options"] == "DENY"
    assert headers["cache-control"] == "no-store"


def test_api_exige_token(panel):
    status, _, body = call(panel, "GET", "/api/info", token=None)
    assert status == 401
    status, _, _ = call(panel, "GET", "/api/info", token="errado")
    assert status == 401
    status, _, body = call(panel, "GET", "/api/info")
    assert status == 200
    info = as_json(body)
    assert info["version"] == "0.0.0"
    assert info["checks"] >= 1


def test_host_estranho_e_bloqueado(panel):
    status, _, _ = call(panel, "GET", "/", token=None, host="atacante.example:80")
    assert status == 421


def test_origem_estranha_nao_altera_estado(panel):
    status, _, body = call(
        panel,
        "POST",
        "/api/auditorias",
        {"alvo": "local", "autorizado": True},
        origin="http://atacante.example",
    )
    assert status == 403


def test_arquivos_estaticos_nao_saem_da_pasta(panel):
    assert call(panel, "GET", "/../server.py", token=None)[0] == 404
    assert call(panel, "GET", "/js/../../server.py", token=None)[0] == 404
    status, headers, _ = call(panel, "GET", "/js/main.js", token=None)
    assert status == 200
    assert headers["content-type"].startswith("text/javascript")


def test_auditoria_exige_autorizacao_e_alvo_valido(panel):
    status, _, body = call(panel, "POST", "/api/auditorias", {"alvo": "https://exemplo.com.br"})
    assert status == 400
    assert "autorização" in as_json(body)["erro"]
    status, _, body = call(panel, "POST", "/api/auditorias", {"alvo": "", "autorizado": True})
    assert status == 400
    status, _, body = call(
        panel, "POST", "/api/auditorias", {"alvo": "local", "autorizado": True, "portas": "1;rm"}
    )
    assert status == 400


def test_auditoria_de_projeto_do_inicio_ao_fim(panel, tmp_path: Path):
    project = tmp_path / "projeto"
    project.mkdir()
    (project / "app.py").write_text("print('ok')\n", encoding="utf-8")
    status, _, body = call(
        panel,
        "POST",
        "/api/auditorias",
        {"alvo": str(project), "tipo": "projeto", "autorizado": True, "perfil": "rapido"},
    )
    assert status == 202, body
    job_id = as_json(body)["job"]["id"]
    deadline = time.monotonic() + 60
    job: dict[str, Any] = {}
    while time.monotonic() < deadline:
        job = as_json(call(panel, "GET", f"/api/auditorias/{job_id}")[2])["job"]
        if job["status"] not in ("na_fila", "em_andamento"):
            break
        time.sleep(0.2)
    assert job["status"] == "concluida", job
    status, _, body = call(panel, "GET", f"/api/resultados/{job_id}")
    assert status == 200
    result = as_json(body)
    assert result["analysis"]["posture"]["grade"]
    assert result["target_key"].startswith("projeto:")
    history = as_json(call(panel, "GET", "/api/historico")[2])["scans"]
    assert [s["id"] for s in history] == [job_id]


def _saved_result(store: Store) -> ScanResult:
    load_builtin_checks()
    entry = kb.require("web.hsts.ausente")
    result = ScanResult(
        id="resultado01",
        target="https://exemplo.com.br",
        kind=TargetKind.URL,
        profile="padrao",
        started_at="2026-11-01T10:00:00+00:00",
        finished_at="2026-11-01T10:01:00+00:00",
        status="concluida",
        findings=[
            Finding(
                check_id=entry.id,
                title=entry.title,
                severity=entry.severity,
                asset="https://exemplo.com.br/",
                source="web.transport",
            )
        ],
    )
    analyze(result)
    store.save(result)
    return result


def test_triagem_recalcula_a_nota(panel):
    result = _saved_result(panel.app.store)
    before = result.analysis["posture"]["score"]
    fp = result.findings[0].fingerprint
    status, _, body = call(
        panel,
        "POST",
        "/api/resultados/resultado01/triagem",
        {"fingerprint": fp, "status": "falso_positivo", "nota": "testado à mão"},
    )
    assert status == 200, body
    data = as_json(body)
    assert data["findings"][0]["status"] == "falso_positivo"
    assert data["analysis"]["posture"]["score"] > before
    status, _, _ = call(
        panel, "POST", "/api/resultados/resultado01/triagem", {"fingerprint": fp, "status": "x"}
    )
    assert status == 400


def test_configuracoes_validam_portas(panel):
    status, _, body = call(panel, "GET", "/api/configuracoes")
    assert status == 200
    settings = as_json(body)["settings"]
    status, _, body = call(
        panel, "PUT", "/api/configuracoes", {"settings": {**settings, "http_timeout": 7}}
    )
    assert status == 200
    assert as_json(body)["settings"]["http_timeout"] == 7
    status, _, _ = call(
        panel, "PUT", "/api/configuracoes", {"settings": {**settings, "ports": "$(x)"}}
    )
    assert status == 400


def test_kb_e_checagens(panel):
    data = as_json(call(panel, "GET", "/api/checagens")[2])
    assert any(c["id"] == "web.transport" for c in data["checks"])
    status, _, body = call(panel, "GET", "/api/kb/web.hsts.ausente")
    assert status == 200
    assert as_json(body)["steps"]
    assert call(panel, "GET", "/api/kb/nao.existe")[0] == 404


def test_relatorios_baixados_pelo_painel(panel):
    result = _saved_result(panel.app.store)
    expected = {
        "html": ("text/html", b"<!doctype html"),
        "pdf": ("application/pdf", b"%PDF"),
        "json": ("application/json", b"{"),
        "sarif": ("application/sarif+json", b"{"),
        "csv": ("text/csv", b""),
    }
    for fmt, (content_type, start) in expected.items():
        status, headers, body = call(panel, "GET", f"/api/resultados/{result.id}/relatorio.{fmt}")
        assert status == 200, (fmt, body[:200])
        assert headers["content-type"].startswith(content_type), fmt
        assert body.lstrip(b"\xef\xbb\xbf \r\n")[: len(start)].lower() == start.lower(), fmt
        disposition = headers["content-disposition"]
        assert disposition.startswith("inline" if fmt == "html" else "attachment"), fmt
        assert f"eigan-{result.id}-" in disposition
        # O relatório nunca roda script, nem aberto direto pelo painel.
        assert "default-src 'none'" in headers["content-security-policy"]
    _, headers, _ = call(panel, "GET", f"/api/resultados/{result.id}/relatorio.html?baixar=1")
    assert headers["content-disposition"].startswith("attachment")
    status, _, _ = call(panel, "GET", f"/api/resultados/{result.id}/relatorio.html", token=None)
    assert status == 401


def test_exportar_relatorios_para_a_pasta(panel):
    result = _saved_result(panel.app.store)
    status, _, body = call(
        panel, "POST", f"/api/resultados/{result.id}/exportar", {"formatos": ["json", "csv"]}
    )
    assert status == 200, body
    files = as_json(body)["arquivos"]
    assert sorted(files) == ["csv", "json"]
    assert all(Path(path).is_file() for path in files.values())
    status, _, _ = call(
        panel, "POST", f"/api/resultados/{result.id}/exportar", {"formatos": ["docx"]}
    )
    assert status == 400
