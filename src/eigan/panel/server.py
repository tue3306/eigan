"""Painel local do EIGAN: servidor HTTP da biblioteca padrão, ouvindo só em 127.0.0.1.

Proteções (o painel controla auditorias e lê o histórico):

- escuta apenas em loopback — outras máquinas da rede não alcançam o painel;
- token aleatório por execução, exigido em toda a API (cabeçalho ``X-EIGAN-Token`` ou,
  para SSE e downloads, parâmetro ``t``);
- cabeçalho ``Host`` conferido (bloqueia DNS rebinding) e ``Origin`` conferido em
  requisições que alteram estado (bloqueia CSRF);
- CSP restritiva, ``nosniff``, sem cache e sem incorporação em outros sites;
- arquivos estáticos servidos de uma lista fechada de extensões, sem sair da pasta.
"""

from __future__ import annotations

import json
import logging
import os
import re
import secrets
import subprocess
import sys
import threading
import webbrowser
from collections.abc import Callable
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .. import APP_NAME, APP_TAGLINE, __version__
from ..core import atualizacao, kb, paths, vulndb
from ..core.kb import EFFORT_LABEL, FIX_GROUPS, OWASP_2021
from ..core.models import Category, Severity, TargetKind, TriageStatus
from ..core.registry import all_checks, load_builtin_checks
from ..core.settings import (
    PROFILE_HELP,
    PROFILE_LABEL,
    PROFILES,
    Settings,
    load_settings,
    save_settings,
)
from ..core.target import TargetError, current_platform, detect_kind
from ..intel import diff as intel_diff
from ..service import set_triage
from ..storage import Store, target_key
from .jobs import JobManager

log = logging.getLogger(__name__)

STATIC_ROOT = Path(__file__).resolve().parent / "static"
STATIC_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
}
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; "
    "form-action 'none'; frame-ancestors 'none'"
)
REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'none'"
MAX_BODY = 1_000_000
DEFAULT_PORT = 8765
PORTS_RE = re.compile(r"^(auto|top100|top300|top1000|todas|[0-9][0-9,\- ]{0,300})$")
REPORT_TYPES = {
    "html": "text/html; charset=utf-8",
    "pdf": "application/pdf",
    "json": "application/json; charset=utf-8",
    "sarif": "application/sarif+json; charset=utf-8",
    "csv": "text/csv; charset=utf-8",
}
REPORT_NAMES = {
    "html": "eigan-relatorio.html",
    "pdf": "eigan-relatorio.pdf",
    "json": "eigan-resultado.json",
    "sarif": "eigan-resultado.sarif",
    "csv": "eigan-achados.csv",
}


class ApiError(Exception):
    def __init__(self, status: HTTPStatus, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class PanelApp:
    """Estado compartilhado pelo servidor: histórico, auditorias e token."""

    def __init__(self, store: Store | None = None, *, token: str | None = None) -> None:
        load_builtin_checks()
        self.store = store or Store()
        self.jobs = JobManager(self.store, load_settings)
        self.token = token or secrets.token_urlsafe(32)
        self.port = 0
        self.server: ThreadingHTTPServer | None = None

    # -- hosts e origens aceitos ---------------------------------------------------
    def allowed_hosts(self) -> set[str]:
        return {f"127.0.0.1:{self.port}", f"localhost:{self.port}", f"[::1]:{self.port}"}

    def allowed_origins(self) -> set[str]:
        return {f"http://{host}" for host in self.allowed_hosts()}

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/"

    def shutdown_later(self) -> None:
        def stop() -> None:
            self.jobs.cancel_all()
            if self.server is not None:
                self.server.shutdown()

        threading.Timer(0.3, stop).start()


class PanelServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False  # no Windows, reuse permitiria outro processo na mesma porta

    def __init__(self, address: tuple[str, int], app: PanelApp) -> None:
        super().__init__(address, PanelHandler)
        self.app = app


Route = tuple[str, re.Pattern[str], str]
ROUTES: list[Route] = [
    (method, re.compile(pattern), name)
    for method, pattern, name in (
        ("GET", r"^/api/info$", "info"),
        ("GET", r"^/api/detectar$", "detect"),
        ("GET", r"^/api/checagens$", "checks"),
        ("GET", r"^/api/kb/(?P<id>[a-z0-9_.]+)$", "kb_entry"),
        ("GET", r"^/api/auditorias$", "jobs_list"),
        ("POST", r"^/api/auditorias$", "jobs_start"),
        ("GET", r"^/api/auditorias/(?P<id>[a-f0-9]{6,32})$", "job_get"),
        ("GET", r"^/api/auditorias/(?P<id>[a-f0-9]{6,32})/eventos$", "job_events"),
        ("POST", r"^/api/auditorias/(?P<id>[a-f0-9]{6,32})/cancelar$", "job_cancel"),
        ("GET", r"^/api/historico$", "history"),
        ("GET", r"^/api/alvos$", "targets"),
        ("GET", r"^/api/resultados/(?P<id>[a-zA-Z0-9_-]{6,40})$", "result_get"),
        ("DELETE", r"^/api/resultados/(?P<id>[a-zA-Z0-9_-]{6,40})$", "result_delete"),
        ("POST", r"^/api/resultados/(?P<id>[a-zA-Z0-9_-]{6,40})/triagem$", "result_triage"),
        (
            "GET",
            r"^/api/resultados/(?P<id>[a-zA-Z0-9_-]{6,40})/relatorio\.(?P<fmt>html|pdf|json|sarif|csv)$",
            "result_report",
        ),
        ("POST", r"^/api/resultados/(?P<id>[a-zA-Z0-9_-]{6,40})/exportar$", "result_export"),
        ("GET", r"^/api/comparar$", "compare"),
        ("GET", r"^/api/configuracoes$", "settings_get"),
        ("PUT", r"^/api/configuracoes$", "settings_put"),
        ("GET", r"^/api/catalogos$", "catalogs_get"),
        ("POST", r"^/api/catalogos/atualizar$", "catalogs_update"),
        ("POST", r"^/api/abrir-pasta$", "open_folder"),
        ("POST", r"^/api/escolher-caminho$", "pick_path"),
        ("POST", r"^/api/encerrar$", "shutdown"),
    )
]


class PanelHandler(BaseHTTPRequestHandler):
    server: PanelServer
    protocol_version = "HTTP/1.1"
    server_version = "EIGAN"
    sys_version = ""

    # -- infraestrutura ----------------------------------------------------------------
    @property
    def app(self) -> PanelApp:
        return self.server.app

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 — assinatura da stdlib
        log.debug("%s - %s", self.address_string(), format % args)

    def _security_headers(self, csp: str = CSP) -> None:
        self.send_header("Content-Security-Policy", csp)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

    def _send(
        self,
        status: HTTPStatus,
        body: bytes,
        content_type: str,
        *,
        csp: str = CSP,
        extra: dict[str, str] | None = None,
        cache: bool = False,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "max-age=300" if cache else "no-store")
        self._security_headers(csp)
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, data: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def _error(self, status: HTTPStatus, message: str) -> None:
        self._json({"erro": message}, status)

    def _host_ok(self) -> bool:
        return (self.headers.get("Host") or "").lower() in self.app.allowed_hosts()

    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin")
        return origin is None or origin.lower() in self.app.allowed_origins()

    def _token_ok(self, query: dict[str, list[str]]) -> bool:
        given = self.headers.get("X-EIGAN-Token") or (query.get("t") or [""])[0]
        return bool(given) and secrets.compare_digest(given, self.app.token)

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            raise ApiError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Requisição grande demais.")
        if not length:
            return {}
        content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if content_type != "application/json":
            raise ApiError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "Envie JSON.")
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ApiError(HTTPStatus.BAD_REQUEST, "JSON inválido.") from exc
        if not isinstance(data, dict):
            raise ApiError(HTTPStatus.BAD_REQUEST, "JSON inválido.")
        return data

    # -- despacho ------------------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 — nome exigido pela stdlib
        self._dispatch("GET")

    def do_HEAD(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def do_PUT(self) -> None:  # noqa: N802
        self._dispatch("PUT")

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch("DELETE")

    def _dispatch(self, method: str) -> None:
        if not self._host_ok():
            self._error(HTTPStatus.MISDIRECTED_REQUEST, "Host não permitido.")
            return
        parts = urlsplit(self.path)
        path = parts.path
        query = parse_qs(parts.query)
        try:
            if not path.startswith("/api/"):
                if method != "GET":
                    raise ApiError(HTTPStatus.METHOD_NOT_ALLOWED, "Método não permitido.")
                self._static(path)
                return
            if method != "GET" and not self._origin_ok():
                raise ApiError(HTTPStatus.FORBIDDEN, "Origem não permitida.")
            if not self._token_ok(query):
                raise ApiError(
                    HTTPStatus.UNAUTHORIZED, "Sessão do painel inválida. Recarregue a página."
                )
            for route_method, pattern, name in ROUTES:
                match = pattern.match(path)
                if match and route_method == method:
                    handler: Callable[..., None] = getattr(self, f"api_{name}")
                    handler(query=query, **match.groupdict())
                    return
            if any(p.match(path) for _m, p, _n in ROUTES):
                raise ApiError(HTTPStatus.METHOD_NOT_ALLOWED, "Método não permitido.")
            raise ApiError(HTTPStatus.NOT_FOUND, "Recurso não encontrado.")
        except ApiError as exc:
            self._error(exc.status, exc.message)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass
        except Exception:  # noqa: BLE001 — nunca derruba o painel; o detalhe vai para o log
            log.exception("erro no painel em %s %s", method, path)
            try:
                self._error(HTTPStatus.INTERNAL_SERVER_ERROR, "Erro interno. Veja o log do EIGAN.")
            except OSError:
                pass

    # -- arquivos estáticos --------------------------------------------------------------
    def _static(self, path: str) -> None:
        if path in ("", "/", "/index.html"):
            html = (STATIC_ROOT / "index.html").read_text(encoding="utf-8")
            html = html.replace("__EIGAN_TOKEN__", self.app.token).replace(
                "__EIGAN_VERSION__", __version__
            )
            self._send(HTTPStatus.OK, html.encode("utf-8"), STATIC_TYPES[".html"])
            return
        if path == "/favicon.ico":
            path = "/eigan.svg"
        relative = path.lstrip("/")
        target = (STATIC_ROOT / relative).resolve()
        if (
            not target.is_relative_to(STATIC_ROOT)
            or target.suffix not in STATIC_TYPES
            or not target.is_file()
        ):
            raise ApiError(HTTPStatus.NOT_FOUND, "Arquivo não encontrado.")
        self._send(HTTPStatus.OK, target.read_bytes(), STATIC_TYPES[target.suffix], cache=False)

    # -- API: informações --------------------------------------------------------------
    def api_info(self, **_: Any) -> None:
        settings = load_settings()
        stats = kb.stats()
        self._json(
            {
                "app": APP_NAME,
                "version": __version__,
                "tagline": APP_TAGLINE,
                "platform": current_platform(),
                "python": sys.version.split()[0],
                "frozen": bool(getattr(sys, "frozen", False)),
                "data_dir": str(paths.data_dir()),
                "reports_dir": str(paths.reports_dir()),
                "profiles": [
                    {"id": p, "label": PROFILE_LABEL[p], "help": PROFILE_HELP[p]} for p in PROFILES
                ],
                "kinds": [{"id": k.value, "label": k.label} for k in TargetKind],
                "severities": [{"id": s.value, "label": s.label} for s in Severity],
                "categories": [{"id": c.value, "label": c.label} for c in Category],
                "triage": [{"id": t.value, "label": _TRIAGE_LABEL[t]} for t in TriageStatus],
                "default_profile": settings.profile,
                "checks": len(all_checks()),
                "kb_entries": stats.total,
                "kev_catalog": vulndb.catalog_info(),
                "catalogos": atualizacao.resumo(),
                "running": self.app.jobs.active(),
            }
        )

    def api_detect(self, query: dict[str, list[str]], **_: Any) -> None:
        text = (query.get("alvo") or [""])[0].strip()
        if not text:
            self._json({"kind": None, "label": ""})
            return
        try:
            kind = detect_kind(text)
        except TargetError as exc:
            self._json({"kind": None, "label": "", "erro": str(exc)})
            return
        self._json({"kind": kind.value, "label": kind.label})

    def api_checks(self, **_: Any) -> None:
        self._json(
            {
                "checks": [c.to_dict() for c in all_checks()],
                "kb": [
                    {
                        "id": e.id,
                        "title": e.title,
                        "category": e.category.value,
                        "severity": e.severity.value,
                        "summary": e.summary,
                        "fix_group": e.fix_group,
                    }
                    for e in kb.all_entries()
                ],
                "fix_groups": FIX_GROUPS,
                "effort": EFFORT_LABEL,
                "owasp": OWASP_2021,
            }
        )

    def api_kb_entry(self, id: str, **_: Any) -> None:  # noqa: A002
        entry = kb.get(id)
        if entry is None:
            raise ApiError(HTTPStatus.NOT_FOUND, "Entrada não encontrada na base.")
        self._json(entry.to_dict())

    # -- API: auditorias em andamento ---------------------------------------------------
    def api_jobs_list(self, **_: Any) -> None:
        self._json({"jobs": self.app.jobs.summaries()})

    def api_jobs_start(self, **_: Any) -> None:
        body = self._body()
        text = str(body.get("alvo") or "").strip()
        if not text:
            raise ApiError(HTTPStatus.BAD_REQUEST, "Informe o que deseja auditar.")
        if len(text) > 2048:
            raise ApiError(HTTPStatus.BAD_REQUEST, "Alvo longo demais.")
        if body.get("autorizado") is not True:
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "Confirme que você tem autorização para avaliar este alvo.",
            )
        kind = body.get("tipo") or None
        if kind is not None and kind not in {k.value for k in TargetKind}:
            raise ApiError(HTTPStatus.BAD_REQUEST, "Tipo de alvo desconhecido.")
        profile = body.get("perfil") or None
        if profile is not None and profile not in PROFILES:
            raise ApiError(HTTPStatus.BAD_REQUEST, "Perfil desconhecido.")
        options: dict[str, Any] = {}
        ports = str(body.get("portas") or "").strip().lower()
        if ports:
            if not PORTS_RE.match(ports):
                raise ApiError(
                    HTTPStatus.BAD_REQUEST,
                    "Portas inválidas. Use auto, top100, top1000, todas ou uma lista como 22,80,8000-8100.",
                )
            options["ports"] = ports
        if "incluir_portas" in body:
            options["include_ports"] = bool(body.get("incluir_portas"))
        try:
            job = self.app.jobs.start(text, kind=kind, profile=profile, options=options)
        except TargetError as exc:
            raise ApiError(HTTPStatus.BAD_REQUEST, str(exc)) from exc
        self._json({"job": job.summary()}, HTTPStatus.ACCEPTED)

    def _job(self, job_id: str) -> Any:
        job = self.app.jobs.get(job_id)
        if job is None:
            raise ApiError(
                HTTPStatus.NOT_FOUND, "Auditoria não encontrada (o painel foi reiniciado?)."
            )
        return job

    def api_job_get(self, id: str, **_: Any) -> None:  # noqa: A002
        self._json({"job": self._job(id).summary()})

    def api_job_cancel(self, id: str, **_: Any) -> None:  # noqa: A002
        self._job(id)
        self._json({"cancelada": self.app.jobs.cancel(id)})

    def api_job_events(self, id: str, query: dict[str, list[str]], **_: Any) -> None:  # noqa: A002
        job = self._job(id)
        try:
            seq = int(self.headers.get("Last-Event-ID") or -1) + 1
        except ValueError:
            seq = 0
        if seq <= 0:
            try:
                seq = max(0, int((query.get("desde") or ["0"])[0]))
            except ValueError:
                seq = 0
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Accel-Buffering", "no")
        self._security_headers()
        self.end_headers()
        self.close_connection = True
        while True:
            events = job.events_since(seq, timeout=15.0)
            if not events:
                self.wfile.write(b": ping\n\n")
            for event in events:
                payload = json.dumps(event, ensure_ascii=False)
                self.wfile.write(f"id: {event['seq']}\ndata: {payload}\n\n".encode())
                seq = int(event["seq"]) + 1
            self.wfile.flush()
            if job.finished and not job.events_since(seq, timeout=0):
                self.wfile.write(b"event: fim\ndata: {}\n\n")
                self.wfile.flush()
                return

    # -- API: histórico e resultados ----------------------------------------------------
    def api_history(self, query: dict[str, list[str]], **_: Any) -> None:
        target = (query.get("alvo") or [""])[0] or None
        try:
            limit = int((query.get("limite") or ["300"])[0])
        except ValueError:
            limit = 300
        self._json({"scans": self.app.store.scans(target=target, limit=limit)})

    def api_targets(self, **_: Any) -> None:
        self._json({"targets": self.app.store.targets()})

    def _result(self, scan_id: str) -> Any:
        result = self.app.store.get(scan_id)
        if result is None:
            raise ApiError(HTTPStatus.NOT_FOUND, "Auditoria não encontrada no histórico.")
        return result

    def api_result_get(self, id: str, **_: Any) -> None:  # noqa: A002
        result = self._result(id)
        data = result.to_dict()
        data["target_key"] = target_key(result.kind.value, result.target)
        self._json(data)

    def api_result_delete(self, id: str, **_: Any) -> None:  # noqa: A002
        if not self.app.store.delete(id):
            raise ApiError(HTTPStatus.NOT_FOUND, "Auditoria não encontrada no histórico.")
        self._json({"excluida": True})

    def api_result_triage(self, id: str, **_: Any) -> None:  # noqa: A002
        body = self._body()
        fingerprint = str(body.get("fingerprint") or "")
        try:
            status = TriageStatus(str(body.get("status") or ""))
        except ValueError as exc:
            raise ApiError(HTTPStatus.BAD_REQUEST, "Situação inválida.") from exc
        note = str(body.get("nota") or "")[:1000]
        result = set_triage(self.app.store, id, fingerprint, status, note)
        if result is None:
            raise ApiError(HTTPStatus.NOT_FOUND, "Achado não encontrado nesta auditoria.")
        data = result.to_dict()
        data["target_key"] = target_key(result.kind.value, result.target)
        self._json(data)

    def api_result_report(self, id: str, fmt: str, query: dict[str, list[str]], **_: Any) -> None:  # noqa: A002
        from .. import reports

        result = self._result(id)
        body: bytes
        if fmt == "pdf":
            body = reports.render_pdf(result)
        else:
            renderer = getattr(reports, f"render_{fmt}")
            body = renderer(result).encode("utf-8")
        download = (query.get("baixar") or ["0"])[0] == "1"
        disposition = "attachment" if download or fmt != "html" else "inline"
        name = REPORT_NAMES[fmt].replace("eigan-", f"eigan-{id}-")
        self._send(
            HTTPStatus.OK,
            body,
            REPORT_TYPES[fmt],
            csp=REPORT_CSP,
            extra={"Content-Disposition": f'{disposition}; filename="{name}"'},
        )

    def api_result_export(self, id: str, **_: Any) -> None:  # noqa: A002
        from .. import reports

        body = self._body()
        formats = body.get("formatos") or list(reports.FORMATS)
        if not isinstance(formats, list) or not all(f in reports.FORMATS for f in formats):
            raise ApiError(HTTPStatus.BAD_REQUEST, "Formato de relatório desconhecido.")
        written = reports.write_reports(self._result(id), formats)
        folder = next(iter(written.values())).parent if written else paths.reports_dir()
        self._json({"pasta": str(folder), "arquivos": {k: str(v) for k, v in written.items()}})

    def api_compare(self, query: dict[str, list[str]], **_: Any) -> None:
        old_id = (query.get("a") or [""])[0]
        new_id = (query.get("b") or [""])[0]
        old, new = self._result(old_id), self._result(new_id)
        if target_key(old.kind.value, old.target) != target_key(new.kind.value, new.target):
            raise ApiError(
                HTTPStatus.BAD_REQUEST, "Só é possível comparar auditorias do mesmo alvo."
            )
        if old.started_at > new.started_at:
            old, new = new, old
        data = intel_diff.compare(new, old)
        data["current_id"] = new.id
        data["current_date"] = new.started_at
        data["grade_after"] = new.analysis.get("posture", {}).get("grade", "")
        data["target"] = new.target
        self._json(data)

    # -- API: configurações -------------------------------------------------------------
    def api_settings_get(self, **_: Any) -> None:
        self._json({"settings": load_settings().to_dict(), "defaults": Settings().to_dict()})

    def api_settings_put(self, **_: Any) -> None:
        body = self._body()
        raw = body.get("settings")
        if not isinstance(raw, dict):
            raise ApiError(HTTPStatus.BAD_REQUEST, "Configurações inválidas.")
        ports = str(raw.get("ports", "auto")).strip().lower()
        if not PORTS_RE.match(ports):
            raise ApiError(HTTPStatus.BAD_REQUEST, "Portas inválidas.")
        settings = Settings.from_dict({**load_settings().to_dict(), **raw})
        save_settings(settings)
        self._json({"settings": settings.to_dict()})

    # -- API: catálogos de dados ---------------------------------------------------------
    def api_catalogs_get(self, **_: Any) -> None:
        self._json({**atualizacao.resumo(), "atualizando": atualizacao.ocupado()})

    def api_catalogs_update(self, **_: Any) -> None:
        """Baixa os catálogos só quando o usuário clica; a auditoria nunca faz isso."""
        body = self._body()
        nomes = body.get("fontes") or list(atualizacao.PADRAO)
        if not isinstance(nomes, list) or not all(
            isinstance(n, str) and n in atualizacao.FONTES for n in nomes
        ):
            raise ApiError(HTTPStatus.BAD_REQUEST, "Fonte de dados desconhecida.")
        try:
            resultados = atualizacao.atualizar([str(n) for n in nomes])
        except RuntimeError as exc:
            raise ApiError(HTTPStatus.CONFLICT, str(exc)) from exc
        self._json(
            {
                "ok": all(r["ok"] for r in resultados),
                "resultados": resultados,
                **atualizacao.resumo(),
            }
        )

    # -- API: integração com o sistema ---------------------------------------------------
    def api_open_folder(self, **_: Any) -> None:
        body = self._body()
        which = str(body.get("pasta") or "relatorios")
        base = paths.data_dir().resolve()
        if which == "relatorios":
            folder = paths.reports_dir()
        elif which == "dados":
            folder = paths.data_dir()
        else:
            folder = Path(which)
        folder = folder.resolve()
        if not folder.is_relative_to(base) or not folder.is_dir():
            raise ApiError(HTTPStatus.BAD_REQUEST, "Só é possível abrir pastas do EIGAN.")
        _open_in_file_manager(folder)
        self._json({"aberta": str(folder)})

    def api_pick_path(self, **_: Any) -> None:
        body = self._body()
        mode = str(body.get("modo") or "pasta")
        try:
            chosen = _pick_path(mode)
        except RuntimeError as exc:
            raise ApiError(HTTPStatus.NOT_IMPLEMENTED, str(exc)) from exc
        self._json({"caminho": chosen})

    def api_shutdown(self, **_: Any) -> None:
        self._json({"encerrando": True}, HTTPStatus.ACCEPTED)
        self.app.shutdown_later()


_TRIAGE_LABEL = {
    TriageStatus.OPEN: "Aberto",
    TriageStatus.ACCEPTED: "Risco aceito",
    TriageStatus.FALSE_POSITIVE: "Falso positivo",
    TriageStatus.FIXED: "Corrigido",
}


def _open_in_file_manager(folder: Path) -> None:
    if sys.platform == "win32":
        os.startfile(folder)  # noqa: S606 — pasta validada
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(folder)])  # noqa: S603, S607
    else:
        subprocess.Popen(["xdg-open", str(folder)])  # noqa: S603, S607


_pick_lock = threading.Lock()


def _pick_path(mode: str) -> str:
    """Abre o seletor nativo (tkinter). ``RuntimeError`` se não houver interface gráfica."""
    if not _pick_lock.acquire(blocking=False):
        raise RuntimeError("Já há um seletor aberto.")
    try:
        try:
            import tkinter
            from tkinter import filedialog
        except ImportError as exc:
            raise RuntimeError("Seletor indisponível. Digite o caminho.") from exc
        try:
            root = tkinter.Tk()
        except tkinter.TclError as exc:
            raise RuntimeError("Sem interface gráfica disponível. Digite o caminho.") from exc
        try:
            root.withdraw()
            root.attributes("-topmost", True)
            if mode == "arquivo":
                chosen = filedialog.askopenfilename(parent=root, title="Escolha o arquivo de log")
            else:
                chosen = filedialog.askdirectory(parent=root, title="Escolha a pasta")
        finally:
            root.destroy()
        return str(chosen or "")
    finally:
        _pick_lock.release()


def create_server(
    *, host: str = "127.0.0.1", port: int = DEFAULT_PORT, app: PanelApp | None = None
) -> PanelServer:
    """Cria o servidor; tenta a porta pedida e as 15 seguintes antes de usar uma livre."""
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("O painel só escuta em 127.0.0.1 (loopback).")
    app = app or PanelApp()
    candidates = [port + i for i in range(16)] if port else []
    candidates.append(0)
    last_error: OSError | None = None
    for candidate in candidates:
        try:
            server = PanelServer((host, candidate), app)
        except OSError as exc:
            last_error = exc
            continue
        app.port = int(server.server_address[1])
        app.server = server
        return server
    raise OSError(f"Não foi possível abrir o painel: {last_error}")


def serve(*, port: int = DEFAULT_PORT, open_browser: bool = True, quiet: bool = False) -> int:
    server = create_server(port=port)
    app = server.app
    if not quiet:
        print(f"EIGAN {__version__} — painel em {app.url}")
        print(
            "Mantenha esta janela aberta enquanto usa o painel. Para encerrar, feche-a ou use Ctrl+C.",
            flush=True,
        )
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(app.url)).start()
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        app.jobs.cancel_all()
        server.server_close()
    return 0
