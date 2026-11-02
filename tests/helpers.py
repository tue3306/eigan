"""Ajudantes de teste: servidor HTTP(S) local programável e execução de uma checagem.

Nenhum teste toca a Internet: os alvos são servidores locais (127.0.0.1) que
devolvem exatamente as respostas de cada cenário.
"""

from __future__ import annotations

import ssl
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from eigan.core import kb
from eigan.core.context import CheckContext, ScanContext
from eigan.core.models import Fact, Finding, PassedControl
from eigan.core.registry import get_check, load_builtin_checks
from eigan.core.settings import Settings
from eigan.core.target import Target, parse_target

FIXTURES = Path(__file__).parent / "fixtures"


@dataclass
class Route:
    status: int = 200
    body: bytes | str = b""
    headers: list[tuple[str, str]] = field(default_factory=list)
    content_type: str | None = "text/html; charset=utf-8"


RouteSpec = Route | Callable[[BaseHTTPRequestHandler], Route]


@dataclass
class Recorded:
    method: str
    path: str
    headers: dict[str, str]
    body: bytes


class LocalServer:
    def __init__(
        self, routes: dict[str, RouteSpec], *, tls: bool = False, default: Route | None = None
    ):
        self.routes = routes
        self.default = default or Route(404, "<html><body>Not Found</body></html>")
        self.requests: list[Recorded] = []
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args: Any) -> None:  # silencia o console
                pass

            def _serve(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                path = self.path.split("?", 1)[0]
                server.requests.append(
                    Recorded(self.command, self.path, {k: v for k, v in self.headers.items()}, body)
                )
                spec = server.routes.get(path, server.default)
                route = spec(self) if callable(spec) else spec
                payload = route.body.encode("utf-8") if isinstance(route.body, str) else route.body
                self.send_response(route.status)
                names = {k.lower() for k, _ in route.headers}
                if route.content_type and "content-type" not in names:
                    self.send_header("Content-Type", route.content_type)
                for key, value in route.headers:
                    self.send_header(key, value)
                self.send_header(
                    "Content-Length", str(len(payload) if self.command != "HEAD" else 0)
                )
                self.send_header("Connection", "close")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(payload)

            do_GET = do_POST = do_HEAD = do_OPTIONS = do_PUT = do_DELETE = do_TRACE = _serve

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(
                FIXTURES / "tls" / "localhost.crt", FIXTURES / "tls" / "localhost.key"
            )
            self.httpd.socket = context.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self.scheme = "https" if tls else "http"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"{self.scheme}://127.0.0.1:{self.port}/"

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


@dataclass
class CheckOutcome:
    findings: list[Finding]
    passed: list[PassedControl]
    facts: list[Fact]
    logs: list[str]

    def ids(self) -> set[str]:
        return {f.check_id for f in self.findings}

    def by_id(self, check_id: str) -> list[Finding]:
        return [f for f in self.findings if f.check_id == check_id]

    def fact_keys(self, kind: str) -> set[str]:
        return {f.key for f in self.facts if f.kind == kind}


def run_check(
    check_id: str,
    fact: Fact,
    *,
    target: Target | str = "https://127.0.0.1/",
    settings: Settings | None = None,
    scan: ScanContext | None = None,
) -> CheckOutcome:
    """Executa UMA checagem sobre um fato e devolve o que ela produziu."""
    load_builtin_checks()
    item = get_check(check_id)
    assert item is not None, f"checagem não registrada: {check_id}"
    tgt = parse_target(target) if isinstance(target, str) else target
    ctx = scan or ScanContext(tgt, settings or Settings(http_timeout=5.0))
    before = {key for key in ctx.facts}
    item.func(CheckContext(ctx, item, fact), fact)
    new_facts = [f for key, f in ctx.facts.items() if key not in before]
    for found in ctx.findings.values():
        assert kb.get(found.check_id) is not None, f"achado sem base: {found.check_id}"
        assert found.check_id in item.findings, f"{check_id} reportou {found.check_id} sem declarar"
    return CheckOutcome(list(ctx.findings.values()), list(ctx.passed), new_facts, list(ctx.logs))


def http_fact(url: str) -> Fact:
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return Fact(
        "http.service",
        url,
        {"url": url, "host": parts.hostname, "port": port, "scheme": parts.scheme, "label": url},
    )
