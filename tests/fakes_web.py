"""Apoios dos testes web: cliente HTTP falso e servidor local em IPv6.

O cliente falso responde sem rede e anota cada requisição — serve para cenários
difíceis de montar com um servidor de verdade (nomes de domínio, respostas
cortadas, falhas de conexão) e para contar quantas sondas foram feitas. O
servidor IPv6 é o mesmo ``LocalServer`` dos outros testes, escutando em ``::1``.
"""

from __future__ import annotations

import socket
import threading
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import ThreadingHTTPServer
from typing import Any

from helpers import LocalServer, RouteSpec, http_fact

from eigan.core import kb
from eigan.core.context import CheckContext, ScanContext
from eigan.core.http import Response
from eigan.core.models import Fact, Finding
from eigan.core.registry import get_check, load_builtin_checks
from eigan.core.settings import Settings
from eigan.core.target import parse_target


def response(
    url: str,
    status: int = 200,
    body: bytes | str = b"",
    headers: Iterable[tuple[str, str]] = (),
    content_type: str | None = "text/html; charset=utf-8",
) -> Response:
    """Resposta pronta (como o cliente HTTP do EIGAN devolveria)."""
    header_list = list(headers)
    if content_type and all(k.lower() != "content-type" for k, _ in header_list):
        header_list.insert(0, ("Content-Type", content_type))
    payload = body.encode("utf-8") if isinstance(body, str) else body
    return Response(
        url=url, status=status, reason="", headers=header_list, body=payload, elapsed=0.0
    )


@dataclass(frozen=True)
class Call:
    method: str
    url: str
    headers: dict[str, str]
    max_bytes: int | None


Handler = Callable[[str, str, dict[str, str]], Response | None]


class FakeHttp:
    """Substitui o ``HttpClient``: ``handler(método, url, cabeçalhos)`` decide a resposta."""

    def __init__(self, handler: Handler) -> None:
        self.handler = handler
        self.calls: list[Call] = []
        self.requests_made = 0
        self._lock = threading.Lock()

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        max_bytes: int | None = None,
        **_: Any,
    ) -> Response | None:
        sent = dict(headers or {})
        with self._lock:
            self.calls.append(Call(method.upper(), url, sent, max_bytes))
            self.requests_made += 1
        resp = self.handler(method.upper(), url, sent)
        if resp is not None and max_bytes is not None and len(resp.body) > max_bytes:
            resp = Response(
                url=resp.url,
                status=resp.status,
                reason=resp.reason,
                headers=resp.headers,
                body=resp.body[:max_bytes],
                elapsed=0.0,
                truncated=True,
            )
        return resp

    def get(self, url: str, **kwargs: Any) -> Response | None:
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> Response | None:
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> Response | None:
        return self.request("OPTIONS", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Response | None:
        return self.request("POST", url, **kwargs)

    def methods(self) -> list[str]:
        return [call.method for call in self.calls]

    def urls(self, method: str = "GET") -> list[str]:
        return [call.url for call in self.calls if call.method == method]


def fake_scan(
    handler: Handler, *, settings: Settings | None = None, target: str = "https://127.0.0.1/"
) -> tuple[ScanContext, FakeHttp]:
    """Auditoria cujo cliente HTTP é o falso (nenhuma conexão de rede)."""
    scan = ScanContext(parse_target(target), settings or Settings(http_timeout=5.0))
    fake = FakeHttp(handler)
    scan.http = fake  # type: ignore[assignment]
    return scan, fake


def check_context(scan: ScanContext, url: str, check_id: str = "web.headers") -> CheckContext:
    """Contexto de uma checagem para chamar os apoios de ``web.common`` diretamente."""
    load_builtin_checks()
    item = get_check(check_id)
    assert item is not None
    fact: Fact = http_fact(url)
    return CheckContext(scan, item, fact)


def run_in(scan: ScanContext, check_id: str, url: str) -> list[Finding]:
    """Executa a checagem dentro de uma auditoria já em andamento; devolve os achados novos.

    (``helpers.run_check`` confere TODOS os achados da auditoria contra a checagem
    executada, o que não serve quando várias checagens dividem a mesma auditoria.)
    """
    ctx = check_context(scan, url, check_id)
    before = set(scan.findings)
    ctx.check.func(ctx, ctx.fact)
    new = [found for key, found in scan.findings.items() if key not in before]
    for found in new:
        assert kb.get(found.check_id) is not None, f"achado sem base: {found.check_id}"
        assert found.check_id in ctx.check.findings, f"{check_id} não declara {found.check_id}"
    return new


# -- servidor local -------------------------------------------------------------------


def _send_response_without_server(self: Any, code: int, message: str | None = None) -> None:
    self.log_request(code)
    self.send_response_only(code, message)
    self.send_header("Date", self.date_time_string())


def without_server_header(srv: LocalServer) -> LocalServer:
    """Tira o ``Server: BaseHTTP/0.6 Python/3.x`` que o ``http.server`` envia sozinho.

    Sem isso todo servidor de teste "divulga" a versão do Python; com isso, o
    cabeçalho Server só aparece quando a rota o define.
    """
    srv.httpd.RequestHandlerClass.send_response = _send_response_without_server  # type: ignore[method-assign]
    return srv


# -- servidor local em IPv6 -----------------------------------------------------------


class _Ipv6Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6


def ipv6_available() -> bool:
    """O sistema aceita escutar em ``::1``? (alguns contêineres não têm IPv6)."""
    if not socket.has_ipv6:
        return False
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as sock:
            sock.bind(("::1", 0))
    except OSError:
        return False
    return True


class LocalServer6(LocalServer):
    """O ``LocalServer`` dos testes, escutando em ``[::1]``."""

    def __init__(self, routes: dict[str, RouteSpec]) -> None:
        super().__init__(routes)
        handler = self.httpd.RequestHandlerClass
        self.httpd.shutdown()
        self.httpd.server_close()
        self.httpd = _Ipv6Server(("::1", 0), handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://[::1]:{self.port}/"


@contextmanager
def ipv6_server(routes: dict[str, RouteSpec]) -> Iterator[LocalServer6]:
    srv = LocalServer6(routes)
    try:
        yield srv
    finally:
        srv.stop()
