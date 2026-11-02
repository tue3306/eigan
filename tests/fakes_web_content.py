"""Apoios dos testes de conteúdo web: site falso por tabela de rotas, sem rede."""

from __future__ import annotations

from collections.abc import Mapping
from urllib.parse import urlsplit

from fakes_web import fake_scan, response, run_in

from eigan.core.http import Response
from eigan.core.models import Finding
from eigan.core.settings import Settings

BASE = "https://loja.exemplo.test"
NOT_FOUND = (
    "<html><head><title>Não encontrado</title></head><body>Página não encontrada.</body></html>"
)

Route = str | tuple[int, str] | tuple[int, str, str]


def site(routes: Mapping[str, Route], base: str = BASE, fallback: Route | None = None):
    """Manipulador HTTP falso: ``rotas[caminho]`` é HTML, ``(status, corpo)`` ou
    ``(status, corpo, content-type)``. Caminhos desconhecidos dão 404 (ou ``fallback``)."""

    def handler(method: str, url: str, headers: dict[str, str]) -> Response | None:
        parts = urlsplit(url)
        if parts.scheme != urlsplit(base).scheme:
            return None  # o outro esquema (HTTPS/HTTP) não responde
        path = parts.path or "/"
        spec = routes.get(path, fallback if fallback is not None else (404, NOT_FOUND))
        status, body, ctype = _unpack(spec, path)
        return response(url, status, body, content_type=ctype)

    return handler


def _unpack(spec: Route, path: str) -> tuple[int, str, str]:
    if isinstance(spec, str):
        return 200, spec, "application/javascript" if path.endswith(".js") else "text/html"
    if len(spec) == 2:
        return spec[0], spec[1], "text/html"
    return spec


def audit(
    check_id: str,
    routes: Mapping[str, Route],
    *,
    base: str = BASE,
    fallback: Route | None = None,
    settings: Settings | None = None,
    headers: list[tuple[str, str]] | None = None,
) -> list[Finding]:
    """Roda a checagem sobre ``base + "/"`` e devolve os achados."""
    handler = site(routes, base, fallback)
    if headers:
        inner = handler

        def handler(method: str, url: str, sent: dict[str, str]) -> Response | None:  # noqa: F811
            resp = inner(method, url, sent)
            if resp is not None and urlsplit(url).path in ("", "/"):
                resp.headers.extend(headers)
            return resp

    scan, _ = fake_scan(handler, settings=settings, target=base + "/")
    return run_in(scan, check_id, base + "/")


def ids(findings: list[Finding]) -> set[str]:
    return {f.check_id for f in findings}
