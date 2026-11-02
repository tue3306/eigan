"""Apoios dos testes de exposição e CMS: sites de teste com e sem "soft 404"."""

from __future__ import annotations

from helpers import LocalServer, Route, RouteSpec

from eigan.core.settings import Settings

HOME = "<html><head><title>Início</title></head><body><p>olá</p></body></html>"
NOT_FOUND = "<html><head><title>404</title></head><body>Página não encontrada</body></html>"


def text(body: str) -> Route:
    return Route(200, body, content_type="text/plain; charset=utf-8")


def binary(body: bytes) -> Route:
    return Route(200, body, content_type="application/octet-stream")


def json_route(body: str) -> Route:
    return Route(200, body, content_type="application/json")


def site(serve, routes: dict[str, RouteSpec], *, soft404: bool = False) -> LocalServer:
    """Servidor com a página inicial pronta; ``soft404`` responde 200 para o que não existe."""
    table: dict[str, RouteSpec] = {"/": Route(200, HOME)}
    table.update(routes)
    default = Route(200, HOME) if soft404 else Route(404, NOT_FOUND)
    return serve(table, default=default)


def settings(profile: str = "padrao") -> Settings:
    return Settings(http_timeout=5.0, profile=profile)
