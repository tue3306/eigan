"""Fixtures compartilhadas. Nenhum teste toca a Internet: os alvos são servidores locais."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Callable, Iterator

import pytest

# Isola o diretório de dados do EIGAN durante os testes (histórico/configurações).
os.environ.setdefault("EIGAN_HOME", tempfile.mkdtemp(prefix="eigan-testes-"))

from helpers import LocalServer, Route, RouteSpec  # noqa: E402


@pytest.fixture
def serve() -> Iterator[Callable[..., LocalServer]]:
    """Fábrica de servidores locais: ``srv = serve({"/": Route(...)}, tls=False)``."""
    servers: list[LocalServer] = []

    def factory(
        routes: dict[str, RouteSpec], *, tls: bool = False, default: Route | None = None
    ) -> LocalServer:
        srv = LocalServer(routes, tls=tls, default=default)
        servers.append(srv)
        return srv

    yield factory
    for srv in servers:
        srv.stop()
