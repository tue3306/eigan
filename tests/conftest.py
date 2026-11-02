"""Fixtures compartilhadas. Nenhum teste toca a Internet: os alvos são servidores locais."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Callable, Iterator
from datetime import date

import pytest

# Isola o diretório de dados do EIGAN durante os testes (histórico/configurações).
os.environ.setdefault("EIGAN_HOME", tempfile.mkdtemp(prefix="eigan-testes-"))

from helpers import LocalServer, Route, RouteSpec  # noqa: E402

#: o "hoje" dos testes: depois dos catálogos embarcados e das datas das fontes falsas
HOJE_DOS_TESTES = date(2027, 1, 20)


@pytest.fixture(autouse=True)
def relogio_dos_catalogos(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fixa o dia que os catálogos usam para recusar datas no futuro (testes não dependem do relógio)."""
    from eigan import data

    monkeypatch.setattr(data, "hoje", lambda: HOJE_DOS_TESTES)


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
