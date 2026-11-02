"""Sondas de autenticação de bancos e caches: o serviço entrega dados sem login?

Cada sonda usa um comando de LEITURA de metadados — o mesmo que ferramentas de
auditoria usam — e nunca grava nada:

* Redis ``INFO server``; Memcached ``stats``;
* MongoDB ``listDatabases`` com ``nameOnly``;
* Elasticsearch ``GET /_cluster/health``; CouchDB ``GET /_all_dbs``;
* InfluxDB ``SHOW DATABASES``; ClickHouse ``SELECT version()``;
* Cassandra ``STARTUP`` (o servidor responde READY ou pede autenticação).

Resultado: ``AuthResult`` (aberto ou protegido, com evidência) ou None quando a
resposta não permite concluir.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ...core.context import CheckContext
from ...core.facts import base_url
from ...core.http import Response
from ...core.models import Fact
from . import mongo, probes
from .banners import clean_text
from .common import io_timeout, open_service, talk


@dataclass
class AuthResult:
    open: bool  # True = dados acessíveis sem autenticação
    evidence: str
    details: dict[str, Any] = field(default_factory=dict)
    version: str = ""
    inconclusive: bool = False  # recusou, mas isso não prova que há autenticação


AuthProbe = Callable[[CheckContext, Fact, str, int], AuthResult | None]


def _extra(fact: Fact) -> dict[str, Any]:
    extra = fact.data.get("extra")
    return extra if isinstance(extra, dict) else {}


def _json(resp: Response) -> Any:
    try:
        return json.loads(resp.text)
    except ValueError:
        return None


def _get(ctx: CheckContext, fact: Fact, host: str, port: int, path: str) -> Response | None:
    scheme = "https" if fact.data.get("tls") else "http"
    return ctx.http.get(
        base_url(scheme, host, port) + path, timeout=io_timeout(ctx), max_bytes=262144
    )


def _denied(resp: Response) -> AuthResult | None:
    if resp.status in (401, 403):
        return AuthResult(False, f"O serviço exigiu autenticação (HTTP {resp.status}).")
    return None


def _protected_mode() -> AuthResult:
    """Modo protegido só indica que não há senha e o Redis atende apenas a interface local."""
    return AuthResult(
        False,
        "O Redis recusou comandos em modo protegido (senha não confirmada).",
        inconclusive=True,
    )


def redis(ctx: CheckContext, fact: Fact, host: str, port: int) -> AuthResult | None:
    mode = _extra(fact).get("autenticacao")
    if mode == "senha":
        return AuthResult(False, f"O Redis recusou comandos sem login ({mode}).")
    if mode == "modo protegido":
        return _protected_mode()
    if fact.data.get("tls"):
        return None
    data = talk(ctx, host, port, probes.REDIS_INFO, limit=65536)
    if not data:
        return None
    if data.startswith(b"-DENIED"):
        return _protected_mode()
    if data.startswith((b"-NOAUTH", b"-WRONGPASS")):
        return AuthResult(False, "O Redis exigiu autenticação para o INFO.")
    info = probes.parse_redis_info(data)
    version = info.get("redis_version", "")
    if not version:
        if mode == "nenhuma" and data.startswith(b"-ERR"):
            return AuthResult(
                True, "PING respondido sem senha (o comando INFO está renomeado ou desativado)."
            )
        return None
    evidence = (
        f"PING e INFO respondidos sem exigir senha — redis_version {version}, "
        f"modo {info.get('redis_mode', '?')}, sistema {info.get('os', '?')}."
    )
    return AuthResult(True, evidence, {"redis_version": version}, version)


def memcached(ctx: CheckContext, fact: Fact, host: str, port: int) -> AuthResult | None:
    if fact.data.get("tls"):
        return None
    data = talk(ctx, host, port, probes.MEMCACHED_STATS, limit=32768)
    stats = probes.parse_memcached_stats(data or b"")
    if "pid" not in stats and "version" not in stats:
        return None
    version = stats.get("version", "")
    evidence = (
        f"'stats' respondido sem autenticação: versão {version or '?'}, "
        f"{stats.get('curr_items', '?')} item(ns) no cache, "
        f"{stats.get('curr_connections', '?')} conexão(ões) abertas."
    )
    return AuthResult(True, evidence, {"curr_items": stats.get("curr_items")}, version)


def mongodb(ctx: CheckContext, fact: Fact, host: str, port: int) -> AuthResult | None:
    conn = open_service(ctx, host, port, tls=bool(fact.data.get("tls")))
    if conn is None:
        return None
    command = {"listDatabases": 1, "nameOnly": True}
    with conn:
        if _extra(fact).get("legado"):
            reply = mongo.command(conn, mongo.op_query(command))
        else:
            reply = mongo.command(conn, mongo.op_msg({**command, "$db": "admin"}))
    if reply is None:
        return None
    databases = reply.get("databases")
    if reply.get("ok") and isinstance(databases, list):
        names = [clean_text(db.get("name"), 80) for db in databases if isinstance(db, dict)]
        shown = ", ".join(names[:10]) + (" ..." if len(names) > 10 else "")
        evidence = f"listDatabases respondido sem login: {len(names)} banco(s): {shown}."
        return AuthResult(True, evidence, {"bancos": names[:30]})
    message = str(reply.get("errmsg", "")).lower()
    if (
        reply.get("code") in (13, 18)
        or "auth" in message
        or reply.get("codeName") == "Unauthorized"
    ):
        return AuthResult(False, "O MongoDB exigiu autenticação para listar os bancos.")
    return None


def elasticsearch(ctx: CheckContext, fact: Fact, host: str, port: int) -> AuthResult | None:
    resp = _get(ctx, fact, host, port, "_cluster/health")
    if resp is None:
        return None
    denied = _denied(resp)
    if denied is not None:
        return denied
    data = _json(resp)
    if resp.status != 200 or not isinstance(data, dict) or "cluster_name" not in data:
        return None
    evidence = (
        f"_cluster/health respondido sem login: cluster '{clean_text(data.get('cluster_name'), 80)}', "
        f"status {data.get('status')}, {data.get('number_of_nodes', '?')} nó(s)."
    )
    names = _es_indices(ctx, fact, host, port)
    if names:
        evidence += f" Índices visíveis ({len(names)}): {', '.join(names[:10])}."
    return AuthResult(
        True, evidence, {"cluster": clean_text(data.get("cluster_name"), 80), "indices": names[:30]}
    )


def _es_indices(ctx: CheckContext, fact: Fact, host: str, port: int) -> list[str]:
    resp = _get(ctx, fact, host, port, "_cat/indices?h=index&format=json")
    data = _json(resp) if resp is not None and resp.status == 200 else None
    if not isinstance(data, list):
        return []
    return [
        clean_text(item.get("index"), 80)
        for item in data
        if isinstance(item, dict) and item.get("index")
    ]


def couchdb(ctx: CheckContext, fact: Fact, host: str, port: int) -> AuthResult | None:
    resp = _get(ctx, fact, host, port, "_all_dbs")
    if resp is None:
        return None
    denied = _denied(resp)
    if denied is not None:
        return denied
    data = _json(resp)
    if resp.status != 200 or not isinstance(data, list):
        return None
    names = [str(name) for name in data]
    evidence = f"/_all_dbs respondido sem login: {len(names)} banco(s): {', '.join(names[:10])}."
    return AuthResult(True, evidence, {"bancos": names[:30]})


def influxdb(ctx: CheckContext, fact: Fact, host: str, port: int) -> AuthResult | None:
    resp = _get(ctx, fact, host, port, "query?q=SHOW%20DATABASES")
    if resp is None:
        return None
    denied = _denied(resp)
    if denied is not None:
        return denied
    data = _json(resp)
    if resp.status != 200 or not isinstance(data, dict) or "results" not in data:
        return None
    names: list[str] = []
    for result in data.get("results") or []:
        for series in (result or {}).get("series") or []:
            names.extend(str(row[0]) for row in series.get("values") or [] if row)
    evidence = (
        f"SHOW DATABASES executado sem login: {', '.join(names[:10]) or 'nenhum banco listado'}."
    )
    return AuthResult(True, evidence, {"bancos": names[:30]})


def clickhouse(ctx: CheckContext, fact: Fact, host: str, port: int) -> AuthResult | None:
    resp = _get(ctx, fact, host, port, "?query=SELECT%20version()")
    if resp is None:
        return None
    text = resp.text.strip()
    if resp.status in (401, 403, 516) or "authentication failed" in text.lower():
        return AuthResult(False, f"O ClickHouse exigiu autenticação (HTTP {resp.status}).")
    if resp.status != 200 or not text[:1].isdigit() or len(text) > 64:
        return None
    return AuthResult(
        True, f"SELECT version() executado sem login: {text}.", {"versao": text}, text
    )


def cassandra(ctx: CheckContext, fact: Fact, host: str, port: int) -> AuthResult | None:
    if fact.data.get("tls"):
        return None
    for version in (4, 3):
        data = talk(ctx, host, port, probes.cql_startup(version), limit=4096)
        state = probes.parse_cql_startup(data or b"")
        if state == "pronto":
            return AuthResult(
                True, f"STARTUP (protocolo v{version}) respondido com READY: sem autenticação."
            )
        if state == "autenticar":
            return AuthResult(False, "O Cassandra pediu autenticação (AUTHENTICATE).")
        if state is None:
            return None
    return None


#: serviço -> (sonda, id do achado)
AUTH_PROBES: dict[str, tuple[AuthProbe, str]] = {
    "redis": (redis, "net.redis.sem_senha"),
    "memcached": (memcached, "net.memcached.sem_senha"),
    "mongodb": (mongodb, "net.mongodb.sem_senha"),
    "elasticsearch": (elasticsearch, "net.elasticsearch.sem_senha"),
    "couchdb": (couchdb, "net.couchdb.sem_senha"),
    "influxdb": (influxdb, "net.influxdb.sem_senha"),
    "clickhouse": (clickhouse, "net.clickhouse.sem_senha"),
    "cassandra": (cassandra, "net.cassandra.sem_senha"),
}
