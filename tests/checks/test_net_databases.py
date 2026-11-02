"""Bancos de dados e caches (``net.bancos``): exposição e acesso sem autenticação."""

from __future__ import annotations

import json
from typing import Any

import pytest
from fakes_net import (
    closing,
    cql_frame,
    fake_tcp,
    fast_settings,
    http_response,
    http_routes,
    mongo_command,
    mongo_msg,
    mongo_reply,
    service_fact,
)
from helpers import CheckOutcome, run_check

from eigan.checks.net import common, dbauth, probes
from eigan.checks.net.databases import DATABASES
from eigan.checks.net.ports import catalog
from eigan.core.models import Confidence, Exposure, Fact, Severity


def run_db(fact: Fact) -> CheckOutcome:
    return run_check("net.bancos", fact, settings=fast_settings())


def at(monkeypatch: pytest.MonkeyPatch, exposure: Exposure) -> None:
    monkeypatch.setattr(common, "exposure_of", lambda _host: exposure)


def _json(body: Any, status: int = 200) -> bytes:
    return http_response(status, json.dumps(body), (("Content-Type", "application/json"),))


# -- exposição -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("exposure", "severity"),
    [(Exposure.INTERNET, Severity.HIGH), (Exposure.INTERNAL, Severity.LOW)],
)
def test_banco_confirmado_exposto(
    monkeypatch: pytest.MonkeyPatch, exposure: Exposure, severity: Severity
) -> None:
    at(monkeypatch, exposure)
    out = run_db(service_fact(3306, "mysql", host="10.0.0.5", product="mysql", version="8.0.35"))
    [finding] = out.by_id("net.banco.exposto")
    assert finding.severity is severity
    assert finding.confidence is Confidence.CONFIRMED
    assert finding.asset == "10.0.0.5:3306/tcp"
    assert "MySQL/MariaDB" in finding.evidence
    assert "8.0.35" in finding.evidence
    assert finding.details["servico"] == "MySQL/MariaDB"


def test_porta_de_banco_sem_confirmacao_e_tentativa(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNET)
    out = run_db(service_fact(1521, "oracle-tns", host="203.0.113.5", confirmed=False))
    [finding] = out.by_id("net.banco.exposto")
    assert finding.confidence is Confidence.TENTATIVE
    assert "não foi confirmado" in finding.evidence


def test_banco_nesta_maquina_nao_e_exposicao(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.LOCAL)
    out = run_db(service_fact(3306, "mysql", product="mysql"))
    assert not out.findings
    assert any("escuta nesta máquina" in line for line in out.logs)


def test_postgresql_sem_tls_aparece_na_evidencia(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNAL)
    out = run_db(service_fact(5432, "postgresql", host="10.0.0.5", extra={"tls": False}))
    [finding] = out.by_id("net.banco.exposto")
    assert "não oferece TLS" in finding.evidence
    com_tls = run_db(service_fact(5432, "postgresql", host="10.0.0.6", extra={"tls": True}))
    [other] = com_tls.by_id("net.banco.exposto")
    assert "não oferece TLS" not in other.evidence


def test_servico_comum_nao_dispara_a_checagem() -> None:
    from eigan.core.registry import get_check

    item = get_check("net.bancos")
    assert item is not None
    assert item.when is not None
    assert not item.when(service_fact(80, "http"))
    assert item.when(service_fact(3306, "mysql"))


def test_portas_de_banco_do_catalogo_sao_reconhecidas() -> None:
    names = {port: name for port, name in catalog()}
    for port in (3306, 5432, 1433, 1521, 27017, 6379, 9200, 11211, 5984, 9042, 8086, 8123):
        assert names[port] in DATABASES, f"porta {port}: {names[port]}"


def test_achados_de_autenticacao_tem_mapa_completo() -> None:
    assert set(dbauth.AUTH_PROBES) == {
        "redis",
        "memcached",
        "mongodb",
        "elasticsearch",
        "couchdb",
        "influxdb",
        "clickhouse",
        "cassandra",
    }


# -- Redis ---------------------------------------------------------------------------------------


INFO_REPLY = b"$60\r\n# Server\r\nredis_version:7.2.4\r\nredis_mode:standalone\r\nos:Linux\r\n"


@pytest.mark.parametrize(
    ("exposure", "severity"),
    [
        (Exposure.INTERNET, Severity.CRITICAL),
        (Exposure.INTERNAL, Severity.HIGH),
        (Exposure.LOCAL, Severity.LOW),
    ],
)
def test_redis_sem_senha(
    monkeypatch: pytest.MonkeyPatch, exposure: Exposure, severity: Severity
) -> None:
    at(monkeypatch, exposure)
    with fake_tcp(closing(INFO_REPLY)) as server:
        fact = service_fact(
            server.port, "redis", product="redis", extra={"autenticacao": "nenhuma"}
        )
        out = run_db(fact)
    assert server.received == [probes.REDIS_INFO]
    [finding] = out.by_id("net.redis.sem_senha")
    assert finding.severity is severity
    assert finding.confidence is Confidence.CONFIRMED
    assert "redis_version 7.2.4" in finding.evidence
    assert finding.details["redis_version"] == "7.2.4"
    assert any(f.kind == "tech" and f.data["version"] == "7.2.4" for f in out.facts)


def test_redis_com_info_desativado_ainda_e_sem_senha(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNAL)
    with fake_tcp(closing(b"-ERR unknown command 'INFO'\r\n")) as server:
        out = run_db(service_fact(server.port, "redis", extra={"autenticacao": "nenhuma"}))
    [finding] = out.by_id("net.redis.sem_senha")
    assert "PING respondido sem senha" in finding.evidence


def test_redis_com_senha_vira_ponto_forte(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.LOCAL)
    out = run_db(service_fact(6379, "redis", extra={"autenticacao": "senha"}))
    assert not out.findings
    assert any(p.control == "net.redis.sem_senha" for p in out.passed)


def test_redis_modo_protegido_nao_vira_ponto_forte(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.LOCAL)
    out = run_db(service_fact(6379, "redis", extra={"autenticacao": "modo protegido"}))
    assert not out.findings
    assert not any(p.control == "net.redis.sem_senha" for p in out.passed)
    assert any("modo protegido" in line for line in out.logs)


def test_redis_info_exige_senha(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.LOCAL)
    with fake_tcp(closing(b"-NOAUTH Authentication required.\r\n")) as server:
        out = run_db(service_fact(server.port, "redis", confirmed=False))
    assert not out.findings
    assert any(p.control == "net.redis.sem_senha" for p in out.passed)


@pytest.mark.parametrize(
    "reply", [b"", b"-ERR outra coisa\r\n", b"HTTP/1.1 400 Bad Request\r\n\r\n", b"-NOPERM\r\n"]
)
def test_redis_resposta_inconclusiva_nao_vira_achado(
    monkeypatch: pytest.MonkeyPatch, reply: bytes
) -> None:
    at(monkeypatch, Exposure.LOCAL)
    with fake_tcp(lambda _d: None if not reply else reply) as server:
        out = run_db(service_fact(server.port, "redis", confirmed=False))
    assert not out.findings
    assert not out.passed
    assert any("não foi possível concluir" in line for line in out.logs)


# -- Memcached -----------------------------------------------------------------------------------


STATS = b"STAT pid 12\r\nSTAT version 1.6.21\r\nSTAT curr_items 42\r\nSTAT curr_connections 3\r\nEND\r\n"


@pytest.mark.parametrize(
    ("exposure", "severity"),
    [
        (Exposure.INTERNET, Severity.HIGH),
        (Exposure.INTERNAL, Severity.MEDIUM),
        (Exposure.LOCAL, Severity.LOW),
    ],
)
def test_memcached_aberto(
    monkeypatch: pytest.MonkeyPatch, exposure: Exposure, severity: Severity
) -> None:
    at(monkeypatch, exposure)
    with fake_tcp(closing(STATS)) as server:
        out = run_db(service_fact(server.port, "memcached", product="memcached"))
    assert server.received == [probes.MEMCACHED_STATS]
    [finding] = out.by_id("net.memcached.sem_senha")
    assert finding.severity is severity
    assert "42 item(ns)" in finding.evidence
    assert finding.details["curr_items"] == "42"


@pytest.mark.parametrize(
    "reply", [b"ERROR\r\n", b"CLIENT_ERROR unauthenticated\r\n", b"SERVER_ERROR\r\n"]
)
def test_memcached_sem_stats_nao_vira_achado(monkeypatch: pytest.MonkeyPatch, reply: bytes) -> None:
    at(monkeypatch, Exposure.LOCAL)
    with fake_tcp(closing(reply)) as server:
        out = run_db(service_fact(server.port, "memcached"))
    assert not out.findings


# -- MongoDB -------------------------------------------------------------------------------------


def test_mongodb_lista_bancos_sem_login(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNET)
    commands: list[dict[str, Any]] = []

    def respond(data: bytes) -> bytes | None:
        commands.append(mongo_command(data))
        return mongo_msg({"ok": 1.0, "databases": [{"name": "admin"}, {"name": "clientes"}]})

    with fake_tcp(respond) as server:
        out = run_db(service_fact(server.port, "mongodb", product="mongodb", version="6.0.5"))
    assert commands == [{"listDatabases": 1, "nameOnly": True, "$db": "admin"}]
    [finding] = out.by_id("net.mongodb.sem_senha")
    assert finding.severity is Severity.CRITICAL
    assert "2 banco(s): admin, clientes" in finding.evidence
    assert finding.details["bancos"] == ["admin", "clientes"]


def test_mongodb_legado_usa_op_query(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNAL)

    def respond(data: bytes) -> bytes | None:
        assert int.from_bytes(data[12:16], "little") == 2004
        return mongo_reply({"ok": 1.0, "databases": [{"name": "local"}]})

    with fake_tcp(respond) as server:
        out = run_db(service_fact(server.port, "mongodb", extra={"legado": True}))
    assert out.by_id("net.mongodb.sem_senha")[0].severity is Severity.HIGH


@pytest.mark.parametrize(
    "reply",
    [
        {"ok": 0.0, "errmsg": "command listDatabases requires authentication", "code": 13},
        {"ok": 0.0, "errmsg": "not authorized on admin", "codeName": "Unauthorized"},
        {"ok": 0.0, "errmsg": "Authentication failed", "code": 18},
    ],
)
def test_mongodb_com_login_vira_ponto_forte(
    monkeypatch: pytest.MonkeyPatch, reply: dict[str, Any]
) -> None:
    at(monkeypatch, Exposure.LOCAL)
    with fake_tcp(lambda _d: mongo_msg(reply)) as server:
        out = run_db(service_fact(server.port, "mongodb"))
    assert not out.findings
    assert any(p.control == "net.mongodb.sem_senha" for p in out.passed)


@pytest.mark.parametrize(
    "reply",
    [
        mongo_msg({"ok": 0.0, "errmsg": "algum outro erro"}),
        mongo_msg({"ok": 1.0}),  # sem a lista de bancos
        b"nao sou um mongodb, mas respondi algo",
    ],
)
def test_mongodb_inconclusivo_nao_vira_achado(
    monkeypatch: pytest.MonkeyPatch, reply: bytes
) -> None:
    at(monkeypatch, Exposure.LOCAL)
    with fake_tcp(closing(reply)) as server:
        out = run_db(service_fact(server.port, "mongodb"))
    assert not out.findings
    assert not out.passed


# -- Elasticsearch -------------------------------------------------------------------------------


def test_elasticsearch_aberto_com_indices(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNET)
    routes = {
        "/_cluster/health": _json(
            {"cluster_name": "producao", "status": "green", "number_of_nodes": 3}
        ),
        "/_cat/indices": _json([{"index": "clientes"}, {"index": "pedidos"}]),
    }
    with fake_tcp(http_routes(routes)) as server:
        out = run_db(service_fact(server.port, "elasticsearch", product="elasticsearch"))
    [finding] = out.by_id("net.elasticsearch.sem_senha")
    assert finding.severity is Severity.CRITICAL
    assert "cluster 'producao'" in finding.evidence
    assert "clientes" in finding.evidence
    assert finding.details["indices"] == ["clientes", "pedidos"]


def test_elasticsearch_aberto_sem_indices_legiveis(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNAL)
    routes = {
        "/_cluster/health": _json({"cluster_name": "c", "status": "yellow"}),
        "/_cat/indices": _json({"error": "negado"}, 403),
    }
    with fake_tcp(http_routes(routes)) as server:
        out = run_db(service_fact(server.port, "elasticsearch"))
    [finding] = out.by_id("net.elasticsearch.sem_senha")
    assert finding.details["indices"] == []
    assert "Índices" not in finding.evidence


@pytest.mark.parametrize("status", [401, 403])
def test_elasticsearch_protegido_vira_ponto_forte(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    at(monkeypatch, Exposure.LOCAL)
    routes = {"/_cluster/health": _json({"error": "security_exception"}, status)}
    with fake_tcp(http_routes(routes)) as server:
        out = run_db(service_fact(server.port, "elasticsearch"))
    assert not out.findings
    assert any(p.control == "net.elasticsearch.sem_senha" for p in out.passed)


def test_elasticsearch_soft_404_nao_e_achado(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.LOCAL)
    page = http_response(200, "<html>Bem-vindo</html>")
    with fake_tcp(http_routes({}, default=page)) as server:
        out = run_db(service_fact(server.port, "elasticsearch", confirmed=False))
    assert not out.findings
    assert not out.passed


def test_elasticsearch_com_tls_usa_https(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNAL)
    routes = {"/_cluster/health": _json({"cluster_name": "c", "status": "green"})}
    with fake_tcp(http_routes(routes), tls=True) as server:
        out = run_db(service_fact(server.port, "elasticsearch", tls=True))
    assert out.by_id("net.elasticsearch.sem_senha")


# -- CouchDB, InfluxDB, ClickHouse ----------------------------------------------------------------


def test_couchdb_aberto(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNET)
    with fake_tcp(http_routes({"/_all_dbs": _json(["clientes", "_users"])})) as server:
        out = run_db(service_fact(server.port, "couchdb"))
    [finding] = out.by_id("net.couchdb.sem_senha")
    assert finding.severity is Severity.CRITICAL
    assert "2 banco(s): clientes, _users" in finding.evidence


def test_couchdb_protegido_e_soft_404(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.LOCAL)
    with fake_tcp(http_routes({"/_all_dbs": _json({"error": "unauthorized"}, 401)})) as server:
        out = run_db(service_fact(server.port, "couchdb"))
    assert not out.findings
    assert any(p.control == "net.couchdb.sem_senha" for p in out.passed)
    with fake_tcp(http_routes({}, default=_json({"ok": True}))) as server:
        out = run_db(service_fact(server.port, "couchdb"))
    assert not out.findings
    assert not out.passed


def test_influxdb_aberto(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNAL)
    body = {
        "results": [{"series": [{"name": "databases", "values": [["_internal"], ["metricas"]]}]}]
    }
    with fake_tcp(http_routes({"/query": _json(body)})) as server:
        out = run_db(service_fact(server.port, "influxdb"))
    [finding] = out.by_id("net.influxdb.sem_senha")
    assert finding.severity is Severity.HIGH
    assert "metricas" in finding.evidence
    assert any(b"SHOW%20DATABASES" in data for data in server.received)


def test_influxdb_protegido_e_outro_json(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.LOCAL)
    with fake_tcp(http_routes({"/query": _json({"error": "unable to parse"}, 401)})) as server:
        out = run_db(service_fact(server.port, "influxdb"))
    assert not out.findings
    assert any(p.control == "net.influxdb.sem_senha" for p in out.passed)
    with fake_tcp(http_routes({"/query": _json({"status": "ok"})})) as server:
        out = run_db(service_fact(server.port, "influxdb"))
    assert not out.findings
    assert not out.passed


def test_clickhouse_aberto(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNET)
    page = http_response(200, "23.8.2.7\n")
    with fake_tcp(http_routes({"/": page})) as server:
        out = run_db(service_fact(server.port, "clickhouse", product="clickhouse"))
    [finding] = out.by_id("net.clickhouse.sem_senha")
    assert finding.severity is Severity.CRITICAL
    assert "23.8.2.7" in finding.evidence
    assert any(f.kind == "tech" and f.data["version"] == "23.8.2.7" for f in out.facts)


@pytest.mark.parametrize(
    "page",
    [
        http_response(516, "Code: 516. DB::Exception: default: Authentication failed"),
        http_response(403, "Code: 497. Not enough privileges"),
        http_response(500, "Code: 194. Authentication failed: password is incorrect"),
    ],
)
def test_clickhouse_protegido(monkeypatch: pytest.MonkeyPatch, page: bytes) -> None:
    at(monkeypatch, Exposure.LOCAL)
    with fake_tcp(http_routes({"/": page})) as server:
        out = run_db(service_fact(server.port, "clickhouse"))
    assert not out.findings
    assert any(p.control == "net.clickhouse.sem_senha" for p in out.passed)


def test_clickhouse_pagina_qualquer_nao_vira_achado(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.LOCAL)
    with fake_tcp(
        http_routes({"/": http_response(200, "<html>2024 ok</html>" + "x" * 80)})
    ) as server:
        out = run_db(service_fact(server.port, "clickhouse"))
    assert not out.findings
    assert not out.passed


# -- Cassandra -----------------------------------------------------------------------------------


def test_cassandra_ready_sem_autenticacao(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNET)
    with fake_tcp(closing(cql_frame(0x02))) as server:
        out = run_db(service_fact(server.port, "cassandra"))
    [finding] = out.by_id("net.cassandra.sem_senha")
    assert finding.severity is Severity.CRITICAL
    assert "READY" in finding.evidence


def test_cassandra_pede_autenticacao(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.LOCAL)
    with fake_tcp(closing(cql_frame(0x03))) as server:
        out = run_db(service_fact(server.port, "cassandra"))
    assert not out.findings
    assert any(p.control == "net.cassandra.sem_senha" for p in out.passed)


def test_cassandra_tenta_a_versao_anterior_do_protocolo(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.LOCAL)

    def respond(data: bytes) -> bytes | None:
        return cql_frame(0x00, b"versao invalida") if data[0] == 4 else cql_frame(0x02, version=3)

    with fake_tcp(respond) as server:
        out = run_db(service_fact(server.port, "cassandra"))
    assert out.by_id("net.cassandra.sem_senha")
    assert "v3" in out.by_id("net.cassandra.sem_senha")[0].evidence


def test_cassandra_resposta_estranha_nao_conclui(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.LOCAL)
    with fake_tcp(closing(b"HTTP/1.1 400 Bad Request\r\n\r\n")) as server:
        out = run_db(service_fact(server.port, "cassandra"))
    assert not out.findings
    assert not out.passed
    with fake_tcp(lambda _d: cql_frame(0x00, b"erro")) as server:
        out = run_db(service_fact(server.port, "cassandra"))
    assert not out.findings
    assert not out.passed
