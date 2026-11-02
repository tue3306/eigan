"""Bancos de dados e caches: porta acessível pela rede e acesso sem autenticação.

Dois níveis de problema:

1. a porta do banco aceita conexões de fora do servidor (``net.banco.exposto``) —
   não reportado quando o endereço é desta própria máquina; na Internet é grave, na
   rede interna é uma questão de segmentação (defesa em profundidade);
2. o serviço entrega dados sem login (Redis, MongoDB, Elasticsearch, Memcached,
   CouchDB, InfluxDB, ClickHouse, Cassandra) — ver as sondas em ``dbauth.py``.

Não há teste de senha em bancos que exigem login (MySQL, PostgreSQL, SQL Server,
Oracle): isso seria adivinhação de credencial.
"""

from __future__ import annotations

from ...core import facts
from ...core.context import CheckContext
from ...core.models import Category, Confidence, Exposure, Fact, Severity
from ...core.registry import check
from . import (
    common,
    dbauth,
    kb_bancos,  # noqa: F401 — registra as entradas da base
)
from .common import host_port, service_asset, where
from .services import add_tech

#: nome do serviço (fato ``service``, confirmado ou só o nome da porta) -> nome exibido
DATABASES: dict[str, str] = {
    "mysql": "MySQL/MariaDB",
    "mysql-alt": "MySQL/MariaDB",
    "mysqlx": "MySQL (X Protocol)",
    "postgresql": "PostgreSQL",
    "postgresql-alt": "PostgreSQL",
    "pgbouncer": "PgBouncer (PostgreSQL)",
    "mssql": "Microsoft SQL Server",
    "oracle-tns": "Oracle Database",
    "oracle-tns-alt": "Oracle Database",
    "oracle-ttc": "Oracle Database",
    "mongodb": "MongoDB",
    "mongodb-shard": "MongoDB",
    "mongodb-config": "MongoDB",
    "redis": "Redis",
    "redis-alt": "Redis",
    "redis-sentinel": "Redis Sentinel",
    "elasticsearch": "Elasticsearch",
    "elasticsearch-alt": "Elasticsearch",
    "memcached": "Memcached",
    "couchdb": "CouchDB",
    "cassandra": "Cassandra",
    "cassandra-thrift": "Cassandra",
    "influxdb": "InfluxDB",
    "clickhouse": "ClickHouse",
    "clickhouse-http": "ClickHouse",
    "cockroachdb": "CockroachDB",
    "rethinkdb": "RethinkDB",
    "firebird": "Firebird",
    "db2": "IBM Db2",
    "derby": "Apache Derby",
    "sap-hana-sql": "SAP HANA",
    "neo4j-bolt": "Neo4j",
    "arangodb": "ArangoDB",
    "couchbase": "Couchbase",
    "couchbase-data": "Couchbase",
}
#: severidade do acesso sem senha: (Internet, rede interna, esta máquina)
UNAUTH_SEVERITY: dict[str, tuple[Severity, Severity, Severity]] = {
    "memcached": (Severity.HIGH, Severity.MEDIUM, Severity.LOW),
}
_DEFAULT_UNAUTH = (Severity.CRITICAL, Severity.HIGH, Severity.LOW)


def _is_database(fact: Fact) -> bool:
    return str(fact.data.get("service")) in DATABASES


@check(
    id="net.bancos",
    name="Bancos de dados e caches expostos",
    category=Category.NETWORK,
    consumes=facts.SERVICE,
    when=_is_database,
    description=(
        "Aponta bancos de dados e caches acessíveis pela rede e verifica, com comandos de "
        "leitura de metadados, se eles entregam dados sem autenticação."
    ),
    findings=("net.banco.exposto", *(finding for _, finding in dbauth.AUTH_PROBES.values())),
    facts=(facts.TECH,),
    order=30,
)
def check_databases(ctx: CheckContext, fact: Fact) -> None:
    host, port = host_port(fact)
    service = str(fact.data.get("service"))
    label = DATABASES[service]
    asset = service_asset(host, port)
    _report_exposure(ctx, fact, host, port, label, asset)
    entry = dbauth.AUTH_PROBES.get(service)
    if entry is None:
        return
    probe, finding_id = entry
    ctx.check_cancel()
    result = probe(ctx, fact, host, port)
    if result is None:
        ctx.log(f"{asset}: não foi possível concluir se o {label} exige autenticação.")
        return
    if result.version:
        product = str(fact.data.get("product") or service)
        add_tech(ctx, host, port, product, result.version, "service", result.evidence)
    if result.inconclusive:
        ctx.log(f"{asset}: {result.evidence}")
        return
    if not result.open:
        ctx.passed(finding_id, f"{label} exige autenticação", asset)
        return
    internet, internal, local = UNAUTH_SEVERITY.get(service, _DEFAULT_UNAUTH)
    ctx.report(
        finding_id,
        asset=asset,
        severity=common.by_exposure(host, internet=internet, internal=internal, local=local),
        evidence=f"{result.evidence} ({where(host)})",
        details=result.details,
        confidence=Confidence.CONFIRMED,
        tech=[str(fact.data.get("product") or service)],
    )


def _report_exposure(
    ctx: CheckContext, fact: Fact, host: str, port: int, label: str, asset: str
) -> None:
    exposure = common.exposure_of(host)
    if exposure is Exposure.LOCAL:
        ctx.log(f"{asset}: {label} escuta nesta máquina (sem exposição de rede para avaliar).")
        return
    confirmed = bool(fact.data.get("confirmed"))
    product = " ".join(str(x) for x in (fact.data.get("product"), fact.data.get("version")) if x)
    if confirmed:
        what = f"respondeu como {label}" + (f" ({product})" if product else "")
    else:
        what = f"está aberta (porta padrão do {label}; o protocolo não foi confirmado)"
    evidence = f"A porta {port}/tcp {where(host)} {what}."
    extra = fact.data.get("extra")
    if (
        fact.data.get("service") == "postgresql"
        and isinstance(extra, dict)
        and extra.get("tls") is False
    ):
        evidence += " O servidor também não oferece TLS (resposta 'N' ao SSLRequest)."
    if exposure is not Exposure.INTERNET:
        evidence += " Confirme que só os servidores de aplicação alcançam esta porta."
    ctx.report(
        "net.banco.exposto",
        asset=asset,
        severity=Severity.HIGH if exposure is Exposure.INTERNET else Severity.LOW,
        evidence=evidence,
        details={"servico": label},
        confidence=Confidence.CONFIRMED if confirmed else Confidence.TENTATIVE,
        tech=[str(fact.data.get("service"))],
    )
