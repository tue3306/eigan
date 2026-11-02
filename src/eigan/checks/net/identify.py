"""Identificação do serviço de uma porta aberta (banner, sondas e HTTP/TLS).

Estratégia, parecida com a de ferramentas de inventário:

1. portas conhecidas pelo cliente-fala-primeiro (HTTP, Redis, RDP...) começam
   pela sonda específica;
2. as demais esperam o banner (SSH, FTP, SMTP, MySQL, VNC...);
3. sem banner, tentam TLS e depois HTTP;
4. nada reconhecido: fica o nome provável da porta, marcado como não confirmado.
"""

from __future__ import annotations

import ssl
from collections.abc import Callable
from typing import Any

from ...core import netutil
from ...core.context import CheckContext
from ...core.facts import base_url
from ...core.http import insecure_context
from ...core.target import is_ip
from . import mongo, probes, winproto
from .banners import Identified, classify_220, classify_banner
from .common import Connection, connect_timeout, greeting_timeout, io_timeout, printable, talk
from .httpid import identify_http
from .ports import service_name

Probe = Callable[[CheckContext, str, int], Identified | None]

#: implícito-TLS de correio/arquivos: o banner chega depois do handshake
TLS_BANNER_PORTS = frozenset({465, 990, 992, 993, 995})


def _probe_http(ctx: CheckContext, host: str, port: int) -> Identified | None:
    return identify_http(ctx, host, port, "http")


def _probe_tls(ctx: CheckContext, host: str, port: int) -> Identified | None:
    """Handshake TLS tolerante; depois descobre o protocolo que roda por dentro."""
    sock = netutil.tcp_connect(host, port, connect_timeout(ctx))
    if sock is None:
        return None
    server_name = None if is_ip(host) else host
    try:
        tls = insecure_context().wrap_socket(sock, server_hostname=server_name)
    except (ssl.SSLError, OSError, ValueError):
        sock.close()
        return None
    try:
        version = tls.version() or ""
        if port not in TLS_BANNER_PORTS:
            tls.close()
            found = identify_http(ctx, host, port, "https")
            if found is not None:
                found.extra.setdefault("versao_tls", version)
                return found
            return _tls_banner(ctx, host, port, version)
        data = netutil.recv_some(tls, limit=4096, timeout=io_timeout(ctx))
    finally:
        tls.close()
    found = classify_banner(data, port) if data else None
    if found is None:
        return Identified("tls", tls=True, extra={"versao_tls": version})
    found.tls = True
    found.extra.setdefault("versao_tls", version)
    return found


def _tls_banner(ctx: CheckContext, host: str, port: int, version: str) -> Identified:
    """Serviço TLS que não falou HTTP: tenta ler um banner (ex.: IMAPS em porta diferente)."""
    sock = netutil.tcp_connect(host, port, connect_timeout(ctx))
    data = b""
    if sock is not None:
        try:
            tls = insecure_context().wrap_socket(
                sock, server_hostname=None if is_ip(host) else host
            )
            data = netutil.recv_some(tls, limit=4096, timeout=min(2.0, io_timeout(ctx)))
            tls.close()
        except (ssl.SSLError, OSError, ValueError):
            sock.close()
    found = classify_banner(data, port) if data else None
    if found is None:
        return Identified("tls", tls=True, extra={"versao_tls": version})
    found.tls = True
    found.extra.setdefault("versao_tls", version)
    return found


def _probe_redis(ctx: CheckContext, host: str, port: int) -> Identified | None:
    data = talk(ctx, host, port, probes.REDIS_PING)
    return probes.parse_redis(data) if data else None


def _probe_memcached(ctx: CheckContext, host: str, port: int) -> Identified | None:
    data = talk(ctx, host, port, probes.MEMCACHED_VERSION)
    return probes.parse_memcached(data) if data else None


def _probe_postgres(ctx: CheckContext, host: str, port: int) -> Identified | None:
    data = talk(ctx, host, port, probes.POSTGRES_SSLREQUEST, limit=1024)
    return probes.parse_postgres(data) if data else None


def _probe_mssql(ctx: CheckContext, host: str, port: int) -> Identified | None:
    data = talk(ctx, host, port, probes.mssql_prelogin())
    return probes.parse_mssql(data) if data else None


def _probe_ajp(ctx: CheckContext, host: str, port: int) -> Identified | None:
    data = talk(ctx, host, port, probes.AJP_CPING, limit=64)
    return probes.parse_ajp(data) if data else None


def _probe_amqp(ctx: CheckContext, host: str, port: int) -> Identified | None:
    data = talk(ctx, host, port, probes.AMQP_HEADER)
    return probes.parse_amqp(data) if data else None


def _probe_cql(ctx: CheckContext, host: str, port: int) -> Identified | None:
    data = talk(ctx, host, port, probes.CQL_OPTIONS)
    return probes.parse_cql(data) if data else None


def _probe_oracle(ctx: CheckContext, host: str, port: int) -> Identified | None:
    data = talk(ctx, host, port, probes.tns_connect(), limit=4096)
    return probes.parse_tns(data) if data else None


def _probe_rdp(ctx: CheckContext, host: str, port: int) -> Identified | None:
    request = winproto.rdp_request(
        winproto.PROTOCOL_SSL | winproto.PROTOCOL_HYBRID | winproto.PROTOCOL_HYBRID_EX
    )
    data = talk(ctx, host, port, request, limit=512)
    negotiation = winproto.parse_rdp(data) if data else None
    if negotiation is None:
        return None
    return Identified("rdp", banner=f"X.224: {negotiation.describe()}")


def _probe_smb(ctx: CheckContext, host: str, port: int) -> Identified | None:
    for request in (winproto.smb2_negotiate(), winproto.smb1_negotiate()):
        data = talk(ctx, host, port, request, limit=4096)
        result = winproto.parse_smb(data) if data else None
        if result is not None:
            extra = {"dialeto": result.dialect, "assinatura_obrigatoria": result.signing_required}
            return Identified("smb", banner=f"SMB {result.dialect}", extra=extra)
    return None


def _probe_dns(ctx: CheckContext, host: str, port: int) -> Identified | None:
    data = talk(ctx, host, port, probes.DNS_QUERY_TCP, limit=4096)
    return probes.parse_dns_tcp(data) if data else None


def _probe_mongodb(ctx: CheckContext, host: str, port: int) -> Identified | None:
    """``hello`` (OP_MSG); servidores antigos (< 3.6) recebem ``isMaster`` via OP_QUERY."""
    reply, info = _mongo_hello(ctx, host, port, legacy=False)
    if reply is None:
        reply, info = _mongo_hello(ctx, host, port, legacy=True)
    if reply is None:
        return None
    version = str(info.get("version", "")) if info else ""
    extra = {"wire": reply.get("maxWireVersion"), "legado": bool(reply.get("_legado"))}
    return Identified("mongodb", "mongodb", version, extra=extra)


def _mongo_hello(
    ctx: CheckContext, host: str, port: int, *, legacy: bool
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Resposta do ``hello``/``isMaster`` e do ``buildInfo`` (versão), na mesma conexão."""
    conn = Connection.open(host, port, connect_timeout(ctx), io_timeout(ctx))
    if conn is None:
        return None, None
    with conn:
        if legacy:
            reply = mongo.command(conn, mongo.op_query({"isMaster": 1}))
            info = mongo.command(conn, mongo.op_query({"buildInfo": 1})) if reply else None
            if reply is not None:
                reply["_legado"] = True
            return reply, info
        reply = mongo.command(conn, mongo.op_msg({"hello": 1, "$db": "admin"}))
        if reply is not None and not reply.get("ok"):
            reply = mongo.command(conn, mongo.op_msg({"isMaster": 1, "$db": "admin"}))
        info = (
            mongo.command(conn, mongo.op_msg({"buildInfo": 1, "$db": "admin"})) if reply else None
        )
        return reply, info


PROBES: dict[str, Probe] = {
    "http": _probe_http,
    "tls": _probe_tls,
    "redis": _probe_redis,
    "memcached": _probe_memcached,
    "postgres": _probe_postgres,
    "mssql": _probe_mssql,
    "ajp": _probe_ajp,
    "amqp": _probe_amqp,
    "cql": _probe_cql,
    "oracle": _probe_oracle,
    "rdp": _probe_rdp,
    "smb": _probe_smb,
    "mongodb": _probe_mongodb,
    "dns": _probe_dns,
}

_HTTP_FIRST = ("http", "tls")
_TLS_FIRST = ("tls", "http")
#: portas em que o cliente fala primeiro: começam pela sonda certa (sem esperar banner)
PORT_HINTS: dict[int, tuple[str, ...]] = {
    **{p: _HTTP_FIRST for p in (80, 81, 591, 2375, 3000, 5000, 5001, 5601, 5984, 5988, 7001, 7080,
                                7990, 8000, 8001, 8002, 8008, 8010, 8080, 8081, 8082, 8086, 8088,
                                8090, 8111, 8123, 8161, 8180, 8222, 8500, 8888, 8983, 9000, 9001,
                                9080, 9090, 9091, 9093, 9200, 9201, 9229, 9600, 9990, 10255,
                                15672, 16686)},
    **{p: _TLS_FIRST for p in (443, 943, 2083, 2087, 2096, 2376, 2379, 2380, 4443, 5986, 5989,
                               6443, 6984, 7443, 7473, 8006, 8172, 8443, 8834, 9443, 10000, 10250,
                               10443, 16993)},
    **{p: ("tls",) for p in TLS_BANNER_PORTS},
    6379: ("redis",), 6380: ("redis",), 26379: ("redis",),
    11211: ("memcached",),
    27017: ("mongodb",), 27018: ("mongodb",), 27019: ("mongodb",),
    5432: ("postgres",), 5433: ("postgres",),
    1433: ("mssql",),
    8009: ("ajp",),
    5671: ("tls",), 5672: ("amqp",),
    9042: ("cql",),
    1521: ("oracle",), 1526: ("oracle",), 2483: ("oracle",),
    3389: ("rdp",),
    445: ("smb",),
    53: ("dns",),
}  # fmt: skip


def grab_banner(ctx: CheckContext, host: str, port: int) -> bytes | None:
    """Conecta e espera o servidor falar. None se a porta não aceitar a conexão."""
    wait = greeting_timeout(ctx, port)
    conn = Connection.open(host, port, connect_timeout(ctx), wait)
    if conn is None:
        return None
    with conn:
        return conn.read_some(limit=4096, timeout=wait, idle=0.5)


def _disambiguate_220(ctx: CheckContext, host: str, port: int, banner: bytes) -> Identified:
    """Banner 220 sem pistas: ``EHLO`` responde 250 no SMTP e erro no FTP."""
    conn = Connection.open(host, port, connect_timeout(ctx), io_timeout(ctx))
    text = banner.decode("latin-1")
    if conn is not None:
        with conn:
            conn.read_some(limit=4096, idle=0.3)
            if conn.send(b"EHLO eigan.invalid\r\n"):
                reply = conn.read_some(limit=4096, idle=0.3).decode("latin-1")
                conn.send(b"QUIT\r\n")
                fake_port = 25 if reply.startswith("250") else 21
                return classify_220(text, fake_port)
    return classify_220(text, 21)


def identify(ctx: CheckContext, host: str, port: int) -> Identified:
    """Melhor identificação possível do serviço em ``host:port``."""
    tried: set[str] = set()
    for name in PORT_HINTS.get(port, ()):
        ctx.check_cancel()
        tried.add(name)
        found = PROBES[name](ctx, host, port)
        if found is not None:
            return found
    banner = grab_banner(ctx, host, port)
    if banner:
        found = classify_banner(banner, port)
        if found is not None and found.service == "ftp-ou-smtp":
            found = _disambiguate_220(ctx, host, port, banner)
        if found is not None:
            return found
    elif banner is None:
        return Identified(service_name(port) or "desconhecido", confirmed=False)
    if not banner:
        for name in _TLS_FIRST:
            if name in tried:
                continue
            ctx.check_cancel()
            found = PROBES[name](ctx, host, port)
            if found is not None:
                return found
    guess = service_name(port) or "desconhecido"
    return Identified(guess, banner=printable(banner or b""), confirmed=False)


def service_url(host: str, port: int, tls: bool) -> str:
    return base_url("https" if tls else "http", host, port)


__all__ = ["Identified", "identify", "service_url"]
