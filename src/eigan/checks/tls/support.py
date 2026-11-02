"""Versões de protocolo aceitas pelo servidor — sondadas uma vez e compartilhadas.

As checagens de protocolos e de cifras usam o mesmo mapa de versões; ``ctx.memo``
garante que as sondas rodem uma única vez por serviço em cada auditoria.

TLS 1.2 e 1.3 são testados primeiro com o módulo ``ssl`` (handshake completo e
real); se ele falhar, a sonda crua (``wire``) decide entre "recusado" e
"inconclusivo". As versões antigas só podem ser testadas pela sonda crua: o
OpenSSL 3 nem as oferece.
"""

from __future__ import annotations

import ssl
from collections.abc import Callable
from dataclasses import dataclass, field, replace

from ...core import netutil
from ...core.context import CheckContext
from ...core.http import insecure_context
from . import suites, wire
from .common import Endpoint, io_timeout
from .suites import SSL2, SSL3, TLS10, TLS11, TLS12, TLS13

ACCEPTED = "aceito"
REFUSED = "recusado"
INCONCLUSIVE = "inconclusivo"

#: ordem das sondas: das modernas para as antigas
PROBE_ORDER = (TLS12, TLS13, TLS11, TLS10, SSL3, SSL2)
#: versões obsoletas, da mais grave para a menos grave
LEGACY = (SSL2, SSL3, TLS10, TLS11)
#: versões em que as suítes de cifra do TLS 1.2 e anteriores fazem sentido
CIPHER_VERSIONS = (TLS12, TLS11, TLS10, SSL3)

#: sondas seguidas sem resposta antes de desistir do serviço
_MAX_SILENT = 2

_SSL_VERSIONS = {TLS12: "TLSv1_2", TLS13: "TLSv1_3"}


@dataclass(frozen=True)
class Probe:
    version: int
    state: str
    suite: int | None = None
    detail: str = ""
    reached: bool = True  # False = nem a conexão TCP abriu
    closed: bool = False  # recusa sem alerta TLS: conexão derrubada (pode ser limite de taxa)
    no_reply: bool = False  # o servidor aceitou a conexão e ficou calado

    @property
    def accepted(self) -> bool:
        return self.state == ACCEPTED

    @property
    def refused(self) -> bool:
        return self.state == REFUSED


@dataclass
class VersionMap:
    endpoint: Endpoint
    reachable: bool = True
    results: dict[int, Probe] = field(default_factory=dict)

    def probe(self, version: int) -> Probe | None:
        return self.results.get(version)

    def accepted(self, version: int) -> bool:
        probe = self.results.get(version)
        return probe is not None and probe.accepted

    def refused(self, version: int) -> bool:
        probe = self.results.get(version)
        return probe is not None and probe.refused

    def legacy_accepted(self) -> list[int]:
        return [v for v in LEGACY if self.accepted(v)]

    def cipher_versions(self) -> list[int]:
        """Versões aceitas em que as suítes clássicas valem (da mais nova para a mais antiga)."""
        return [v for v in CIPHER_VERSIONS if self.accepted(v)]

    def inconclusive(self) -> list[int]:
        return [v for v, p in self.results.items() if p.state == INCONCLUSIVE]


def suites_for(version: int) -> tuple[int, ...]:
    if version == TLS13:
        return suites.TLS13_PROBE
    if version == TLS12:
        return suites.TLS12_PROBE
    if version == SSL3:
        return suites.SSL3_PROBE
    return suites.LEGACY_PROBE


def interpret(reply: wire.Reply, version: int, offered: tuple[int, ...] | list[int]) -> Probe:
    """Traduz a resposta do servidor em aceito / recusado / inconclusivo."""
    if reply.kind == wire.SERVER_HELLO and reply.hello is not None:
        hello = reply.hello
        if hello.selected == version:
            if hello.suite in offered:
                kind = "HelloRetryRequest" if hello.retry else "ServerHello"
                return Probe(
                    version, ACCEPTED, hello.suite, f"{kind} com {suites.name(hello.suite)}"
                )
            return Probe(
                version,
                INCONCLUSIVE,
                detail=f"o servidor escolheu {suites.name(hello.suite)}, que não foi oferecida",
            )
        if SSL3 <= hello.selected < version:
            chosen = suites.version_name(hello.selected)
            return Probe(version, REFUSED, detail=f"o servidor respondeu com {chosen}")
        return Probe(
            version,
            INCONCLUSIVE,
            detail=f"versão inesperada no ServerHello (0x{hello.selected:04X})",
        )
    if reply.kind in (wire.ALERT, wire.CLOSED):
        return Probe(version, REFUSED, detail=reply.detail, closed=reply.kind == wire.CLOSED)
    return Probe(
        version,
        INCONCLUSIVE,
        detail=reply.detail,
        reached=reply.kind != wire.NO_CONNECTION,
        no_reply=reply.kind == wire.NO_REPLY,
    )


def raw_probe(
    endpoint: Endpoint, version: int, offered: tuple[int, ...] | list[int], timeout: float
) -> Probe:
    """ClientHello cru de ``version`` oferecendo só ``offered``."""
    sni = endpoint.sni
    reply = wire.exchange(
        endpoint.host, endpoint.port, wire.client_hello(version, offered, sni), timeout
    )
    if sni and reply.kind == wire.ALERT and reply.alert == wire.ALERT_UNRECOGNIZED_NAME:
        # o servidor não conhece o nome pedido: repete sem SNI (vale o site padrão)
        payload = wire.client_hello(version, offered, None)
        reply = wire.exchange(endpoint.host, endpoint.port, payload, timeout)
    return interpret(reply, version, offered)


def sslv2_probe(endpoint: Endpoint, timeout: float) -> Probe:
    reply = wire.exchange(
        endpoint.host, endpoint.port, wire.sslv2_client_hello(), timeout, sslv2=True
    )
    if reply.kind == wire.SSL2_SERVER_HELLO:
        if reply.sslv2_ciphers > 0:
            return Probe(
                SSL2, ACCEPTED, detail=f"SERVER-HELLO do SSL 2.0 com {reply.sslv2_ciphers} cifra(s)"
            )
        return Probe(SSL2, INCONCLUSIVE, detail="o servidor fala SSL 2.0, mas não ofereceu cifras")
    if reply.kind in (wire.ALERT, wire.CLOSED):
        return Probe(SSL2, REFUSED, detail=reply.detail, closed=reply.kind == wire.CLOSED)
    return Probe(
        SSL2,
        INCONCLUSIVE,
        detail=reply.detail,
        reached=reply.kind != wire.NO_CONNECTION,
        no_reply=reply.kind == wire.NO_REPLY,
    )


def ssl_probe(endpoint: Endpoint, version: int, timeout: float) -> Probe | None:
    """Handshake completo pelo módulo ``ssl``; None quando não deu para concluir."""
    name = _SSL_VERSIONS.get(version)
    if name is None or (version == TLS13 and not ssl.HAS_TLSv1_3):
        return None
    try:
        context = insecure_context()
        context.minimum_version = getattr(ssl.TLSVersion, name)
        context.maximum_version = getattr(ssl.TLSVersion, name)
    except (AttributeError, ValueError, ssl.SSLError):
        return None
    sock = netutil.tcp_connect(endpoint.host, endpoint.port, timeout)
    if sock is None:
        return Probe(version, INCONCLUSIVE, detail="não foi possível conectar", reached=False)
    try:
        sock.settimeout(timeout)
        with context.wrap_socket(sock, server_hostname=endpoint.sni) as tls:
            negotiated = tls.version() or ""
            cipher = tls.cipher()
        if negotiated.replace("v", " ").replace("_", ".") != suites.version_name(version):
            return None
        detail = f"handshake completo com {cipher[0]}" if cipher else "handshake completo"
        return Probe(version, ACCEPTED, detail=detail)
    except (ssl.SSLError, OSError, ValueError):
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


def probe_version(endpoint: Endpoint, version: int, timeout: float) -> Probe:
    if version == SSL2:
        return sslv2_probe(endpoint, timeout)
    if version in _SSL_VERSIONS:
        done = ssl_probe(endpoint, version, timeout)
        if done is not None:
            return done
    return raw_probe(endpoint, version, suites_for(version), timeout)


def probe_versions(
    endpoint: Endpoint, timeout: float, check_cancel: Callable[[], None]
) -> VersionMap:
    """Sonda as seis versões, das modernas para as antigas."""
    found = VersionMap(endpoint)
    silent = 0
    for version in PROBE_ORDER:
        check_cancel()
        probe = probe_version(endpoint, version, timeout)
        if not probe.reached and not found.results:
            found.reachable = False
            return found
        found.results[version] = probe
        silent = silent + 1 if probe.no_reply else 0
        if silent >= _MAX_SILENT:
            break  # porta que aceita a conexão e não responde: insistir só gasta tempo
    _control(found, timeout, check_cancel)
    return found


def _control(found: VersionMap, timeout: float, check_cancel: Callable[[], None]) -> None:
    """Confere se o servidor ainda atende: conexão derrubada não prova recusa da versão.

    Limite de taxa, WAF ou balanceador derrubam as conexões depois das primeiras sondas e
    isso se parece com "versão recusada". Repete uma versão já aceita; se ela não passar mais,
    as recusas sem alerta viram inconclusivas.
    """
    closed = [v for v, p in found.results.items() if p.closed]
    control = next((v for v in (TLS12, TLS13) if found.accepted(v)), None)
    if not closed or control is None:
        return
    check_cancel()
    if probe_version(found.endpoint, control, timeout).accepted:
        return
    for version in closed:
        found.results[version] = replace(
            found.results[version],
            state=INCONCLUSIVE,
            detail="conexão derrubada sem alerta e o servidor deixou de responder à sonda de controle",
        )


def version_map(ctx: CheckContext, endpoint: Endpoint) -> VersionMap:
    """Mapa de versões do serviço (uma vez por auditoria, compartilhado entre checagens)."""
    key = f"tls.versoes:{endpoint.host}:{endpoint.port}:{endpoint.sni or ''}"
    return ctx.memo(key, lambda: probe_versions(endpoint, io_timeout(ctx), ctx.check_cancel))
