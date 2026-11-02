"""Utilitários de rede (stdlib): resolução, classificação de endereço e sockets."""

from __future__ import annotations

import ipaddress
import socket
from functools import lru_cache

from .models import Exposure

#: endereços de metadados de nuvem — nunca lidos por redirecionamento
METADATA_HOSTS = frozenset(
    {"169.254.169.254", "fd00:ec2::254", "100.100.100.200", "metadata.google.internal"}
)


@lru_cache(maxsize=2048)
def resolve(host: str) -> tuple[str, ...]:
    """IPs do host (IPv4 primeiro). Vazio se não resolver."""
    host = host.strip("[]")
    try:
        ipaddress.ip_address(host)
        return (host,)
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        return ()
    seen: list[str] = []
    for _family, _t, _p, _c, sockaddr in infos:
        ip = str(sockaddr[0])
        if ip not in seen:
            seen.append(ip)
    seen.sort(key=lambda ip: 0 if "." in ip else 1)
    return tuple(seen)


def ip_exposure(ip: str) -> Exposure:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return Exposure.INTERNET
    if addr.is_loopback:
        return Exposure.LOCAL
    if addr.is_private or addr.is_link_local or addr.is_reserved or addr.is_unspecified:
        return Exposure.INTERNAL
    # 100.64.0.0/10 (CGNAT) não é "private" no ipaddress, mas não é Internet pública
    if isinstance(addr, ipaddress.IPv4Address) and addr in ipaddress.ip_network("100.64.0.0/10"):
        return Exposure.INTERNAL
    return Exposure.INTERNET


def host_exposure(host: str) -> Exposure:
    """Exposição de um host pelo primeiro IP resolvido (Internet se não resolver)."""
    ips = resolve(host)
    if not ips:
        if host.endswith((".local", ".lan", ".internal", ".corp", ".home")):
            return Exposure.INTERNAL
        return Exposure.INTERNET
    return ip_exposure(ips[0])


def is_metadata_address(host: str) -> bool:
    if host.strip("[]").lower() in METADATA_HOSTS:
        return True
    return any(ip in METADATA_HOSTS for ip in resolve(host))


def tcp_connect(host: str, port: int, timeout: float) -> socket.socket | None:
    """Abre uma conexão TCP ou devolve None (fechada/filtrada/sem rota)."""
    try:
        return socket.create_connection((host, port), timeout=timeout)
    except (OSError, ValueError):
        return None


def port_open(host: str, port: int, timeout: float) -> bool:
    sock = tcp_connect(host, port, timeout)
    if sock is None:
        return False
    try:
        sock.close()
    except OSError:
        pass
    return True


def recv_some(
    sock: socket.socket, limit: int = 4096, timeout: float = 3.0, idle: float = 0.4
) -> bytes:
    """Lê até ``limit`` bytes (nunca levanta).

    Espera até ``timeout`` pelo primeiro pedaço; depois disso, para assim que a
    conexão fica ``idle`` segundos em silêncio — serve para banners de texto e
    para protocolos binários sem esperar o tempo todo.
    """
    chunks: list[bytes] = []
    total = 0
    try:
        sock.settimeout(timeout)
        while total < limit:
            chunk = sock.recv(min(8192, limit - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            sock.settimeout(idle)
    except (TimeoutError, OSError):
        pass
    return b"".join(chunks)


def exchange(
    host: str, port: int, payload: bytes | None, *, timeout: float = 4.0, limit: int = 8192
) -> bytes | None:
    """Conecta, envia ``payload`` (opcional) e devolve a resposta. None se não conectar."""
    sock = tcp_connect(host, port, timeout)
    if sock is None:
        return None
    try:
        if payload:
            sock.sendall(payload)
        return recv_some(sock, limit=limit, timeout=timeout)
    except OSError:
        return b""
    finally:
        try:
            sock.close()
        except OSError:
            pass
