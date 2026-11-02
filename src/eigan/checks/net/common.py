"""Apoio comum às checagens de rede: tempos limite, conexões, ativo e severidade.

Tudo aqui é pequeno e sem estado: conexão TCP com leitura bufferizada e prazo
(para conversar com protocolos binários sem travar), o formato padrão do ativo
(``host:porta/tcp``) e a escolha de severidade pela exposição do endereço —
o mesmo problema pesa mais na Internet do que na rede interna.
"""

from __future__ import annotations

import socket
import ssl
import threading
import time
from types import TracebackType

from ...core import netutil
from ...core.context import CheckContext
from ...core.http import insecure_context
from ...core.models import Exposure, Fact, Severity
from ...core.target import is_ip

EXPOSURE_TEXT = {
    Exposure.INTERNET: "acessível pela Internet",
    Exposure.INTERNAL: "acessível na rede interna",
    Exposure.LOCAL: "acessível nesta máquina",
}


def connect_timeout(ctx: CheckContext) -> float:
    """Tempo para abrir uma conexão TCP (configuração ``port_timeout``)."""
    return max(0.3, float(ctx.settings.port_timeout))


def io_timeout(ctx: CheckContext) -> float:
    """Tempo de espera por uma resposta de protocolo (banner, handshake, comando)."""
    return max(2.0, float(ctx.settings.port_timeout) * 2.5)


#: portas em que o servidor fala primeiro e pode demorar (postscreen, greet_pause)
GREETING_PORTS = frozenset({21, 25, 110, 143, 587, 2121, 2525})
GREETING_WAIT = 8.0


def greeting_timeout(ctx: CheckContext, port: int) -> float:
    """Espera pelo cumprimento inicial; maior em FTP/SMTP/POP3/IMAP (atrasam de propósito)."""
    base = io_timeout(ctx)
    return max(base, GREETING_WAIT) if port in GREETING_PORTS else base


def service_asset(host: str, port: int, proto: str = "tcp") -> str:
    """Ativo no formato padrão de serviço: ``host:porta/tcp`` (IPv6 entre colchetes)."""
    netloc = f"[{host}]" if ":" in host else host
    return f"{netloc}:{port}/{proto}"


def exposure_of(host: str) -> Exposure:
    """Exposição do endereço (Internet, rede interna ou esta máquina)."""
    return netutil.host_exposure(host)


def host_port(fact: Fact) -> tuple[str, int]:
    """Host e porta de um fato ``service``/``port.open``/``tls.service``."""
    host = str(fact.data.get("host") or fact.key.rsplit(":", 1)[0])
    try:
        port = int(fact.data.get("port") or 0)
    except (TypeError, ValueError):
        port = 0
    return host, port


def by_exposure(
    host: str,
    *,
    internet: Severity,
    internal: Severity,
    local: Severity | None = None,
) -> Severity:
    """Severidade conforme onde o endereço vive (Internet, rede interna ou esta máquina)."""
    exposure = exposure_of(host)
    if exposure is Exposure.INTERNET:
        return internet
    if exposure is Exposure.LOCAL:
        return local or internal
    return internal


def where(host: str) -> str:
    """Frase curta de exposição para evidências ("acessível pela Internet")."""
    return EXPOSURE_TEXT.get(exposure_of(host), "acessível pela rede")


def on_internet(host: str) -> bool:
    """O endereço é público (a exposição à Internet muda a severidade e alguns achados)."""
    return exposure_of(host) is Exposure.INTERNET


def port_gate(ctx: CheckContext) -> threading.BoundedSemaphore:
    """Semáforo da auditoria inteira: limita conexões simultâneas a ``port_workers``."""
    workers = max(1, int(ctx.settings.port_workers))
    return ctx.memo("net.port_gate", lambda: threading.BoundedSemaphore(workers))


def printable(data: bytes, limit: int = 300) -> str:
    """Texto legível de um banner (bytes de controle viram espaço)."""
    text = data[:limit].decode("utf-8", errors="replace")
    return "".join(ch if ch.isprintable() or ch in "\n\t" else " " for ch in text).strip()


class Connection:
    """Conexão TCP com leitura bufferizada e prazo. Leituras nunca levantam exceção."""

    def __init__(self, sock: socket.socket, timeout: float) -> None:
        self.sock = sock
        self.timeout = timeout
        self.buffer = b""
        self.closed = False

    @classmethod
    def open(cls, host: str, port: int, connect: float, timeout: float) -> Connection | None:
        sock = netutil.tcp_connect(host, port, connect)
        return cls(sock, timeout) if sock is not None else None

    def __enter__(self) -> Connection:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def send(self, data: bytes) -> bool:
        try:
            self.sock.settimeout(self.timeout)
            self.sock.sendall(data)
            return True
        except OSError:
            return False

    def _fill(self, deadline: float, limit: int = 65536) -> bool:
        """Lê mais um pedaço até o prazo. False em fim de conexão ou tempo esgotado."""
        if self.closed:
            return False
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        try:
            self.sock.settimeout(remaining)
            chunk = self.sock.recv(limit)
        except OSError:  # inclui o tempo esgotado (TimeoutError)
            return False
        if not chunk:
            self.closed = True
            return False
        self.buffer += chunk
        return True

    def read_exact(self, size: int, timeout: float | None = None) -> bytes:
        """Exatamente ``size`` bytes (ou menos, se a conexão fechar ou o prazo acabar)."""
        deadline = time.monotonic() + (timeout if timeout is not None else self.timeout)
        while len(self.buffer) < size and self._fill(deadline):
            pass
        data, self.buffer = self.buffer[:size], self.buffer[size:]
        return data

    def read_until(self, marker: bytes, limit: int = 8192, timeout: float | None = None) -> bytes:
        """Até ``marker`` (inclusive), no máximo ``limit`` bytes."""
        deadline = time.monotonic() + (timeout if timeout is not None else self.timeout)
        while marker not in self.buffer and len(self.buffer) < limit and self._fill(deadline):
            pass
        index = self.buffer.find(marker)
        cut = index + len(marker) if index >= 0 else min(len(self.buffer), limit)
        data, self.buffer = self.buffer[:cut], self.buffer[cut:]
        return data

    def read_some(
        self, limit: int = 8192, timeout: float | None = None, idle: float = 0.4
    ) -> bytes:
        """O que chegar: espera o primeiro pedaço até o prazo e para após ``idle`` de silêncio."""
        deadline = time.monotonic() + (timeout if timeout is not None else self.timeout)
        if not self.buffer and not self._fill(deadline):
            return b""
        while len(self.buffer) < limit and self._fill(min(deadline, time.monotonic() + idle)):
            pass
        data, self.buffer = self.buffer[:limit], self.buffer[limit:]
        return data


def talk(
    ctx: CheckContext,
    host: str,
    port: int,
    payload: bytes | None,
    *,
    limit: int = 8192,
    idle: float = 0.4,
) -> bytes | None:
    """Conecta, envia ``payload`` (opcional) e devolve a resposta. None se não conectar."""
    conn = Connection.open(host, port, connect_timeout(ctx), io_timeout(ctx))
    if conn is None:
        return None
    with conn:
        if payload and not conn.send(payload):
            return b""
        return conn.read_some(limit=limit, idle=idle)


def open_service(
    ctx: CheckContext, host: str, port: int, *, tls: bool = False
) -> Connection | None:
    """Conexão com o serviço; com ``tls``, faz antes o handshake (sem validar o certificado)."""
    sock = netutil.tcp_connect(host, port, connect_timeout(ctx))
    if sock is None:
        return None
    if not tls:
        return Connection(sock, greeting_timeout(ctx, port))
    try:
        sock.settimeout(io_timeout(ctx))
        wrapped = insecure_context().wrap_socket(
            sock, server_hostname=None if is_ip(host) else host
        )
    except (ssl.SSLError, OSError, ValueError):
        try:
            sock.close()
        except OSError:
            pass
        return None
    return Connection(wrapped, io_timeout(ctx))
