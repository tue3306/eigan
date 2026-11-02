"""Servidores falsos e respostas prontas para os testes de rede (127.0.0.1, sem Internet).

``fake_tcp`` sobe um servidor TCP (ou TLS) que cumprimenta ao abrir a conexão e responde
cada pedido com uma função; os bytes recebidos ficam em ``received``. O restante são
construtores das respostas binárias de cada protocolo (RDP, SMB, TDS, AMQP, CQL...).
"""

from __future__ import annotations

import socket
import ssl
import struct
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from eigan.checks.net import mongo
from eigan.core.models import Fact
from eigan.core.settings import Settings

CERT_DIR = Path(__file__).parent / "fixtures" / "tls"

#: recebe o pedido e devolve os bytes da resposta (``None`` encerra a conexão)
Responder = Callable[[bytes], bytes | None]


class FakeTcp:
    """Servidor TCP de um cenário: uma thread por conexão, encerrado por ``stop``."""

    def __init__(
        self,
        respond: Responder | None = None,
        *,
        greeting: bytes = b"",
        tls: bool = False,
        hangup: bool = False,
    ) -> None:
        self.respond = respond
        self.greeting = greeting
        self.hangup = hangup
        self.received: list[bytes] = []
        self.connections = 0
        self._stop = threading.Event()
        self._context: ssl.SSLContext | None = None
        if tls:
            self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self._context.load_cert_chain(CERT_DIR / "localhost.crt", CERT_DIR / "localhost.key")
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(32)
        self._listener.settimeout(0.05)
        self.port: int = self._listener.getsockname()[1]
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            self.connections += 1
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(3.0)
            if self._context is not None:
                conn = self._context.wrap_socket(conn, server_side=True)
            if self.greeting:
                conn.sendall(self.greeting)
            if not self.hangup:
                self._dialog(conn)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _dialog(self, conn: socket.socket) -> None:
        conn.settimeout(0.05)
        while not self._stop.is_set():
            try:
                data = conn.recv(65536)
            except TimeoutError:
                continue
            if not data:
                return
            self.received.append(data)
            reply = self.respond(data) if self.respond is not None else b""
            if reply is None:
                return
            if reply:
                conn.sendall(reply)

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self._listener.close()


@contextmanager
def fake_tcp(
    respond: Responder | None = None,
    *,
    greeting: bytes = b"",
    tls: bool = False,
    hangup: bool = False,
) -> Iterator[FakeTcp]:
    """Servidor de um cenário. ``hangup`` encerra logo depois da saudação."""
    server = FakeTcp(respond, greeting=greeting, tls=tls, hangup=hangup)
    try:
        yield server
    finally:
        server.stop()


def line_replies(table: dict[str, bytes], default: bytes | None = None) -> Responder:
    """Responde linha a linha pelo começo do comando (sem diferenciar maiúsculas)."""

    def respond(data: bytes) -> bytes | None:
        out = b""
        for line in data.decode("latin-1").splitlines():
            for prefix, reply in table.items():
                if line.upper().startswith(prefix.upper()):
                    out += reply
                    break
            else:
                if default is None:
                    return None
                out += default
        return out

    return respond


def closing(reply: bytes) -> Responder:
    """Responde uma vez e encerra (o cliente não precisa esperar o tempo de silêncio)."""
    state = {"sent": False}

    def respond(_data: bytes) -> bytes | None:
        if state["sent"]:
            return None
        state["sent"] = True
        return reply

    return respond


def http_response(
    status: int = 200, body: str | bytes = "", headers: tuple[tuple[str, str], ...] = ()
) -> bytes:
    """Resposta HTTP/1.1 crua (permite controlar cabeçalhos como ``Server``)."""
    payload = body.encode("utf-8") if isinstance(body, str) else body
    lines = [f"HTTP/1.1 {status} Resposta", f"Content-Length: {len(payload)}", "Connection: close"]
    lines += [f"{name}: {value}" for name, value in headers]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + payload


def http_routes(routes: dict[str, bytes], default: bytes | None = None) -> Responder:
    """Responde pelo caminho (com a query, se a rota tiver). Sem rota: ``default`` ou 404."""
    fallback = default if default is not None else http_response(404, "404 page not found\n")

    def respond(data: bytes) -> bytes | None:
        parts = data.split(b" ", 2)
        if len(parts) < 3:
            return None
        target = parts[1].decode("latin-1")
        return routes.get(target, routes.get(target.split("?", 1)[0], fallback))

    return respond


def fast_settings(**values: Any) -> Settings:
    """Configurações com tempos curtos para os testes."""
    values.setdefault("http_timeout", 5.0)
    values.setdefault("port_timeout", 0.5)
    return Settings(**values)


def service_fact(port: int, service: str, *, host: str = "127.0.0.1", **data: Any) -> Fact:
    """Fato ``service`` igual ao que ``net.services`` produz."""
    payload: dict[str, Any] = {
        "host": host,
        "port": port,
        "service": service,
        "product": "",
        "version": "",
        "banner": "",
        "tls": False,
        "confirmed": True,
        "extra": {},
        "label": f"{host}:{port}",
    }
    payload.update(data)
    return Fact("service", f"{host}:{port}", payload)


# -- RDP ---------------------------------------------------------------------------------
def rdp_confirm(kind: int | None = None, value: int = 0) -> bytes:
    """X.224 Connection Confirm. ``kind``: 2 = RDP_NEG_RSP, 3 = RDP_NEG_FAILURE, None = sem bloco."""
    tail = b"" if kind is None else struct.pack("<BBHI", kind, 0, 8, value)
    tpdu = b"\xd0" + b"\x00\x00" + b"\x12\x34" + b"\x00" + tail
    body = bytes([len(tpdu)]) + tpdu
    return struct.pack(">BBH", 3, 0, 4 + len(body)) + body


def rdp_requested(request: bytes) -> int:
    """``requestedProtocols`` de um X.224 Connection Request (últimos 4 bytes do RDP_NEG_REQ)."""
    return int.from_bytes(request[-4:], "little")


# -- SMB ---------------------------------------------------------------------------------
def _netbios(payload: bytes) -> bytes:
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


def smb1_response(
    *, dialect_index: int = 0, security_mode: int = 0x03, word_count: int = 0x11, status: int = 0
) -> bytes:
    """Resposta ao SMB_COM_NEGOTIATE (cabeçalho de 32 bytes + parâmetros)."""
    header = (
        b"\xffSMB\x72"
        + struct.pack("<I", status)
        + b"\x88"
        + struct.pack("<H", 0xC001)
        + b"\x00" * 12
        + b"\x00\x00"
        + b"\xfe\xff"
        + b"\x00\x00\x00\x00"
    )
    if word_count == 0x11:
        words = struct.pack("<H", dialect_index) + bytes([security_mode]) + b"\x00" * 31
    else:
        words = struct.pack("<H", dialect_index)
    return _netbios(header + bytes([word_count]) + words + b"\x00\x00")


def smb2_response(*, dialect: int = 0x0302, security_mode: int = 0x01, status: int = 0) -> bytes:
    """Resposta ao NEGOTIATE do SMB2 (cabeçalho de 64 bytes + corpo)."""
    header = b"\xfeSMB" + struct.pack("<HHI", 64, 0, status) + struct.pack("<HH", 0, 1)
    header += b"\x00" * (64 - len(header))
    body = struct.pack("<HHH", 65, security_mode, dialect) + b"\x00" * 58
    return _netbios(header + body)


# -- MySQL, SQL Server, AMQP, Cassandra, Oracle --------------------------------------------
def mysql_greeting(version: str = "8.0.35") -> bytes:
    """Pacote inicial do protocolo 10: tamanho (3 bytes), sequência 0, 0x0a e a versão."""
    body = b"\x0a" + version.encode("ascii") + b"\x00" + struct.pack("<I", 7) + b"abcdefgh\x00"
    return len(body).to_bytes(3, "little") + b"\x00" + body


def mysql_error(code: int = 1130, message: str = "Host is not allowed to connect") -> bytes:
    body = b"\xff" + struct.pack("<H", code) + message.encode("utf-8")
    return len(body).to_bytes(3, "little") + b"\x00" + body


def tds_prelogin_response(major: int = 15, minor: int = 0, build: int = 2000) -> bytes:
    """Resposta TDS (tipo 0x04) com os tokens VERSION e ENCRYPTION."""
    options = (
        (0x00, bytes([major, minor]) + build.to_bytes(2, "big") + b"\x00\x00"),
        (0x01, b"\x02"),
    )
    offset = 5 * len(options) + 1
    table, values = b"", b""
    for token, value in options:
        table += struct.pack(">BHH", token, offset, len(value))
        values += value
        offset += len(value)
    payload = table + b"\xff" + values
    return struct.pack(">BBHHBB", 0x04, 0x01, 8 + len(payload), 0, 1, 0) + payload


def amqp_start(product: str = "RabbitMQ", version: str = "3.12.13") -> bytes:
    """Frame ``Connection.Start`` com uma tabela de propriedades do servidor."""

    def text(name: str, value: str) -> bytes:
        raw = value.encode("utf-8")
        return bytes([len(name)]) + name.encode("ascii") + b"S" + struct.pack(">I", len(raw)) + raw

    nested = b"\x0bdirect_replyt\x01"
    table = (
        bytes([12])
        + b"capabilities"
        + b"F"
        + struct.pack(">I", len(nested))
        + nested
        + b"\x06secureT"
        + b"\x00" * 8
        + text("product", product)
        + text("version", version)
    )
    payload = struct.pack(">HH", 10, 10) + b"\x00\x09" + struct.pack(">I", len(table)) + table
    payload += struct.pack(">I", 5) + b"PLAIN" + struct.pack(">I", 5) + b"en_US"
    return b"\x01\x00\x00" + struct.pack(">I", len(payload)) + payload + b"\xce"


def cql_frame(opcode: int, body: bytes = b"", version: int = 4) -> bytes:
    """Resposta do protocolo nativo do Cassandra (bit de resposta ligado)."""
    return struct.pack(">BBHBI", 0x80 | version, 0, 0, opcode, len(body)) + body


def cql_supported() -> bytes:
    """SUPPORTED: multimapa de strings com ``CQL_VERSION``."""

    def short(text: str) -> bytes:
        raw = text.encode("ascii")
        return struct.pack(">H", len(raw)) + raw

    body = struct.pack(">H", 1) + short("CQL_VERSION") + struct.pack(">H", 1) + short("3.4.5")
    return cql_frame(0x06, body)


def tns_refuse(text: str) -> bytes:
    """Pacote TNS REFUSE (tipo 4) com o texto do listener."""
    data = text.encode("ascii")
    return (
        struct.pack(">HHBBH", 12 + len(data), 0, 4, 0, 0)
        + b"\x01\x01"
        + struct.pack(">H", len(data))
        + data
    )


# -- MongoDB -------------------------------------------------------------------------------
def mongo_msg(document: dict[str, Any], response_to: int = 1) -> bytes:
    """Resposta OP_MSG com uma seção do tipo 0."""
    body = struct.pack("<I", 0) + b"\x00" + mongo.encode(document)
    return struct.pack("<iiii", 16 + len(body), 99, response_to, mongo.OP_MSG) + body


def mongo_reply(document: dict[str, Any], response_to: int = 1) -> bytes:
    """Resposta OP_REPLY (servidores anteriores ao 3.6)."""
    body = struct.pack("<iqii", 8, 0, 0, 1) + mongo.encode(document)
    return struct.pack("<iiii", 16 + len(body), 99, response_to, mongo.OP_REPLY) + body


def mongo_command(request: bytes) -> dict[str, Any]:
    """Documento de comando de um pedido OP_MSG ou OP_QUERY."""
    opcode = struct.unpack_from("<i", request, 12)[0]
    if opcode == mongo.OP_MSG:
        return mongo.decode(request, 21)[0]
    name_end = request.index(b"\x00", 20)
    return mongo.decode(request, name_end + 1 + 8)[0]
