"""Handshake "cru": ClientHello montado à mão e leitura da primeira resposta do servidor.

Serve para descobrir se o servidor ACEITA versões e cifras antigas — algo que o módulo
``ssl`` (OpenSSL 3) muitas vezes nem consegue oferecer. A sonda envia um ClientHello
comum, lê o ServerHello (ou o alerta) e fecha a conexão: o handshake nunca é concluído
e nada além do que um cliente legítimo enviaria sai daqui.

Formatos conferidos nas RFCs 5246 (TLS 1.2), 8446 (TLS 1.3), 6066 (SNI), 5746
(renegociação), 7685 (padding) e no rascunho do SSL 2.0 (draft-hickman-netscape-ssl-00).
O ``TLS_FALLBACK_SCSV`` (RFC 7507) nunca é enviado: com ele, um servidor moderno
recusaria a versão antiga de propósito e a sonda daria falso negativo.
"""

from __future__ import annotations

import hashlib
import os
import struct
import time
from dataclasses import dataclass, field

from ...core import netutil
from .suites import SSL2, SSL3, TLS10, TLS12, TLS13

CONTENT_ALERT = 21
CONTENT_HANDSHAKE = 22
_RECORD_TYPES = frozenset({20, 21, 22, 23})
HS_CLIENT_HELLO = 1
HS_SERVER_HELLO = 2
HS_CERTIFICATE = 11

EXT_SERVER_NAME = 0
EXT_SUPPORTED_GROUPS = 10
EXT_EC_POINT_FORMATS = 11
EXT_SIGNATURE_ALGORITHMS = 13
EXT_PADDING = 21
EXT_SUPPORTED_VERSIONS = 43
EXT_PSK_KEY_EXCHANGE_MODES = 45
EXT_KEY_SHARE = 51
EXT_RENEGOTIATION_INFO = 0xFF01

#: x25519, secp256r1, secp384r1, secp521r1 (RFC 8446, 4.2.7)
GROUPS = (0x001D, 0x0017, 0x0018, 0x0019)
X25519 = 0x001D
#: ECDSA, RSA-PSS, Ed25519, RSA PKCS#1 e, por último, as legadas com SHA-1 (RFC 8446, 4.2.3)
SIGNATURE_SCHEMES = (
    0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0807, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
)  # fmt: skip
#: Random especial do HelloRetryRequest: SHA-256 de "HelloRetryRequest" (RFC 8446, 4.1.3)
HRR_RANDOM = hashlib.sha256(b"HelloRetryRequest").digest()

#: descrição dos alertas (RFC 5246, 7.2 e RFC 8446, 6)
ALERTS = {
    0: "close_notify",
    10: "unexpected_message",
    20: "bad_record_mac",
    22: "record_overflow",
    40: "handshake_failure",
    42: "bad_certificate",
    47: "illegal_parameter",
    48: "unknown_ca",
    49: "access_denied",
    50: "decode_error",
    51: "decrypt_error",
    70: "protocol_version",
    71: "insufficient_security",
    80: "internal_error",
    86: "inappropriate_fallback",
    90: "user_canceled",
    109: "missing_extension",
    110: "unsupported_extension",
    112: "unrecognized_name",
    116: "certificate_required",
    120: "no_application_protocol",
}
ALERT_UNRECOGNIZED_NAME = 112

#: SSL 2.0: tipos de mensagem e as 7 especificações de cifra do rascunho original
SSL2_MSG_ERROR = 0
SSL2_MSG_CLIENT_HELLO = 1
SSL2_MSG_SERVER_HELLO = 4
SSL2_CIPHER_SPECS = bytes.fromhex("010080020080030080040080050080060040" + "0700C0")

MAX_REPLY = 32 * 1024
_MAX_RECORD = 18432  # 2^14 + 2048 (RFC 5246, 6.2.3)

# Tipos de resposta
SERVER_HELLO = "server_hello"
ALERT = "alerta"
SSL2_SERVER_HELLO = "sslv2"
CLOSED = "fechado"
NO_REPLY = "sem_resposta"
NO_CONNECTION = "sem_conexao"
INVALID = "invalido"


class WireError(ValueError):
    """Mensagem de handshake mal formada."""


@dataclass(frozen=True)
class ServerHello:
    version: int  # legacy_version do ServerHello
    selected: int  # versão negociada (supported_versions no TLS 1.3)
    suite: int
    compression: int
    extensions: dict[int, bytes] = field(default_factory=dict)
    retry: bool = False  # HelloRetryRequest (TLS 1.3)


@dataclass(frozen=True)
class Reply:
    kind: str
    hello: ServerHello | None = None
    alert: int | None = None
    sslv2_ciphers: int = 0
    detail: str = ""


# -- montagem do ClientHello ------------------------------------------------------------
def _u16(value: int) -> bytes:
    return struct.pack("!H", value)


def _vec8(data: bytes) -> bytes:
    return bytes([len(data)]) + data


def _vec16(data: bytes) -> bytes:
    return _u16(len(data)) + data


def _ext(kind: int, data: bytes) -> bytes:
    return _u16(kind) + _vec16(data)


def _list16(values: tuple[int, ...] | list[int]) -> bytes:
    return b"".join(_u16(value) for value in values)


def _server_name(host: str) -> bytes:
    """Extensão SNI (RFC 6066). Nome impossível de codificar: segue sem SNI."""
    try:
        name = host.encode("idna")
    except UnicodeError:
        return b""
    return _ext(EXT_SERVER_NAME, _vec16(b"\x00" + _vec16(name)))


def _extensions(version: int, sni: str | None, tls13: bool) -> bytes:
    exts = _server_name(sni) if sni else b""
    if tls13:
        exts += _ext(EXT_SUPPORTED_VERSIONS, _vec8(_u16(TLS13)))
        exts += _ext(EXT_KEY_SHARE, _vec16(_u16(X25519) + _vec16(os.urandom(32))))
        exts += _ext(EXT_PSK_KEY_EXCHANGE_MODES, _vec8(b"\x01"))  # psk_dhe_ke
    exts += _ext(EXT_SUPPORTED_GROUPS, _vec16(_list16(GROUPS)))
    exts += _ext(EXT_EC_POINT_FORMATS, _vec8(b"\x00"))  # uncompressed
    if tls13 or version >= TLS12:  # RFC 5246, 7.4.1.4.1: não oferecer antes do TLS 1.2
        exts += _ext(EXT_SIGNATURE_ALGORITHMS, _vec16(_list16(SIGNATURE_SCHEMES)))
    exts += _ext(EXT_RENEGOTIATION_INFO, _vec8(b""))
    return exts


def _with_padding(base_len: int, exts: bytes) -> bytes:
    """Evita ClientHello de 256 a 511 bytes, que trava algumas implementações (RFC 7685)."""
    total = 4 + base_len + 2 + len(exts)
    if 0xFF < total < 0x200:
        pad = max(1, 0x200 - total - 4)
        exts += _ext(EXT_PADDING, b"\x00" * pad)
    return exts


def client_hello(
    version: int, cipher_suites: tuple[int, ...] | list[int], sni: str | None
) -> bytes:
    """Registro com um ClientHello de ``version`` (SSLv3 até TLS 1.3) oferecendo as suítes dadas."""
    tls13 = version == TLS13
    session_id = os.urandom(32) if tls13 else b""  # modo de compatibilidade (RFC 8446, D.4)
    body = _u16(TLS12 if tls13 else version) + os.urandom(32) + _vec8(session_id)
    body += _vec16(_list16(cipher_suites))
    body += _vec8(b"\x00")  # compressão: só "null"
    if version >= TLS10:  # o SSLv3 não tem extensões
        body += _vec16(_with_padding(len(body), _extensions(version, sni, tls13)))
    message = bytes([HS_CLIENT_HELLO]) + len(body).to_bytes(3, "big") + body
    record_version = SSL3 if version == SSL3 else TLS10  # máxima compatibilidade no registro
    return struct.pack("!BHH", CONTENT_HANDSHAKE, record_version, len(message)) + message


def sslv2_client_hello() -> bytes:
    """CLIENT-HELLO do SSL 2.0 com cabeçalho de 2 bytes e as 7 cifras do protocolo."""
    body = bytes([SSL2_MSG_CLIENT_HELLO]) + struct.pack(
        "!HHHH", SSL2, len(SSL2_CIPHER_SPECS), 0, 16
    )
    body += SSL2_CIPHER_SPECS + os.urandom(16)
    return _u16(0x8000 | len(body)) + body


# -- leitura da resposta ----------------------------------------------------------------
def parse_server_hello(body: bytes) -> ServerHello:
    """Corpo de um ServerHello (sem o cabeçalho de 4 bytes do handshake)."""
    if len(body) < 38:
        raise WireError("ServerHello curto demais")
    version = int.from_bytes(body[0:2], "big")
    random = body[2:34]
    pos = 35 + body[34]
    if pos + 3 > len(body):
        raise WireError("ServerHello truncado")
    suite = int.from_bytes(body[pos : pos + 2], "big")
    compression = body[pos + 2]
    pos += 3
    extensions: dict[int, bytes] = {}
    if pos + 2 <= len(body):
        end = pos + 2 + int.from_bytes(body[pos : pos + 2], "big")
        if end > len(body):
            raise WireError("extensões do ServerHello truncadas")
        pos += 2
        while pos + 4 <= end:
            kind = int.from_bytes(body[pos : pos + 2], "big")
            size = int.from_bytes(body[pos + 2 : pos + 4], "big")
            if pos + 4 + size > end:
                raise WireError("extensão do ServerHello truncada")
            extensions[kind] = body[pos + 4 : pos + 4 + size]
            pos += 4 + size
    selected = version
    chosen = extensions.get(EXT_SUPPORTED_VERSIONS)
    if chosen is not None and len(chosen) == 2:
        selected = int.from_bytes(chosen, "big")
    return ServerHello(version, selected, suite, compression, extensions, random == HRR_RANDOM)


def parse_tls_reply(buffer: bytes) -> Reply | None:
    """Interpreta os registros recebidos; ``None`` quando ainda faltam bytes."""
    handshake = b""
    pos = 0
    while pos + 5 <= len(buffer):
        kind = buffer[pos]
        length = int.from_bytes(buffer[pos + 3 : pos + 5], "big")
        if kind not in _RECORD_TYPES or buffer[pos + 1] != 3 or length > _MAX_RECORD:
            return Reply(INVALID, detail="a resposta não é um registro TLS")
        if pos + 5 + length > len(buffer):
            return None
        fragment = buffer[pos + 5 : pos + 5 + length]
        pos += 5 + length
        if kind == CONTENT_ALERT:
            if len(fragment) < 2:
                return Reply(INVALID, detail="alerta TLS truncado")
            level, description = fragment[0], fragment[1]
            if level == 1 and description != 0:
                continue  # aviso (não fatal): o ServerHello pode vir a seguir
            return Reply(ALERT, alert=description, detail=alert_text(description))
        if kind != CONTENT_HANDSHAKE:
            return Reply(INVALID, detail=f"registro tipo {kind} antes do ServerHello")
        handshake += fragment
        if len(handshake) < 4:
            continue
        if handshake[0] != HS_SERVER_HELLO:
            return Reply(
                INVALID, detail=f"mensagem de handshake {handshake[0]} no lugar do ServerHello"
            )
        size = int.from_bytes(handshake[1:4], "big")
        if len(handshake) >= 4 + size:
            try:
                hello = parse_server_hello(handshake[4 : 4 + size])
            except WireError as exc:
                return Reply(INVALID, detail=str(exc))
            return Reply(SERVER_HELLO, hello=hello)
    return None


def parse_sslv2_reply(buffer: bytes) -> Reply | None:
    """Resposta a um CLIENT-HELLO do SSL 2.0; ``None`` quando ainda faltam bytes."""
    if len(buffer) < 2:
        return None
    if not buffer[0] & 0x80:
        if buffer[0] == CONTENT_ALERT:
            return Reply(ALERT, detail="o servidor respondeu com um alerta TLS")
        return Reply(INVALID, detail="a resposta não é SSL 2.0")
    length = ((buffer[0] & 0x7F) << 8) | buffer[1]
    if len(buffer) < 2 + length:
        return None
    message = buffer[2 : 2 + length]
    if len(message) >= 11 and message[0] == SSL2_MSG_SERVER_HELLO:
        version = int.from_bytes(message[3:5], "big")
        if version == SSL2:
            ciphers = int.from_bytes(message[7:9], "big") // 3
            return Reply(SSL2_SERVER_HELLO, sslv2_ciphers=ciphers, detail="SERVER-HELLO SSL 2.0")
    if message[:1] == bytes([SSL2_MSG_ERROR]):
        return Reply(ALERT, detail="MSG-ERROR do SSL 2.0")
    return Reply(INVALID, detail="mensagem SSL 2.0 inesperada")


def handshake_messages(buffer: bytes) -> list[tuple[int, bytes]] | None:
    """Mensagens de handshake completas dos registros recebidos.

    ``None`` quando a conversa não serve (alerta, outro tipo de registro); as mensagens
    incompletas do fim do buffer ficam de fora até o resto chegar.
    """
    stream = b""
    pos = 0
    while pos + 5 <= len(buffer):
        kind = buffer[pos]
        length = int.from_bytes(buffer[pos + 3 : pos + 5], "big")
        if kind != CONTENT_HANDSHAKE or buffer[pos + 1] != 3 or length > _MAX_RECORD:
            return None
        stream += buffer[pos + 5 : pos + 5 + length]
        pos += 5 + length
    messages: list[tuple[int, bytes]] = []
    pos = 0
    while pos + 4 <= len(stream):
        size = int.from_bytes(stream[pos + 1 : pos + 4], "big")
        if pos + 4 + size > len(stream):
            break
        messages.append((stream[pos], stream[pos + 4 : pos + 4 + size]))
        pos += 4 + size
    return messages


def parse_certificates(body: bytes) -> list[bytes]:
    """Corpo da mensagem Certificate do TLS 1.2 e anteriores: DER de cada certificado."""
    if len(body) < 3:
        raise WireError("mensagem Certificate curta demais")
    total = int.from_bytes(body[:3], "big")
    if 3 + total > len(body):
        raise WireError("mensagem Certificate truncada")
    chain: list[bytes] = []
    pos = 3
    while pos + 3 <= 3 + total:
        size = int.from_bytes(body[pos : pos + 3], "big")
        pos += 3
        if pos + size > 3 + total:
            raise WireError("certificado truncado")
        chain.append(body[pos : pos + size])
        pos += size
    return chain


def alert_text(description: int) -> str:
    return f"alerta {ALERTS.get(description, str(description))}"


# -- conversa com o servidor ------------------------------------------------------------
def exchange(host: str, port: int, payload: bytes, timeout: float, *, sslv2: bool = False) -> Reply:
    """Conecta, envia ``payload`` e lê até ter o ServerHello, um alerta ou o fim da conexão."""
    sock = netutil.tcp_connect(host, port, timeout)
    if sock is None:
        return Reply(NO_CONNECTION, detail="não foi possível conectar")
    parse = parse_sslv2_reply if sslv2 else parse_tls_reply
    deadline = time.monotonic() + timeout
    buffer = b""
    try:
        sock.sendall(payload)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return Reply(NO_REPLY, detail=f"sem resposta em {timeout:.0f} s")
            sock.settimeout(remaining)
            chunk = sock.recv(8192)
            if not chunk:
                return Reply(CLOSED, detail="conexão encerrada pelo servidor")
            buffer += chunk
            reply = parse(buffer)
            if reply is not None:
                return reply
            if len(buffer) > MAX_REPLY:
                return Reply(INVALID, detail="resposta grande demais sem ServerHello")
    except TimeoutError:
        return Reply(NO_REPLY, detail=f"sem resposta em {timeout:.0f} s")
    except OSError:
        return Reply(CLOSED, detail="conexão reiniciada pelo servidor")
    finally:
        try:
            sock.close()
        except OSError:
            pass


def read_certificates(
    host: str, port: int, payload: bytes, timeout: float, *, limit: int = 256 * 1024
) -> list[bytes]:
    """Lê a cadeia que o servidor entrega no handshake cru (vazio se não conseguir).

    No TLS 1.2 e anteriores o certificado trafega em texto claro logo depois do
    ServerHello: a conexão é fechada ali, sem concluir o handshake.
    """
    sock = netutil.tcp_connect(host, port, timeout)
    if sock is None:
        return []
    deadline = time.monotonic() + timeout
    buffer = b""
    try:
        sock.sendall(payload)
        while len(buffer) < limit:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return []
            sock.settimeout(remaining)
            chunk = sock.recv(16384)
            if not chunk:
                return []
            buffer += chunk
            messages = handshake_messages(buffer)
            if messages is None:
                return []
            for kind, body in messages:
                if kind == HS_CERTIFICATE:
                    return parse_certificates(body)
        return []
    except (OSError, WireError):
        return []
    finally:
        try:
            sock.close()
        except OSError:
            pass
