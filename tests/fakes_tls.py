"""Apoio dos testes de TLS: servidores locais e certificados montados à mão.

* :class:`FakeTlsServer` lê o ClientHello e responde bytes prontos (ServerHello ou alerta), sem
  criptografia nenhuma: é o que permite simular SSLv2, SSLv3, RC4 e EXPORT, que o OpenSSL local
  nem sabe mais falar.
* :class:`RealTlsServer` faz um handshake de verdade apresentando um certificado qualquer. Como
  o servidor só confere se a chave pública bate com a chave privada, um certificado montado à
  mão com a chave pública da fixture (assinatura falsa) funciona com a chave da fixture.
* As funções de DER montam certificados com as datas, nomes e algoritmos de cada cenário.
"""

from __future__ import annotations

import base64
import ipaddress
import socket
import ssl
import struct
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import TracebackType

from helpers import FIXTURES

from eigan.checks.tls import asn1
from eigan.core.models import Fact

FIXTURE_CERT = FIXTURES / "tls" / "localhost.crt"
FIXTURE_KEY = FIXTURES / "tls" / "localhost.key"

SSL2 = 0x0002
SSL3 = 0x0300
TLS10 = 0x0301
TLS11 = 0x0302
TLS12 = 0x0303
TLS13 = 0x0304

# Suítes usadas nos cenários (códigos da IANA)
RSA_RC4_SHA = 0x0005
RSA_RC4_MD5 = 0x0004
RSA_DES = 0x0009
RSA_3DES = 0x000A
RSA_NULL_SHA = 0x0002
RSA_EXPORT_RC4 = 0x0003
DHE_RSA_EXPORT_DES = 0x0014
DH_ANON_AES = 0x0034
RSA_AES128 = 0x002F
RSA_AES256 = 0x0035
RSA_AES128_GCM = 0x009C
ECDHE_RSA_AES128 = 0xC013
ECDHE_RSA_AES128_GCM = 0xC02F
DHE_RSA_AES128 = 0x0033
AES128_GCM_SHA256 = 0x1301
FALLBACK_SCSV = 0x5600

EXT_SERVER_NAME = 0
EXT_SIGNATURE_ALGORITHMS = 13
EXT_SUPPORTED_VERSIONS = 43
EXT_KEY_SHARE = 51
EXT_RENEGOTIATION_INFO = 0xFF01

ALERT_HANDSHAKE_FAILURE = 40
ALERT_PROTOCOL_VERSION = 70
ALERT_UNRECOGNIZED_NAME = 112


# -- ClientHello visto pelo servidor -----------------------------------------------------
@dataclass
class ClientHello:
    sslv2: bool
    record_version: int
    version: int
    suites: list[int]
    extensions: dict[int, bytes] = field(default_factory=dict)
    size: int = 0
    session_id: bytes = b""

    @property
    def sni(self) -> str | None:
        data = self.extensions.get(EXT_SERVER_NAME)
        return data[5:].decode("ascii") if data else None

    @property
    def supported_versions(self) -> list[int]:
        data = self.extensions.get(EXT_SUPPORTED_VERSIONS)
        if not data:
            return []
        return [int.from_bytes(data[i : i + 2], "big") for i in range(1, len(data), 2)]


def parse_client_hello(record: bytes) -> ClientHello:
    """Interpreta um registro completo com um ClientHello (TLS ou SSL 2.0)."""
    if record[0] & 0x80:
        kind, version, specs, session, challenge = struct.unpack("!BHHHH", record[2:11])
        assert kind == 1
        suites = [int.from_bytes(record[11 + i : 11 + i + 3], "big") for i in range(0, specs, 3)]
        assert len(record) == 11 + specs + session + challenge
        return ClientHello(True, SSL2, version, suites, size=len(record))
    assert record[0] == 22
    record_version = int.from_bytes(record[1:3], "big")
    message = record[5:]
    assert message[0] == 1
    body = message[4 : 4 + int.from_bytes(message[1:4], "big")]
    version = int.from_bytes(body[:2], "big")
    pos = 34
    session_id = body[pos + 1 : pos + 1 + body[pos]]
    pos += 1 + body[pos]
    size = int.from_bytes(body[pos : pos + 2], "big")
    suites = [int.from_bytes(body[pos + 2 + i : pos + 4 + i], "big") for i in range(0, size, 2)]
    pos += 2 + size
    pos += 1 + body[pos]  # métodos de compressão
    extensions: dict[int, bytes] = {}
    if pos + 2 <= len(body):
        end = pos + 2 + int.from_bytes(body[pos : pos + 2], "big")
        pos += 2
        while pos + 4 <= end:
            kind = int.from_bytes(body[pos : pos + 2], "big")
            length = int.from_bytes(body[pos + 2 : pos + 4], "big")
            extensions[kind] = body[pos + 4 : pos + 4 + length]
            pos += 4 + length
    return ClientHello(False, record_version, version, suites, extensions, len(record), session_id)


def _recv_exact(conn: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            return b""
        data += chunk
    return data


def _read_client_hello(conn: socket.socket) -> ClientHello | None:
    head = _recv_exact(conn, 2)
    if not head:
        return None
    if head[0] & 0x80:
        size = ((head[0] & 0x7F) << 8) | head[1]
        body = _recv_exact(conn, size)
        return parse_client_hello(head + body) if body else None
    rest = _recv_exact(conn, 3)
    if not rest:
        return None
    body = _recv_exact(conn, int.from_bytes(rest[1:3], "big"))
    return parse_client_hello(head + rest + body) if body else None


# -- bytes que o servidor responde -------------------------------------------------------
def record(kind: int, version: int, payload: bytes) -> bytes:
    return struct.pack("!BHH", kind, version, len(payload)) + payload


def handshake(kind: int, body: bytes) -> bytes:
    return bytes([kind]) + len(body).to_bytes(3, "big") + body


def server_hello_body(
    version: int,
    suite: int,
    *,
    extensions: dict[int, bytes] | None = None,
    random: bytes = b"\x42" * 32,
    session_id: bytes = b"",
    compression: int = 0,
) -> bytes:
    body = struct.pack("!H", version) + random + bytes([len(session_id)]) + session_id
    body += struct.pack("!HB", suite, compression)
    if extensions is not None:
        raw = b"".join(struct.pack("!HH", k, len(v)) + v for k, v in extensions.items())
        body += struct.pack("!H", len(raw)) + raw
    return body


def server_hello(version: int, suite: int, **options: object) -> bytes:
    """Registro com um ServerHello."""
    body = server_hello_body(version, suite, **options)  # type: ignore[arg-type]
    return record(22, min(version, TLS12), handshake(2, body))


def tls13_server_hello(suite: int = AES128_GCM_SHA256, **options: object) -> bytes:
    """ServerHello do TLS 1.3: versão real na extensão ``supported_versions``."""
    extensions = {EXT_SUPPORTED_VERSIONS: struct.pack("!H", TLS13)}
    body = server_hello_body(TLS12, suite, extensions=extensions, **options)  # type: ignore[arg-type]
    return record(22, TLS12, handshake(2, body))


def alert(description: int, *, level: int = 2, version: int = TLS12) -> bytes:
    return record(21, version, bytes([level, description]))


def certificate_message(chain: Iterable[bytes]) -> bytes:
    raw = b"".join(len(der).to_bytes(3, "big") + der for der in chain)
    return handshake(11, len(raw).to_bytes(3, "big") + raw)


def sslv2_server_hello(ciphers: int = 2, *, version: int = SSL2, kind: int = 4) -> bytes:
    specs = b"\x01\x00\x80" * ciphers
    body = struct.pack("!BBBHHHH", kind, 0, 1, version, 0, len(specs), 16) + specs + b"\x00" * 16
    return struct.pack("!H", 0x8000 | len(body)) + body


#: resposta especial: fica calado até o cliente desistir
SILENT = b"<silencio>"
Policy = Callable[[ClientHello], bytes | None]


@dataclass
class TlsProfile:
    """Servidor falso simples: versão -> suítes aceitas, em ordem de preferência."""

    versions: dict[int, tuple[int, ...]] = field(default_factory=dict)
    sslv2_ciphers: int = 0
    silent_versions: frozenset[int] = frozenset()
    chain: tuple[bytes, ...] = ()

    def __call__(self, hello: ClientHello) -> bytes | None:
        if hello.sslv2:
            return sslv2_server_hello(self.sslv2_ciphers) if self.sslv2_ciphers else None
        if TLS13 in hello.supported_versions and TLS13 in self.versions:
            return self._tls13(hello)
        requested = min(hello.version, TLS12)
        usable = [v for v in self.versions if v <= requested and v != TLS13]
        if requested in self.silent_versions:
            return SILENT
        if not usable:
            return alert(ALERT_PROTOCOL_VERSION, version=max(requested, TLS10))
        version = max(usable)
        for suite in self.versions[version]:
            if suite in hello.suites:
                reply = server_hello(version, suite)
                if self.chain:
                    reply += record(22, version, certificate_message(self.chain))
                return reply
        return alert(ALERT_HANDSHAKE_FAILURE, version=version)

    def _tls13(self, hello: ClientHello) -> bytes:
        for suite in self.versions[TLS13]:
            if suite in hello.suites:
                return tls13_server_hello(suite)
        return alert(ALERT_HANDSHAKE_FAILURE)


class _ThreadedServer:
    """Laço de accept em segundo plano, encerrado no fim do ``with``."""

    def __init__(self) -> None:
        self._stop = threading.Event()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(64)
        self._sock.settimeout(0.1)
        self.port: int = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def __enter__(self) -> _ThreadedServer:
        self._thread.start()
        return self

    def __exit__(
        self,
        kind: type[BaseException] | None,
        value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self._stop.set()
        self._thread.join(timeout=3)
        self._sock.close()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(target=self._guarded, args=(conn,), daemon=True).start()

    def _guarded(self, conn: socket.socket) -> None:
        try:
            with conn:
                conn.settimeout(5)
                self._handle(conn)
        except OSError:
            pass

    def _handle(self, conn: socket.socket) -> None:
        raise NotImplementedError


class FakeTlsServer(_ThreadedServer):
    """Lê o ClientHello, anota e responde o que a política mandar."""

    def __init__(self, policy: Policy) -> None:
        super().__init__()
        self.policy = policy
        self.hellos: list[ClientHello] = []

    def __enter__(self) -> FakeTlsServer:
        super().__enter__()
        return self

    def _handle(self, conn: socket.socket) -> None:
        hello = _read_client_hello(conn)
        if hello is None:
            return
        self.hellos.append(hello)
        reply = self.policy(hello)
        if reply == SILENT:
            conn.recv(1)  # espera o cliente desistir
        elif reply:
            conn.sendall(reply)
            conn.shutdown(socket.SHUT_WR)
            conn.settimeout(1)
            conn.recv(1)  # deixa o cliente fechar primeiro (evita RST antes de ele ler)


class RawReplyServer(_ThreadedServer):
    """Responde sempre os mesmos bytes (serviço que não fala TLS, por exemplo)."""

    def __init__(self, reply: bytes) -> None:
        super().__init__()
        self.reply = reply

    def __enter__(self) -> RawReplyServer:
        super().__enter__()
        return self

    def _handle(self, conn: socket.socket) -> None:
        conn.recv(4096)
        conn.sendall(self.reply)


class RealTlsServer(_ThreadedServer):
    """Handshake TLS de verdade apresentando os certificados pedidos (com a chave da fixture)."""

    def __init__(self, directory: Path, *chain: bytes, seclevel0: bool = False) -> None:
        super().__init__()
        path = directory / f"cadeia-{self.port}.pem"
        path.write_text("".join(to_pem(der) for der in chain), encoding="ascii")
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if seclevel0:
            self._context.set_ciphers("ALL:@SECLEVEL=0")
        self._context.load_cert_chain(path, FIXTURE_KEY)

    def __enter__(self) -> RealTlsServer:
        super().__enter__()
        return self

    def _handle(self, conn: socket.socket) -> None:
        try:
            with self._context.wrap_socket(conn, server_side=True) as tls:
                tls.recv(1)
        except ssl.SSLError:
            pass


def tls_fact(port: int, host: str = "127.0.0.1", sni: str | None = None, **extra: object) -> Fact:
    """Fato ``tls.service`` no formato produzido por ``ctx.add_tls_service``."""
    key = f"{host}:{port}"
    return Fact("tls.service", key, {"host": host, "port": port, "sni": sni, "label": key, **extra})


# -- DER ---------------------------------------------------------------------------------
OID_RSA = "1.2.840.113549.1.1.1"
OID_EC = "1.2.840.10045.2.1"
OID_DSA = "1.2.840.10040.4.1"
OID_ED25519 = "1.3.101.112"
OID_P224 = "1.3.132.0.33"
OID_P256 = "1.2.840.10045.3.1.7"
OID_P384 = "1.3.132.0.34"
OID_SHA256_RSA = "1.2.840.113549.1.1.11"
OID_SHA1_RSA = "1.2.840.113549.1.1.5"
OID_MD5_RSA = "1.2.840.113549.1.1.4"
OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"
OID_RSA_PSS = "1.2.840.113549.1.1.10"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_SHA1 = "1.3.14.3.2.26"
OID_CN = "2.5.4.3"
OID_O = "2.5.4.10"
OID_SAN = "2.5.29.17"
OID_BASIC = "2.5.29.19"
OID_SKI = "2.5.29.14"
OID_AKI = "2.5.29.35"
OID_AIA = "1.3.6.1.5.5.7.1.1"
OID_CA_ISSUERS = "1.3.6.1.5.5.7.48.2"
OID_OCSP = "1.3.6.1.5.5.7.48.1"


def der(tag: int, value: bytes) -> bytes:
    size = len(value)
    if size < 0x80:
        return bytes([tag, size]) + value
    raw = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(raw)]) + raw + value


def seq(*parts: bytes) -> bytes:
    return der(0x30, b"".join(parts))


def set_of(*parts: bytes) -> bytes:
    return der(0x31, b"".join(parts))


def integer(value: int) -> bytes:
    size = value.bit_length() // 8 + 1
    return der(0x02, value.to_bytes(size, "big", signed=True))


def oid(text: str) -> bytes:
    arcs = [int(arc) for arc in text.split(".")]
    out = bytearray()
    for arc in [arcs[0] * 40 + arcs[1], *arcs[2:]]:
        chunk = [arc & 0x7F]
        while arc := arc >> 7:
            chunk.append(0x80 | (arc & 0x7F))
        out += bytes(reversed(chunk))
    return der(0x06, bytes(out))


def utf8(text: str) -> bytes:
    return der(0x0C, text.encode("utf-8"))


def bit_string(value: bytes) -> bytes:
    return der(0x03, b"\x00" + value)


def octet(value: bytes) -> bytes:
    return der(0x04, value)


def explicit(number: int, value: bytes) -> bytes:
    return der(0xA0 | number, value)


def der_time(moment: datetime) -> bytes:
    """UTCTime até 2049 e GeneralizedTime depois, como manda a RFC 5280."""
    if moment.year < 2050:
        return der(0x17, moment.strftime("%y%m%d%H%M%SZ").encode("ascii"))
    return der(0x18, moment.strftime("%Y%m%d%H%M%SZ").encode("ascii"))


def name(cn: str | None = None, org: str | None = None) -> bytes:
    rdns = []
    if org is not None:
        rdns.append(set_of(seq(oid(OID_O), utf8(org))))
    if cn is not None:
        rdns.append(set_of(seq(oid(OID_CN), utf8(cn))))
    return seq(*rdns)


def rsa_spki(bits: int = 2048) -> bytes:
    modulus = (1 << (bits - 1)) | 1
    key = seq(integer(modulus), integer(65537))
    return seq(seq(oid(OID_RSA), der(0x05, b"")), bit_string(key))


def ec_spki(curve: str = OID_P256) -> bytes:
    return seq(seq(oid(OID_EC), oid(curve)), bit_string(b"\x04" + b"\x01" * 64))


def ed25519_spki() -> bytes:
    return seq(seq(oid(OID_ED25519)), bit_string(b"\x01" * 32))


def dsa_spki(bits: int = 1024) -> bytes:
    params = seq(integer((1 << (bits - 1)) | 1), integer(3), integer(2))
    return seq(seq(oid(OID_DSA), params), bit_string(integer(5)))


def fixture_der() -> bytes:
    return asn1.pem_certificates(FIXTURE_CERT.read_text(encoding="ascii"))[0]


def fixture_spki() -> bytes:
    """A chave pública da fixture: permite certificados falsos com a chave da fixture."""
    tbs = asn1.parse_one(fixture_der()).children()[0].children()
    return tbs[6].raw  # versão, serial, assinatura, emissor, validade, titular, chave


def sig_algorithm(algorithm: str = OID_SHA256_RSA) -> bytes:
    return seq(oid(algorithm), der(0x05, b""))


def pss_algorithm(digest: str | None = OID_SHA256) -> bytes:
    params = seq() if digest is None else seq(explicit(0, seq(oid(digest), der(0x05, b""))))
    return seq(oid(OID_RSA_PSS), params)


def build_cert(
    *,
    cn: str | None = "site.exemplo",
    org: str | None = None,
    issuer: bytes | None = None,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    days_left: float = 200,
    lifetime_days: float = 365,
    san_dns: Iterable[str] = ("site.exemplo",),
    san_ip: Iterable[str] = (),
    spki: bytes | None = None,
    signature: bytes | None = None,
    ca: bool = False,
    ski: bytes | None = None,
    aki: bytes | None = None,
    aia: Iterable[str] = (),
    extra_extensions: Iterable[bytes] = (),
    version3: bool = True,
) -> bytes:
    """Certificado DER com uma assinatura falsa (quem lê aqui não confere a assinatura)."""
    now = datetime.now(UTC).replace(microsecond=0)
    end = not_after or now + timedelta(days=days_left)
    start = not_before or end - timedelta(days=lifetime_days)
    algorithm = signature if signature is not None else sig_algorithm()
    subject = name(cn, org)
    fields = [
        integer(0x1234ABCD),
        algorithm,
        issuer if issuer is not None else name("CA Exemplo", "Autoridade Exemplo"),
        seq(der_time(start), der_time(end)),
        subject,
        spki if spki is not None else rsa_spki(),
    ]
    if version3:
        fields.insert(0, explicit(0, integer(2)))
        extensions = _extensions(san_dns, san_ip, ca, ski, aki, aia, extra_extensions)
        if extensions:
            fields.append(explicit(3, seq(*extensions)))
    return seq(seq(*fields), algorithm, bit_string(b"\x5a" * 256))


def _extensions(
    san_dns: Iterable[str],
    san_ip: Iterable[str],
    ca: bool,
    ski: bytes | None,
    aki: bytes | None,
    aia: Iterable[str],
    extra: Iterable[bytes],
) -> list[bytes]:
    found = list(extra)
    names = [der(0x82, value.encode("ascii")) for value in san_dns]
    names += [der(0x87, ipaddress.ip_address(value).packed) for value in san_ip]
    if names:
        found.append(extension(OID_SAN, seq(*names)))
    if ca:
        found.append(extension(OID_BASIC, seq(der(0x01, b"\xff")), critical=True))
    if ski is not None:
        found.append(extension(OID_SKI, octet(ski)))
    if aki is not None:
        found.append(extension(OID_AKI, seq(der(0x80, aki))))
    urls = [
        seq(oid(OID_OCSP), der(0x86, b"http://ocsp.exemplo/")),
        *(seq(oid(OID_CA_ISSUERS), der(0x86, url.encode("ascii"))) for url in aia),
    ]
    if list(aia):
        found.append(extension(OID_AIA, seq(*urls)))
    return found


def extension(identifier: str, value: bytes, *, critical: bool = False) -> bytes:
    parts = [oid(identifier)]
    if critical:
        parts.append(der(0x01, b"\xff"))
    return seq(*parts, octet(value))


def to_pem(certificate: bytes) -> str:
    body = base64.encodebytes(certificate).decode("ascii")
    return f"-----BEGIN CERTIFICATE-----\n{body}-----END CERTIFICATE-----\n"


def fixture_trust() -> ssl.SSLContext:
    """Repositório de autoridades que só confia na fixture (substitui o do sistema nos testes)."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.load_verify_locations(FIXTURE_CERT)
    return context
