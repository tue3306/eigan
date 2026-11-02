"""Sondas de protocolos em que o CLIENTE fala primeiro (pedido fixo + intérprete).

Cada pedido é o mesmo que um cliente legítimo enviaria para começar a conversa
(ex.: ``PING`` do Redis, ``version`` do Memcached, ``SSLRequest`` do
PostgreSQL). Nada aqui faz E/S: são os bytes do pedido e a interpretação da
resposta, testáveis isoladamente.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from typing import Any

from .banners import Identified

# -- Redis ---------------------------------------------------------------------
REDIS_PING = b"*1\r\n$4\r\nPING\r\n"
REDIS_INFO = b"*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n"


def parse_redis(data: bytes) -> Identified | None:
    """Resposta ao ``PING``: ``+PONG`` (sem senha), ``-NOAUTH`` (com senha) ou ``-DENIED``."""
    head = data[:200]
    if head.startswith(b"+PONG"):
        return Identified("redis", "redis", extra={"autenticacao": "nenhuma"})
    if head.startswith((b"-NOAUTH", b"-WRONGPASS")) or (
        head.startswith(b"-ERR") and b"Authentication required" in head
    ):
        return Identified("redis", "redis", extra={"autenticacao": "senha"})
    if head.startswith(b"-DENIED"):
        return Identified("redis", "redis", extra={"autenticacao": "modo protegido"})
    return None


def parse_redis_info(data: bytes) -> dict[str, str]:
    """Campos ``chave:valor`` da resposta ao ``INFO server`` (bulk string RESP)."""
    text = data.decode("utf-8", errors="replace")
    fields: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep and key and not key.startswith(("$", "#")):
            fields[key.strip()] = value.strip()
    return fields


# -- Memcached -----------------------------------------------------------------
MEMCACHED_VERSION = b"version\r\n"
MEMCACHED_STATS = b"stats\r\n"
_MEMCACHED = re.compile(rb"^VERSION (\S+)\r?\n")


def parse_memcached(data: bytes) -> Identified | None:
    match = _MEMCACHED.match(data)
    if not match:
        return None
    return Identified("memcached", "memcached", match.group(1).decode("ascii", "replace"))


def parse_memcached_stats(data: bytes) -> dict[str, str]:
    stats: dict[str, str] = {}
    for line in data.decode("ascii", errors="replace").splitlines():
        parts = line.split(" ", 2)
        if len(parts) == 3 and parts[0] == "STAT":
            stats[parts[1]] = parts[2]
    return stats


# -- PostgreSQL ----------------------------------------------------------------
#: SSLRequest: tamanho 8 + código 80877103 (o cliente pergunta se o servidor aceita TLS)
POSTGRES_SSLREQUEST = struct.pack("!II", 8, 80877103)


def parse_postgres(data: bytes) -> Identified | None:
    """``S`` (aceita TLS) ou ``N`` (não aceita); ``E`` = erro de servidor antigo."""
    if data in (b"S", b"N"):
        return Identified("postgresql", "postgresql", extra={"tls": data == b"S"})
    if data[:1] == b"E" and (b"SFATAL" in data or b"VFATAL" in data):
        return Identified("postgresql", "postgresql", extra={"tls": False})
    return None


# -- Microsoft SQL Server (TDS PRELOGIN) ---------------------------------------
_MSSQL_NAMES = {
    8: "2000", 9: "2005", 10: "2008", 11: "2012", 12: "2014",
    13: "2016", 14: "2017", 15: "2019", 16: "2022", 17: "2025",
}  # fmt: skip


def mssql_prelogin() -> bytes:
    """Pacote PRELOGIN (TDS 0x12) com VERSION, ENCRYPTION, INSTOPT, THREADID e MARS."""
    options = (
        (0x00, b"\x00" * 6),  # VERSION (do cliente)
        (0x01, b"\x02"),  # ENCRYPTION: ENCRYPT_NOT_SUP
        (0x02, b"\x00"),  # INSTOPT: instância padrão
        (0x03, b"\x00" * 4),  # THREADID
        (0x04, b"\x00"),  # MARS desligado
    )
    offset = 5 * len(options) + 1
    table, values = b"", b""
    for token, value in options:
        table += struct.pack(">BHH", token, offset, len(value))
        values += value
        offset += len(value)
    payload = table + b"\xff" + values
    return struct.pack(">BBHHBB", 0x12, 0x01, 8 + len(payload), 0, 1, 0) + payload


def parse_mssql(data: bytes) -> Identified | None:
    """Resposta TDS (tipo 0x04) com o token VERSION → ``15.0.2000`` (SQL Server 2019)."""
    if len(data) < 9 or data[0] != 0x04:
        return None
    payload = data[8:]
    pos = 0
    while pos + 5 <= len(payload) and payload[pos] != 0xFF:
        token, offset, length = struct.unpack(">BHH", payload[pos : pos + 5])
        pos += 5
        if token == 0x00 and length >= 6 and offset + 6 <= len(payload):
            major, minor = payload[offset], payload[offset + 1]
            build = int.from_bytes(payload[offset + 2 : offset + 4], "big")
            extra: dict[str, Any] = {}
            if major in _MSSQL_NAMES:
                extra["edicao"] = f"SQL Server {_MSSQL_NAMES[major]}"
            return Identified("mssql", "mssql", f"{major}.{minor}.{build}", extra=extra)
    return None


# -- AJP (Apache JServ Protocol) -----------------------------------------------
#: CPing (0x0A) — o "ping" de saúde que o proxy reverso manda ao Tomcat
AJP_CPING = b"\x12\x34\x00\x01\x0a"
AJP_CPONG = b"AB\x00\x01\x09"


def parse_ajp(data: bytes) -> Identified | None:
    """CPong (``AB 00 01 09``): um conector AJP13 respondeu (Tomcat, na maioria dos casos)."""
    if data.startswith(AJP_CPONG):
        return Identified("ajp", banner="CPong AJP13", extra={"cpong": True})
    return None


# -- AMQP 0-9-1 (RabbitMQ e outros) --------------------------------------------
AMQP_HEADER = b"AMQP\x00\x00\x09\x01"


def parse_amqp(data: bytes) -> Identified | None:
    """``Connection.Start`` (classe 10, método 10) com as propriedades do servidor."""
    if data.startswith(b"AMQP"):
        return Identified("amqp", banner="cabeçalho AMQP (versão diferente)")
    if len(data) < 12 or data[0] != 0x01 or data[7:11] != b"\x00\x0a\x00\x0a":
        return None
    props = _amqp_table(data, 13)
    product = props.get("product", "")
    version = props.get("version", "")
    name = "rabbitmq" if "rabbitmq" in product.lower() else product.lower().split(" ")[0]
    return Identified("amqp", name, version, banner=f"{product} {version}".strip())


def _amqp_table(data: bytes, pos: int) -> dict[str, str]:
    """Lê os campos texto (tipo 'S') da tabela de propriedades; para no primeiro tipo desconhecido."""
    fixed = {"t": 1, "b": 1, "B": 1, "s": 2, "u": 2, "I": 4, "i": 4, "l": 8, "L": 8,
             "f": 4, "d": 8, "D": 5, "T": 8, "V": 0}  # fmt: skip
    result: dict[str, str] = {}
    if pos + 4 > len(data):
        return result
    end = min(len(data), pos + 4 + int.from_bytes(data[pos : pos + 4], "big"))
    pos += 4
    while pos < end:
        size = data[pos]
        name = data[pos + 1 : pos + 1 + size].decode("utf-8", errors="replace")
        pos += 1 + size
        if pos >= end:
            break
        kind = chr(data[pos])
        pos += 1
        if kind in ("S", "x", "F", "A"):
            length = int.from_bytes(data[pos : pos + 4], "big")
            if kind == "S":
                result[name] = data[pos + 4 : pos + 4 + length].decode("utf-8", errors="replace")
            pos += 4 + length
        elif kind in fixed:
            pos += fixed[kind]
        else:
            break
    return result


# -- Cassandra (protocolo nativo CQL) ------------------------------------------
#: OPTIONS na versão 4 do protocolo: versão, flags, stream, opcode 0x05, corpo vazio
CQL_OPTIONS = b"\x04\x00\x00\x00\x05\x00\x00\x00\x00"


def cql_startup(version: int = 4) -> bytes:
    """STARTUP (opcode 0x01) com ``CQL_VERSION`` — o início normal de uma sessão, sem login."""
    body = struct.pack(">H", 1) + _cql_string("CQL_VERSION") + _cql_string("3.0.0")
    return struct.pack(">BBHBI", version, 0, 1, 0x01, len(body)) + body


def _cql_string(text: str) -> bytes:
    raw = text.encode("utf-8")
    return struct.pack(">H", len(raw)) + raw


def parse_cql_startup(data: bytes) -> str | None:
    """``"pronto"`` (READY: sem autenticação), ``"autenticar"`` (AUTHENTICATE) ou ``"erro"``."""
    if len(data) < 9 or not data[0] & 0x80:
        return None
    return {0x02: "pronto", 0x03: "autenticar", 0x00: "erro"}.get(data[4])


def parse_cql(data: bytes) -> Identified | None:
    """Resposta SUPPORTED (0x06) ou ERROR (0x00) de um nó Cassandra/ScyllaDB."""
    if len(data) < 9 or not data[0] & 0x80 or data[4] not in (0x00, 0x06):
        return None
    if data[0] & 0x7F not in range(1, 7):
        return None
    cql = re.search(rb"CQL_VERSION\x00\x01\x00.(\d[\d.]*)", data, re.S)
    extra = {"cql": cql.group(1).decode()} if cql else {}
    return Identified("cassandra", "cassandra", extra=extra)


# -- VNC (RFB, RFC 6143) ---------------------------------------------------------
#: tipos de segurança do registro da IANA (https://www.iana.org/assignments/rfb/rfb.xhtml)
RFB_NONE = 1
RFB_VNC_AUTH = 2
RFB_TIGHT = 16
RFB_TLS = 18
RFB_VENCRYPT = 19
#: tipos que só negociam a autenticação de verdade depois (túnel/subtipos, que podem ser "None")
RFB_NEGOTIATED_LATER = frozenset({RFB_TIGHT, RFB_TLS, RFB_VENCRYPT})
RFB_SECURITY = {
    0: "Inválido", 1: "Nenhuma (sem senha)", 2: "Autenticação VNC", 5: "RealVNC", 6: "RealVNC",
    16: "Tight", 17: "Ultra", 18: "TLS", 19: "VeNCrypt", 20: "SASL (GTK-VNC)", 30: "Apple",
}  # fmt: skip


@dataclass(frozen=True)
class RfbSecurity:
    """O que o servidor VNC ofereceu: tipos de segurança OU o motivo da recusa."""

    types: tuple[int, ...] = ()
    reason: str = ""  # preenchido quando o servidor recusou a conexão

    @property
    def no_auth(self) -> bool:
        return RFB_NONE in self.types

    def describe(self) -> str:
        return ", ".join(f"{t} ({RFB_SECURITY.get(t, 'desconhecido')})" for t in self.types)


def rfb_client_version(server: tuple[int, int]) -> bytes:
    """Versão que o cliente responde: 3.8 (ou 3.7/3.3 para servidores antigos).

    Pela RFC 6143, versões diferentes de 3.3, 3.7 e 3.8 são tratadas como 3.3.
    """
    major, minor = server
    if major > 3 or minor >= 8:
        return b"RFB 003.008\n"
    if minor == 7:
        return b"RFB 003.007\n"
    return b"RFB 003.003\n"


def parse_rfb_security(data: bytes, client_minor: int) -> RfbSecurity | None:
    """Resposta do servidor depois da versão do cliente (RFC 6143, 7.1.2).

    * 3.7/3.8: ``U8`` quantidade de tipos + os tipos (``U8`` cada); 0 tipos = recusa,
      seguida de ``U32`` tamanho + motivo;
    * 3.3: o servidor escolhe sozinho e manda um ``U32`` (0 = recusa + motivo,
      1 = sem autenticação, 2 = autenticação VNC).
    """
    if client_minor >= 7:
        if not data:
            return None
        count = data[0]
        if count == 0:
            return RfbSecurity(reason=_rfb_reason(data[1:]))
        if len(data) < 1 + count:
            return None
        return RfbSecurity(types=tuple(data[1 : 1 + count]))
    if len(data) < 4:
        return None
    chosen = int.from_bytes(data[:4], "big")
    if chosen == 0:
        return RfbSecurity(reason=_rfb_reason(data[4:]))
    return RfbSecurity(types=(chosen,))


def _rfb_reason(data: bytes) -> str:
    if len(data) < 4:
        return "sem motivo informado"
    size = min(int.from_bytes(data[:4], "big"), 300)
    return data[4 : 4 + size].decode("utf-8", errors="replace").strip() or "sem motivo informado"


# -- DNS sobre TCP -----------------------------------------------------------------
#: consulta mínima e sem recursão (RD=0) pelo NS da raiz: só confirma que a porta fala DNS
DNS_PROBE_ID = 0x4549
_DNS_QUERY = (
    struct.pack(">HHHHHH", DNS_PROBE_ID, 0x0000, 1, 0, 0, 0) + b"\x00" + struct.pack(">HH", 2, 1)
)
DNS_QUERY_TCP = struct.pack(">H", len(_DNS_QUERY)) + _DNS_QUERY
_DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def parse_dns_tcp(data: bytes) -> Identified | None:
    """Resposta DNS por TCP (tamanho de 2 bytes + cabeçalho) com o mesmo id e o bit QR."""
    if len(data) < 14 or int.from_bytes(data[:2], "big") < 12:
        return None
    ident, flags = struct.unpack(">HH", data[2:6])
    if ident != DNS_PROBE_ID or not flags & 0x8000:
        return None
    rcode = _DNS_RCODES.get(flags & 0x000F, str(flags & 0x000F))
    return Identified("dns", banner=f"resposta DNS ({rcode})", extra={"rcode": rcode})


# -- Oracle (TNS listener) -------------------------------------------------------
TNS_VERSION_COMMAND = "(CONNECT_DATA=(COMMAND=version))"
_TNS_TYPES = {2: "ACCEPT", 4: "REFUSE", 5: "REDIRECT", 11: "RESEND", 12: "MARKER"}
_VSNNUM = re.compile(rb"VSNNUM=(\d+)")
_TNS_VERSION = re.compile(rb"Version (\d+(?:\.\d+)+)")


def tns_connect(connect_data: str = TNS_VERSION_COMMAND) -> bytes:
    """Pacote TNS CONNECT (tipo 1) com cabeçalho de 58 bytes e os dados de conexão."""
    data = connect_data.encode("ascii")
    header = struct.pack(">HHBBH", 58 + len(data), 0, 1, 0, 0)
    body = struct.pack(
        ">HHHHHHHHHHIBB",
        0x0136,  # versão do protocolo
        0x012C,  # versão compatível mais antiga
        0,  # opções de serviço
        0x0800,  # SDU
        0x7FFF,  # TDU máximo
        0x7F08,  # características do protocolo
        0,  # line turnaround
        1,  # valor 1 no hardware (ordem dos bytes)
        len(data),  # tamanho dos dados de conexão
        58,  # deslocamento dos dados de conexão
        0,  # máximo de dados recebíveis
        0,  # flags de conexão 0
        0,  # flags de conexão 1
    )
    padding = b"\x00" * (58 - len(header) - len(body))
    return header + body + padding + data


def decode_vsnnum(value: int) -> str:
    """``VSNNUM`` do listener → versão (ex.: 318767104 → 19.0.0.0.0)."""
    parts = (
        value >> 24,
        (value >> 20) & 0xF,
        (value >> 12) & 0xFF,
        (value >> 8) & 0xF,
        value & 0xFF,
    )
    return ".".join(str(p) for p in parts)


def parse_tns(data: bytes) -> Identified | None:
    """Resposta do listener Oracle (ACCEPT/REFUSE/REDIRECT/RESEND) e, se houver, a versão."""
    if len(data) < 8 or data[4] not in _TNS_TYPES:
        return None
    length = int.from_bytes(data[0:2], "big")
    if length < 8 or data[5] != 0:
        return None
    version = ""
    text = _TNS_VERSION.search(data)
    number = _VSNNUM.search(data)
    if text:
        version = text.group(1).decode("ascii")
    elif number:
        version = decode_vsnnum(int(number.group(1)))
    extra = {"resposta": _TNS_TYPES[data[4]]}
    return Identified("oracle-tns", "oracle", version, extra=extra)
