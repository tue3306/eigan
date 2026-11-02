"""MongoDB: BSON mínimo e o protocolo de fio (OP_MSG e, para servidores antigos, OP_QUERY).

Só o necessário para os comandos de leitura de metadados que as ferramentas de
auditoria usam: ``hello``/``isMaster`` (identificação), ``buildInfo`` (versão)
e ``listDatabases`` com ``nameOnly`` (o servidor exige login ou não?).
Referências: https://bsonspec.org/spec.html e
https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/
"""

from __future__ import annotations

import itertools
import struct
from typing import Any

from .common import Connection

OP_REPLY = 1
OP_QUERY = 2004
OP_MSG = 2013
#: as respostas de metadados são pequenas; um tamanho maior que isso é tratado como inválido
MAX_MESSAGE = 2 * 1024 * 1024

_request_ids = itertools.count(1)


class BsonError(ValueError):
    """Documento BSON malformado."""


# -- codificação ------------------------------------------------------------------
def encode(document: dict[str, Any]) -> bytes:
    """Codifica um dicionário em BSON (tipos: bool, int, float, str, dict, list, None, bytes)."""
    body = b"".join(_element(str(key), value) for key, value in document.items())
    return struct.pack("<i", len(body) + 5) + body + b"\x00"


def _cstring(text: str) -> bytes:
    raw = text.encode("utf-8")
    if b"\x00" in raw:
        raise BsonError("nome com byte nulo")
    return raw + b"\x00"


def _element(name: str, value: Any) -> bytes:
    key = _cstring(name)
    if isinstance(value, bool):
        return b"\x08" + key + (b"\x01" if value else b"\x00")
    if isinstance(value, int):
        if -(2**31) <= value < 2**31:
            return b"\x10" + key + struct.pack("<i", value)
        return b"\x12" + key + struct.pack("<q", value)
    if isinstance(value, float):
        return b"\x01" + key + struct.pack("<d", value)
    if isinstance(value, str):
        raw = value.encode("utf-8") + b"\x00"
        return b"\x02" + key + struct.pack("<i", len(raw)) + raw
    if isinstance(value, dict):
        return b"\x03" + key + encode(value)
    if isinstance(value, (list, tuple)):
        return b"\x04" + key + encode({str(i): item for i, item in enumerate(value)})
    if value is None:
        return b"\x0a" + key
    if isinstance(value, bytes):
        return b"\x05" + key + struct.pack("<i", len(value)) + b"\x00" + value
    raise BsonError(f"tipo não suportado: {type(value).__name__}")


# -- decodificação ----------------------------------------------------------------
_FIXED = {0x01: 8, 0x07: 12, 0x09: 8, 0x11: 8, 0x12: 8, 0x13: 16, 0x10: 4, 0x08: 1}
_EMPTY = {0x06, 0x0A, 0x7F, 0xFF}


def decode(data: bytes, offset: int = 0) -> tuple[dict[str, Any], int]:
    """Decodifica o documento que começa em ``offset``; devolve (documento, fim)."""
    if offset + 5 > len(data):
        raise BsonError("documento truncado")
    size = struct.unpack_from("<i", data, offset)[0]
    end = offset + size
    if size < 5 or end > len(data) or data[end - 1] != 0:
        raise BsonError("tamanho de documento inválido")
    result: dict[str, Any] = {}
    pos = offset + 4
    while pos < end - 1:
        kind = data[pos]
        name_end = data.index(b"\x00", pos + 1, end)
        name = data[pos + 1 : name_end].decode("utf-8", errors="replace")
        result[name], pos = _value(data, kind, name_end + 1, end)
    return result, end


def _value(data: bytes, kind: int, pos: int, end: int) -> tuple[Any, int]:
    if kind in (0x02, 0x0D, 0x0E):  # string, código JS, símbolo
        length = struct.unpack_from("<i", data, pos)[0]
        if length < 1 or pos + 4 + length > end:
            raise BsonError("string inválida")
        return data[pos + 4 : pos + 3 + length].decode("utf-8", errors="replace"), pos + 4 + length
    if kind in (0x03, 0x04):
        doc, new_pos = decode(data, pos)
        return (list(doc.values()) if kind == 0x04 else doc), new_pos
    if kind == 0x05:  # binário: tamanho + subtipo + bytes
        length = struct.unpack_from("<i", data, pos)[0]
        if length < 0 or pos + 5 + length > end:
            raise BsonError("binário inválido")
        return data[pos + 5 : pos + 5 + length], pos + 5 + length
    if kind in _FIXED:
        size = _FIXED[kind]
        raw = data[pos : pos + size]
        if len(raw) < size:
            raise BsonError("valor truncado")
        return _fixed_value(kind, raw), pos + size
    if kind in _EMPTY:
        return None, pos
    if kind == 0x0B:  # regex: dois cstrings
        first = data.index(b"\x00", pos, end)
        second = data.index(b"\x00", first + 1, end)
        return data[pos:first].decode("utf-8", "replace"), second + 1
    raise BsonError(f"tipo BSON não suportado: 0x{kind:02x}")


def _fixed_value(kind: int, raw: bytes) -> Any:
    if kind == 0x01:
        return struct.unpack("<d", raw)[0]
    if kind == 0x08:
        return raw != b"\x00"
    if kind == 0x10:
        return struct.unpack("<i", raw)[0]
    if kind in (0x09, 0x12):
        return struct.unpack("<q", raw)[0]
    return raw.hex()  # ObjectId, timestamp, decimal128: só para exibição


# -- protocolo de fio ---------------------------------------------------------------
def op_msg(command: dict[str, Any]) -> bytes:
    """OP_MSG com uma seção do tipo 0 (o comando)."""
    body = struct.pack("<I", 0) + b"\x00" + encode(command)
    return struct.pack("<iiii", 16 + len(body), next(_request_ids), 0, OP_MSG) + body


def op_query(command: dict[str, Any], collection: str = "admin.$cmd") -> bytes:
    """OP_QUERY legado (servidores anteriores ao 3.6), usado só como plano B."""
    body = struct.pack("<i", 0) + _cstring(collection) + struct.pack("<ii", 0, -1) + encode(command)
    return struct.pack("<iiii", 16 + len(body), next(_request_ids), 0, OP_QUERY) + body


def parse_reply(data: bytes) -> dict[str, Any] | None:
    """Primeiro documento de uma resposta OP_MSG ou OP_REPLY. None se não for MongoDB."""
    if len(data) < 21:
        return None
    length, _request, _response, opcode = struct.unpack_from("<iiii", data, 0)
    if length != len(data):
        return None
    try:
        if opcode == OP_MSG and data[20] == 0:
            return decode(data, 21)[0]
        if opcode == OP_REPLY and len(data) >= 36:
            return decode(data, 36)[0]
    except (BsonError, ValueError, struct.error, RecursionError):
        return None
    return None


def command(conn: Connection, request: bytes) -> dict[str, Any] | None:
    """Envia uma mensagem e lê a resposta completa (cabeçalho + corpo)."""
    if not conn.send(request):
        return None
    header = conn.read_exact(16)
    if len(header) < 16:
        return None
    length = struct.unpack_from("<i", header, 0)[0]
    if not 21 <= length <= MAX_MESSAGE:
        return None
    rest = conn.read_exact(length - 16)
    return parse_reply(header + rest)
