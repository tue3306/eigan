"""Leitor DER mínimo (ASN.1) — só o necessário para ler certificados X.509.

Sem dependências: lê TLV (tag, tamanho, valor) com limites rígidos. Qualquer dado
malformado vira :class:`Asn1Error` (nunca exceção inesperada nem leitura fora do
buffer), porque o certificado vem do alvo e pode ser hostil ou simplesmente quebrado.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime

# Classes de tag (bits 8-7 do primeiro byte)
CLASS_UNIVERSAL = 0
CLASS_CONTEXT = 2

# Tags universais usadas em certificados
TAG_BOOLEAN = 0x01
TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_UTF8_STRING = 0x0C
TAG_SEQUENCE = 0x10
TAG_SET = 0x11
TAG_NUMERIC_STRING = 0x12
TAG_PRINTABLE_STRING = 0x13
TAG_T61_STRING = 0x14
TAG_IA5_STRING = 0x16
TAG_UTC_TIME = 0x17
TAG_GENERALIZED_TIME = 0x18
TAG_VISIBLE_STRING = 0x1A
TAG_UNIVERSAL_STRING = 0x1C
TAG_BMP_STRING = 0x1E

_ONE_BYTE_STRINGS = {
    TAG_NUMERIC_STRING,
    TAG_PRINTABLE_STRING,
    TAG_T61_STRING,
    TAG_IA5_STRING,
    TAG_VISIBLE_STRING,
}
_PEM_CERT = re.compile(
    r"-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----"
)
_TIME = re.compile(r"^(\d{2}|\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:\.\d+)?Z$")
#: nenhum OID legítimo chega perto disso; o limite evita inteiros gigantes vindos do alvo
MAX_OID_BYTES = 64


class Asn1Error(ValueError):
    """Estrutura DER inválida ou diferente do esperado."""


@dataclass(frozen=True)
class Tlv:
    """Um elemento DER: classe, se é construído, número da tag, valor e bytes originais."""

    cls: int
    constructed: bool
    tag: int
    value: bytes
    raw: bytes

    def is_universal(self, tag: int) -> bool:
        return self.cls == CLASS_UNIVERSAL and self.tag == tag

    def is_context(self, number: int) -> bool:
        return self.cls == CLASS_CONTEXT and self.tag == number

    def children(self) -> list[Tlv]:
        """Elementos contidos no valor (para SEQUENCE, SET e tags explícitas)."""
        if not self.constructed:
            raise Asn1Error(f"elemento primitivo (tag {self.tag}) não tem filhos")
        return parse_all(self.value)

    def expect(self, tag: int) -> Tlv:
        """Devolve o próprio elemento se for a tag universal esperada (senão, erro)."""
        if not self.is_universal(tag):
            raise Asn1Error(f"esperava tag universal {tag}, veio classe {self.cls} tag {self.tag}")
        return self


def read(data: bytes, pos: int = 0) -> tuple[Tlv, int]:
    """Lê um TLV a partir de ``pos`` e devolve o elemento e a posição seguinte."""
    start = pos
    if pos >= len(data):
        raise Asn1Error("fim inesperado dos dados")
    first = data[pos]
    pos += 1
    tag = first & 0x1F
    if tag == 0x1F:  # tag de número alto (vários bytes)
        tag = 0
        for _ in range(4):
            if pos >= len(data):
                raise Asn1Error("tag truncada")
            byte = data[pos]
            pos += 1
            tag = (tag << 7) | (byte & 0x7F)
            if not byte & 0x80:
                break
        else:
            raise Asn1Error("tag longa demais")
    if pos >= len(data):
        raise Asn1Error("tamanho ausente")
    length = data[pos]
    pos += 1
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4:
            raise Asn1Error("tamanho indefinido ou grande demais (inválido em DER)")
        if pos + count > len(data):
            raise Asn1Error("tamanho truncado")
        length = int.from_bytes(data[pos : pos + count], "big")
        pos += count
    end = pos + length
    if end > len(data):
        raise Asn1Error("valor ultrapassa o fim dos dados")
    item = Tlv(first >> 6, bool(first & 0x20), tag, data[pos:end], data[start:end])
    return item, end


def parse_all(data: bytes) -> list[Tlv]:
    """Todos os TLV consecutivos de ``data``."""
    items: list[Tlv] = []
    pos = 0
    while pos < len(data):
        item, pos = read(data, pos)
        items.append(item)
    return items


def parse_one(data: bytes) -> Tlv:
    """Exatamente um TLV ocupando todos os bytes (sobra de bytes é erro)."""
    item, end = read(data, 0)
    if end != len(data):
        raise Asn1Error("bytes sobrando depois do elemento")
    return item


def decode_oid(value: bytes) -> str:
    """OBJECT IDENTIFIER em texto pontuado (ex.: ``2.5.4.3``)."""
    if not value or value[-1] & 0x80:
        raise Asn1Error("OID vazio ou truncado")
    if len(value) > MAX_OID_BYTES:
        raise Asn1Error("OID longo demais")
    arcs: list[int] = []
    current = 0
    for byte in value:
        current = (current << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(current)
            current = 0
    first = arcs[0]
    head = [first // 40, first % 40] if first < 80 else [2, first - 80]
    return ".".join(str(arc) for arc in head + arcs[1:])


def decode_int(value: bytes) -> int:
    """INTEGER (complemento de dois, big-endian)."""
    if not value:
        raise Asn1Error("INTEGER vazio")
    return int.from_bytes(value, "big", signed=True)


def decode_uint(value: bytes) -> int:
    """INTEGER lido sem sinal (módulo RSA sem o zero à esquerda não vira número negativo)."""
    if not value:
        raise Asn1Error("INTEGER vazio")
    return int.from_bytes(value, "big")


def decode_bool(value: bytes) -> bool:
    if len(value) != 1:
        raise Asn1Error("BOOLEAN com tamanho inválido")
    return value[0] != 0


def bit_string_bytes(item: Tlv) -> bytes:
    """Conteúdo de um BIT STRING (descarta o byte de bits não usados)."""
    item.expect(TAG_BIT_STRING)
    if not item.value:
        raise Asn1Error("BIT STRING vazio")
    return item.value[1:]


def decode_time(item: Tlv) -> datetime:
    """UTCTime ou GeneralizedTime em UTC (RFC 5280, seção 4.1.2.5).

    No UTCTime, anos ``50``-``99`` são 1950-1999 e ``00``-``49`` são 2000-2049.
    """
    if not (item.is_universal(TAG_UTC_TIME) or item.is_universal(TAG_GENERALIZED_TIME)):
        raise Asn1Error("esperava UTCTime ou GeneralizedTime")
    try:
        text = item.value.decode("ascii")
    except UnicodeDecodeError as exc:
        raise Asn1Error("data com caracteres inválidos") from exc
    match = _TIME.match(text)
    if match is None:
        raise Asn1Error(f"data em formato não suportado: {text!r}")
    year_text, month, day, hour, minute, second = match.groups()
    if item.tag == TAG_UTC_TIME:
        if len(year_text) != 2:
            raise Asn1Error("UTCTime com ano de 4 dígitos")
        short = int(year_text)
        year = 1900 + short if short >= 50 else 2000 + short
    else:
        if len(year_text) != 4:
            raise Asn1Error("GeneralizedTime com ano de 2 dígitos")
        year = int(year_text)
    try:
        return datetime(
            year,
            int(month),
            int(day),
            int(hour),
            int(minute),
            int(second or 0),
            tzinfo=UTC,
        )
    except ValueError as exc:
        raise Asn1Error(f"data inválida: {text!r}") from exc


MAX_TEXT = 256


def clean_text(text: str, limit: int = MAX_TEXT) -> str:
    """Remove caracteres de controle/formatação e corta o texto vindo do certificado do alvo.

    O certificado é controlado por quem responde na porta: sem isso, sequências ANSI, quebras
    de linha e textos gigantes iriam parar no terminal, no banco e nos relatórios.
    """
    cleaned = "".join(
        ch
        if ch == " " or unicodedata.category(ch) not in ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp")
        else "�"
        for ch in text[: limit + 1]
    )
    return cleaned[: limit - 1] + "…" if len(cleaned) > limit else cleaned


def _decode_raw_string(item: Tlv) -> str:
    if item.tag == TAG_UTF8_STRING:
        return item.value.decode("utf-8", errors="replace")
    if item.tag == TAG_BMP_STRING:
        return item.value.decode("utf-16-be", errors="replace")
    if item.tag == TAG_UNIVERSAL_STRING:
        return item.value.decode("utf-32-be", errors="replace")
    if item.tag in _ONE_BYTE_STRINGS:
        return item.value.decode("latin-1")
    raise Asn1Error(f"tipo de texto não suportado (tag {item.tag})")


def decode_string(item: Tlv) -> str:
    """Texto de um campo de nome (UTF8String, PrintableString, BMPString...), já higienizado."""
    if item.cls != CLASS_UNIVERSAL:
        raise Asn1Error("esperava texto com tag universal")
    return clean_text(_decode_raw_string(item))


def pem_certificates(text: str) -> list[bytes]:
    """DER de cada bloco ``BEGIN CERTIFICATE`` de um texto PEM."""
    blocks: list[bytes] = []
    for match in _PEM_CERT.finditer(text):
        body = "".join(match.group(1).split())
        try:
            blocks.append(base64.b64decode(body, validate=True))
        except (binascii.Error, ValueError) as exc:
            raise Asn1Error("bloco PEM com base64 inválido") from exc
    return blocks
