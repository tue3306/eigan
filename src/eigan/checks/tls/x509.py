"""Leitura de certificados X.509 (RFC 5280) e conferência de nome (RFC 9525).

Extrai só o que a auditoria usa: titular e emissor, validade, nomes alternativos
(SAN), tipo e tamanho da chave pública, algoritmo de assinatura e as extensões que
dizem se o certificado é autoassinado. Os OIDs foram conferidos na tabela de objetos
do OpenSSL e na RFC 5280 / Baseline Requirements do CA/Browser Forum.
"""

from __future__ import annotations

import hashlib
import ipaddress
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TypeVar

from . import asn1
from .asn1 import Asn1Error, Tlv

T = TypeVar("T")

#: atributos de nome (RFC 5280, apêndice A)
NAME_ATTRS = {
    "2.5.4.3": "CN",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.6": "C",
    "2.5.4.8": "ST",
    "2.5.4.7": "L",
    "2.5.4.5": "serialNumber",
    "1.2.840.113549.1.9.1": "emailAddress",
}

#: algoritmo de assinatura -> (nome, hash). ``None`` = hash embutido (EdDSA).
SIGNATURES: dict[str, tuple[str, str | None]] = {
    "1.2.840.113549.1.1.2": ("md2WithRSAEncryption", "md2"),
    "1.2.840.113549.1.1.4": ("md5WithRSAEncryption", "md5"),
    "1.2.840.113549.1.1.5": ("sha1WithRSAEncryption", "sha1"),
    "1.3.14.3.2.29": ("sha1WithRSA", "sha1"),
    "1.2.840.113549.1.1.14": ("sha224WithRSAEncryption", "sha224"),
    "1.2.840.113549.1.1.11": ("sha256WithRSAEncryption", "sha256"),
    "1.2.840.113549.1.1.12": ("sha384WithRSAEncryption", "sha384"),
    "1.2.840.113549.1.1.13": ("sha512WithRSAEncryption", "sha512"),
    "1.2.840.10045.4.1": ("ecdsa-with-SHA1", "sha1"),
    "1.2.840.10045.4.3.1": ("ecdsa-with-SHA224", "sha224"),
    "1.2.840.10045.4.3.2": ("ecdsa-with-SHA256", "sha256"),
    "1.2.840.10045.4.3.3": ("ecdsa-with-SHA384", "sha384"),
    "1.2.840.10045.4.3.4": ("ecdsa-with-SHA512", "sha512"),
    "1.2.840.10040.4.3": ("dsaWithSHA1", "sha1"),
    "2.16.840.1.101.3.4.3.1": ("dsa_with_SHA224", "sha224"),
    "2.16.840.1.101.3.4.3.2": ("dsa_with_SHA256", "sha256"),
    "1.3.101.112": ("Ed25519", None),
    "1.3.101.113": ("Ed448", None),
}
RSASSA_PSS = "1.2.840.113549.1.1.10"

#: hashes usados no RSASSA-PSS (RFC 4055)
HASHES = {
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.4": "sha224",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
    "1.2.840.113549.2.5": "md5",
    "1.2.840.113549.2.2": "md2",
}
#: hashes com colisões práticas: não servem mais para assinar certificados
WEAK_HASHES = frozenset({"md2", "md5", "sha1"})

KEY_RSA = "1.2.840.113549.1.1.1"
KEY_EC = "1.2.840.10045.2.1"
KEY_DSA = "1.2.840.10040.4.1"
#: curvas nomeadas -> (nome, bits)
CURVES = {
    "1.2.840.10045.3.1.7": ("P-256", 256),
    "1.3.132.0.34": ("P-384", 384),
    "1.3.132.0.35": ("P-521", 521),
    "1.3.132.0.33": ("P-224", 224),
    "1.2.840.10045.3.1.1": ("P-192", 192),
    "1.3.132.0.10": ("secp256k1", 256),
    "1.3.36.3.3.2.8.1.1.7": ("brainpoolP256r1", 256),
    "1.3.36.3.3.2.8.1.1.11": ("brainpoolP384r1", 384),
    "1.3.36.3.3.2.8.1.1.13": ("brainpoolP512r1", 512),
}
EDDSA = {"1.3.101.112": ("Ed25519", 256), "1.3.101.113": ("Ed448", 456)}

EXT_SAN = "2.5.29.17"
EXT_BASIC_CONSTRAINTS = "2.5.29.19"
EXT_SKI = "2.5.29.14"
EXT_AKI = "2.5.29.35"
EXT_AIA = "1.3.6.1.5.5.7.1.1"
#: accessMethod de "onde baixar o certificado do emissor" (RFC 5280, 4.2.2.1)
AIA_CA_ISSUERS = "1.3.6.1.5.5.7.48.2"


@dataclass(frozen=True)
class Name:
    """Nome distinto (titular ou emissor). ``raw`` é o DER original, usado nas comparações."""

    raw: bytes
    attrs: tuple[tuple[str, str], ...]

    def get(self, short: str) -> str | None:
        for key, value in self.attrs:
            if key == short:
                return value
        return None

    @property
    def text(self) -> str:
        return ", ".join(f"{key}={value}" for key, value in self.attrs) or "(vazio)"


@dataclass(frozen=True)
class PublicKey:
    kind: str  # RSA, RSA-PSS, EC, DSA, Ed25519, Ed448 ou o OID quando desconhecida
    bits: int  # 0 quando não foi possível medir
    curve: str | None = None

    @property
    def label(self) -> str:
        if self.kind == "EC":
            return f"EC {self.curve or 'curva desconhecida'}"
        if self.kind in ("Ed25519", "Ed448"):
            return self.kind
        return f"{self.kind} {self.bits} bits" if self.bits else self.kind


@dataclass(frozen=True)
class Certificate:
    der: bytes
    version: int
    serial: int
    subject: Name
    issuer: Name
    not_before: datetime
    not_after: datetime
    san_dns: tuple[str, ...]
    san_ip: tuple[str, ...]
    key: PublicKey
    signature: str
    signature_hash: str | None
    is_ca: bool
    ski: bytes | None
    aki: bytes | None
    ca_issuers: tuple[str, ...] = ()

    @property
    def common_name(self) -> str | None:
        return self.subject.get("CN")

    @property
    def self_issued(self) -> bool:
        return self.subject.raw == self.issuer.raw

    @property
    def self_signed(self) -> bool:
        """Emissor = titular e, se houver identificadores de chave, eles coincidem."""
        if not self.self_issued:
            return False
        return self.aki is None or self.ski is None or self.aki == self.ski

    @property
    def weak_signature(self) -> bool:
        return self.signature_hash in WEAK_HASHES

    @property
    def lifetime(self) -> timedelta:
        return self.not_after - self.not_before

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.der).hexdigest()

    @property
    def names(self) -> tuple[str, ...]:
        return self.san_dns + self.san_ip


def parse_certificate(der: bytes) -> Certificate:
    """Lê um certificado DER. Levanta :class:`Asn1Error` se a estrutura for inválida."""
    cert = asn1.parse_one(der).expect(asn1.TAG_SEQUENCE)
    parts = cert.children()
    if len(parts) != 3:
        raise Asn1Error("Certificate precisa de 3 partes")
    tbs = parts[0].expect(asn1.TAG_SEQUENCE).children()
    signature, signature_hash = _signature(parts[1])
    pos = 0
    version = 1
    if tbs and tbs[0].is_context(0):
        version = asn1.decode_int(_only_child(tbs[0]).expect(asn1.TAG_INTEGER).value) + 1
        pos = 1
    if len(tbs) < pos + 6:
        raise Asn1Error("TBSCertificate incompleto")
    serial = asn1.decode_int(tbs[pos].expect(asn1.TAG_INTEGER).value)
    issuer = _name(tbs[pos + 2])
    validity = tbs[pos + 3].expect(asn1.TAG_SEQUENCE).children()
    if len(validity) != 2:
        raise Asn1Error("Validity precisa de duas datas")
    subject = _name(tbs[pos + 4])
    key = _public_key(tbs[pos + 5])
    extensions = _extensions(tbs[pos + 6 :])
    san_empty: tuple[tuple[str, ...], tuple[str, ...]] = ((), ())
    san_dns, san_ip = _tolerant(_san, extensions.get(EXT_SAN), san_empty)
    return Certificate(
        der=der,
        version=version,
        serial=serial,
        subject=subject,
        issuer=issuer,
        not_before=asn1.decode_time(validity[0]),
        not_after=asn1.decode_time(validity[1]),
        san_dns=san_dns,
        san_ip=san_ip,
        key=key,
        signature=signature,
        signature_hash=signature_hash,
        is_ca=_tolerant(_is_ca, extensions.get(EXT_BASIC_CONSTRAINTS), False),
        ski=_tolerant(_ski, extensions.get(EXT_SKI), None),
        aki=_tolerant(_aki, extensions.get(EXT_AKI), None),
        ca_issuers=_tolerant(_ca_issuers, extensions.get(EXT_AIA), ()),
    )


def _tolerant(parser: Callable[[bytes | None], T], value: bytes | None, default: T) -> T:
    """Extensão opcional quebrada não impede de ler o resto do certificado."""
    try:
        return parser(value)
    except Asn1Error:
        return default


def _only_child(item: Tlv) -> Tlv:
    children = item.children()
    if len(children) != 1:
        raise Asn1Error("esperava exatamente um elemento")
    return children[0]


def _algorithm(item: Tlv) -> tuple[str, Tlv | None]:
    """AlgorithmIdentifier: (OID, parâmetros ou None)."""
    fields = item.expect(asn1.TAG_SEQUENCE).children()
    if not fields:
        raise Asn1Error("AlgorithmIdentifier vazio")
    oid = asn1.decode_oid(fields[0].expect(asn1.TAG_OID).value)
    params = fields[1] if len(fields) > 1 and not fields[1].is_universal(asn1.TAG_NULL) else None
    return oid, params


def _signature(item: Tlv) -> tuple[str, str | None]:
    oid, params = _algorithm(item)
    if oid == RSASSA_PSS:
        return "rsassaPss", _pss_hash(params)
    name, digest = SIGNATURES.get(oid, (oid, "desconhecido"))
    return name, digest


def _pss_hash(params: Tlv | None) -> str:
    """Hash do RSASSA-PSS: campo [0] dos parâmetros; o padrão da RFC 4055 é SHA-1."""
    if params is None:
        return "sha1"
    for field in params.expect(asn1.TAG_SEQUENCE).children():
        if field.is_context(0):
            oid, _ = _algorithm(_only_child(field))
            return HASHES.get(oid, "desconhecido")
    return "sha1"


def _name(item: Tlv) -> Name:
    attrs: list[tuple[str, str]] = []
    for rdn in item.expect(asn1.TAG_SEQUENCE).children():
        for pair in rdn.expect(asn1.TAG_SET).children():
            fields = pair.expect(asn1.TAG_SEQUENCE).children()
            if len(fields) != 2:
                raise Asn1Error("atributo de nome mal formado")
            oid = asn1.decode_oid(fields[0].expect(asn1.TAG_OID).value)
            try:
                value = asn1.decode_string(fields[1])
            except Asn1Error:
                value = fields[1].value.hex()[:64]
            attrs.append((NAME_ATTRS.get(oid, oid), value))
    return Name(item.raw, tuple(attrs))


def _public_key(item: Tlv) -> PublicKey:
    fields = item.expect(asn1.TAG_SEQUENCE).children()
    if len(fields) != 2:
        raise Asn1Error("SubjectPublicKeyInfo mal formado")
    oid, params = _algorithm(fields[0])
    key_bytes = asn1.bit_string_bytes(fields[1])
    if oid in (KEY_RSA, RSASSA_PSS):
        numbers = asn1.parse_one(key_bytes).expect(asn1.TAG_SEQUENCE).children()
        if len(numbers) != 2:
            raise Asn1Error("RSAPublicKey mal formado")
        modulus = asn1.decode_uint(numbers[0].expect(asn1.TAG_INTEGER).value)
        return PublicKey("RSA" if oid == KEY_RSA else "RSA-PSS", modulus.bit_length())
    if oid == KEY_EC:
        if params is None or not params.is_universal(asn1.TAG_OID):
            return PublicKey("EC", 0, "parâmetros explícitos")
        curve_oid = asn1.decode_oid(params.value)
        curve, bits = CURVES.get(curve_oid, (curve_oid, 0))
        return PublicKey("EC", bits, curve)
    if oid in EDDSA:
        name, bits = EDDSA[oid]
        return PublicKey(name, bits)
    if oid == KEY_DSA:
        bits = 0
        if params is not None and params.is_universal(asn1.TAG_SEQUENCE):
            numbers = params.children()
            if numbers:
                bits = asn1.decode_uint(numbers[0].expect(asn1.TAG_INTEGER).value).bit_length()
        return PublicKey("DSA", bits)
    return PublicKey(oid, 0)


def _extensions(rest: list[Tlv]) -> dict[str, bytes]:
    """Extensões (campo [3]) por OID -> conteúdo do OCTET STRING."""
    found: dict[str, bytes] = {}
    for item in rest:
        if not item.is_context(3):
            continue  # issuerUniqueID [1] / subjectUniqueID [2]: ignorados
        for ext in _only_child(item).expect(asn1.TAG_SEQUENCE).children():
            fields = ext.expect(asn1.TAG_SEQUENCE).children()
            if len(fields) < 2:
                raise Asn1Error("extensão mal formada")
            oid = asn1.decode_oid(fields[0].expect(asn1.TAG_OID).value)
            found[oid] = fields[-1].expect(asn1.TAG_OCTET_STRING).value
    return found


def _san(value: bytes | None) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """subjectAltName: dNSName [2] e iPAddress [7] (RFC 5280, seção 4.2.1.6)."""
    if value is None:
        return (), ()
    dns: list[str] = []
    ips: list[str] = []
    for name in asn1.parse_one(value).expect(asn1.TAG_SEQUENCE).children():
        if name.is_context(2):
            dns.append(asn1.clean_text(name.value.decode("ascii", errors="replace")))
        elif name.is_context(7) and len(name.value) in (4, 16):
            ips.append(str(ipaddress.ip_address(name.value)))
    return tuple(dns), tuple(ips)


def _is_ca(value: bytes | None) -> bool:
    if value is None:
        return False
    fields = asn1.parse_one(value).expect(asn1.TAG_SEQUENCE).children()
    return (
        bool(fields)
        and fields[0].is_universal(asn1.TAG_BOOLEAN)
        and asn1.decode_bool(fields[0].value)
    )


def _ski(value: bytes | None) -> bytes | None:
    if value is None:
        return None
    return asn1.parse_one(value).expect(asn1.TAG_OCTET_STRING).value


def _aki(value: bytes | None) -> bytes | None:
    if value is None:
        return None
    for field in asn1.parse_one(value).expect(asn1.TAG_SEQUENCE).children():
        if field.is_context(0):
            return field.value
    return None


def _ca_issuers(value: bytes | None) -> tuple[str, ...]:
    """URLs do emissor na extensão Authority Information Access (RFC 5280, 4.2.2.1)."""
    if value is None:
        return ()
    urls: list[str] = []
    for access in asn1.parse_one(value).expect(asn1.TAG_SEQUENCE).children():
        fields = access.expect(asn1.TAG_SEQUENCE).children()
        if len(fields) != 2:
            raise Asn1Error("AccessDescription mal formado")
        method = asn1.decode_oid(fields[0].expect(asn1.TAG_OID).value)
        if method == AIA_CA_ISSUERS and fields[1].is_context(6):  # uniformResourceIdentifier
            urls.append(asn1.clean_text(fields[1].value.decode("ascii", errors="replace"), 512))
    return tuple(urls)


# -- conferência do nome (RFC 9525) ---------------------------------------------------
def _reference(name: str) -> str | None:
    """Nome de referência normalizado (minúsculas, sem ponto final, IDNA em A-label)."""
    text = name.strip().rstrip(".").lower()
    if not text:
        return None
    try:
        return text.encode("idna").decode("ascii")
    except UnicodeError:
        return None


def dns_matches(presented: str, reference: str) -> bool:
    """Um DNS-ID do certificado vale para o nome? Curinga só no rótulo inteiro mais à esquerda."""
    pattern = presented.strip().rstrip(".").lower()
    host = _reference(reference)
    if not pattern or host is None:
        return False
    if "*" not in pattern:
        return pattern == host
    labels = pattern.split(".")
    if labels[0] != "*" or any("*" in label for label in labels[1:]) or len(labels) < 3:
        return False  # curinga parcial, fora da esquerda ou sobre um sufixo inteiro: inválido
    host_labels = host.split(".")
    return (
        len(host_labels) == len(labels) and bool(host_labels[0]) and host_labels[1:] == labels[1:]
    )


def matches_host(cert: Certificate, reference: str) -> bool:
    """O certificado vale para ``reference`` (nome DNS ou IP)? O CN não é considerado."""
    try:
        address = ipaddress.ip_address(reference.strip("[]"))
    except ValueError:
        return any(dns_matches(name, reference) for name in cert.san_dns)
    return any(ipaddress.ip_address(ip) == address for ip in cert.san_ip)
