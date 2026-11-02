"""Suítes de cifra: nomes do registro da IANA (embarcado) e as listas usadas nas sondas.

A classificação é feita pelo nome oficial da suíte (``TLS_<troca de chaves>_WITH_<cifra>``),
como sugerem as ferramentas de referência: ``_NULL_`` = sem criptografia, ``_anon_`` = sem
autenticação, ``EXPORT`` = chave reduzida de exportação, ``RC4``/``DES``/``RC2``/``IDEA`` =
cifras quebradas, ``3DES`` = blocos de 64 bits (SWEET32) e ``ECDHE``/``DHE`` = sigilo futuro.
"""

from __future__ import annotations

from functools import lru_cache

from ...data import load_json

SSL2 = 0x0002
SSL3 = 0x0300
TLS10 = 0x0301
TLS11 = 0x0302
TLS12 = 0x0303
TLS13 = 0x0304

VERSION_NAMES = {
    SSL2: "SSLv2",
    SSL3: "SSLv3",
    TLS10: "TLS 1.0",
    TLS11: "TLS 1.1",
    TLS12: "TLS 1.2",
    TLS13: "TLS 1.3",
}

#: rótulo em português de cada família de cifra fraca
FAMILY_LABEL = {
    "null": "NULL (sem criptografia)",
    "anon": "anônima (sem autenticação do servidor)",
    "export": "EXPORT (chave de exportação de 40/56 bits)",
    "rc4": "RC4",
    "des": "DES (56 bits)",
    "rc2": "RC2",
    "idea": "IDEA",
    "3des": "3DES (blocos de 64 bits)",
}
INSECURE_FAMILIES = frozenset({"null", "anon", "export"})
BROKEN_FAMILIES = frozenset({"rc4", "des", "rc2", "idea"})

#: sinais (SCSV) e famílias que exigem configuração prévia (PSK, SRP, Kerberos)
_SKIP_IN_PROBES = ("_SCSV", "_PSK_", "_SRP_", "_KRB5_")

#: TLS 1.2 — modernas primeiro e legadas no fim: "sem suíte em comum" não pode
#: ser confundido com "sem TLS 1.2"
TLS12_PROBE: tuple[int, ...] = (
    0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0x009E, 0x009F, 0xCCAA, 0x00A2, 0x00A3,
    0xC023, 0xC027, 0xC024, 0xC028, 0xC009, 0xC013, 0xC00A, 0xC014,
    0x0067, 0x006B, 0x0040, 0x006A, 0x0033, 0x0039, 0x0032, 0x0038, 0x0045, 0x0044,
    0x009C, 0x009D, 0x003C, 0x003D, 0x002F, 0x0035, 0x0041,
    0xC012, 0xC008, 0x0016, 0x0013, 0x000A, 0xC011, 0xC007, 0x0005, 0x0004,
)  # fmt: skip
#: TLS 1.0 e 1.1 — sem as suítes exclusivas do TLS 1.2 (GCM, SHA-256, ChaCha20)
LEGACY_PROBE: tuple[int, ...] = (
    0xC014, 0xC013, 0xC00A, 0xC009, 0x0039, 0x0033, 0x0038, 0x0032, 0x0045, 0x0044,
    0x0035, 0x002F, 0x0041, 0xC012, 0xC008, 0x0016, 0x0013, 0x000A,
    0xC011, 0xC007, 0x0005, 0x0004, 0x0015, 0x0012, 0x0009, 0x0007,
)  # fmt: skip
#: SSLv3 — sem curvas elípticas (o SSLv3 não tem extensões) e com o SCSV de
#: renegociação (RFC 5746) no lugar da extensão
SSL3_PROBE: tuple[int, ...] = (
    0x0039, 0x0033, 0x0038, 0x0032, 0x0035, 0x002F, 0x0016, 0x0013, 0x000A,
    0x0005, 0x0004, 0x0015, 0x0012, 0x0009, 0x0007, 0x00FF,
)  # fmt: skip
TLS13_PROBE: tuple[int, ...] = (0x1301, 0x1302, 0x1303, 0x1304)


@lru_cache(maxsize=1)
def catalog() -> dict[int, str]:
    """Código -> nome IANA (``tls_suites.json``)."""
    data = load_json("tls_suites.json")
    return {int(code, 16): str(name) for code, name in data["suites"].items()}


def name(code: int) -> str:
    return catalog().get(code, f"0x{code:04X}")


def version_name(version: int | None) -> str:
    if version is None:
        return "desconhecida"
    return VERSION_NAMES.get(version, f"0x{version:04X}")


def families(code: int) -> frozenset[str]:
    """Famílias fracas a que a suíte pertence (vazio = nenhuma)."""
    text = name(code)
    found: set[str] = set()
    if "_WITH_NULL_" in text:
        found.add("null")
    if "_anon_" in text:
        found.add("anon")
    if "_EXPORT" in text:
        found.add("export")
    if "_RC4_" in text:
        found.add("rc4")
    if "_DES_CBC_" in text or "_DES40_" in text:
        found.add("des")
    if "_RC2_" in text:
        found.add("rc2")
    if "_IDEA_" in text:
        found.add("idea")
    if "_3DES_" in text:
        found.add("3des")
    return frozenset(found)


def forward_secret(code: int) -> bool:
    """Troca de chaves efêmera (ECDHE/DHE) ou TLS 1.3 — com sigilo futuro."""
    if 0x1300 <= code <= 0x13FF:
        return True
    text = name(code)
    return text.startswith(("TLS_ECDHE_", "TLS_DHE_")) and "_PSK_" not in text


def rsa_key_exchange(code: int) -> bool:
    """Troca de chaves RSA estática (``TLS_RSA_WITH_*``): sem sigilo futuro."""
    return name(code).startswith("TLS_RSA_WITH_")


def is_cbc(code: int) -> bool:
    return "_CBC_" in name(code)


def is_dhe_export(code: int) -> bool:
    """``TLS_DHE_*_EXPORT_*`` — as suítes do Logjam (CVE-2015-4000)."""
    text = name(code)
    return text.startswith("TLS_DHE_") and "_EXPORT_" in text


def _probe_candidates() -> list[int]:
    return [
        code
        for code, text in sorted(catalog().items())
        if not any(mark in text for mark in _SKIP_IN_PROBES) and not 0x1300 <= code <= 0x13FF
    ]


@lru_cache(maxsize=1)
def insecure_suites() -> tuple[int, ...]:
    """NULL, anônimas e EXPORT."""
    return tuple(c for c in _probe_candidates() if families(c) & INSECURE_FAMILIES)


@lru_cache(maxsize=1)
def broken_suites() -> tuple[int, ...]:
    """RC4, DES, RC2 e IDEA com autenticação (as inseguras ficam no grupo próprio)."""
    return tuple(
        c
        for c in _probe_candidates()
        if families(c) & BROKEN_FAMILIES and not families(c) & INSECURE_FAMILIES
    )


@lru_cache(maxsize=1)
def triple_des_suites() -> tuple[int, ...]:
    """3DES com autenticação (SWEET32)."""
    return tuple(c for c in _probe_candidates() if families(c) == frozenset({"3des"}))


@lru_cache(maxsize=1)
def forward_secret_suites() -> tuple[int, ...]:
    """Todas as ECDHE/DHE autenticadas — basta o servidor aceitar uma."""
    return tuple(
        c for c in _probe_candidates() if forward_secret(c) and not families(c) & INSECURE_FAMILIES
    )


@lru_cache(maxsize=1)
def rsa_suites() -> tuple[int, ...]:
    """Troca de chaves RSA (sem sigilo futuro), excluindo as de exportação e NULL."""
    return tuple(
        c
        for c in _probe_candidates()
        if rsa_key_exchange(c) and not families(c) & INSECURE_FAMILIES
    )
