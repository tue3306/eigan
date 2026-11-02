"""Leitor DER e certificados X.509: bytes montados à mão e o certificado da fixture."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from fakes_tls import (
    FIXTURE_CERT,
    OID_AKI,
    OID_BASIC,
    OID_ECDSA_SHA256,
    OID_MD5_RSA,
    OID_P224,
    OID_P384,
    OID_SAN,
    OID_SHA1,
    OID_SHA1_RSA,
    build_cert,
    der,
    dsa_spki,
    ec_spki,
    ed25519_spki,
    extension,
    fixture_der,
    integer,
    oid,
    pss_algorithm,
    rsa_spki,
    seq,
    sig_algorithm,
    to_pem,
)

from eigan.checks.tls import asn1, x509
from eigan.checks.tls.asn1 import Asn1Error


# -- TLV ---------------------------------------------------------------------------------
def test_tlv_tamanho_curto_e_longo() -> None:
    short = asn1.parse_one(b"\x04\x03abc")
    assert (short.tag, short.value, short.constructed) == (asn1.TAG_OCTET_STRING, b"abc", False)
    payload = b"x" * 300
    long_form = asn1.parse_one(b"\x04\x82\x01\x2c" + payload)
    assert long_form.value == payload
    assert long_form.raw[:4] == b"\x04\x82\x01\x2c"


def test_tlv_filhos_e_tag_de_contexto() -> None:
    item = asn1.parse_one(der(0xA3, der(0x30, b"\x05\x00")))
    assert item.is_context(3) and item.constructed
    [child] = item.children()
    assert child.is_universal(asn1.TAG_SEQUENCE)
    assert child.children()[0].is_universal(asn1.TAG_NULL)


def test_tlv_tag_de_numero_alto() -> None:
    item, end = asn1.read(b"\x9f\x81\x01\x01z")
    assert (item.cls, item.tag, item.value, end) == (asn1.CLASS_CONTEXT, 129, b"z", 5)


@pytest.mark.parametrize(
    "data",
    [
        b"",  # vazio
        b"\x04",  # sem tamanho
        b"\x04\x05abc",  # valor além do fim
        b"\x04\x80abc",  # tamanho indefinido (proibido em DER)
        b"\x04\x85\x01\x02\x03\x04\x05",  # tamanho grande demais
        b"\x04\x82\x01",  # tamanho truncado
        b"\x1f",  # tag longa truncada
        b"\x1f\x81\x81\x81\x81\x81\x01",  # tag longa demais
    ],
)
def test_tlv_malformado_vira_erro_proprio(data: bytes) -> None:
    with pytest.raises(Asn1Error):
        asn1.read(data)


def test_um_unico_elemento_nao_aceita_sobra() -> None:
    with pytest.raises(Asn1Error):
        asn1.parse_one(b"\x05\x00\x05\x00")


def test_primitivo_nao_tem_filhos_e_expect_confere_a_tag() -> None:
    item = asn1.parse_one(b"\x02\x01\x05")
    with pytest.raises(Asn1Error):
        item.children()
    with pytest.raises(Asn1Error):
        item.expect(asn1.TAG_SEQUENCE)


# -- valores -----------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("raw", "text"),
    [
        (b"\x55\x04\x03", "2.5.4.3"),
        (b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b", "1.2.840.113549.1.1.11"),
        (b"\x2b\x65\x70", "1.3.101.112"),
        (b"\x88\x37", "2.999"),  # primeiro subidentificador acima de 80
        (b"\x00", "0.0"),
    ],
)
def test_oid(raw: bytes, text: str) -> None:
    assert asn1.decode_oid(raw) == text


@pytest.mark.parametrize("raw", [b"", b"\x86", b"\xff" * 5000 + b"\x01"])
def test_oid_invalido_ou_gigante(raw: bytes) -> None:
    """O limite impede que um OID hostil estoure a conversão de inteiro para texto."""
    with pytest.raises(Asn1Error):
        asn1.decode_oid(raw)


def test_inteiros() -> None:
    assert asn1.decode_int(b"\x01\x00") == 256
    assert asn1.decode_int(b"\xff") == -1
    assert asn1.decode_uint(b"\xff") == 255
    for decoder in (asn1.decode_int, asn1.decode_uint):
        with pytest.raises(Asn1Error):
            decoder(b"")


def test_booleano_e_bit_string() -> None:
    assert asn1.decode_bool(b"\xff") is True
    assert asn1.decode_bool(b"\x00") is False
    with pytest.raises(Asn1Error):
        asn1.decode_bool(b"\x00\x00")
    assert asn1.bit_string_bytes(asn1.parse_one(b"\x03\x03\x00\xab\xcd")) == b"\xab\xcd"
    with pytest.raises(Asn1Error):
        asn1.bit_string_bytes(asn1.parse_one(b"\x03\x00"))


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (der(0x17, b"491231235959Z"), datetime(2049, 12, 31, 23, 59, 59, tzinfo=UTC)),
        (der(0x17, b"500101000000Z"), datetime(1950, 1, 1, tzinfo=UTC)),
        (der(0x17, b"2501011200Z"), datetime(2025, 1, 1, 12, 0, tzinfo=UTC)),
        (der(0x18, b"21261008210534Z"), datetime(2126, 10, 8, 21, 5, 34, tzinfo=UTC)),
        (der(0x18, b"20500101000000.5Z"), datetime(2050, 1, 1, tzinfo=UTC)),
    ],
)
def test_datas_utctime_e_generalizedtime(raw: bytes, expected: datetime) -> None:
    assert asn1.decode_time(asn1.parse_one(raw)) == expected


@pytest.mark.parametrize(
    "raw",
    [
        der(0x17, b"251301120000Z"),  # mês 13
        der(0x17, b"20250101120000Z"),  # UTCTime com ano de 4 dígitos
        der(0x18, b"250101120000Z"),  # GeneralizedTime com ano de 2 dígitos
        der(0x17, b"250101120000"),  # sem o Z
        der(0x17, b"25010112\xff000Z"),  # não é texto
        der(0x04, b"250101120000Z"),  # não é data
    ],
)
def test_datas_invalidas(raw: bytes) -> None:
    with pytest.raises(Asn1Error):
        asn1.decode_time(asn1.parse_one(raw))


@pytest.mark.parametrize(
    ("tag", "raw", "text"),
    [
        (0x0C, "São Paulo".encode(), "São Paulo"),
        (0x13, b"Exemplo", "Exemplo"),
        (0x16, b"a@b", "a@b"),
        (0x14, "Mexico é".encode("latin-1"), "Mexico é"),
        (0x1E, "Ação".encode("utf-16-be"), "Ação"),
        (0x1C, "Ação".encode("utf-32-be"), "Ação"),
    ],
)
def test_textos_de_nome(tag: int, raw: bytes, text: str) -> None:
    assert asn1.decode_string(asn1.parse_one(der(tag, raw))) == text


def test_texto_de_tipo_desconhecido() -> None:
    with pytest.raises(Asn1Error):
        asn1.decode_string(asn1.parse_one(der(0x02, b"\x01")))
    with pytest.raises(Asn1Error):
        asn1.decode_string(asn1.parse_one(der(0x80, b"x")))


def test_pem() -> None:
    first, second = build_cert(), build_cert(cn="outro")
    assert asn1.pem_certificates(to_pem(first) + "lixo\n" + to_pem(second)) == [first, second]
    assert asn1.pem_certificates("nada aqui") == []
    with pytest.raises(Asn1Error):
        asn1.pem_certificates("-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----")


# -- certificado da fixture --------------------------------------------------------------
def test_certificado_da_fixture() -> None:
    raw = fixture_der()
    assert asn1.pem_certificates(FIXTURE_CERT.read_text(encoding="ascii")) == [raw]
    cert = x509.parse_certificate(raw)
    assert cert.version == 3
    assert cert.common_name == "localhost"
    assert cert.subject.get("O") == "EIGAN Testes"
    assert cert.issuer.text == cert.subject.text
    assert cert.not_before == datetime(2026, 11, 1, 21, 5, 34, tzinfo=UTC)
    assert cert.not_after == datetime(2126, 10, 8, 21, 5, 34, tzinfo=UTC)
    assert cert.san_dns == ("localhost",)
    assert cert.san_ip == ("127.0.0.1",)
    assert cert.names == ("localhost", "127.0.0.1")
    assert (cert.key.kind, cert.key.bits, cert.key.label) == ("RSA", 2048, "RSA 2048 bits")
    assert (cert.signature, cert.signature_hash) == ("sha256WithRSAEncryption", "sha256")
    assert cert.is_ca and cert.self_signed and cert.self_issued
    assert not cert.weak_signature
    assert cert.ski == cert.aki and cert.ski is not None
    assert cert.ski.hex().startswith("09ec939d")
    assert cert.sha256 == hashlib.sha256(raw).hexdigest()
    assert cert.ca_issuers == ()


# -- certificados montados ---------------------------------------------------------------
def test_chaves_ec() -> None:
    cert = x509.parse_certificate(build_cert(spki=ec_spki(OID_P384)))
    assert (cert.key.kind, cert.key.curve, cert.key.bits) == ("EC", "P-384", 384)
    assert cert.key.label == "EC P-384"
    assert x509.parse_certificate(build_cert(spki=ec_spki(OID_P224))).key.bits == 224


def test_curva_desconhecida_fica_sem_tamanho() -> None:
    cert = x509.parse_certificate(build_cert(spki=ec_spki("1.2.3.4")))
    assert (cert.key.kind, cert.key.curve, cert.key.bits) == ("EC", "1.2.3.4", 0)


def test_curva_com_parametros_explicitos() -> None:
    spki = seq(seq(oid("1.2.840.10045.2.1"), seq(integer(1))), der(0x03, b"\x00\x04"))
    key = x509.parse_certificate(build_cert(spki=spki)).key
    assert (key.kind, key.bits, key.curve) == ("EC", 0, "parâmetros explícitos")


def test_chaves_ed25519_dsa_e_desconhecida() -> None:
    assert x509.parse_certificate(build_cert(spki=ed25519_spki())).key.label == "Ed25519"
    assert x509.parse_certificate(build_cert(spki=dsa_spki(1024))).key.bits == 1024
    unknown = seq(seq(oid("1.2.3.4.5")), der(0x03, b"\x00\x01"))
    key = x509.parse_certificate(build_cert(spki=unknown)).key
    assert (key.kind, key.bits) == ("1.2.3.4.5", 0)


def test_modulo_rsa_sem_zero_a_esquerda_nao_vira_negativo() -> None:
    modulus = der(0x02, b"\xff" * 128)  # fora do padrão: o bit alto ligado sem o zero na frente
    key_bytes = seq(modulus, integer(65537))
    spki = seq(seq(oid("1.2.840.113549.1.1.1"), der(0x05, b"")), der(0x03, b"\x00" + key_bytes))
    assert x509.parse_certificate(build_cert(spki=spki)).key.bits == 1024


def test_tamanho_exato_do_modulo_rsa() -> None:
    assert x509.parse_certificate(build_cert(spki=rsa_spki(1024))).key.bits == 1024
    assert x509.parse_certificate(build_cert(spki=rsa_spki(4096))).key.bits == 4096


@pytest.mark.parametrize(
    ("algorithm", "label", "digest", "weak"),
    [
        (OID_SHA1_RSA, "sha1WithRSAEncryption", "sha1", True),
        (OID_MD5_RSA, "md5WithRSAEncryption", "md5", True),
        (OID_ECDSA_SHA256, "ecdsa-with-SHA256", "sha256", False),
        ("1.3.101.112", "Ed25519", None, False),
        ("1.2.3.4", "1.2.3.4", "desconhecido", False),
    ],
)
def test_algoritmos_de_assinatura(
    algorithm: str, label: str, digest: str | None, weak: bool
) -> None:
    cert = x509.parse_certificate(build_cert(signature=sig_algorithm(algorithm)))
    assert (cert.signature, cert.signature_hash, cert.weak_signature) == (label, digest, weak)


def test_rsassa_pss_le_o_hash_dos_parametros() -> None:
    cert = x509.parse_certificate(build_cert(signature=pss_algorithm()))
    assert (cert.signature, cert.signature_hash, cert.weak_signature) == (
        "rsassaPss",
        "sha256",
        False,
    )
    # Sem o campo [0], o padrão da RFC 4055 é SHA-1.
    default = x509.parse_certificate(build_cert(signature=pss_algorithm(None)))
    assert default.signature_hash == "sha1" and default.weak_signature
    explicit_sha1 = x509.parse_certificate(build_cert(signature=pss_algorithm(OID_SHA1)))
    assert explicit_sha1.signature_hash == "sha1"


def test_generalized_time_em_data_distante() -> None:
    end = datetime(2060, 5, 4, 3, 2, 1, tzinfo=UTC)
    cert = x509.parse_certificate(build_cert(not_before=end - timedelta(days=10), not_after=end))
    assert cert.not_after == end
    assert cert.lifetime == timedelta(days=10)


def test_certificado_v1_sem_extensoes() -> None:
    cert = x509.parse_certificate(build_cert(version3=False, cn="antigo"))
    assert cert.version == 1
    assert cert.names == () and not cert.is_ca
    assert cert.common_name == "antigo"


def test_autoassinado_exige_mesmo_nome_e_mesma_chave() -> None:
    from fakes_tls import name

    same = name("x")
    assert x509.parse_certificate(build_cert(cn="x", issuer=same)).self_signed
    linked = build_cert(cn="x", issuer=same, ski=b"\x01" * 20, aki=b"\x01" * 20)
    assert x509.parse_certificate(linked).self_signed
    # Mesmo nome com identificadores de chave diferentes: é uma raiz renovada, não autoassinado.
    renewed = build_cert(cn="x", issuer=same, ski=b"\x01" * 20, aki=b"\x02" * 20)
    parsed = x509.parse_certificate(renewed)
    assert parsed.self_issued and not parsed.self_signed
    assert not x509.parse_certificate(build_cert(cn="x")).self_signed


def test_aia_guarda_so_o_endereco_do_emissor() -> None:
    cert = x509.parse_certificate(build_cert(aia=("http://ca.exemplo/intermediario.der",)))
    assert cert.ca_issuers == ("http://ca.exemplo/intermediario.der",)


def test_extensao_opcional_quebrada_nao_impede_a_leitura() -> None:
    raw = build_cert(
        san_dns=(),
        extra_extensions=(
            extension(OID_SAN, b"\x30\x05"),  # SAN truncado
            extension(OID_BASIC, b"\xff"),
            extension(OID_AKI, b"\x30\x01"),
        ),
    )
    cert = x509.parse_certificate(raw)
    assert cert.names == () and not cert.is_ca and cert.aki is None
    assert cert.common_name == "site.exemplo"


def test_nome_com_tipo_estranho_vira_hexadecimal() -> None:
    from fakes_tls import set_of

    issuer = seq(set_of(seq(oid("2.5.4.3"), der(0x02, b"\x07"))))
    assert x509.parse_certificate(build_cert(issuer=issuer)).issuer.get("CN") == "07"


def test_certificado_truncado_em_qualquer_ponto_vira_erro_proprio() -> None:
    raw = fixture_der()
    for cut in range(0, len(raw), 7):
        with pytest.raises(Asn1Error):
            x509.parse_certificate(raw[:cut])


def test_bytes_corrompidos_nunca_vazam_outra_excecao() -> None:
    """O certificado vem do alvo: lixo só pode virar Asn1Error ou um certificado lido."""
    raw = bytearray(build_cert(san_ip=("10.0.0.1",), aia=("http://a/",), ski=b"\x01", aki=b"\x02"))
    for position in range(len(raw)):
        for mask in (0x01, 0x80, 0xFF):
            corrupted = bytearray(raw)
            corrupted[position] ^= mask
            try:
                x509.parse_certificate(bytes(corrupted))
            except Asn1Error:
                pass


@pytest.mark.parametrize(
    "raw",
    [
        seq(seq(), seq()),  # só duas partes
        seq(seq(), sig_algorithm(), der(0x03, b"\x00")),  # TBS vazio
        seq(seq(integer(1)), sig_algorithm(), der(0x03, b"\x00")),
        b"\x02\x01\x01",  # nem é SEQUENCE
    ],
)
def test_estrutura_errada(raw: bytes) -> None:
    with pytest.raises(Asn1Error):
        x509.parse_certificate(raw)


# -- conferência do nome (RFC 9525) ------------------------------------------------------
@pytest.mark.parametrize(
    ("presented", "reference", "expected"),
    [
        ("site.exemplo", "site.exemplo", True),
        ("SITE.exemplo", "site.EXEMPLO", True),
        ("site.exemplo.", "site.exemplo", True),
        ("site.exemplo", "site.exemplo.", True),
        ("site.exemplo", "outro.exemplo", False),
        ("*.exemplo.com.br", "www.exemplo.com.br", True),
        ("*.exemplo.com.br", "exemplo.com.br", False),  # não vale para o domínio pai
        ("*.exemplo.com.br", "a.b.exemplo.com.br", False),  # só um rótulo
        ("w*.exemplo.com.br", "www.exemplo.com.br", False),  # curinga parcial é inválido
        ("www.*.com.br", "www.exemplo.com.br", False),  # só no rótulo mais à esquerda
        ("*.*.com.br", "a.b.com.br", False),
        ("*.com", "exemplo.com", False),  # não pode cobrir um sufixo inteiro
        ("", "exemplo.com", False),
        ("exemplo.com", "", False),
        ("xn--ao-siap.exemplo", "ação.exemplo", True),  # nome internacional vira A-label
    ],
)
def test_nome_dns(presented: str, reference: str, expected: bool) -> None:
    assert x509.dns_matches(presented, reference) is expected


def test_nome_impossivel_de_codificar_nao_casa() -> None:
    assert x509.dns_matches("a.exemplo", "a" * 70 + ".exemplo") is False


def test_cn_nao_conta_e_ip_precisa_estar_no_san() -> None:
    only_cn = x509.parse_certificate(build_cert(cn="site.exemplo", san_dns=()))
    assert not x509.matches_host(only_cn, "site.exemplo")
    with_ip = x509.parse_certificate(
        build_cert(san_dns=("a.exemplo",), san_ip=("192.0.2.1", "2001:db8::1"))
    )
    assert x509.matches_host(with_ip, "192.0.2.1")
    assert x509.matches_host(with_ip, "[2001:db8::1]")
    assert x509.matches_host(with_ip, "2001:0db8::0001")
    assert not x509.matches_host(with_ip, "192.0.2.2")
    # Nome DNS não vale para o endereço, mesmo que o texto seja igual.
    text_only = x509.parse_certificate(build_cert(san_dns=("192.0.2.1",)))
    assert not x509.matches_host(text_only, "192.0.2.1")
