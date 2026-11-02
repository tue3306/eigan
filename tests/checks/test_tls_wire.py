"""ClientHello montado à mão e leitura das respostas do servidor."""

from __future__ import annotations

import hashlib
import socket
import struct

import pytest
from fakes_tls import (
    ALERT_HANDSHAKE_FAILURE,
    ALERT_PROTOCOL_VERSION,
    EXT_KEY_SHARE,
    EXT_RENEGOTIATION_INFO,
    EXT_SIGNATURE_ALGORITHMS,
    EXT_SUPPORTED_VERSIONS,
    FALLBACK_SCSV,
    RSA_AES128,
    SILENT,
    SSL2,
    SSL3,
    TLS10,
    TLS11,
    TLS12,
    TLS13,
    FakeTlsServer,
    RawReplyServer,
    alert,
    certificate_message,
    handshake,
    parse_client_hello,
    record,
    server_hello,
    server_hello_body,
    sslv2_server_hello,
)

from eigan.checks.tls import suites, wire


# -- montagem ----------------------------------------------------------------------------
@pytest.mark.parametrize("version", [TLS10, TLS11, TLS12])
def test_client_hello_classico(version: int) -> None:
    hello = parse_client_hello(wire.client_hello(version, (0x002F, 0x0035), "site.exemplo"))
    assert hello.record_version == TLS10  # máxima compatibilidade no registro
    assert hello.version == version
    assert hello.suites == [0x002F, 0x0035]
    assert hello.sni == "site.exemplo"
    assert EXT_RENEGOTIATION_INFO in hello.extensions
    assert EXT_SUPPORTED_VERSIONS not in hello.extensions
    assert hello.session_id == b""


def test_assinaturas_so_a_partir_do_tls12() -> None:
    """A RFC 5246 pede que clientes antigos não ofereçam ``signature_algorithms``."""
    for version in (TLS10, TLS11):
        hello = parse_client_hello(wire.client_hello(version, (0x002F,), None))
        assert EXT_SIGNATURE_ALGORITHMS not in hello.extensions
    hello = parse_client_hello(wire.client_hello(TLS12, (0x002F,), None))
    assert EXT_SIGNATURE_ALGORITHMS in hello.extensions


def test_client_hello_sslv3_nao_tem_extensoes() -> None:
    hello = parse_client_hello(wire.client_hello(SSL3, suites.SSL3_PROBE, "site.exemplo"))
    assert hello.record_version == SSL3
    assert hello.version == SSL3
    assert hello.extensions == {}
    assert hello.sni is None
    assert 0x00FF in hello.suites  # o SCSV de renegociação faz o papel da extensão


def test_client_hello_tls13() -> None:
    hello = parse_client_hello(wire.client_hello(TLS13, suites.TLS13_PROBE, "site.exemplo"))
    assert hello.record_version == TLS10
    assert hello.version == TLS12  # legacy_version da RFC 8446
    assert hello.supported_versions == [TLS13]
    assert len(hello.session_id) == 32  # modo de compatibilidade com middleboxes
    group, size = struct.unpack("!HH", hello.extensions[EXT_KEY_SHARE][2:6])
    assert (group, size) == (wire.X25519, 32)


def test_sem_nome_nao_ha_sni() -> None:
    assert parse_client_hello(wire.client_hello(TLS12, (0x002F,), None)).sni is None


def test_nome_impossivel_de_codificar_segue_sem_sni() -> None:
    hello = parse_client_hello(wire.client_hello(TLS12, (0x002F,), "a" * 70 + ".exemplo"))
    assert hello.sni is None


@pytest.mark.parametrize(
    ("version", "offered"),
    [
        (TLS12, suites.TLS12_PROBE),
        (TLS11, suites.LEGACY_PROBE),
        (TLS10, suites.LEGACY_PROBE),
        (SSL3, suites.SSL3_PROBE),
        (TLS13, suites.TLS13_PROBE),
        (TLS12, suites.insecure_suites()),
        (TLS12, suites.broken_suites()),
        (TLS12, suites.triple_des_suites()),
        (TLS12, suites.forward_secret_suites()),
        (TLS12, suites.rsa_suites()),
    ],
)
def test_sondas_nunca_levam_fallback_scsv(version: int, offered: tuple[int, ...]) -> None:
    """Com o TLS_FALLBACK_SCSV, um servidor moderno recusaria de propósito (falso negativo)."""
    hello = parse_client_hello(wire.client_hello(version, offered, "site.exemplo"))
    assert FALLBACK_SCSV not in hello.suites
    assert hello.suites == list(offered)


def test_tamanho_problematico_ganha_padding() -> None:
    """Implementações antigas travam com ClientHello de 256 a 511 bytes (RFC 7685)."""
    for count in range(1, 140):
        offered = tuple(range(0x0100, 0x0100 + count))
        raw = wire.client_hello(TLS12, offered, "site.exemplo")
        message = len(raw) - 5
        assert not 256 <= message < 512, f"{count} suítes geraram {message} bytes"
        assert parse_client_hello(raw).suites == list(offered)


def test_client_hello_sslv2() -> None:
    raw = wire.sslv2_client_hello()
    hello = parse_client_hello(raw)
    assert hello.sslv2 and hello.version == SSL2
    assert raw[0] & 0x80
    assert len(raw) == 2 + ((raw[0] & 0x7F) << 8 | raw[1])
    assert hello.suites[:2] == [0x010080, 0x020080]
    assert len(hello.suites) == 7


def test_random_do_hello_retry_request() -> None:
    assert wire.HRR_RANDOM == hashlib.sha256(b"HelloRetryRequest").digest()
    assert wire.HRR_RANDOM.hex().startswith("cf21ad74")


# -- ServerHello -------------------------------------------------------------------------
def test_server_hello_com_sessao_e_extensoes() -> None:
    body = server_hello_body(
        TLS12,
        RSA_AES128,
        session_id=b"\x07" * 16,
        compression=1,
        extensions={EXT_RENEGOTIATION_INFO: b"\x00"},
    )
    hello = wire.parse_server_hello(body)
    assert (hello.version, hello.selected, hello.suite) == (TLS12, TLS12, RSA_AES128)
    assert hello.compression == 1
    assert hello.extensions == {EXT_RENEGOTIATION_INFO: b"\x00"}
    assert hello.retry is False


def test_server_hello_tls13_usa_a_extensao() -> None:
    body = server_hello_body(
        TLS12, 0x1301, extensions={EXT_SUPPORTED_VERSIONS: struct.pack("!H", TLS13)}
    )
    hello = wire.parse_server_hello(body)
    assert (hello.version, hello.selected) == (TLS12, TLS13)


def test_hello_retry_request() -> None:
    body = server_hello_body(TLS12, 0x1301, random=wire.HRR_RANDOM)
    assert wire.parse_server_hello(body).retry is True


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"\x03\x03" + b"\x00" * 30,  # curto demais
        b"\x03\x03" + b"\x00" * 32 + b"\x20" + b"\x00" * 3,  # sessão além do fim
        server_hello_body(TLS12, 1) + b"\x00\x10\x00",  # extensões truncadas
        server_hello_body(TLS12, 1) + b"\x00\x04\x00\x01\x00\x09",  # extensão truncada
    ],
)
def test_server_hello_mal_formado(body: bytes) -> None:
    with pytest.raises(wire.WireError):
        wire.parse_server_hello(body)


# -- registros ---------------------------------------------------------------------------
def test_resposta_completa() -> None:
    reply = wire.parse_tls_reply(server_hello(TLS10, RSA_AES128))
    assert reply is not None and reply.kind == wire.SERVER_HELLO
    assert reply.hello is not None and reply.hello.suite == RSA_AES128


def test_resposta_fragmentada_em_varios_registros_e_pedacos() -> None:
    message = handshake(2, server_hello_body(TLS12, RSA_AES128))
    raw = record(22, TLS12, message[:10]) + record(22, TLS12, message[10:])
    for cut in range(len(raw)):
        assert wire.parse_tls_reply(raw[:cut]) is None
    reply = wire.parse_tls_reply(raw)
    assert reply is not None and reply.kind == wire.SERVER_HELLO


def test_mensagens_seguintes_no_mesmo_registro() -> None:
    message = handshake(2, server_hello_body(TLS12, RSA_AES128)) + certificate_message([b"x"])
    reply = wire.parse_tls_reply(record(22, TLS12, message))
    assert reply is not None and reply.kind == wire.SERVER_HELLO


def test_alerta_fatal() -> None:
    reply = wire.parse_tls_reply(alert(ALERT_PROTOCOL_VERSION))
    assert reply is not None and reply.kind == wire.ALERT
    assert reply.alert == ALERT_PROTOCOL_VERSION
    assert "protocol_version" in reply.detail


def test_alerta_de_aviso_nao_encerra_e_o_server_hello_vale() -> None:
    raw = alert(112, level=1) + server_hello(TLS12, RSA_AES128)
    reply = wire.parse_tls_reply(raw)
    assert reply is not None and reply.kind == wire.SERVER_HELLO
    assert wire.parse_tls_reply(alert(112, level=1)) is None


def test_close_notify_encerra() -> None:
    reply = wire.parse_tls_reply(alert(0, level=1))
    assert reply is not None and reply.kind == wire.ALERT


def test_alerta_desconhecido_mostra_o_numero() -> None:
    assert "199" in wire.alert_text(199)


@pytest.mark.parametrize(
    "raw",
    [
        b"HTTP/1.1 400 Bad Request\r\n\r\n",  # serviço que não fala TLS
        b"SSH-2.0-OpenSSH_9.6\r\n",
        record(23, TLS12, b"x"),  # dados de aplicação antes do ServerHello
        record(21, TLS12, b"\x02"),  # alerta truncado
        record(22, TLS12, handshake(11, b"")),  # outra mensagem no lugar do ServerHello
        record(22, TLS12, handshake(2, b"\x03")),  # ServerHello mal formado
        struct.pack("!BHH", 22, TLS12, 30000),  # registro grande demais
    ],
)
def test_resposta_invalida(raw: bytes) -> None:
    reply = wire.parse_tls_reply(raw)
    assert reply is not None and reply.kind == wire.INVALID


# -- SSL 2.0 -----------------------------------------------------------------------------
def test_resposta_sslv2() -> None:
    raw = sslv2_server_hello(ciphers=3)
    for cut in range(len(raw)):
        assert wire.parse_sslv2_reply(raw[:cut]) is None
    reply = wire.parse_sslv2_reply(raw)
    assert reply is not None and reply.kind == wire.SSL2_SERVER_HELLO
    assert reply.sslv2_ciphers == 3


@pytest.mark.parametrize(
    ("raw", "kind"),
    [
        (alert(ALERT_HANDSHAKE_FAILURE), wire.ALERT),
        (b"\x80\x03\x00\x00\x01", wire.ALERT),  # MSG-ERROR
        (b"HTTP/1.1 400 Bad Request\r\n\r\n", wire.INVALID),
        (sslv2_server_hello(version=TLS10), wire.INVALID),  # versão errada não é SSLv2
        (sslv2_server_hello(kind=7), wire.INVALID),
    ],
)
def test_resposta_que_nao_e_sslv2(raw: bytes, kind: str) -> None:
    reply = wire.parse_sslv2_reply(raw)
    assert reply is not None and reply.kind == kind


# -- leitura da cadeia -------------------------------------------------------------------
def test_mensagem_certificate() -> None:
    body = certificate_message([b"primeiro", b"segundo"])[4:]
    assert wire.parse_certificates(body) == [b"primeiro", b"segundo"]
    assert wire.parse_certificates(b"\x00\x00\x00") == []


@pytest.mark.parametrize("body", [b"", b"\x00", b"\x00\x00\x09abc", b"\x00\x00\x04\x00\x00\x09a"])
def test_mensagem_certificate_mal_formada(body: bytes) -> None:
    with pytest.raises(wire.WireError):
        wire.parse_certificates(body)


def test_mensagens_de_handshake() -> None:
    first = handshake(2, b"aa")
    second = handshake(11, b"bbb")
    joined = first + second
    assert wire.handshake_messages(record(22, TLS12, joined)) == [(2, b"aa"), (11, b"bbb")]
    # A última mensagem incompleta fica de fora até o resto chegar.
    assert wire.handshake_messages(record(22, TLS12, joined[:-1])) == [(2, b"aa")]
    assert wire.handshake_messages(alert(40)) is None


# -- conversa com o servidor -------------------------------------------------------------
HELLO = wire.client_hello(TLS12, (RSA_AES128,), None)


def _closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def test_exchange_le_o_server_hello() -> None:
    with FakeTlsServer(lambda _hello: server_hello(TLS12, RSA_AES128)) as srv:
        reply = wire.exchange("127.0.0.1", srv.port, HELLO, 2.0)
    assert reply.kind == wire.SERVER_HELLO


def test_exchange_conexao_recusada() -> None:
    assert wire.exchange("127.0.0.1", _closed_port(), HELLO, 1.0).kind == wire.NO_CONNECTION


def test_exchange_conexao_encerrada() -> None:
    with FakeTlsServer(lambda _hello: None) as srv:
        assert wire.exchange("127.0.0.1", srv.port, HELLO, 2.0).kind == wire.CLOSED


def test_exchange_sem_resposta_respeita_o_prazo() -> None:
    with FakeTlsServer(lambda _hello: SILENT) as srv:
        assert wire.exchange("127.0.0.1", srv.port, HELLO, 0.2).kind == wire.NO_REPLY


def test_exchange_resposta_interminavel_tem_limite(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(wire, "MAX_REPLY", 10)
    incomplete = alert(112, level=1) * 4 + b"\x16\x03\x03\x40"
    with RawReplyServer(incomplete) as srv:
        assert wire.exchange("127.0.0.1", srv.port, HELLO, 2.0).kind == wire.INVALID


def test_read_certificates() -> None:
    reply = server_hello(TLS12, RSA_AES128) + record(
        22, TLS12, certificate_message([b"folha", b"meio"])
    )
    with FakeTlsServer(lambda _hello: reply) as srv:
        assert wire.read_certificates("127.0.0.1", srv.port, HELLO, 2.0) == [b"folha", b"meio"]


@pytest.mark.parametrize(
    "reply",
    [
        alert(ALERT_HANDSHAKE_FAILURE),
        server_hello(TLS12, RSA_AES128),  # termina sem o certificado
        server_hello(TLS12, RSA_AES128) + record(22, TLS12, handshake(11, b"\x00\x00\x09a")),
    ],
)
def test_read_certificates_sem_cadeia(reply: bytes) -> None:
    with FakeTlsServer(lambda _hello: reply) as srv:
        assert wire.read_certificates("127.0.0.1", srv.port, HELLO, 2.0) == []


def test_read_certificates_sem_conexao_e_sem_resposta() -> None:
    assert wire.read_certificates("127.0.0.1", _closed_port(), HELLO, 1.0) == []
    with FakeTlsServer(lambda _hello: SILENT) as srv:
        assert wire.read_certificates("127.0.0.1", srv.port, HELLO, 0.2) == []
