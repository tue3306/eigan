"""Intérpretes de protocolo com bytes montados à mão (sem rede)."""

from __future__ import annotations

import struct

import pytest
from fakes_net import (
    amqp_start,
    cql_frame,
    cql_supported,
    mongo_msg,
    mongo_reply,
    mysql_error,
    mysql_greeting,
    rdp_confirm,
    smb1_response,
    smb2_response,
    tds_prelogin_response,
    tns_refuse,
)

from eigan.checks.net import banners, mongo, probes, winproto
from eigan.checks.net.common import printable, service_asset

# -- banners ------------------------------------------------------------------------------


def test_banner_ssh_openssh_com_comentario() -> None:
    found = banners.classify_banner(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n", 22)
    assert found is not None
    assert (found.service, found.product, found.version) == ("ssh", "openssh", "8.9p1")
    assert found.extra["protocolo"] == "2.0"
    assert found.extra["comentario"] == "Ubuntu-3ubuntu0.10"


def test_banner_ssh_openssh_windows_e_dropbear() -> None:
    windows = banners.parse_ssh_banner("SSH-2.0-OpenSSH_for_Windows_8.1")
    assert windows is not None
    assert windows.version == "8.1"
    assert windows.extra["plataforma"] == "windows"
    dropbear = banners.parse_ssh_banner("SSH-2.0-dropbear_2022.83")
    assert dropbear is not None
    assert (dropbear.product, dropbear.version) == ("dropbear", "2022.83")


def test_banner_ssh_invalido_nao_vira_servico() -> None:
    assert banners.parse_ssh_banner("nao é ssh") is None
    assert banners.classify_banner(b"SSH-\r\n", 22) is None


def test_saudacao_mysql_oficial() -> None:
    found = banners.parse_mysql_greeting(mysql_greeting("8.0.35"))
    assert found is not None
    assert (found.service, found.product, found.version) == ("mysql", "mysql", "8.0.35")


def test_saudacao_mariadb_com_prefixo_de_compatibilidade() -> None:
    found = banners.parse_mysql_greeting(mysql_greeting("5.5.5-10.6.12-MariaDB-0ubuntu0.22.04.1"))
    assert found is not None
    assert (found.product, found.version) == ("mariadb", "10.6.12")


def test_mysql_erro_inicial_host_bloqueado() -> None:
    found = banners.parse_mysql_greeting(mysql_error(1130))
    assert found is not None
    assert found.service == "mysql"
    assert found.extra["erro"] == 1130


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\x05\x00",
        b"GET / HTTP/1.1\r\n",
        # número de sequência diferente de 0
        b"\x0a\x00\x00\x01\x0a8.0.1\x00\x00\x00\x00",
        # protocolo 10 sem versão numérica
        b"\x08\x00\x00\x00\x0aabc\x00\x00\x00\x00",
        # pacote de erro com código fora da faixa do MySQL
        b"\x05\x00\x00\x00\xff\x01\x00ab",
    ],
)
def test_saudacao_mysql_falso_positivo(data: bytes) -> None:
    assert banners.parse_mysql_greeting(data) is None


def test_telnet_iac_e_rfb() -> None:
    assert banners.is_telnet(b"\xff\xfd\x18\xff\xfd\x20")
    assert banners.is_telnet(b"\xff\xfb\x01")
    assert not banners.is_telnet(b"\xff\x00")
    assert not banners.is_telnet(b"220 ftp\r\n")
    assert banners.rfb_version(b"RFB 003.008\n") == (3, 8)
    assert banners.rfb_version(b"RFB 3.8\n") is None


@pytest.mark.parametrize(
    ("data", "port", "service", "product", "version"),
    [
        (b"220 (vsFTPd 3.0.5)\r\n", 2100, "ftp", "vsftpd", "3.0.5"),
        (b"220 ProFTPD 1.3.5 Server (Debian)\r\n", 21, "ftp", "proftpd", "1.3.5"),
        (b"220-FileZilla Server 1.8.0\r\n220 ok\r\n", 21, "ftp", "filezilla-server", "1.8.0"),
        (b"220 Microsoft FTP Service\r\n", 21, "ftp", "iis-ftp", ""),
        (b"220 mx.exemplo.com ESMTP Postfix (Ubuntu)\r\n", 25, "smtp", "postfix", ""),
        (b"220 mx.exemplo.com ESMTP Exim 4.96 Mon, 1 Jan\r\n", 25, "smtp", "exim", "4.96"),
        (b"220 ftp.empresa.com ESMTP\r\n", 25, "smtp", "", ""),
        (b"220 Bem-vindo\r\n", 21, "ftp", "", ""),
        (b"220 Bem-vindo\r\n", 587, "smtp", "", ""),
        (b"+OK Dovecot (Ubuntu) ready.\r\n", 110, "pop3", "dovecot", ""),
        (b"* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n", 143, "imap", "dovecot", ""),
        (b"* PREAUTH IMAP4rev1 server\r\n", 143, "imap", "", ""),
        (b"HTTP/1.1 400 Bad Request\r\n\r\n", 8000, "http", "", ""),
        (b"-NOAUTH Authentication required.\r\n", 7000, "redis", "redis", ""),
        (b"login: ", 23, "telnet", "", ""),
    ],
)
def test_classificacao_de_banners(
    data: bytes, port: int, service: str, product: str, version: str
) -> None:
    found = banners.classify_banner(data, port)
    assert found is not None
    assert (found.service, found.product, found.version) == (service, product, version)
    assert found.confirmed


def test_banner_220_sem_pista_pede_desempate() -> None:
    found = banners.classify_banner(b"220 Bem-vindo\r\n", 7777)
    assert found is not None
    assert found.service == "ftp-ou-smtp"
    assert not found.confirmed


def test_banner_vnc_guarda_versao_do_protocolo_como_extra() -> None:
    found = banners.classify_banner(b"RFB 003.008\n", 5900)
    assert found is not None
    assert (found.service, found.product, found.version) == ("vnc", "vnc", "")
    assert found.extra["rfb"] == "3.8"


@pytest.mark.parametrize("data", [b"", b"qualquer coisa\r\n", b"\x00\x01\x02\x03", b"login: "])
def test_classificacao_nao_inventa_servico(data: bytes) -> None:
    assert banners.classify_banner(data, 7777) is None


def test_printable_remove_bytes_de_controle() -> None:
    assert printable(b"abc\x00\x01def") == "abc  def"
    assert printable(b"x" * 500, limit=10) == "x" * 10


def test_ativo_de_servico_ipv6_entre_colchetes() -> None:
    assert service_asset("10.0.0.1", 80) == "10.0.0.1:80/tcp"
    assert service_asset("::1", 53, "udp") == "[::1]:53/udp"


# -- Redis, Memcached, PostgreSQL ----------------------------------------------------------


def test_redis_ping_formas_de_resposta() -> None:
    assert probes.REDIS_PING == b"*1\r\n$4\r\nPING\r\n"
    aberto = probes.parse_redis(b"+PONG\r\n")
    assert aberto is not None
    assert aberto.extra["autenticacao"] == "nenhuma"
    senha = probes.parse_redis(b"-NOAUTH Authentication required.\r\n")
    assert senha is not None
    assert senha.extra["autenticacao"] == "senha"
    protegido = probes.parse_redis(b"-DENIED Redis is running in protected mode\r\n")
    assert protegido is not None
    assert protegido.extra["autenticacao"] == "modo protegido"
    assert probes.parse_redis(b"HTTP/1.1 400 Bad Request\r\n") is None
    assert probes.parse_redis(b"") is None


def test_redis_info_campos() -> None:
    body = b"# Server\r\nredis_version:7.2.4\r\nos:Linux 5.15\r\nredis_mode:standalone\r\n"
    info = probes.parse_redis_info(b"$%d\r\n" % len(body) + body)
    assert info == {"redis_version": "7.2.4", "os": "Linux 5.15", "redis_mode": "standalone"}


def test_memcached_versao_e_stats() -> None:
    found = probes.parse_memcached(b"VERSION 1.6.21\r\n")
    assert found is not None
    assert found.version == "1.6.21"
    assert probes.parse_memcached(b"ERROR\r\n") is None
    stats = probes.parse_memcached_stats(b"STAT pid 12\r\nSTAT version 1.6.21\r\nEND\r\n")
    assert stats == {"pid": "12", "version": "1.6.21"}
    assert probes.parse_memcached_stats(b"ERROR\r\n") == {}


def test_postgres_sslrequest_bytes_e_respostas() -> None:
    assert probes.POSTGRES_SSLREQUEST == bytes.fromhex("0000000804D2162F")
    com_tls = probes.parse_postgres(b"S")
    assert com_tls is not None
    assert com_tls.extra["tls"] is True
    sem_tls = probes.parse_postgres(b"N")
    assert sem_tls is not None
    assert sem_tls.extra["tls"] is False
    antigo = probes.parse_postgres(b"E\x00\x00\x00\x20SFATAL\x00VFATAL\x00")
    assert antigo is not None
    assert probes.parse_postgres(b"SN") is None
    assert probes.parse_postgres(b"Erro generico") is None


# -- SQL Server ----------------------------------------------------------------------------


def test_mssql_prelogin_estrutura() -> None:
    packet = probes.mssql_prelogin()
    kind, status, length = struct.unpack(">BBH", packet[:4])
    assert (kind, status, length) == (0x12, 0x01, len(packet))
    payload = packet[8:]
    assert payload[0] == 0x00  # primeiro token: VERSION
    # a tabela termina em 0xFF e o primeiro deslocamento aponta logo depois dela
    assert payload[25] == 0xFF
    assert struct.unpack(">H", payload[1:3])[0] == 26


def test_mssql_resposta_com_versao() -> None:
    found = probes.parse_mssql(tds_prelogin_response(15, 0, 2000))
    assert found is not None
    assert (found.service, found.product, found.version) == ("mssql", "mssql", "15.0.2000")
    assert found.extra["edicao"] == "SQL Server 2019"


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\x04\x01",
        b"HTTP/1.1 200 OK\r\n\r\n",
        struct.pack(">BBHHBB", 0x04, 1, 9, 0, 1, 0) + b"\xff",
    ],
)
def test_mssql_falso_positivo(data: bytes) -> None:
    assert probes.parse_mssql(data) is None


# -- AJP e AMQP ----------------------------------------------------------------------------


def test_ajp_cping_cpong() -> None:
    assert probes.AJP_CPING == bytes.fromhex("123400010A")
    found = probes.parse_ajp(bytes.fromhex("4142000109"))
    assert found is not None
    assert found.service == "ajp"
    assert found.extra["cpong"] is True
    assert probes.parse_ajp(b"AB\x00\x02\x04\x00") is None
    assert probes.parse_ajp(b"HTTP/1.1 400") is None


def test_amqp_connection_start_com_tabela_aninhada() -> None:
    found = probes.parse_amqp(amqp_start("RabbitMQ", "3.12.13"))
    assert found is not None
    assert (found.service, found.product, found.version) == ("amqp", "rabbitmq", "3.12.13")


def test_amqp_cabecalho_de_outra_versao_e_lixo() -> None:
    found = probes.parse_amqp(b"AMQP\x00\x00\x09\x01")
    assert found is not None
    assert found.service == "amqp"
    assert probes.parse_amqp(b"\x01\x00\x00\x00\x00\x00\x10nada disso aqui") is None
    assert probes.parse_amqp(b"") is None


def test_amqp_tabela_truncada_nao_quebra() -> None:
    frame = amqp_start()
    for size in range(12, len(frame), 7):
        probes.parse_amqp(frame[:size])  # nunca levanta exceção


# -- Cassandra -----------------------------------------------------------------------------


def test_cql_options_e_supported() -> None:
    assert probes.CQL_OPTIONS == b"\x04\x00\x00\x00\x05\x00\x00\x00\x00"
    found = probes.parse_cql(cql_supported())
    assert found is not None
    assert found.service == "cassandra"
    assert found.extra["cql"] == "3.4.5"
    erro = probes.parse_cql(cql_frame(0x00, b"\x00\x00\x00\x0a\x00\x02no"))
    assert erro is not None
    assert probes.parse_cql(b"\x04\x00\x00\x00\x06\x00\x00\x00\x00") is None  # sem bit de resposta
    assert probes.parse_cql(cql_frame(0x02)) is None  # READY não é resposta a OPTIONS
    assert probes.parse_cql(b"HTTP/1.1 400 Bad Request") is None


def test_cql_startup_estrutura_e_estados() -> None:
    frame = probes.cql_startup(4)
    version, flags, stream, opcode, length = struct.unpack(">BBHBI", frame[:9])
    assert (version, flags, stream, opcode) == (4, 0, 1, 0x01)
    assert length == len(frame) - 9
    assert b"CQL_VERSION" in frame
    assert probes.parse_cql_startup(cql_frame(0x02)) == "pronto"
    assert probes.parse_cql_startup(cql_frame(0x03)) == "autenticar"
    assert probes.parse_cql_startup(cql_frame(0x00)) == "erro"
    assert probes.parse_cql_startup(cql_frame(0x08)) is None
    assert probes.parse_cql_startup(b"\x04\x00\x00\x00\x02\x00\x00\x00\x00") is None
    assert probes.parse_cql_startup(b"") is None


# -- VNC -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("server", "reply"),
    [
        ((3, 8), b"RFB 003.008\n"),
        ((3, 889), b"RFB 003.008\n"),
        ((4, 0), b"RFB 003.008\n"),
        ((3, 7), b"RFB 003.007\n"),
        ((3, 3), b"RFB 003.003\n"),
        ((3, 6), b"RFB 003.003\n"),
    ],
)
def test_rfb_versao_do_cliente(server: tuple[int, int], reply: bytes) -> None:
    assert probes.rfb_client_version(server) == reply


def test_rfb_tipos_de_seguranca_38() -> None:
    sem_senha = probes.parse_rfb_security(b"\x02\x01\x02", 8)
    assert sem_senha is not None
    assert sem_senha.types == (1, 2)
    assert sem_senha.no_auth
    assert "Nenhuma" in sem_senha.describe()
    com_senha = probes.parse_rfb_security(b"\x01\x02", 8)
    assert com_senha is not None
    assert not com_senha.no_auth
    assert "desconhecido" in probes.RfbSecurity(types=(99,)).describe()


def test_rfb_recusa_e_truncado() -> None:
    recusa = probes.parse_rfb_security(b"\x00\x00\x00\x00\x09too many!", 8)
    assert recusa is not None
    assert recusa.types == ()
    assert recusa.reason == "too many!"
    assert probes.parse_rfb_security(b"", 8) is None
    assert probes.parse_rfb_security(b"\x03\x01", 8) is None


def test_rfb_versao_33_servidor_escolhe() -> None:
    sem_senha = probes.parse_rfb_security(struct.pack(">I", 1), 3)
    assert sem_senha is not None
    assert sem_senha.no_auth
    com_senha = probes.parse_rfb_security(struct.pack(">I", 2), 3)
    assert com_senha is not None
    assert com_senha.types == (2,)
    recusa = probes.parse_rfb_security(struct.pack(">I", 0) + struct.pack(">I", 2) + b"no", 3)
    assert recusa is not None
    assert recusa.reason == "no"
    assert probes.parse_rfb_security(b"\x00\x00", 3) is None


# -- DNS e Oracle --------------------------------------------------------------------------


def test_dns_por_tcp_confirma_o_protocolo() -> None:
    query = probes.DNS_QUERY_TCP
    assert int.from_bytes(query[:2], "big") == len(query) - 2
    flags = int.from_bytes(query[4:6], "big")
    assert flags & 0x0100 == 0  # sem pedir recursão
    answer = bytes(query[:2]) + struct.pack(">HH", probes.DNS_PROBE_ID, 0x8405) + b"\x00" * 8
    found = probes.parse_dns_tcp(answer)
    assert found is not None
    assert found.extra["rcode"] == "REFUSED"
    wrong_id = bytes(query[:2]) + struct.pack(">HH", 0x1111, 0x8000) + b"\x00" * 8
    assert probes.parse_dns_tcp(wrong_id) is None
    not_reply = bytes(query[:2]) + struct.pack(">HH", probes.DNS_PROBE_ID, 0x0000) + b"\x00" * 8
    assert probes.parse_dns_tcp(not_reply) is None
    assert probes.parse_dns_tcp(b"SSH-2.0-x\r\n") is None


def test_tns_pacote_connect_estrutura() -> None:
    packet = probes.tns_connect()
    assert int.from_bytes(packet[:2], "big") == len(packet)
    assert packet[4] == 1  # CONNECT
    assert packet[58:] == probes.TNS_VERSION_COMMAND.encode("ascii")
    # tamanho e deslocamento dos dados de conexão no corpo do pacote
    assert struct.unpack(">HH", packet[24:28]) == (len(probes.TNS_VERSION_COMMAND), 58)


def test_tns_versao_em_texto_e_vsnnum() -> None:
    texto = probes.parse_tns(tns_refuse("TNSLSNR for Linux: Version 19.3.0.0.0 - Production"))
    assert texto is not None
    assert (texto.service, texto.product, texto.version) == ("oracle-tns", "oracle", "19.3.0.0.0")
    numero = probes.parse_tns(
        tns_refuse("(DESCRIPTION=(ERR=1189)(VSNNUM=318767104)(ERROR_STACK=()))")
    )
    assert numero is not None
    assert numero.version == "19.0.0.0.0"
    assert probes.decode_vsnnum(0x0B200200) == "11.2.0.2.0"
    assert probes.parse_tns(b"HTTP/1.1 400 Bad Request\r\n") is None
    assert probes.parse_tns(b"\x00\x05\x00\x00\x09\x00\x00\x00") is None


# -- RDP -----------------------------------------------------------------------------------


def test_rdp_pedido_estrutura() -> None:
    request = winproto.rdp_request(winproto.PROTOCOL_SSL | winproto.PROTOCOL_HYBRID)
    assert request[:2] == b"\x03\x00"
    assert int.from_bytes(request[2:4], "big") == len(request)
    assert request[4] == len(request) - 5  # LI não conta a si mesmo
    assert request[5] == 0xE0
    assert b"Cookie: mstshash=eigan\r\n" in request
    # RDP_NEG_REQ: tipo 1, flags 0, tamanho 8, protocolos 3
    assert request[-8:] == bytes.fromhex("0100080003000000")


def test_rdp_resposta_seleciona_protocolo() -> None:
    result = winproto.parse_rdp(rdp_confirm(0x02, winproto.PROTOCOL_HYBRID))
    assert result is not None
    assert result.accepted
    assert result.selected == winproto.PROTOCOL_HYBRID
    assert "CredSSP" in result.describe()


def test_rdp_resposta_falha_com_codigo() -> None:
    result = winproto.parse_rdp(rdp_confirm(0x03, winproto.HYBRID_REQUIRED_BY_SERVER))
    assert result is not None
    assert not result.accepted
    assert result.failure == 5
    assert "HYBRID_REQUIRED_BY_SERVER" in result.describe()


def test_rdp_servidor_antigo_sem_negociacao() -> None:
    result = winproto.parse_rdp(rdp_confirm())
    assert result is not None
    assert result.legacy
    assert result.selected == winproto.PROTOCOL_RDP
    assert "antigo" in result.describe()


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\x03\x00\x00\x0b",
        b"HTTP/1.1 400 Bad Request\r\n",
        b"\x03\x00\x00\x0b\x06\xe0\x00\x00\x00\x00\x00",
    ],
)
def test_rdp_falso_positivo(data: bytes) -> None:
    assert winproto.parse_rdp(data) is None


# -- SMB -----------------------------------------------------------------------------------


def test_smb1_negotiate_estrutura() -> None:
    packet = winproto.smb1_negotiate()
    assert packet[0] == 0
    assert int.from_bytes(packet[1:4], "big") == len(packet) - 4
    smb = packet[4:]
    assert smb[:5] == b"\xffSMB\x72"
    assert smb[32] == 0  # WordCount
    assert int.from_bytes(smb[33:35], "little") == 12  # ByteCount
    assert smb[35:] == b"\x02NT LM 0.12\x00"


def test_smb2_negotiate_estrutura() -> None:
    packet = winproto.smb2_negotiate()
    smb = packet[4:]
    assert smb[:4] == b"\xfeSMB"
    assert int.from_bytes(smb[4:6], "little") == 64
    assert int.from_bytes(smb[12:14], "little") == 0  # NEGOTIATE
    body = smb[64:]
    size, count, mode = struct.unpack("<HHH", body[:6])
    assert (size, count, mode) == (36, 4, 1)
    dialects = struct.unpack("<4H", body[36:44])
    assert dialects == (0x0202, 0x0210, 0x0300, 0x0302)
    assert winproto.smb2_negotiate() != packet  # ClientGuid muda a cada pedido


def test_smb1_habilitado_exige_wordcount_e_dialeto() -> None:
    result = winproto.parse_smb(smb1_response(security_mode=0x0C))
    assert result is not None
    assert (result.version, result.dialect) == (1, "NT LM 0.12")
    assert result.signing_enabled
    assert result.signing_required
    opcional = winproto.parse_smb(smb1_response(security_mode=0x04))
    assert opcional is not None
    assert not opcional.signing_required


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\x00\x00\x00",
        smb1_response(dialect_index=0xFFFF),  # nenhum dialeto serve
        smb1_response(word_count=1),  # resposta curta de recusa
        smb1_response(status=0xC0000022),  # erro
        b"\x82\x00\x00\x00",  # NetBIOS: resposta negativa de sessão
        b"\x00\x00\x00\x10HTTP/1.1 400 Bad",
    ],
)
def test_smb_falso_positivo(data: bytes) -> None:
    assert winproto.parse_smb(data) is None


def test_smb2_assinatura_no_security_mode() -> None:
    obrigatoria = winproto.parse_smb(smb2_response(dialect=0x0311, security_mode=0x03))
    assert obrigatoria is not None
    assert (obrigatoria.version, obrigatoria.dialect) == (2, "3.1.1")
    assert obrigatoria.signing_required
    opcional = winproto.parse_smb(smb2_response(dialect=0x0210, security_mode=0x01))
    assert opcional is not None
    assert opcional.dialect == "2.1"
    assert opcional.signing_enabled
    assert not opcional.signing_required
    desabilitada = winproto.parse_smb(smb2_response(security_mode=0x00))
    assert desabilitada is not None
    assert not desabilitada.signing_enabled
    assert winproto.parse_smb(smb2_response(status=0xC00000BB)) is None


# -- BSON e protocolo de fio do MongoDB ------------------------------------------------------


def test_bson_exemplo_da_especificacao() -> None:
    # exemplo publicado em https://bsonspec.org/faq.html
    raw = b"\x16\x00\x00\x00\x02hello\x00\x06\x00\x00\x00world\x00\x00"
    assert mongo.encode({"hello": "world"}) == raw
    assert mongo.decode(raw) == ({"hello": "world"}, len(raw))


def test_bson_ida_e_volta_de_todos_os_tipos() -> None:
    document = {
        "ok": 1.5,
        "nome": "açúcar",
        "ativo": True,
        "falso": False,
        "pequeno": 7,
        "grande": 2**40,
        "negativo": -3,
        "aninhado": {"a": 1, "b": {"c": "d"}},
        "lista": [1, "dois", {"tres": 3}],
        "nada": None,
        "bin": b"\x00\x01\x02",
    }
    decoded, end = mongo.decode(mongo.encode(document))
    assert decoded == document
    assert end == len(mongo.encode(document))


def test_bson_tipos_extras_na_decodificacao() -> None:
    oid = b"\x01" * 12
    regex = b"abc\x00i\x00"
    elements = (
        b"\x07oid\x00" + oid
        + b"\x09data\x00" + struct.pack("<q", 1000)
        + b"\x11ts\x00" + struct.pack("<q", 5)
        + b"\x13dec\x00" + b"\x02" * 16
        + b"\x0bre\x00" + regex
        + b"\x06undef\x00"
        + b"\xffmin\x00"
        + b"\x7fmax\x00"
        + b"\x0dcode\x00" + struct.pack("<i", 2) + b"x\x00"
    )  # fmt: skip
    raw = struct.pack("<i", len(elements) + 5) + elements + b"\x00"
    decoded, _end = mongo.decode(raw)
    assert decoded["oid"] == oid.hex()
    assert decoded["data"] == 1000
    assert decoded["re"] == "abc"
    assert decoded["undef"] is None
    assert decoded["code"] == "x"


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\x05\x00\x00",
        b"\x04\x00\x00\x00\x00",  # tamanho menor que o mínimo
        b"\x06\x00\x00\x00\x00\x00",  # elemento com tipo 0
        b"\xff\x00\x00\x00\x00",  # tamanho maior que os dados
        b"\x0c\x00\x00\x00\x02a\x00\x7f\x00\x00\x00\x00",  # string maior que o documento
        b"\x08\x00\x00\x00\x99a\x00\x00",  # tipo desconhecido
        b"\x0c\x00\x00\x00\x05a\x00\x7f\x00\x00\x00\x00",  # binário maior que o documento
    ],
)
def test_bson_malformado_nao_passa(raw: bytes) -> None:
    with pytest.raises((mongo.BsonError, ValueError)):
        mongo.decode(raw)


def test_bson_nome_com_byte_nulo_e_tipo_desconhecido_na_codificacao() -> None:
    with pytest.raises(mongo.BsonError):
        mongo.encode({"a\x00b": 1})
    with pytest.raises(mongo.BsonError):
        mongo.encode({"a": object()})


def test_op_msg_estrutura() -> None:
    request = mongo.op_msg({"hello": 1, "$db": "admin"})
    length, _req, response_to, opcode = struct.unpack_from("<iiii", request)
    assert length == len(request)
    assert (response_to, opcode) == (0, mongo.OP_MSG)
    assert struct.unpack_from("<I", request, 16)[0] == 0  # flagBits
    assert request[20] == 0  # seção do tipo 0
    assert mongo.decode(request, 21)[0] == {"hello": 1, "$db": "admin"}


def test_op_query_estrutura() -> None:
    request = mongo.op_query({"isMaster": 1})
    assert struct.unpack_from("<i", request, 12)[0] == mongo.OP_QUERY
    assert b"admin.$cmd\x00" in request


def test_parse_reply_op_msg_e_op_reply() -> None:
    assert mongo.parse_reply(mongo_msg({"ok": 1.0})) == {"ok": 1.0}
    assert mongo.parse_reply(mongo_reply({"ismaster": True})) == {"ismaster": True}


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"HTTP/1.1 200 OK\r\n\r\n aaaaaaaaaaaaaaaaaaaaaaaaa",
        # tamanho do cabeçalho não confere com os dados
        struct.pack("<iiii", 999, 1, 1, mongo.OP_MSG) + b"\x00" * 10,
        # opcode desconhecido
        struct.pack("<iiii", 26, 1, 1, 1234) + b"\x00" * 10,
        # documento BSON corrompido
        struct.pack("<iiii", 26, 1, 1, mongo.OP_MSG) + b"\x00\x00\x00\x00\x00" + b"\xff" * 5,
    ],
)
def test_parse_reply_falso_positivo(data: bytes) -> None:
    assert mongo.parse_reply(data) is None


def test_redis_texto_de_http_nao_e_redis() -> None:
    assert probes.parse_redis(b"HTTP/1.1 401 Unauthorized\r\nAuthentication required") is None
    assert probes.parse_redis(b"HTTP/1.1 400 Bad Request\r\nAuthentication required") is None


def test_rdp_resposta_truncada_nao_e_legado() -> None:
    truncada = b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x1f"
    assert winproto.parse_rdp(truncada) is None
    legado = winproto.parse_rdp(b"\x03\x00\x00\x0b\x06\xd0\x00\x00\x12\x34\x00")
    assert legado is not None and legado.legacy
