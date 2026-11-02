"""Protocolos em texto puro: Telnet, FTP (TLS e anônimo) e e-mail (STARTTLS)."""

from __future__ import annotations

import pytest
from fakes_net import fake_tcp, fast_settings, line_replies, service_fact
from helpers import CheckOutcome, run_check

from eigan.checks.net import cleartext, common
from eigan.core.models import Confidence, Exposure, Fact, Severity


def at(monkeypatch: pytest.MonkeyPatch, exposure: Exposure) -> None:
    monkeypatch.setattr(common, "exposure_of", lambda _host: exposure)


def run_it(check_id: str, fact: Fact) -> CheckOutcome:
    return run_check(check_id, fact, settings=fast_settings())


# -- Telnet --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("exposure", "severity"),
    [
        (Exposure.INTERNET, Severity.HIGH),
        (Exposure.INTERNAL, Severity.HIGH),
        (Exposure.LOCAL, Severity.MEDIUM),
    ],
)
def test_telnet_confirmado(
    monkeypatch: pytest.MonkeyPatch, exposure: Exposure, severity: Severity
) -> None:
    at(monkeypatch, exposure)
    out = run_it("net.telnet", service_fact(23, "telnet", banner="negociação Telnet (IAC)"))
    [finding] = out.by_id("net.telnet.ativo")
    assert finding.severity is severity
    assert finding.confidence is Confidence.CONFIRMED
    assert "negociação Telnet" in finding.evidence


def test_telnet_so_pela_porta_e_tentativa() -> None:
    out = run_it("net.telnet", service_fact(23, "telnet", confirmed=False))
    [finding] = out.by_id("net.telnet.ativo")
    assert finding.confidence is Confidence.TENTATIVE
    assert "porta padrão" in finding.evidence


def test_telnet_sobre_tls_nao_e_texto_puro() -> None:
    out = run_it("net.telnet", service_fact(992, "telnet", tls=True))
    assert not out.findings


# -- FTP: TLS -------------------------------------------------------------------------------------


FEAT_WITH_TLS = b"211-Features:\r\n AUTH TLS\r\n PBSZ\r\n PROT\r\n211 End\r\n"
FEAT_WITHOUT_TLS = b"211-Features:\r\n MDTM\r\n SIZE\r\n211 End\r\n"
REFUSE_ANON = b"530 Login incorrect.\r\n"


def ftp_server(**replies: bytes) -> dict[str, bytes]:
    table = {
        "FEAT": FEAT_WITHOUT_TLS,
        "AUTH": b"500 AUTH nao reconhecido\r\n",
        "USER": b"331 Please specify the password.\r\n",
        "PASS": REFUSE_ANON,
        "QUIT": b"221 Goodbye.\r\n",
    }
    table.update(replies)
    return table


def run_ftp(
    table: dict[str, bytes], *, greeting: bytes = b"220 (vsFTPd 3.0.5)\r\n", **data: object
) -> CheckOutcome:
    with fake_tcp(line_replies(table, default=b"500 ?\r\n"), greeting=greeting) as server:
        return run_it("net.ftp", service_fact(server.port, "ftp", product="vsftpd", **data))


@pytest.mark.parametrize(
    ("exposure", "severity"),
    [(Exposure.INTERNET, Severity.MEDIUM), (Exposure.INTERNAL, Severity.LOW)],
)
def test_ftp_sem_tls(
    monkeypatch: pytest.MonkeyPatch, exposure: Exposure, severity: Severity
) -> None:
    at(monkeypatch, exposure)
    out = run_ftp(ftp_server())
    [finding] = out.by_id("net.ftp.sem_tls")
    assert finding.severity is severity
    assert finding.confidence is Confidence.CONFIRMED
    assert "AUTH TLS" in finding.evidence
    assert finding.tech == ["vsftpd"]


def test_ftp_feat_anuncia_tls() -> None:
    out = run_ftp(ftp_server(FEAT=FEAT_WITH_TLS))
    assert "net.ftp.sem_tls" not in out.ids()
    assert any(p.control == "net.ftp.tls" and "FEAT" in p.text for p in out.passed)


def test_ftp_auth_tls_aceito_sem_feat() -> None:
    out = run_ftp(
        ftp_server(FEAT=b"500 FEAT desconhecido\r\n", AUTH=b"234 Proceed with negotiation.\r\n")
    )
    assert "net.ftp.sem_tls" not in out.ids()
    assert any(p.control == "net.ftp.tls" and "234" in p.text for p in out.passed)


def test_ftp_recusa_temporaria_nao_conclui() -> None:
    out = run_ftp(ftp_server(AUTH=b"421 Too many connections\r\n"))
    assert "net.ftp.sem_tls" not in out.ids()
    assert not any(p.control == "net.ftp.tls" for p in out.passed)
    assert any("TLS não avaliado" in line for line in out.logs)


def test_ftp_com_saudacao_estranha_nao_conclui() -> None:
    out = run_ftp(ftp_server(), greeting=b"421 Servico indisponivel\r\n")
    assert not out.findings
    assert not out.passed
    assert any("TLS não avaliado" in line for line in out.logs)
    assert any("login anônimo não avaliado" in line for line in out.logs)


def test_ftps_implicito_vale_como_tls() -> None:
    table = ftp_server()
    with fake_tcp(line_replies(table), greeting=b"220 FTPS\r\n", tls=True) as server:
        out = run_it("net.ftp", service_fact(server.port, "ftp", tls=True))
    assert "net.ftp.sem_tls" not in out.ids()
    assert any(p.control == "net.ftp.tls" and "implícito" in p.text for p in out.passed)
    assert any(p.control == "net.ftp.anonimo" for p in out.passed)


# -- FTP: anônimo ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("exposure", "severity"),
    [
        (Exposure.INTERNET, Severity.HIGH),
        (Exposure.INTERNAL, Severity.MEDIUM),
        (Exposure.LOCAL, Severity.LOW),
    ],
)
def test_ftp_anonimo_aceito(
    monkeypatch: pytest.MonkeyPatch, exposure: Exposure, severity: Severity
) -> None:
    at(monkeypatch, exposure)
    table = ftp_server(PASS=b"230 Login successful.\r\n")
    with fake_tcp(line_replies(table, default=b"500 ?\r\n"), greeting=b"220 FTP\r\n") as server:
        out = run_it("net.ftp", service_fact(server.port, "ftp"))
    [finding] = out.by_id("net.ftp.anonimo")
    assert finding.severity is severity
    assert finding.confidence is Confidence.CONFIRMED
    assert "USER anonymous" in finding.evidence
    assert "230" in finding.evidence
    # só login e saída: nada de listar, baixar ou gravar
    commands = b"".join(server.received).upper()
    assert b"QUIT" in commands
    for forbidden in (b"LIST", b"NLST", b"RETR", b"STOR", b"PASV", b"PORT"):
        assert forbidden not in commands


def test_ftp_anonimo_sem_pedir_senha() -> None:
    out = run_ftp(ftp_server(USER=b"230 Login successful.\r\n"))
    assert out.by_id("net.ftp.anonimo")


def test_ftp_anonimo_recusado_e_ponto_forte() -> None:
    out = run_ftp(ftp_server())
    assert "net.ftp.anonimo" not in out.ids()
    assert any(p.control == "net.ftp.anonimo" for p in out.passed)


def test_ftp_usuario_recusado_direto() -> None:
    out = run_ftp(ftp_server(USER=b"530 This FTP server does not allow anonymous logins\r\n"))
    assert "net.ftp.anonimo" not in out.ids()
    assert any(p.control == "net.ftp.anonimo" for p in out.passed)


@pytest.mark.parametrize(
    "reply",
    [
        b"530 Non-anonymous sessions must use encryption.\r\n",
        b"530 SSL required\r\n",
        b"421 Too many connections\r\n",
    ],
)
def test_ftp_anonimo_inconclusivo(reply: bytes) -> None:
    out = run_ftp(ftp_server(USER=reply))
    assert "net.ftp.anonimo" not in out.ids()
    assert not any(p.control == "net.ftp.anonimo" for p in out.passed)
    assert any("login anônimo não avaliado" in line for line in out.logs)


# -- SMTP -----------------------------------------------------------------------------------------


def run_mail(
    service: str, table: dict[str, bytes], greeting: bytes, port: int | None = None
) -> CheckOutcome:
    with fake_tcp(line_replies(table, default=b"500 ?\r\n"), greeting=greeting) as server:
        fact = service_fact(server.port, service, product="postfix")
        if port is not None:
            fact.data["_porta_ficticia"] = port
        return run_it("net.correio", fact)


def test_smtp_com_starttls() -> None:
    table = {
        "EHLO": b"250-mx.exemplo\r\n250-SIZE 1000\r\n250 STARTTLS\r\n",
        "QUIT": b"221 tchau\r\n",
    }
    out = run_mail("smtp", table, b"220 mx ESMTP Postfix\r\n")
    assert not out.findings
    assert any(p.control == "net.correio.tls" and "SMTP" in p.text for p in out.passed)


@pytest.mark.parametrize(
    ("exposure", "severity"),
    [(Exposure.INTERNET, Severity.MEDIUM), (Exposure.INTERNAL, Severity.LOW)],
)
def test_smtp_porta_25_sem_starttls(
    monkeypatch: pytest.MonkeyPatch, exposure: Exposure, severity: Severity
) -> None:
    at(monkeypatch, exposure)
    table = {"EHLO": b"250-mx.exemplo\r\n250 SIZE 1000\r\n", "QUIT": b"221 tchau\r\n"}
    out = run_mail("smtp", table, b"220 mx ESMTP Postfix\r\n")
    [finding] = out.by_id("net.smtp.sem_starttls")
    assert finding.severity is severity
    assert "SIZE" in finding.evidence
    assert finding.tech == ["postfix"]


@pytest.mark.parametrize(
    ("exposure", "severity"),
    [(Exposure.INTERNET, Severity.HIGH), (Exposure.INTERNAL, Severity.MEDIUM)],
)
def test_smtp_submissao_sem_starttls_pesa_mais(
    monkeypatch: pytest.MonkeyPatch, exposure: Exposure, severity: Severity
) -> None:
    at(monkeypatch, exposure)
    table = {"EHLO": b"250 mx.exemplo\r\n", "QUIT": b"221 tchau\r\n"}
    with fake_tcp(line_replies(table), greeting=b"220 mx ESMTP\r\n") as server:
        monkeypatch.setattr(cleartext, "SUBMISSION_PORTS", frozenset({server.port}))
        out = run_it("net.correio", service_fact(server.port, "smtp"))
    assert out.by_id("net.smtp.sem_starttls")[0].severity is severity


def test_smtp_antigo_sem_ehlo() -> None:
    table = {"EHLO": b"502 Command not implemented\r\n", "QUIT": b"221 tchau\r\n"}
    out = run_mail("smtp", table, b"220 mx SMTP\r\n")
    [finding] = out.by_id("net.smtp.sem_starttls")
    assert "EHLO não reconhecido" in finding.evidence


@pytest.mark.parametrize(
    ("greeting", "table"),
    [
        (b"554 Sem servico\r\n", {"EHLO": b"554 nao\r\n"}),
        (b"220 mx\r\n", {"EHLO": b"421 Tente depois\r\n"}),
    ],
)
def test_smtp_recusa_nao_vira_achado_nem_ponto_forte(
    greeting: bytes, table: dict[str, bytes]
) -> None:
    out = run_mail("smtp", table, greeting)
    assert not out.findings
    assert not out.passed
    assert any("não respondeu como esperado" in line for line in out.logs)


def test_correio_com_tls_implicito_nao_conecta() -> None:
    out = run_it("net.correio", service_fact(993, "imap", tls=True))
    assert not out.findings
    assert any("TLS implícito" in p.text for p in out.passed)


# -- POP3 -----------------------------------------------------------------------------------------


def test_pop3_com_stls() -> None:
    table = {"CAPA": b"+OK\r\nUSER\r\nSTLS\r\n.\r\n", "QUIT": b"+OK\r\n"}
    out = run_mail("pop3", table, b"+OK Dovecot ready.\r\n")
    assert not out.findings
    assert any("POP3 oferece STARTTLS" in p.text for p in out.passed)


@pytest.mark.parametrize(
    ("exposure", "severity"),
    [(Exposure.INTERNET, Severity.MEDIUM), (Exposure.INTERNAL, Severity.LOW)],
)
def test_pop3_sem_stls(
    monkeypatch: pytest.MonkeyPatch, exposure: Exposure, severity: Severity
) -> None:
    at(monkeypatch, exposure)
    table = {"CAPA": b"+OK\r\nUSER\r\nUIDL\r\n.\r\n", "QUIT": b"+OK\r\n"}
    out = run_mail("pop3", table, b"+OK pronto\r\n")
    [finding] = out.by_id("net.correio.sem_tls")
    assert finding.severity is severity
    assert "USER, UIDL" in finding.evidence


def test_pop3_sem_capa_tenta_stls() -> None:
    table = {"CAPA": b"-ERR desconhecido\r\n", "STLS": b"+OK Begin TLS\r\n"}
    out = run_mail("pop3", table, b"+OK pronto\r\n")
    assert not out.findings
    assert any("POP3" in p.text for p in out.passed)


def test_pop3_sem_capa_e_sem_stls() -> None:
    table = {"CAPA": b"-ERR desconhecido\r\n", "STLS": b"-ERR nao\r\n", "QUIT": b"+OK\r\n"}
    out = run_mail("pop3", table, b"+OK pronto\r\n")
    [finding] = out.by_id("net.correio.sem_tls")
    assert "sem CAPA e sem STLS" in finding.evidence


def test_pop3_saudacao_invalida_nao_conclui() -> None:
    out = run_mail("pop3", {}, b"-ERR ocupado\r\n")
    assert not out.findings
    assert not out.passed


# -- IMAP -----------------------------------------------------------------------------------------


def test_imap_starttls_na_saudacao() -> None:
    greeting = b"* OK [CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED] pronto\r\n"
    table = {"A1 ": b"* CAPABILITY IMAP4rev1\r\na1 OK\r\n", "A2 ": b"* BYE\r\na2 OK\r\n"}
    out = run_mail("imap", table, greeting)
    assert not out.findings
    assert any("IMAP oferece STARTTLS" in p.text for p in out.passed)


def test_imap_starttls_no_capability() -> None:
    table = {"A1 ": b"* CAPABILITY IMAP4rev1 STARTTLS\r\na1 OK done\r\n", "A2 ": b"a2 OK\r\n"}
    out = run_mail("imap", table, b"* OK pronto\r\n")
    assert not out.findings
    assert any("IMAP oferece STARTTLS" in p.text for p in out.passed)


@pytest.mark.parametrize(
    ("exposure", "severity"),
    [(Exposure.INTERNET, Severity.MEDIUM), (Exposure.INTERNAL, Severity.LOW)],
)
def test_imap_sem_starttls(
    monkeypatch: pytest.MonkeyPatch, exposure: Exposure, severity: Severity
) -> None:
    at(monkeypatch, exposure)
    table = {"A1 ": b"* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\na1 OK done\r\n", "A2 ": b"a2 OK\r\n"}
    out = run_mail("imap", table, b"* OK pronto\r\n")
    [finding] = out.by_id("net.correio.sem_tls")
    assert finding.severity is severity
    assert "IMAP4REV1" in finding.evidence


def test_imap_sem_resposta_ao_capability_nao_conclui() -> None:
    table = {"A1 ": b"a1 NO agora nao\r\n", "A2 ": b"a2 OK\r\n"}
    out = run_mail("imap", table, b"* OK pronto\r\n")
    assert not out.findings
    assert not out.passed


# -- leitura de respostas -----------------------------------------------------------------------


def test_leitura_de_resposta_multilinha_e_inconclusiva() -> None:
    with fake_tcp(greeting=b"220-linha 1\r\n220-linha 2\r\n220 fim\r\n", hangup=True) as server:
        conn = common.Connection.open("127.0.0.1", server.port, 1.0, 1.0)
        assert conn is not None
        with conn:
            code, lines = cleartext.read_reply(conn)
    assert code == 220
    assert len(lines) == 3
    with fake_tcp(greeting=b"sem codigo nenhum\r\n", hangup=True) as server:
        conn = common.Connection.open("127.0.0.1", server.port, 1.0, 1.0)
        assert conn is not None
        with conn:
            code, lines = cleartext.read_reply(conn)
    assert code == 0
    assert lines == ["sem codigo nenhum"]


def test_resposta_do_servidor_nao_carrega_bytes_de_controle() -> None:
    from eigan.checks.net.banners import clean_text

    assert "\x1b" not in clean_text("220 \x1b]0;pwn\x07\x1b[2J ProFTPD")
