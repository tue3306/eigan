"""Acesso remoto e compartilhamento: RDP, SMB, VNC e o conector AJP."""

from __future__ import annotations

import struct

import pytest
from fakes_net import (
    Responder,
    fake_tcp,
    fast_settings,
    rdp_confirm,
    rdp_requested,
    service_fact,
    smb1_response,
    smb2_response,
)
from helpers import CheckOutcome, run_check

from eigan.checks.net import common, remote, winproto
from eigan.checks.net.winproto import RdpNegotiation
from eigan.core import vulndb
from eigan.core.context import ScanContext
from eigan.core.models import Confidence, Exposure, Fact, Severity
from eigan.core.registry import get_check
from eigan.core.target import parse_target


def at(monkeypatch: pytest.MonkeyPatch, exposure: Exposure) -> None:
    monkeypatch.setattr(common, "exposure_of", lambda _host: exposure)


def run_it(check_id: str, fact: Fact) -> CheckOutcome:
    return run_check(check_id, fact, settings=fast_settings())


# -- RDP ------------------------------------------------------------------------------------------


RSP_RDP = rdp_confirm(0x02, winproto.PROTOCOL_RDP)
RSP_TLS = rdp_confirm(0x02, winproto.PROTOCOL_SSL)
FAIL_SSL = rdp_confirm(0x03, 1)
FAIL_NLA = rdp_confirm(0x03, winproto.HYBRID_REQUIRED_BY_SERVER)


def rdp_server(classic: bytes | None, tls_only: bytes | None) -> Responder:
    """Responde conforme o ``requestedProtocols`` do pedido (0 = RDP padrão, 1 = só TLS)."""

    def respond(data: bytes) -> bytes | None:
        return classic if rdp_requested(data) == winproto.PROTOCOL_RDP else tls_only

    return respond


def run_rdp(classic: bytes | None, tls_only: bytes | None, **data: object) -> CheckOutcome:
    with fake_tcp(rdp_server(classic, tls_only)) as server:
        return run_it("net.rdp", service_fact(server.port, "rdp", **data))


@pytest.mark.parametrize(
    ("exposure", "severity"),
    [
        (Exposure.INTERNET, Severity.HIGH),
        (Exposure.INTERNAL, Severity.MEDIUM),
        (Exposure.LOCAL, Severity.LOW),
    ],
)
def test_rdp_aceita_seguranca_padrao(
    monkeypatch: pytest.MonkeyPatch, exposure: Exposure, severity: Severity
) -> None:
    at(monkeypatch, exposure)
    out = run_rdp(RSP_RDP, RSP_TLS)
    [finding] = out.by_id("net.rdp.sem_nla")
    assert finding.severity is severity
    assert finding.confidence is Confidence.CONFIRMED
    assert "sem TLS e sem NLA" in finding.title
    assert finding.details["sem_tls"] is True
    assert finding.tech == ["windows"]


def test_rdp_aceita_so_tls_sem_nla(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNAL)
    out = run_rdp(FAIL_SSL, RSP_TLS)
    [finding] = out.by_id("net.rdp.sem_nla")
    assert finding.details["sem_tls"] is False
    assert "tela de logon" in finding.evidence
    assert "sem TLS e sem NLA" not in finding.title


def test_rdp_antigo_sem_negociacao_e_sem_nla(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNAL)
    out = run_rdp(rdp_confirm(), rdp_confirm())
    assert out.by_id("net.rdp.sem_nla")[0].details["sem_tls"] is True


@pytest.mark.parametrize("code", [5, 6, 7])
def test_rdp_com_autenticacao_previa_e_ponto_forte(
    monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    at(monkeypatch, Exposure.INTERNAL)
    refused = rdp_confirm(0x03, code)
    out = run_rdp(refused, refused)
    assert not out.findings
    assert any(p.control == "net.rdp.sem_nla" for p in out.passed)


def test_rdp_codigo_5_no_classico_e_exige_tls_no_outro(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNAL)
    out = run_rdp(FAIL_NLA, FAIL_SSL)
    assert not out.findings
    assert any(p.control == "net.rdp.sem_nla" for p in out.passed)


def test_rdp_exposto_na_internet_mesmo_com_nla(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNET)
    out = run_rdp(FAIL_NLA, FAIL_NLA)
    [finding] = out.by_id("net.rdp.exposto")
    assert finding.severity is Severity.HIGH
    assert "X.224" in finding.evidence
    assert "net.rdp.sem_nla" not in out.ids()


@pytest.mark.parametrize("exposure", [Exposure.INTERNAL, Exposure.LOCAL])
def test_rdp_fora_da_internet_nao_e_exposicao(
    monkeypatch: pytest.MonkeyPatch, exposure: Exposure
) -> None:
    at(monkeypatch, exposure)
    out = run_rdp(FAIL_NLA, FAIL_NLA)
    assert "net.rdp.exposto" not in out.ids()


def test_rdp_resposta_incoerente_nao_conclui(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNAL)
    # o servidor "seleciona" um protocolo que não foi pedido: nada se pode afirmar
    hybrid = rdp_confirm(0x02, winproto.PROTOCOL_HYBRID)
    out = run_rdp(hybrid, hybrid)
    assert not out.findings
    assert not out.passed
    assert any("não foi possível concluir" in line for line in out.logs)


def test_rdp_falhas_sem_relacao_com_nla_nao_concluem(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNAL)
    out = run_rdp(FAIL_SSL, rdp_confirm(0x03, 3))
    assert not out.findings
    assert not out.passed


def test_porta_que_nao_fala_rdp_nao_vira_achado(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNET)
    out = run_rdp(
        b"HTTP/1.1 400 Bad Request\r\n\r\n", b"HTTP/1.1 400 Bad Request\r\n\r\n", confirmed=False
    )
    assert not out.findings
    assert any("não respondeu à negociação RDP" in line for line in out.logs)


def test_veredito_nla_tabela() -> None:
    classic_ok = RdpNegotiation(selected=winproto.PROTOCOL_RDP)
    tls_ok = RdpNegotiation(selected=winproto.PROTOCOL_SSL)
    needs_nla = RdpNegotiation(failure=5)
    needs_tls = RdpNegotiation(failure=1)
    assert remote.nla_verdict(classic_ok, None)[0] is False
    assert remote.nla_verdict(None, tls_ok)[0] is False
    assert remote.nla_verdict(needs_tls, tls_ok)[0] is False
    assert remote.nla_verdict(needs_nla, needs_nla)[0] is True
    assert remote.nla_verdict(needs_nla, None)[0] is True
    assert remote.nla_verdict(None, needs_nla)[0] is True
    assert remote.nla_verdict(None, None)[0] is None
    assert remote.nla_verdict(needs_tls, None)[0] is None
    # um aceite "estranho" invalida a conclusão de que a NLA é obrigatória
    assert remote.nla_verdict(needs_nla, RdpNegotiation(selected=2))[0] is None


# -- SMB ------------------------------------------------------------------------------------------


def smb_server(v1: bytes | None, v2: bytes | None) -> Responder:
    def respond(data: bytes) -> bytes | None:
        return v1 if data[4:8] == b"\xffSMB" else v2

    return respond


def run_smb(v1: bytes | None, v2: bytes | None) -> CheckOutcome:
    with fake_tcp(smb_server(v1, v2)) as server:
        return run_it("net.smb", service_fact(server.port, "smb"))


REQUIRED = smb2_response(security_mode=0x03)
OPTIONAL = smb2_response(security_mode=0x01)


@pytest.mark.parametrize(
    ("exposure", "severity"),
    [
        (Exposure.INTERNET, Severity.HIGH),
        (Exposure.INTERNAL, Severity.HIGH),
        (Exposure.LOCAL, Severity.MEDIUM),
    ],
)
def test_smb1_ativo(
    monkeypatch: pytest.MonkeyPatch, exposure: Exposure, severity: Severity
) -> None:
    at(monkeypatch, exposure)
    out = run_smb(smb1_response(), REQUIRED)
    [finding] = out.by_id("net.smb.v1")
    assert finding.severity is severity
    assert finding.confidence is Confidence.CONFIRMED
    assert "NT LM 0.12" in finding.evidence
    assert "WordCount 0x11" in finding.evidence


def test_pedido_de_smb1_oferece_so_nt_lm(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNAL)
    with fake_tcp(smb_server(smb1_response(), REQUIRED)) as server:
        run_it("net.smb", service_fact(server.port, "smb"))
    smb1 = next(data for data in server.received if data[4:8] == b"\xffSMB")
    assert smb1.count(b"\x02") == 1
    assert smb1.endswith(b"\x02NT LM 0.12\x00")


@pytest.mark.parametrize(
    "v1",
    [
        None,  # conexão encerrada
        smb1_response(dialect_index=0xFFFF, word_count=1),
        smb1_response(dialect_index=0xFFFF),
        smb1_response(status=0xC0000002),
    ],
)
def test_smb1_recusado_e_ponto_forte(monkeypatch: pytest.MonkeyPatch, v1: bytes | None) -> None:
    at(monkeypatch, Exposure.INTERNAL)
    out = run_smb(v1, REQUIRED)
    assert "net.smb.v1" not in out.ids()
    assert any(p.control == "net.smb.v1" for p in out.passed)


def test_servidor_que_responde_smb2_ao_pedido_smb1_nao_e_smb1(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    at(monkeypatch, Exposure.INTERNAL)
    out = run_smb(smb2_response(dialect=0x02FF, security_mode=0x03), REQUIRED)
    assert "net.smb.v1" not in out.ids()
    assert any(p.control == "net.smb.v1" for p in out.passed)


@pytest.mark.parametrize(
    ("exposure", "severity"),
    [
        (Exposure.INTERNET, Severity.MEDIUM),
        (Exposure.INTERNAL, Severity.MEDIUM),
        (Exposure.LOCAL, Severity.LOW),
    ],
)
def test_assinatura_opcional(
    monkeypatch: pytest.MonkeyPatch, exposure: Exposure, severity: Severity
) -> None:
    at(monkeypatch, exposure)
    out = run_smb(None, OPTIONAL)
    [finding] = out.by_id("net.smb.assinatura_opcional")
    assert finding.severity is severity
    assert "habilitada, mas opcional" in finding.evidence
    assert finding.details["dialeto"] == "3.0.2"


def test_assinatura_desabilitada(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNAL)
    out = run_smb(None, smb2_response(security_mode=0x00))
    assert "desabilitada" in out.by_id("net.smb.assinatura_opcional")[0].evidence


def test_assinatura_obrigatoria_e_ponto_forte(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNAL)
    out = run_smb(None, REQUIRED)
    assert not out.findings
    assert any(p.control == "net.smb.assinatura_opcional" for p in out.passed)


def test_servidor_so_smb1_avalia_a_assinatura_do_smb1(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNAL)
    out = run_smb(smb1_response(security_mode=0x03), None)
    assert out.by_id("net.smb.v1")
    assert out.by_id("net.smb.assinatura_opcional")
    out = run_smb(smb1_response(security_mode=0x0F), None)
    assert out.by_id("net.smb.v1")
    assert "net.smb.assinatura_opcional" not in out.ids()


def test_smb_exposto_na_internet(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNET)
    out = run_smb(None, REQUIRED)
    [finding] = out.by_id("net.smb.exposto")
    assert finding.severity is Severity.HIGH
    assert "dialeto 3.0.2" in finding.evidence


@pytest.mark.parametrize("exposure", [Exposure.INTERNAL, Exposure.LOCAL])
def test_smb_fora_da_internet_nao_e_exposicao(
    monkeypatch: pytest.MonkeyPatch, exposure: Exposure
) -> None:
    at(monkeypatch, exposure)
    assert "net.smb.exposto" not in run_smb(None, REQUIRED).ids()


def test_porta_que_nao_fala_smb_nao_vira_achado(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNET)
    out = run_smb(b"HTTP/1.1 400 Bad Request\r\n\r\n", b"HTTP/1.1 400 Bad Request\r\n\r\n")
    assert not out.findings
    assert not out.passed
    assert any("não respondeu ao NEGOTIATE" in line for line in out.logs)


def test_smb2_com_erro_e_smb1_recusado_nao_afirma_nada(monkeypatch: pytest.MonkeyPatch) -> None:
    # servidor só com SMB 3.1.1 recusa o pedido sem contextos de negociação
    at(monkeypatch, Exposure.INTERNET)
    out = run_smb(None, smb2_response(status=0xC00000BB))
    assert not out.findings
    assert not out.passed


# -- VNC ------------------------------------------------------------------------------------------


def run_vnc(greeting: bytes, security: bytes, **data: object) -> tuple[CheckOutcome, list[bytes]]:
    def respond(request: bytes) -> bytes | None:
        return security if request.startswith(b"RFB ") else None

    with fake_tcp(respond, greeting=greeting) as server:
        out = run_it("net.vnc", service_fact(server.port, "vnc", **data))
    return out, server.received


RFB38 = b"RFB 003.008\n"


@pytest.mark.parametrize(
    ("exposure", "severity"),
    [
        (Exposure.INTERNET, Severity.CRITICAL),
        (Exposure.INTERNAL, Severity.HIGH),
        (Exposure.LOCAL, Severity.MEDIUM),
    ],
)
def test_vnc_sem_senha(
    monkeypatch: pytest.MonkeyPatch, exposure: Exposure, severity: Severity
) -> None:
    at(monkeypatch, exposure)
    out, received = run_vnc(RFB38, b"\x02\x01\x02")
    [finding] = out.by_id("net.vnc.sem_senha")
    assert finding.severity is severity
    assert finding.confidence is Confidence.CONFIRMED
    assert "RFB 3.8" in finding.evidence
    assert "tipo de segurança 1" in finding.evidence
    assert ("net.vnc.exposto" in out.ids()) is (exposure is Exposure.INTERNET)
    # a conexão fecha sem escolher um tipo de segurança: só a versão do cliente foi enviada
    assert received == [b"RFB 003.008\n"]


def test_vnc_com_senha_na_internet(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNET)
    out, _received = run_vnc(RFB38, b"\x01\x02")
    [finding] = out.by_id("net.vnc.exposto")
    assert finding.severity is Severity.HIGH
    assert "Autenticação VNC" in finding.evidence
    assert "net.vnc.sem_senha" not in out.ids()
    assert any(p.control == "net.vnc.sem_senha" for p in out.passed)


@pytest.mark.parametrize("exposure", [Exposure.INTERNAL, Exposure.LOCAL])
def test_vnc_com_senha_fora_da_internet(
    monkeypatch: pytest.MonkeyPatch, exposure: Exposure
) -> None:
    at(monkeypatch, exposure)
    out, _received = run_vnc(RFB38, b"\x01\x02")
    assert not out.findings
    assert any(p.control == "net.vnc.sem_senha" for p in out.passed)


@pytest.mark.parametrize("kind", [16, 18, 19])
def test_vnc_com_autenticacao_negociada_depois_fica_inconclusivo(
    monkeypatch: pytest.MonkeyPatch, kind: int
) -> None:
    at(monkeypatch, Exposure.INTERNAL)
    out, _received = run_vnc(RFB38, bytes([1, kind]))
    assert not out.findings
    assert not out.passed
    assert any("negociada depois" in line for line in out.logs)


def test_vnc_tight_na_internet_ainda_e_exposicao(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNET)
    out, _received = run_vnc(RFB38, b"\x01\x10")
    assert out.by_id("net.vnc.exposto")
    assert "net.vnc.sem_senha" not in out.ids()


def test_vnc_33_servidor_escolhe(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNAL)
    out, received = run_vnc(b"RFB 003.003\n", struct.pack(">I", 1))
    assert out.by_id("net.vnc.sem_senha")
    assert received == [b"RFB 003.003\n"]
    out, _received = run_vnc(b"RFB 003.003\n", struct.pack(">I", 2))
    assert not out.findings
    assert any(p.control == "net.vnc.sem_senha" for p in out.passed)


def test_vnc_37_e_versao_desconhecida(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNAL)
    out, received = run_vnc(b"RFB 003.007\n", b"\x01\x01")
    assert out.by_id("net.vnc.sem_senha")
    assert received == [b"RFB 003.007\n"]
    out, received = run_vnc(b"RFB 003.889\n", b"\x01\x02")
    assert not out.findings
    assert received == [b"RFB 003.008\n"]


def test_vnc_recusa_a_conexao(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNET)
    reason = b"Too many security failures"
    out, _received = run_vnc(RFB38, b"\x00" + struct.pack(">I", len(reason)) + reason)
    [finding] = out.by_id("net.vnc.exposto")
    assert "recusou a conexão" in finding.evidence
    assert "Too many security failures" in finding.evidence
    assert "net.vnc.sem_senha" not in out.ids()
    assert not out.passed


def test_vnc_33_recusa_com_motivo(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNAL)
    reason = b"bloqueado"
    out, _received = run_vnc(b"RFB 003.003\n", struct.pack(">II", 0, len(reason)) + reason)
    assert not out.findings
    assert any("bloqueado" in line for line in out.logs)


def test_porta_que_nao_fala_rfb_nao_vira_achado(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNET)
    out, received = run_vnc(b"SSH-2.0-OpenSSH_9.6\r\n", b"")
    assert not out.findings
    assert received == []
    assert any("RFB" in line for line in out.logs)


def test_vnc_servidor_mudo_depois_da_versao(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNET)

    def respond(_request: bytes) -> bytes | None:
        return None  # encerra sem oferecer tipos

    with fake_tcp(respond, greeting=RFB38) as server:
        out = run_it("net.vnc", service_fact(server.port, "vnc"))
    assert not out.findings


# -- AJP ------------------------------------------------------------------------------------------


AJP = service_fact(8009, "ajp", host="10.0.0.5")


def tomcat_tech(version: str, host: str = "10.0.0.5") -> Fact:
    return Fact(
        "tech",
        f"{host}:tomcat",
        {"host": host, "name": "tomcat", "version": version, "kind": "server", "label": "tomcat"},
    )


def scan_with(*known: Fact) -> ScanContext:
    scan = ScanContext(parse_target("https://127.0.0.1/"), fast_settings())
    for fact in known:
        scan.add_fact(fact)
    return scan


@pytest.mark.parametrize(
    ("exposure", "severity"),
    [(Exposure.INTERNET, Severity.HIGH), (Exposure.INTERNAL, Severity.MEDIUM)],
)
def test_ajp_exposto_sem_versao(
    monkeypatch: pytest.MonkeyPatch, exposure: Exposure, severity: Severity
) -> None:
    at(monkeypatch, exposure)
    out = run_it("net.ajp", AJP)
    [finding] = out.by_id("net.ajp.exposto")
    assert finding.severity is severity
    assert finding.confidence is Confidence.CONFIRMED
    assert finding.cves == []
    assert not finding.kev
    assert "CPong" in finding.evidence
    assert "CVE-2020-1938" in finding.evidence
    assert finding.tech == ["tomcat"]


def test_ajp_nesta_maquina_nao_e_exposicao(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.LOCAL)
    out = run_it("net.ajp", AJP)
    assert not out.findings
    assert any("nesta máquina" in line for line in out.logs)


@pytest.mark.parametrize("exposure", [Exposure.INTERNET, Exposure.INTERNAL])
def test_ajp_com_tomcat_vulneravel_esta_no_kev(
    monkeypatch: pytest.MonkeyPatch, exposure: Exposure
) -> None:
    at(monkeypatch, exposure)
    out = run_check("net.ajp", AJP, scan=scan_with(tomcat_tech("9.0.30")))
    [finding] = out.by_id("net.ajp.exposto")
    assert finding.cves == ["CVE-2020-1938"]
    assert finding.kev is True
    assert finding.severity is Severity.CRITICAL
    assert finding.confidence is Confidence.FIRM
    assert "Tomcat 9.0.30" in finding.evidence


def test_ajp_com_tomcat_corrigido_nao_cita_o_cve(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNAL)
    out = run_check("net.ajp", AJP, scan=scan_with(tomcat_tech("9.0.31")))
    [finding] = out.by_id("net.ajp.exposto")
    assert finding.cves == []
    assert finding.severity is Severity.LOW
    assert finding.confidence is Confidence.CONFIRMED
    assert "Tomcat 9.0.31 identificado" in finding.evidence


def test_ajp_corrigido_na_internet_e_medio(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNET)
    out = run_check("net.ajp", AJP, scan=scan_with(tomcat_tech("9.0.31")))
    [finding] = out.by_id("net.ajp.exposto")
    assert finding.severity is Severity.MEDIUM
    assert "secret" in finding.evidence


def test_vnc_sem_senha_na_internet_tambem_e_exposto(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNET)
    out, _ = run_vnc(RFB38, b"")
    assert out.by_id("net.vnc.sem_senha")
    assert out.by_id("net.vnc.exposto")


def test_ajp_versao_de_outro_host_nao_conta(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNAL)
    out = run_check("net.ajp", AJP, scan=scan_with(tomcat_tech("9.0.30", host="10.0.0.9")))
    assert out.by_id("net.ajp.exposto")[0].cves == []


def test_versao_descoberta_depois_atualiza_o_achado(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNAL)
    scan = scan_with(AJP)
    first = run_check("net.ajp", AJP, scan=scan)
    assert first.by_id("net.ajp.exposto")[0].cves == []
    later = run_check("net.ajp.versao", tomcat_tech("8.5.50"), scan=scan)
    [finding] = later.by_id("net.ajp.exposto")
    assert finding.cves == ["CVE-2020-1938"]
    assert finding.kev is True
    assert finding.severity is Severity.CRITICAL


def test_versao_corrigida_ou_sem_ajp_nao_gera_nada(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNAL)
    assert not run_check("net.ajp.versao", tomcat_tech("9.0.31"), scan=scan_with(AJP)).findings
    assert not run_check("net.ajp.versao", tomcat_tech("9.0.30"), scan=scan_with()).findings


def test_checagem_de_versao_so_roda_para_tomcat_com_versao() -> None:
    item = get_check("net.ajp.versao")
    assert item is not None
    assert item.when is not None
    assert item.when(tomcat_tech("9.0.30"))
    assert not item.when(tomcat_tech(""))
    nginx = Fact("tech", "h:nginx", {"host": "h", "name": "nginx", "version": "1.2.3"})
    assert not item.when(nginx)


@pytest.mark.parametrize(
    ("version", "affected"),
    [
        ("9.0.0.M1", True),
        ("9.0.30", True),
        ("9.0.31", False),
        ("9.0.100", False),
        ("8.5.0", True),
        ("8.5.50", True),
        ("8.5.51", False),
        ("7.0.0", True),
        ("7.0.99", True),
        ("7.0.100", False),
        ("8.0.53", False),  # fora das faixas publicadas pela NVD
        ("6.0.53", False),
        ("10.1.0", False),
        ("", False),
    ],
)
def test_faixas_da_ghostcat(version: str, affected: bool) -> None:
    assert remote.ghostcat_affected(version) is affected


def test_ghostcat_esta_no_catalogo_kev_embarcado() -> None:
    assert vulndb.is_kev("CVE-2020-1938")
