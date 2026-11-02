"""Certificado TLS: servidor de verdade com certificados montados à mão (chave da fixture)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fakes_tls import (
    OID_MD5_RSA,
    OID_SHA1_RSA,
    RawReplyServer,
    RealTlsServer,
    build_cert,
    fixture_der,
    fixture_spki,
    fixture_trust,
    name,
    rsa_spki,
    sig_algorithm,
    tls_fact,
)
from helpers import run_check

from eigan.checks.tls import certificate


@pytest.fixture(autouse=True)
def _confia_so_na_fixture(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(certificate, "trust_context", fixture_trust)


def _run(tmp_path: Path, der: bytes, *, sni: str | None = "site.exemplo"):
    with RealTlsServer(tmp_path, der) as srv:
        return run_check("tls.certificate", tls_fact(srv.port, sni=sni))


def _cert(**options: object) -> bytes:
    options.setdefault("spki", fixture_spki())
    return build_cert(**options)  # type: ignore[arg-type]


def test_certificado_da_fixture_confiavel_e_com_nome_correto(tmp_path: Path):
    out = _run(tmp_path, fixture_der(), sni="localhost")
    assert not out.findings
    assert out.fact_keys("tls.cert")
    assert out.passed


def test_expirado(tmp_path: Path):
    out = _run(tmp_path, _cert(days_left=-5))
    [finding] = out.by_id("tls.certificado.expirado")
    assert finding.severity.value == "high"


def test_expira_em_20_dias_e_media(tmp_path: Path):
    out = _run(tmp_path, _cert(days_left=20))
    [finding] = out.by_id("tls.certificado.expira_em_breve")
    assert finding.severity.value == "medium"


def test_expira_em_3_dias_e_alta(tmp_path: Path):
    out = _run(tmp_path, _cert(days_left=3))
    [finding] = out.by_id("tls.certificado.expira_em_breve")
    assert finding.severity.value == "high"


def test_validade_longe_nao_alerta(tmp_path: Path):
    out = _run(tmp_path, _cert(days_left=200))
    assert "tls.certificado.expira_em_breve" not in out.ids()
    assert "tls.certificado.expirado" not in out.ids()


def test_certificado_curto_dentro_da_janela_normal_nao_alerta(tmp_path: Path):
    out = _run(tmp_path, _cert(days_left=20, lifetime_days=47))
    assert "tls.certificado.expira_em_breve" not in out.ids()


def test_ainda_nao_valido(tmp_path: Path):
    start = datetime.now(UTC) + timedelta(days=3)
    out = _run(tmp_path, _cert(not_before=start, not_after=start + timedelta(days=90)))
    assert "tls.certificado.ainda_nao_valido" in out.ids()


def test_autoassinado(tmp_path: Path):
    out = _run(tmp_path, _cert(issuer=name("site.exemplo", None)))
    assert "tls.certificado.autoassinado" in out.ids()
    assert "tls.certificado.nao_confiavel" not in out.ids()


def test_emissor_desconhecido_nao_e_autoassinado(tmp_path: Path):
    out = _run(tmp_path, _cert())
    assert "tls.certificado.nao_confiavel" in out.ids()
    assert "tls.certificado.autoassinado" not in out.ids()


def test_cadeia_incompleta_com_aia(tmp_path: Path):
    out = _run(tmp_path, _cert(aia=["http://ca.exemplo/inter.crt"]))
    assert "tls.certificado.cadeia_incompleta" in out.ids()


def test_nome_divergente(tmp_path: Path):
    out = _run(tmp_path, _cert(san_dns=("outro.exemplo",)))
    assert "tls.certificado.nome_divergente" in out.ids()


def test_curinga_cobre_o_nome(tmp_path: Path):
    out = _run(tmp_path, _cert(san_dns=("*.site.exemplo",)), sni="www.site.exemplo")
    assert "tls.certificado.nome_divergente" not in out.ids()


def test_curinga_nao_cobre_dois_niveis(tmp_path: Path):
    out = _run(tmp_path, _cert(san_dns=("*.site.exemplo",)), sni="a.b.site.exemplo")
    assert "tls.certificado.nome_divergente" in out.ids()


def test_ip_no_san_vale_para_acesso_por_ip(tmp_path: Path):
    out = _run(tmp_path, _cert(san_dns=(), san_ip=("127.0.0.1",)), sni=None)
    assert "tls.certificado.nome_divergente" not in out.ids()


def _run_peer(monkeypatch: pytest.MonkeyPatch, der: bytes):
    """Sem handshake: a chave e a assinatura fracas nem seriam aceitas por um servidor real."""
    monkeypatch.setattr(
        certificate, "fetch_peer", lambda endpoint, timeout: certificate.Peer(der, 1)
    )
    with RawReplyServer(b"") as srv:
        return run_check("tls.certificate", tls_fact(srv.port, sni="site.exemplo"))


def test_chave_rsa_fraca(monkeypatch: pytest.MonkeyPatch):
    out = _run_peer(monkeypatch, _cert(spki=rsa_spki(1024)))
    assert "tls.certificado.chave_fraca" in out.ids()


def test_chave_de_2048_bits_e_aceita(monkeypatch: pytest.MonkeyPatch):
    out = _run_peer(monkeypatch, _cert(spki=rsa_spki(2048)))
    assert "tls.certificado.chave_fraca" not in out.ids()


@pytest.mark.parametrize("algorithm", [OID_SHA1_RSA, OID_MD5_RSA])
def test_assinatura_fraca(monkeypatch: pytest.MonkeyPatch, algorithm: str):
    out = _run_peer(monkeypatch, _cert(signature=sig_algorithm(algorithm)))
    assert "tls.certificado.assinatura_fraca" in out.ids()


def test_assinatura_sha256_nao_alerta(tmp_path: Path):
    out = _run(tmp_path, _cert())
    assert "tls.certificado.assinatura_fraca" not in out.ids()


def test_inventario_do_certificado(tmp_path: Path):
    out = _run(tmp_path, _cert())
    assert len(out.fact_keys("tls.cert")) == 1


def test_servico_que_nao_fala_tls_nao_gera_achado():
    with RawReplyServer(b"SSH-2.0-teste\r\n") as srv:
        out = run_check("tls.certificate", tls_fact(srv.port))
    assert not out.findings
