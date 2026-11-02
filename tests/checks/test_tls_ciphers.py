"""Suítes de cifra: servidores falsos que aceitam (ou não) as suítes oferecidas."""

from __future__ import annotations

from fakes_tls import (
    AES128_GCM_SHA256,
    DH_ANON_AES,
    ECDHE_RSA_AES128_GCM,
    RSA_3DES,
    RSA_AES128,
    RSA_AES128_GCM,
    RSA_EXPORT_RC4,
    RSA_NULL_SHA,
    RSA_RC4_SHA,
    TLS12,
    TLS13,
    FakeTlsServer,
    TlsProfile,
    tls_fact,
)
from helpers import run_check


def _run(profile: TlsProfile):
    with FakeTlsServer(profile) as srv:
        return run_check("tls.ciphers", tls_fact(srv.port))


def test_rc4_aceito():
    out = _run(TlsProfile({TLS12: (RSA_RC4_SHA, ECDHE_RSA_AES128_GCM)}))
    [finding] = out.by_id("tls.cifra.quebrada")
    assert "RC4" in finding.evidence
    assert "CVE-2013-2566" in finding.cves


def test_null_e_export_e_anonima_sao_inseguras():
    for suite in (RSA_NULL_SHA, RSA_EXPORT_RC4, DH_ANON_AES):
        out = _run(TlsProfile({TLS12: (suite, ECDHE_RSA_AES128_GCM)}))
        assert "tls.cifra.insegura" in out.ids(), hex(suite)


def test_3des_aceito():
    out = _run(TlsProfile({TLS12: (RSA_3DES, ECDHE_RSA_AES128_GCM)}))
    [finding] = out.by_id("tls.cifra.3des")
    assert "CVE-2016-2183" in finding.cves


def test_so_rsa_nao_tem_sigilo_futuro():
    out = _run(TlsProfile({TLS12: (RSA_AES128, RSA_AES128_GCM)}))
    assert out.ids() == {"tls.cifra.sem_sigilo_futuro"}


def test_servidor_moderno_tem_pontos_fortes_e_nenhum_achado():
    out = _run(TlsProfile({TLS12: (ECDHE_RSA_AES128_GCM,), TLS13: (AES128_GCM_SHA256,)}))
    assert not out.findings
    controls = {p.control for p in out.passed}
    assert {"tls.cifras.fortes", "tls.cifras.sigilo_futuro"} <= controls


def test_so_tls13():
    out = _run(TlsProfile({TLS13: (AES128_GCM_SHA256,)}))
    assert not out.findings
    assert any(p.control == "tls.cifras.fortes" for p in out.passed)


def test_servidor_calado_nao_vira_achado():
    out = _run(TlsProfile(silent_versions=frozenset({TLS12})))
    assert not out.findings
    assert not any(p.control == "tls.cifras.fortes" for p in out.passed)
