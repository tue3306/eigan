"""Versões do TLS: sondas cruas contra servidores falsos e um servidor TLS de verdade."""

from __future__ import annotations

from pathlib import Path

from fakes_tls import (
    AES128_GCM_SHA256,
    ECDHE_RSA_AES128_GCM,
    RSA_AES128,
    RSA_AES128_GCM,
    SSL3,
    TLS10,
    TLS11,
    TLS12,
    TLS13,
    FakeTlsServer,
    RawReplyServer,
    RealTlsServer,
    TlsProfile,
    fixture_der,
    tls_fact,
)
from helpers import run_check


def _run(port: int):
    return run_check("tls.protocols", tls_fact(port))


def test_so_tls10_gera_achado_e_sem_tls12():
    profile = TlsProfile({TLS10: (RSA_AES128,)})
    with FakeTlsServer(profile) as srv:
        out = _run(srv.port)
    assert "tls.protocolo.tls10" in out.ids()
    assert "tls.versao.sem_tls12" in out.ids()
    assert "tls.versao.sem_tls13" in out.ids()
    assert "tls.protocolo.tls11" not in out.ids()
    assert not any(p.control == "tls.protocolos.modernos" for p in out.passed)


def test_tls11_aceito():
    profile = TlsProfile({TLS11: (RSA_AES128,), TLS12: (RSA_AES128_GCM,)})
    with FakeTlsServer(profile) as srv:
        out = _run(srv.port)
    assert "tls.protocolo.tls11" in out.ids()
    assert "tls.versao.sem_tls12" not in out.ids()


def test_sslv3_com_cbc_cita_poodle():
    profile = TlsProfile({SSL3: (RSA_AES128,), TLS12: (RSA_AES128_GCM,)})
    with FakeTlsServer(profile) as srv:
        out = _run(srv.port)
    [finding] = out.by_id("tls.protocolo.sslv3")
    assert "CVE-2014-3566" in finding.cves


def test_sslv2_aceito():
    profile = TlsProfile({TLS12: (RSA_AES128_GCM,)}, sslv2_ciphers=3)
    with FakeTlsServer(profile) as srv:
        out = _run(srv.port)
    [finding] = out.by_id("tls.protocolo.sslv2")
    assert "CVE-2016-0800" in finding.cves


def test_servidor_so_moderno_vira_ponto_forte():
    profile = TlsProfile({TLS12: (ECDHE_RSA_AES128_GCM,), TLS13: (AES128_GCM_SHA256,)})
    with FakeTlsServer(profile) as srv:
        out = _run(srv.port)
    assert not out.findings
    assert any(p.control == "tls.protocolos.modernos" for p in out.passed)


def test_tls12_sem_tls13_gera_info():
    profile = TlsProfile({TLS12: (ECDHE_RSA_AES128_GCM,)})
    with FakeTlsServer(profile) as srv:
        out = _run(srv.port)
    assert out.ids() == {"tls.versao.sem_tls13"}


def test_servidor_tls_de_verdade_nao_gera_achado_de_versao_antiga(tmp_path: Path):
    with RealTlsServer(tmp_path, fixture_der()) as srv:
        out = _run(srv.port)
    legacy = {
        "tls.protocolo.sslv2",
        "tls.protocolo.sslv3",
        "tls.protocolo.tls10",
        "tls.protocolo.tls11",
    }
    assert not (out.ids() & legacy)
    assert "tls.versao.sem_tls12" not in out.ids()


def test_conexao_que_cai_nao_vira_achado():
    profile = TlsProfile(silent_versions=frozenset({TLS10, TLS11, SSL3, TLS12}))
    with FakeTlsServer(profile) as srv:
        out = run_check("tls.protocols", tls_fact(srv.port))
    assert not out.findings


def test_servico_que_nao_fala_tls():
    with RawReplyServer(b"HTTP/1.1 400 Bad Request\r\n\r\n") as srv:
        out = _run(srv.port)
    assert not out.findings


def test_porta_fechada():
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    out = _run(port)
    assert not out.findings
