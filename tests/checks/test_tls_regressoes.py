"""Regressões da revisão: datas extremas, texto hostil, conexões derrubadas e raiz sob demanda."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from fakes_tls import (
    AES128_GCM_SHA256,
    ECDHE_RSA_AES128_GCM,
    TLS12,
    TLS13,
    FakeTlsServer,
    RealTlsServer,
    TlsProfile,
    build_cert,
    fixture_spki,
    fixture_trust,
    tls_fact,
)
from helpers import run_check

from eigan.checks.tls import asn1, certificate, common
from eigan.core.models import Exposure, Severity


@pytest.fixture
def _confia_so_na_fixture(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(certificate, "trust_context", fixture_trust)


def _run_cert(tmp_path: Path, der: bytes):
    with RealTlsServer(tmp_path, der) as srv:
        return run_check("tls.certificate", tls_fact(srv.port, sni="site.exemplo"))


@pytest.mark.usefixtures("_confia_so_na_fixture")
def test_data_no_limite_do_calendario_nao_derruba_a_checagem(tmp_path: Path):
    der = build_cert(
        spki=fixture_spki(),
        not_before=datetime(1, 1, 1, tzinfo=UTC),
        not_after=datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC),
        san_dns=("outro.exemplo",),
    )
    out = _run_cert(tmp_path, der)
    assert "tls.certificado.nome_divergente" in out.ids()
    assert "tls.certificado.expirado" not in out.ids()


@pytest.mark.usefixtures("_confia_so_na_fixture")
def test_texto_hostil_do_certificado_e_higienizado(tmp_path: Path):
    hostil = "x\x1b[2J\x1b[31mPWNED\nLINHA2" + "A" * 50000
    der = build_cert(
        spki=fixture_spki(),
        cn=hostil,
        org="O\x07rg",
        san_dns=("a.exemplo",) + tuple(f"n{i}.exemplo" for i in range(300)),
    )
    out = _run_cert(tmp_path, der)
    texto = repr([f.evidence for f in out.findings]) + repr(out.facts)
    assert "\x1b" not in texto
    assert "\x07" not in texto
    assert len(texto) < 20000
    [fact] = [f for f in out.facts if f.kind == "tls.cert"]
    assert len(fact.data["san"]) <= 50
    assert fact.data["san_total"] == 301


def test_clean_text_remove_controles_e_corta():
    assert asn1.clean_text("a\x1b[0mb\nc") == "a�[0mb�c"
    assert len(asn1.clean_text("x" * 1000)) == asn1.MAX_TEXT


def test_diretorio_de_cas_sem_permissao_nao_derruba(monkeypatch: pytest.MonkeyPatch):
    def negado(self: Path):
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "iterdir", negado)
    monkeypatch.setattr(Path, "is_dir", lambda self: True)

    class _Ctx:
        def cert_store_stats(self) -> dict[str, int]:
            return {}

    assert certificate._has_authorities(_Ctx()) is False  # type: ignore[arg-type]


@pytest.mark.usefixtures("_confia_so_na_fixture")
def test_raiz_sob_demanda_no_windows_rebaixa_severidade(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(certificate, "_lazy_root_store", lambda: True)
    monkeypatch.setattr(common, "exposure_of", lambda host: Exposure.INTERNET)
    out = _run_cert(tmp_path, build_cert(spki=fixture_spki()))
    [finding] = out.by_id("tls.certificado.nao_confiavel")
    assert finding.severity is Severity.LOW
    assert finding.confidence.value == "tentative"


@pytest.mark.usefixtures("_confia_so_na_fixture")
def test_cadeia_incompleta_e_tentativa(tmp_path: Path):
    out = _run_cert(tmp_path, build_cert(spki=fixture_spki(), aia=["http://ca.exemplo/i.crt"]))
    [finding] = out.by_id("tls.certificado.cadeia_incompleta")
    assert finding.confidence.value == "tentative"


def _limitado(profile: TlsProfile, *, derruba_apos_fraca: bool):
    """Servidor que derruba a conexão (sem alerta) depois da primeira oferta só com suítes fracas."""
    estado = {"derrubando": False}

    def politica(hello):
        fraca = ECDHE_RSA_AES128_GCM not in hello.suites and AES128_GCM_SHA256 not in hello.suites
        if fraca and derruba_apos_fraca:
            estado["derrubando"] = True
        if estado["derrubando"] or fraca:
            return None
        return profile(hello)

    return politica


def test_servidor_que_derruba_tudo_nao_gera_ponto_forte_de_cifras():
    profile = TlsProfile({TLS12: (ECDHE_RSA_AES128_GCM,), TLS13: (AES128_GCM_SHA256,)})
    with FakeTlsServer(_limitado(profile, derruba_apos_fraca=True)) as srv:
        out = run_check("tls.ciphers", tls_fact(srv.port))
    assert not out.findings
    assert not any(p.control == "tls.cifras.fortes" for p in out.passed)


def test_servidor_que_derruba_tudo_nao_gera_ponto_forte_de_protocolos():
    profile = TlsProfile({TLS12: (ECDHE_RSA_AES128_GCM,), TLS13: (AES128_GCM_SHA256,)})
    with FakeTlsServer(_limitado(profile, derruba_apos_fraca=True)) as srv:
        out = run_check("tls.protocols", tls_fact(srv.port))
    assert not any(p.control == "tls.protocolos.modernos" for p in out.passed)


def test_recusa_silenciosa_com_servidor_saudavel_ainda_e_ponto_forte():
    profile = TlsProfile({TLS12: (ECDHE_RSA_AES128_GCM,), TLS13: (AES128_GCM_SHA256,)})
    with FakeTlsServer(_limitado(profile, derruba_apos_fraca=False)) as srv:
        out = run_check("tls.ciphers", tls_fact(srv.port))
    assert not out.findings
    assert any(p.control == "tls.cifras.fortes" for p in out.passed)


def test_so_tls13_com_tls12_calado_nao_gera_ponto_forte():
    profile = TlsProfile({TLS13: (AES128_GCM_SHA256,)}, silent_versions=frozenset({TLS12}))
    with FakeTlsServer(profile) as srv:
        out = run_check("tls.ciphers", tls_fact(srv.port))
    assert not any(p.control == "tls.cifras.fortes" for p in out.passed)
