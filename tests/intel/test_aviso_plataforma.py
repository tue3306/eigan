"""Aviso na narrativa: nota boa de site só de front-end atrás de plataforma/CDN."""

from __future__ import annotations

import pytest

from eigan.core import kb
from eigan.core.models import Fact, Finding, PassedControl, ScanResult, TargetKind
from eigan.core.registry import load_builtin_checks
from eigan.intel.analysis import analyze

load_builtin_checks()


def tech(name: str, kind: str = "cdn") -> Fact:
    return Fact("tech", f"x:{name}", {"name": name, "kind": kind}, source="web.fingerprint")


def frontend(backend: bool) -> Fact:
    return Fact("web.frontend", "https://x.test/", {"backend": backend}, source="web.content")


def result(facts: list[Fact], kind: TargetKind = TargetKind.URL) -> ScanResult:
    return ScanResult(
        id="s1",
        target="https://x.test",
        kind=kind,
        profile="padrao",
        started_at="2026-11-02T10:00:00+00:00",
        finished_at="2026-11-02T10:00:05+00:00",
        status="concluida",
        facts=facts,
        passed=[PassedControl("web.https.forcado", "HTTPS forçado", "https://x.test/")],
    )


def paragraphs(res: ScanResult) -> str:
    return " ".join(analyze(res)["narrative"]["paragraphs"])


@pytest.mark.parametrize(
    "nome",
    ["cloudflare", "render", "vercel", "netlify", "github-pages", "fastly", "cloudfront"],
)
def test_aparece_para_cada_plataforma(nome):
    texto = paragraphs(result([tech(nome), frontend(False)]))
    assert "podem ser da plataforma" in texto
    assert "nada diz sobre uma aplicação que ainda não existe" in texto


@pytest.mark.parametrize(
    "fatos",
    [
        [tech("cloudflare"), frontend(True)],  # há back end
        [tech("nginx", "server"), frontend(False)],  # sem plataforma conhecida
        [tech("cloudflare"), frontend(False), tech("php", "language")],  # linguagem de servidor
        [tech("cloudflare")],  # sem leitura do conteúdo
        [tech("cloudflare"), frontend(False), tech("wordpress", "cms")],  # CMS roda no servidor
        [tech("cloudflare"), frontend(False), tech("gunicorn", "server")],  # servidor de aplicação
        [tech("render", "service"), frontend(False), tech("uvicorn", "server")],
        [tech("cloudflare"), frontend(False), tech("tomcat", "server")],
        [tech("cloudflare"), frontend(False), tech("heroku", "service")],
    ],
)
def test_nao_aparece(fatos):
    assert "plataforma" not in paragraphs(result(fatos))


def test_nao_aparece_fora_de_url():
    res = result([tech("cloudflare"), frontend(False)], kind=TargetKind.HOST)
    assert "plataforma" not in paragraphs(res)


def test_nao_aparece_com_nota_ruim():
    res = result([tech("cloudflare"), frontend(False)])
    res.findings = [
        Finding(
            check_id=c,
            title=kb.require(c).title,
            severity=kb.require(c).severity,
            asset="https://x.test/",
            source="web.transport",
        )
        for c in (
            "web.hsts.ausente",
            "web.csp.ausente",
            "web.https.sem_redirecionamento",
            "web.conteudo.segredo",
            "web.debug.werkzeug",
        )
    ]
    data = analyze(res)
    assert data["posture"]["grade"] not in ("A+", "A", "B")
    assert "podem ser da plataforma" not in " ".join(data["narrative"]["paragraphs"])
