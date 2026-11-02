"""MTA-STS (RFC 8461) e TLS-RPT (RFC 8460): TXT e política lida do servidor local."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from fakes_dns import FALHA, ZonaFalsa, rodar
from helpers import CheckOutcome, LocalServer, Route

from eigan.checks.dns import transporte
from eigan.checks.dns.transporte import Certificado, ler_politica, mx_coberto, verificar_certificado
from eigan.core.models import Confidence, Severity

ORG = "exemplo.com.br"
MX = "mx1.exemplo.com.br"
CAMINHO = "/.well-known/mta-sts.txt"
POLITICA_OK = f"version: STSv1\r\nmode: enforce\r\nmx: {MX}\r\nmax_age: 604800\r\n"
TXT_STS = "v=STSv1; id=20261101T0000"
TXT_RPT = f"v=TLSRPTv1; rua=mailto:tlsrpt@{ORG}"


def _zona(
    mx: list[str] | None = None, sts: Any = TXT_STS, rpt: Any = TXT_RPT, **extra: Any
) -> dict[str, Any]:
    registros: dict[str, Any] = {ORG: {"MX": mx if mx is not None else [f"10 {MX}"]}, **extra}
    if sts is not None:
        registros[f"_mta-sts.{ORG}"] = (
            {"TXT": sts if isinstance(sts, list) else [sts]} if sts != FALHA else FALHA
        )
    if rpt is not None:
        registros[f"_smtp._tls.{ORG}"] = (
            {"TXT": rpt if isinstance(rpt, list) else [rpt]} if rpt != FALHA else FALHA
        )
    return registros


def _rodar(
    monkeypatch: pytest.MonkeyPatch,
    serve: Callable[..., LocalServer],
    politica: Route | None = None,
    registros: dict[str, Any] | None = None,
    certificado: Certificado | None = None,
) -> tuple[CheckOutcome, LocalServer]:
    """Roda dns.mta_sts com a política servida localmente e o certificado simulado."""
    rota = politica if politica is not None else Route(200, POLITICA_OK, content_type="text/plain")
    srv = serve({CAMINHO: rota})
    ZonaFalsa(registros if registros is not None else _zona()).instalar(monkeypatch)
    monkeypatch.setattr(
        transporte, "politica_url", lambda org: f"http://127.0.0.1:{srv.port}{CAMINHO}"
    )
    valido = certificado if certificado is not None else Certificado(True)
    monkeypatch.setattr(transporte, "verificar_certificado", lambda host, tempo, porta=443: valido)
    return rodar("dns.mta_sts", ORG), srv


def _texto(status: int = 200, corpo: str = POLITICA_OK, tipo: str | None = "text/plain") -> Route:
    return Route(status, corpo, content_type=tipo)


# -- quando se aplica ------------------------------------------------------------------
@pytest.mark.parametrize("mx", [[], ["0 ."]])
def test_dominio_que_nao_recebe_email_nao_e_avaliado(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer], mx: list[str]
) -> None:
    saida, srv = _rodar(monkeypatch, serve, registros={ORG: {"MX": mx, "A": ["192.0.2.1"]}})
    assert saida.findings == [] and srv.requests == []


def test_sem_anuncio_mta_sts_nem_tls_rpt(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer]
) -> None:
    saida, srv = _rodar(monkeypatch, serve, registros=_zona(sts=None, rpt=None))
    assert saida.ids() == {"dns.email.mta_sts_ausente", "dns.email.tls_rpt_ausente"}
    assert saida.by_id("dns.email.mta_sts_ausente")[0].severity == Severity.LOW
    assert saida.by_id("dns.email.tls_rpt_ausente")[0].severity == Severity.INFO
    assert srv.requests == []  # sem o TXT ninguém busca a política


def test_mx_sem_resposta_e_nao_verificado(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer]
) -> None:
    saida, _ = _rodar(monkeypatch, serve, registros={ORG: {"MX": FALHA}})
    assert saida.findings == []
    assert any("não verificado" in linha for linha in saida.logs)


def test_txt_sem_resposta_e_nao_verificado(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer]
) -> None:
    saida, _ = _rodar(monkeypatch, serve, registros=_zona(sts=FALHA, rpt=FALHA))
    assert saida.findings == []
    assert any("MTA-STS" in linha for linha in saida.logs) and any(
        "TLS-RPT" in linha for linha in saida.logs
    )


def test_nome_sob_plataforma_nao_e_avaliado(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer]
) -> None:
    ZonaFalsa({"loja.myshopify.com": {"MX": ["10 mx.exemplo.net"]}}).instalar(monkeypatch)
    saida = rodar("dns.mta_sts", "loja.myshopify.com")
    assert saida.findings == []


# -- política válida ----------------------------------------------------------------
def test_enforce_com_todos_os_mx_vira_ponto_forte(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer]
) -> None:
    saida, srv = _rodar(monkeypatch, serve)
    assert saida.findings == []
    assert {p.control for p in saida.passed} == {"dns.email.mta_sts", "dns.email.tls_rpt"}
    assert [r.method for r in srv.requests] == ["GET"]


@pytest.mark.parametrize(
    ("modo", "linha_mx"),
    [("testing", f"mx: {MX}\n"), ("none", "")],
)
def test_modo_que_nao_bloqueia(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer], modo: str, linha_mx: str
) -> None:
    politica = _texto(corpo=f"version: STSv1\nmode: {modo}\n{linha_mx}max_age: 86400\n")
    saida, _ = _rodar(monkeypatch, serve, politica)
    assert saida.ids() == {"dns.email.mta_sts_nao_aplicado"}
    [achado] = saida.by_id("dns.email.mta_sts_nao_aplicado")
    assert achado.severity == Severity.LOW and modo in achado.evidence


def test_curinga_cobre_um_rotulo(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer]
) -> None:
    politica = _texto(corpo="version: STSv1\nmode: enforce\nmx: *.exemplo.com.br\nmax_age: 86400\n")
    saida, _ = _rodar(monkeypatch, serve, politica)
    assert "dns.email.mta_sts_invalido" not in saida.ids()


def test_mx_coberto() -> None:
    assert mx_coberto("mail.example.com", "mail.example.com")
    assert mx_coberto("MAIL.example.com.", "mail.example.COM")
    assert mx_coberto("mail.example.com", "*.example.com")
    assert not mx_coberto("example.com", "*.example.com")
    assert not mx_coberto("foo.bar.example.com", "*.example.com")
    assert not mx_coberto("mail.outro.com", "mail.example.com")


def test_ler_politica_aceita_crlf_e_lf() -> None:
    campos = ler_politica(
        "version: STSv1\r\nmx: a.exemplo\nmx: b.exemplo\nsem-separador\nmax_age: 1"
    )
    assert campos == {"version": ["STSv1"], "mx": ["a.exemplo", "b.exemplo"], "max_age": ["1"]}


# -- política com problema ---------------------------------------------------------------
@pytest.mark.parametrize(
    ("corpo", "trecho"),
    [
        (f"mode: enforce\nmx: {MX}\nmax_age: 86400\n", "version"),
        (f"version: STSv2\nmode: enforce\nmx: {MX}\nmax_age: 86400\n", "deve ser STSv1"),
        (f"Version: STSv1\nmode: enforce\nmx: {MX}\nmax_age: 86400\n", "exatamente 'version'"),
        (f"version: STSv1\nmx: {MX}\nmax_age: 86400\n", "'mode'"),
        (f"version: STSv1\nmode: ENFORCE\nmx: {MX}\nmax_age: 86400\n", "em minúsculas"),
        (f"version: STSv1\nmode: enforce\nmx: {MX}\n", "'max_age'"),
        (f"version: STSv1\nmode: enforce\nmx: {MX}\nmax_age: uma-semana\n", "número de segundos"),
        (f"version: STSv1\nmode: enforce\nmx: {MX}\nmax_age: 31557601\n", "passa do máximo"),
        ("version: STSv1\nmode: enforce\nmax_age: 86400\n", "linha mx"),
    ],
)
def test_campos_da_politica(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer], corpo: str, trecho: str
) -> None:
    saida, _ = _rodar(monkeypatch, serve, _texto(corpo=corpo))
    [achado] = saida.by_id("dns.email.mta_sts_invalido")
    assert trecho in achado.evidence
    assert achado.severity == Severity.MEDIUM
    assert not any(p.control == "dns.email.mta_sts" for p in saida.passed)


def test_mx_fora_da_politica(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer]
) -> None:
    saida, _ = _rodar(monkeypatch, serve, registros=_zona(mx=[f"10 {MX}", "20 mx2.outro.net"]))
    [achado] = saida.by_id("dns.email.mta_sts_invalido")
    assert "mx2.outro.net" in achado.evidence and achado.details["mode"] == "enforce"
    assert achado.confidence == Confidence.CONFIRMED


def test_curinga_nao_cobre_dois_rotulos(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer]
) -> None:
    politica = _texto(corpo="version: STSv1\nmode: enforce\nmx: *.com.br\nmax_age: 86400\n")
    saida, _ = _rodar(monkeypatch, serve, politica)
    assert MX in saida.by_id("dns.email.mta_sts_invalido")[0].evidence


@pytest.mark.parametrize("status", [404, 500, 503])
def test_http_diferente_de_200(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer], status: int
) -> None:
    saida, _ = _rodar(monkeypatch, serve, _texto(status=status, corpo="erro", tipo="text/html"))
    assert f"HTTP {status}" in saida.by_id("dns.email.mta_sts_invalido")[0].evidence


def test_redirecionamento_nao_e_seguido(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer]
) -> None:
    politica = Route(301, "", headers=[("Location", "https://outro.exemplo.net/politica")])
    saida, srv = _rodar(monkeypatch, serve, politica)
    assert "HTTP 301" in saida.by_id("dns.email.mta_sts_invalido")[0].evidence
    assert len(srv.requests) == 1


def test_soft_404_nao_passa_como_politica(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer]
) -> None:
    politica = _texto(corpo="<html><body>Bem-vindo!</body></html>", tipo="text/html")
    saida, _ = _rodar(monkeypatch, serve, politica)
    [achado] = saida.by_id("dns.email.mta_sts_invalido")
    assert "falta o campo" in achado.evidence and "text/plain" in achado.evidence


def test_tipo_de_midia_diferente_e_firme_nao_confirmado(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer]
) -> None:
    saida, _ = _rodar(monkeypatch, serve, _texto(tipo="text/html"))
    [achado] = saida.by_id("dns.email.mta_sts_invalido")
    assert achado.confidence == Confidence.FIRM and "text/plain" in achado.evidence


def test_charset_no_tipo_de_midia_e_aceito(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer]
) -> None:
    saida, _ = _rodar(monkeypatch, serve, _texto(tipo="text/plain; charset=utf-8"))
    assert saida.findings == []


def test_politica_grande_demais(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer]
) -> None:
    corpo = POLITICA_OK + "# " + "x" * (transporte.TAMANHO_MAXIMO + 10) + "\n"
    saida, _ = _rodar(monkeypatch, serve, _texto(corpo=corpo))
    assert "64 KB" in saida.by_id("dns.email.mta_sts_invalido")[0].evidence


# -- certificado ---------------------------------------------------------------------
def test_certificado_invalido(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer]
) -> None:
    ruim = Certificado(False, "certificate has expired")
    saida, _ = _rodar(monkeypatch, serve, certificado=ruim)
    assert "certificate has expired" in saida.by_id("dns.email.mta_sts_invalido")[0].evidence


def test_certificado_nao_verificado_nao_vira_achado(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer]
) -> None:
    saida, _ = _rodar(monkeypatch, serve, certificado=Certificado(None, "sem rota"))
    assert "dns.email.mta_sts_invalido" not in saida.ids()
    assert any("não verificado" in linha for linha in saida.logs)


def test_verificar_certificado_reprova_autoassinado(serve: Callable[..., LocalServer]) -> None:
    srv = serve({"/": Route(200, "ok")}, tls=True)
    certificado = verificar_certificado("127.0.0.1", 5.0, porta=srv.port)
    assert certificado.valido is False and certificado.erro


def test_verificar_certificado_sem_conexao_nao_conclui() -> None:
    assert verificar_certificado("127.0.0.1", 1.0, porta=1).valido is None


# -- anúncio no DNS --------------------------------------------------------------------
@pytest.mark.parametrize(
    ("sts", "trecho"),
    [
        (["v=STSv1; id=1", "v=STSv1; id=2"], "2 registros"),
        (["v=stsv1; id=1"], "exatamente 'v=STSv1;'"),
        (["v=STSv1;"], "falta o campo id"),
        (["v=STSv1; id=com-traco"], "de 1 a 32 letras"),
        ([f"v=STSv1; id={'a' * 33}"], "de 1 a 32 letras"),
    ],
)
def test_anuncio_invalido(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer], sts: list[str], trecho: str
) -> None:
    saida, _ = _rodar(monkeypatch, serve, registros=_zona(sts=sts))
    assert trecho in saida.by_id("dns.email.mta_sts_invalido")[0].evidence


def test_outros_txt_em_mta_sts_sao_descartados(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer]
) -> None:
    saida, _ = _rodar(monkeypatch, serve, registros=_zona(sts=["outra coisa", TXT_STS]))
    assert saida.findings == []


def test_txt_que_nao_e_sts_conta_como_ausente(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer]
) -> None:
    saida, _ = _rodar(monkeypatch, serve, registros=_zona(sts=["outra coisa"]))
    assert "dns.email.mta_sts_ausente" in saida.ids()


def test_politica_inacessivel_com_nome_existente_e_nao_verificada(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer]
) -> None:
    registros = _zona(**{f"mta-sts.{ORG}": {"A": ["192.0.2.80"]}})
    ZonaFalsa(registros).instalar(monkeypatch)
    monkeypatch.setattr(transporte, "politica_url", lambda org: "http://127.0.0.1:1/x")
    saida = rodar("dns.mta_sts", ORG)
    assert "dns.email.mta_sts_invalido" not in saida.ids()
    assert any("não verificada" in linha for linha in saida.logs)


def test_nome_da_politica_inexistente_e_achado(monkeypatch: pytest.MonkeyPatch) -> None:
    ZonaFalsa(_zona()).instalar(monkeypatch)
    monkeypatch.setattr(transporte, "politica_url", lambda org: "http://127.0.0.1:1/x")
    saida = rodar("dns.mta_sts", ORG)
    assert "não existe no DNS" in saida.by_id("dns.email.mta_sts_invalido")[0].evidence


def test_nome_da_politica_com_dns_falhando_e_nao_verificado(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ZonaFalsa(_zona(**{f"mta-sts.{ORG}": FALHA})).instalar(monkeypatch)
    monkeypatch.setattr(transporte, "politica_url", lambda org: "http://127.0.0.1:1/x")
    saida = rodar("dns.mta_sts", ORG)
    assert "dns.email.mta_sts_invalido" not in saida.ids()


def test_url_oficial_da_politica() -> None:
    assert transporte.politica_url(ORG) == f"https://mta-sts.{ORG}{CAMINHO}"


# -- TLS-RPT ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "rpt",
    [
        f"v=TLSRPTv1; rua=mailto:tlsrpt@{ORG}",
        "v=TLSRPTv1; rua=https://relatorios.exemplo.net/tlsrpt",
        f"v=TLSRPTv1;rua=mailto:a@{ORG},https://relatorios.exemplo.net/tlsrpt",
    ],
)
def test_tls_rpt_valido(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer], rpt: str
) -> None:
    saida, _ = _rodar(monkeypatch, serve, registros=_zona(rpt=rpt))
    assert "dns.email.tls_rpt_ausente" not in saida.ids()
    assert any(p.control == "dns.email.tls_rpt" for p in saida.passed)


@pytest.mark.parametrize(
    ("rpt", "trecho"),
    [
        (
            ["v=TLSRPTv1; rua=mailto:a@b.exemplo", "v=TLSRPTv1; rua=mailto:c@d.exemplo"],
            "2 registros",
        ),
        (["v=tlsrptv1; rua=mailto:a@b.exemplo"], "exatamente 'v=TLSRPTv1'"),
        (["v=TLSRPTv1;"], "falta o campo rua"),
        (["v=TLSRPTv1; rua=ftp://b.exemplo/x"], "mailto: ou https://"),
    ],
)
def test_tls_rpt_invalido(
    monkeypatch: pytest.MonkeyPatch, serve: Callable[..., LocalServer], rpt: list[str], trecho: str
) -> None:
    saida, _ = _rodar(monkeypatch, serve, registros=_zona(rpt=rpt))
    [achado] = saida.by_id("dns.email.tls_rpt_ausente")
    assert achado.discriminator == "invalido" and trecho in achado.evidence
    assert not any(p.control == "dns.email.tls_rpt" for p in saida.passed)
