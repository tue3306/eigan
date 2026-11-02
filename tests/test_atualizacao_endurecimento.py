"""Atualização dos catálogos contra fontes hostis: cópia malformada, datas, texto, padrões e prazo."""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from collections.abc import Iterator
from datetime import date
from pathlib import Path
from typing import Any

import pytest
from fakes_atualizacao import (
    FakeResponse,
    kev_feed,
    opener_for,
    psl_text,
    retire_repo,
)

from eigan import data
from eigan.checks.dns import nomes
from eigan.checks.web import jslibs
from eigan.core import atualizacao, baixar, vulndb
from eigan.data import overlay_dir

HOJE = date(2027, 1, 20)
RAIZ = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    monkeypatch.setenv("EIGAN_HOME", str(tmp_path / "eigan"))
    atualizacao._limpar_derivados()
    yield tmp_path / "eigan"
    monkeypatch.undo()
    atualizacao._limpar_derivados()


def rodar(
    routes: dict[str, bytes | Exception], nomes_: list[str], **kw: Any
) -> list[dict[str, Any]]:
    return atualizacao.atualizar(nomes_, opener=opener_for(routes), hoje=HOJE, **kw)


def escrever_copia(nome: str, dados: Any) -> None:
    overlay_dir().mkdir(parents=True, exist_ok=True)
    (overlay_dir() / nome).write_text(json.dumps(dados), encoding="utf-8")
    atualizacao._limpar_derivados()


# -- a cópia baixada precisa ter o formato interno certo ----------------------------------------


def test_catalogos_embarcados_passam_na_conferencia_de_formato() -> None:
    for nome in data.ATUALIZAVEIS:
        assert data.formato.problema(nome, data.load_embedded_json(nome)) is None


@pytest.mark.parametrize(
    ("nome", "campos"),
    [
        ("kev.json", {"publicado": "2027-01-10T00:00:00Z", "itens": [1, 2]}),
        ("kev.json", {"publicado": "2027-01-10T00:00:00Z", "itens": {"CVE-2021-44228": "x"}}),
        ("kev.json", {"publicado": "2027-01-10", "itens": {"CVE-1": ["a", "b", "c", "d", 7]}}),
        ("web_retire.json", {"atualizado": "2027-01-10", "bibliotecas": {"x": 1}}),
        (
            "web_retire.json",
            {
                "atualizado": "2027-01-10",
                "bibliotecas": {"x": {"extractors": [], "vulnerabilities": []}},
            },
        ),
        (
            "web_retire.json",
            {
                "atualizado": "2027-01-10",
                "bibliotecas": {"x": {"extractors": {"uri": [1]}, "vulnerabilities": [{}]}},
            },
        ),
        (
            "web_retire.json",
            {
                "atualizado": "2027-01-10",
                "bibliotecas": {"x": {"extractors": {}, "vulnerabilities": [3]}},
            },
        ),
        ("dns_sufixos.json", {"atualizado": "2027-01-10", "icann": [1, ["a"]], "privado": ["b"]}),
        ("dns_sufixos.json", {"atualizado": "2027-01-10", "icann": ["com"], "privado": "x"}),
    ],
)
def test_copia_com_formato_interno_errado_volta_para_o_embarcado(
    nome: str, campos: dict[str, Any], caplog: pytest.LogCaptureFixture
) -> None:
    escrever_copia(nome, {**data.load_embedded_json(nome), **campos})
    with caplog.at_level(logging.WARNING, logger="eigan.data"):
        assert data.origem(nome) == "embarcado"
    assert "ignorados" in caplog.text
    # os consumidores seguem funcionando com o embarcado
    assert vulndb.is_kev("CVE-2021-44228")
    assert jslibs.repository().by_name["jquery"].vulnerabilities
    assert nomes.sufixo_publico("www.exemplo.com.br") == "com.br"


# -- data no futuro ---------------------------------------------------------------------------


def kev_em(publicado: str) -> dict[str, Any]:
    base = data.load_embedded_json("kev.json")
    return {**base, "publicado": publicado}


def test_copia_com_data_no_futuro_perde_para_o_embarcado(caplog: pytest.LogCaptureFixture) -> None:
    escrever_copia("kev.json", kev_em("2030-01-01T00:00:00Z"))
    with caplog.at_level(logging.WARNING, logger="eigan.data"):
        assert data.origem("kev.json") == "embarcado"
    assert "no futuro" in caplog.text
    [kev] = [c for c in atualizacao.estado(HOJE) if c["nome"] == "kev"]
    assert kev["idade_dias"] >= 0


def test_data_de_amanha_ainda_vale_pela_folga_de_fuso() -> None:
    escrever_copia("kev.json", kev_em("2027-01-21T00:00:00Z"))
    assert data.origem("kev.json") == "baixado"
    escrever_copia("kev.json", kev_em("2027-01-22T00:00:00Z"))
    assert data.origem("kev.json") == "embarcado"


def test_fonte_com_data_no_futuro_e_recusada_e_nao_trava_as_proximas() -> None:
    [resultado] = rodar({atualizacao.KEV_URL: kev_feed(released="2099-01-01T00:00:00Z")}, ["kev"])
    assert resultado["ok"] is False
    assert "futuro" in resultado["erro"]
    assert not (overlay_dir() / "kev.json").exists()
    [seguinte] = rodar({atualizacao.KEV_URL: kev_feed()}, ["kev"])
    assert seguinte["ok"] and seguinte["gravado"]


# -- texto vindo da rede ----------------------------------------------------------------------


def sem_controle(texto: str) -> bool:
    return not re.search(r"[\x00-\x08\x0b-\x1f\x7f-\x9f​-‏‪-‮]", texto)


def test_kev_com_sequencias_de_escape_e_limpo_e_a_versao_tem_teto() -> None:
    feed = json.loads(kev_feed())
    feed["catalogVersion"] = "\x1b[31mPWNED\x1b[0m" + "9" * 500
    feed["vulnerabilities"][0]["vendorProject"] = "Ivanti\x1b[2J\x1b]0;PWNED\x07"
    feed["vulnerabilities"][0]["vulnerabilityName"] = "Nome‮oculto"
    [resultado] = rodar({atualizacao.KEV_URL: json.dumps(feed).encode()}, ["kev"])
    assert resultado["ok"], resultado
    assert sem_controle(resultado["versao"])
    assert len(resultado["versao"]) <= 80
    gravado = json.loads((overlay_dir() / "kev.json").read_text(encoding="utf-8"))
    assert sem_controle(gravado["versao"])
    assert sem_controle(gravado["itens"]["CVE-2027-1000"][0])
    assert "Ivanti" in gravado["itens"]["CVE-2027-1000"][0]
    assert sem_controle(gravado["itens"]["CVE-2027-1000"][2])


def test_sufixos_com_escape_na_versao_e_no_commit_e_limpo() -> None:
    bruto = psl_text().replace(b"2027-01-14_10-00-00_UTC", b"2027-01-14\x1b[2J_UTC")
    bruto = bruto.replace(b"abcdef0123456789", b"abc\x07def")
    [resultado] = rodar({atualizacao.SUFIXOS_URL: bruto}, ["sufixos"])
    assert resultado["ok"], resultado
    assert sem_controle(resultado["versao"])
    assert "abcdef" in resultado["versao"]


def test_mensagem_de_erro_nao_leva_controle_nem_e_gigante() -> None:
    erro = atualizacao._descrever_erro(ValueError("falhou\x1b[2J" + "x" * 5000))
    assert sem_controle(erro)
    assert len(erro) <= 300
    feed = json.loads(kev_feed())
    feed["vulnerabilities"][0]["cveID"] = "CVE-2027-\x1b[31m" + "9" * 100
    [resultado] = rodar({atualizacao.KEV_URL: json.dumps(feed).encode()}, ["kev"])
    assert resultado["ok"] is False
    assert sem_controle(resultado["erro"])


# -- padrões de extração do retire.js ---------------------------------------------------------


def retire_com(extrator: str, valor: Any) -> bytes:
    repo = json.loads(retire_repo())
    repo["jquery"]["extractors"][extrator] = valor
    return json.dumps(repo).encode()


@pytest.mark.parametrize(
    ("extrator", "valor"),
    [
        ("filecontent", ["(a+)+x(§§version§§)"]),
        ("uri", ["(.*a*)*/(§§version§§)"]),
        ("filecontentreplace", ["/(a|b*)*c/$1/"]),
        ("filecontent", ["a" * 1500 + "(§§version§§)"]),
        ("filecontent", ["(§§version§§"]),
    ],
)
def test_retire_com_padrao_perigoso_ou_invalido_e_recusado(extrator: str, valor: Any) -> None:
    [resultado] = rodar({atualizacao.RETIRE_URL: retire_com(extrator, valor)}, ["retire"])
    assert resultado["ok"] is False, resultado
    assert "jquery" in resultado["erro"]
    assert not (overlay_dir() / "web_retire.json").exists()


@pytest.mark.parametrize("valor", [{"a": "b"}, "texto", [["x"]], [1]])
def test_retire_com_extrator_do_tipo_errado_e_recusado(valor: Any) -> None:
    [resultado] = rodar({atualizacao.RETIRE_URL: retire_com("filecontent", valor)}, ["retire"])
    assert resultado["ok"] is False


def test_padroes_da_base_embarcada_passam_e_so_os_de_sempre_sao_ignorados() -> None:
    for biblioteca in data.load_embedded_json("web_retire.json")["bibliotecas"].values():
        assert jslibs.padrao_suspeito(biblioteca["extractors"]) is None
    assert len(jslibs.repository().skipped_patterns) <= 2


def test_padrao_perigoso_reconhece_repeticao_aninhada_sem_teto() -> None:
    assert jslibs.padrao_perigoso("(a+)+x(§§version§§)")
    assert jslibs.padrao_perigoso("(?:a|b*)*c")
    assert jslibs.padrao_perigoso("(")
    assert not jslibs.padrao_perigoso("jquery[-.]v?(§§version§§)")
    assert not jslibs.padrao_perigoso(r"(\s+a){1,3}(§§version§§)")
    assert not jslibs.padrao_perigoso(r"/\*!?[\n *]+jQuery UI (§§version§§)(.*\n)*.*\.ui\.dialog")


def test_cópia_baixada_com_padrao_perigoso_nao_chega_a_ser_compilada() -> None:
    copia = data.load_embedded_json("web_retire.json")
    copia = {**copia, "atualizado": "2027-01-10"}
    copia["bibliotecas"]["jquery"]["extractors"]["filecontent"].append("(a+)+x(§§version§§)")
    escrever_copia("web_retire.json", copia)
    assert data.origem("web_retire.json") == "baixado"
    repo = jslibs.repository()
    assert "(a+)+x(§§version§§)" in repo.skipped_patterns
    assert all("(a+)+" not in p.pattern for p in repo.by_name["jquery"].filecontent)


# -- prazo total do download ------------------------------------------------------------------


class RespostaLenta(FakeResponse):
    """Entrega 1 byte por leitura e gasta 59 s de relógio em cada uma."""

    def __init__(self, url: str, relogio: list[float]) -> None:
        super().__init__(b"x" * 10_000, url)
        self.relogio = relogio

    def read1(self, size: int = -1) -> bytes:
        self.relogio[0] += 59.0
        return super().read(1)


def test_download_lento_estoura_o_prazo_total_e_solta_a_trava(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    relogio = [1000.0]
    monkeypatch.setattr(baixar, "_agora", lambda: relogio[0])
    lidas: list[RespostaLenta] = []

    def abridor(url: str, timeout: float = 0.0) -> RespostaLenta:
        lidas.append(RespostaLenta(url, relogio))
        return lidas[-1]

    [resultado] = atualizacao.atualizar(["kev"], opener=abridor, hoje=HOJE)
    assert resultado["ok"] is False
    assert "tempo" in resultado["erro"]
    assert atualizacao.ocupado() is False
    # parou logo depois de passar de 120 s, sem esperar o arquivo inteiro
    assert len(lidas) == 1
    assert relogio[0] - 1000.0 < 4 * 59.0


def test_prazo_total_e_opcional_e_leitura_sem_read1_continua_funcionando() -> None:
    url = atualizacao.KEV_URL
    corpo = baixar.fetch_bytes(url, 1.0, opener_for({url: b"abc" * 100}), 10_000)
    assert corpo == b"abc" * 100
    com_prazo = baixar.fetch_bytes(url, 1.0, opener_for({url: b"abc"}), 10_000, total=5.0)
    assert com_prazo == b"abc"


# -- painel: data sem fuso ---------------------------------------------------------------------


def _funcao_js(arquivo: str, nome: str) -> str:
    texto = (RAIZ / "src" / "eigan" / "panel" / "static" / "js" / arquivo).read_text(
        encoding="utf-8"
    )
    inicio = texto.index(f"export function {nome}(")
    fim = texto.index("\n}\n", inicio) + 3
    return texto[inicio:fim].replace("export ", "", 1)


@pytest.mark.skipif(shutil.which("node") is None, reason="precisa do Node.js")
@pytest.mark.parametrize("fuso", ["America/Sao_Paulo", "America/Rio_Branco", "UTC", "Asia/Tokyo"])
def test_data_so_dia_nao_muda_de_dia_em_nenhum_fuso(fuso: str) -> None:
    codigo = (
        _funcao_js("ui.js", "dateOnly")
        + 'console.log([dateOnly("2026-11-01"), dateOnly("2026-10-30T17:02:45.366Z"), dateOnly("")].join("|"));'
    )
    saida = subprocess.run(  # noqa: S603 — node local, código do próprio repositório
        [shutil.which("node") or "node", "-e", codigo],
        env={**os.environ, "TZ": fuso},
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    assert saida.stdout.strip() == "01/11/2026|30/10/2026|"


def test_painel_mostra_o_motivo_quando_nada_foi_gravado_e_nao_corta_a_versao() -> None:
    js = (RAIZ / "src" / "eigan" / "panel" / "static" / "js" / "views" / "sobre.js").read_text(
        encoding="utf-8"
    )
    assert "r.gravado" in js
    assert "r.motivo" in js
    assert "slice(0, 40)" not in js
    assert 'split(" (")[0]' in js
