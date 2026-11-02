"""Atualização dos catálogos: conversão, validação, gravação atômica e prioridade da cópia baixada."""

from __future__ import annotations

import dataclasses
import json
import logging
import os
import socket
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pytest
from fakes_atualizacao import (
    KEV_DATA,
    FakeResponse,
    kev_feed,
    ok_routes,
    opener_for,
    psl_text,
    retire_repo,
)

from eigan import data
from eigan.core import atualizacao, baixar, vulndb
from eigan.data import overlay_dir

HOJE = date(2027, 1, 20)


@pytest.fixture(autouse=True)
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Dados do EIGAN isolados e caches limpos antes e depois (a cópia baixada vale para tudo)."""
    monkeypatch.setenv("EIGAN_HOME", str(tmp_path / "eigan"))
    atualizacao._limpar_derivados()
    yield tmp_path / "eigan"
    monkeypatch.undo()
    atualizacao._limpar_derivados()


def rodar(
    routes: dict[str, bytes | Exception] | None = None, nomes: list[str] | None = None, **kw: Any
) -> list[dict[str, Any]]:
    return atualizacao.atualizar(
        nomes, opener=opener_for(routes if routes is not None else ok_routes()), hoje=HOJE, **kw
    )


def por_nome(resultados: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {r["nome"]: r for r in resultados}


# -- conversores ---------------------------------------------------------------------------


def test_converter_kev_usa_o_formato_embarcado() -> None:
    bruto = json.dumps(
        {
            "catalogVersion": "2027.01.15",
            "dateReleased": "2027-01-15T10:00:00Z",
            "vulnerabilities": [
                {
                    "cveID": "cve-2020-0001",
                    "vendorProject": " Acme ",
                    "product": "Painel",
                    "vulnerabilityName": "Acme  Painel\nFalha",
                    "dateAdded": "2020-05-01",
                    "knownRansomwareCampaignUse": "Unknown",
                },
                {
                    "cveID": "CVE-2027-0002",
                    "vendorProject": "Beta",
                    "product": "Gateway",
                    "vulnerabilityName": "Beta Gateway Falha",
                    "dateAdded": "2027-01-10",
                    "knownRansomwareCampaignUse": "Known",
                },
                {"cveID": "sem-cve"},
                "lixo",
            ],
        }
    ).encode()
    convertido = atualizacao.converter_kev(bruto, HOJE)
    embarcado = data.load_embedded_json("kev.json")
    assert list(convertido) == list(embarcado)
    assert convertido["campos"] == embarcado["campos"]
    assert convertido["versao"] == "2027.01.15"
    assert convertido["publicado"] == "2027-01-15T10:00:00Z"
    assert convertido["itens"] == {
        "CVE-2027-0002": ["Beta", "Gateway", "Beta Gateway Falha", "2027-01-10", 1],
        "CVE-2020-0001": ["Acme", "Painel", "Acme Painel Falha", "2020-05-01", 0],
    }
    assert list(convertido["itens"]) == ["CVE-2027-0002", "CVE-2020-0001"]  # mais novos primeiro


def test_converter_kev_recusa_formato_inesperado() -> None:
    with pytest.raises(atualizacao.FalhaAtualizacao):
        atualizacao.converter_kev(b'{"outra": []}', HOJE)
    with pytest.raises(atualizacao.FalhaAtualizacao):
        atualizacao.converter_kev(b"<html>erro</html>", HOJE)


def test_converter_retire_aplica_as_alteracoes_declaradas() -> None:
    convertido = atualizacao.converter_retire(retire_repo(3), HOJE)
    assert list(convertido) == list(data.load_embedded_json("web_retire.json"))
    assert convertido["atualizado"] == "2027-01-20"
    bibliotecas = convertido["bibliotecas"]
    assert "retire-example" not in bibliotecas
    jquery = bibliotecas["jquery"]
    for campo in ("licenses", "bowername", "basePurl"):
        assert campo not in jquery
    assert set(jquery["extractors"]) == {"uri", "filecontent"}
    assert jquery["npmname"] == "lib1"
    assert jquery["vulnerabilities"][0]["below"] == "2.0.0"
    assert "§§version§§" in jquery["extractors"]["uri"][0]


def test_converter_sufixos_separa_secoes_e_converte_idn() -> None:
    texto = "\n".join(
        [
            "// VERSION: 2027-01-14_10-00-00_UTC",
            "// COMMIT: abc123",
            "// ===BEGIN ICANN DOMAINS===",
            "br",
            "com.br   // comentário",
            "*.ck",
            "!www.ck",
            "公司.cn",
            "a‎b.example",
            "// ===END ICANN DOMAINS===",
            "// ===BEGIN PRIVATE DOMAINS===",
            "GitHub.io",
            "// ===END PRIVATE DOMAINS===",
            "fora.example",
        ]
    ).encode()
    convertido = atualizacao.converter_sufixos(texto, HOJE)
    assert convertido["icann"] == ["!www.ck", "*.ck", "br", "com.br", "xn--55qx5d.cn"]
    assert convertido["privado"] == ["github.io"]
    assert convertido["versao"] == "2027-01-14_10-00-00_UTC (commit abc123)"
    assert "a‎b.example" in convertido["obs"]
    assert list(convertido) == list(data.load_embedded_json("dns_sufixos.json"))


def test_serializacao_reproduz_os_arquivos_embarcados() -> None:
    for fonte in atualizacao.FONTES.values():
        embarcado = data.load_embedded_json(fonte.arquivo)
        texto = fonte.serializar(embarcado)
        original = (
            Path(data.__file__).with_name(fonte.arquivo).read_bytes().decode().replace("\r\n", "\n")
        )
        assert texto.rstrip() == original.rstrip(), fonte.nome


# -- atualização completa ------------------------------------------------------------------


def test_atualizar_grava_as_tres_fontes_e_a_cópia_passa_a_valer(home: Path) -> None:
    resultados = por_nome(rodar())
    assert all(r["ok"] and r["gravado"] for r in resultados.values()), resultados
    assert resultados["kev"]["itens"] == 1200
    assert resultados["kev"]["versao"] == "2027.01.15"
    assert resultados["kev"]["data"] == KEV_DATA
    assert resultados["sufixos"]["data"] == "2027-01-20"
    for arquivo in ("kev.json", "web_retire.json", "dns_sufixos.json"):
        assert (overlay_dir() / arquivo).is_file()
    assert overlay_dir() == home / "dados"
    assert data.origem("kev.json") == "baixado"
    assert len(data.load_json("kev.json")["itens"]) == 1200
    assert not list(overlay_dir().glob("*.tmp"))


def test_catalogos_derivados_sao_recarregados() -> None:
    assert not vulndb.is_kev("CVE-2027-77777")
    rodar(
        {atualizacao.KEV_URL: kev_feed(extra="CVE-2027-77777")},
        ["kev"],
    )
    assert vulndb.is_kev("CVE-2027-77777")
    assert vulndb.catalog_info()["versao"] == "2027.01.15"


def test_falha_parcial_nao_para_as_outras_fontes_e_mantem_os_dados() -> None:
    routes = ok_routes()
    del routes[atualizacao.RETIRE_URL]
    routes[atualizacao.SUFIXOS_URL] = urllib.error.URLError("sem rota")
    resultados = por_nome(rodar(routes))
    assert resultados["kev"]["ok"] is True
    assert resultados["retire"]["ok"] is False
    assert "404" in resultados["retire"]["erro"]
    assert resultados["sufixos"]["ok"] is False
    assert "sem rota" in resultados["sufixos"]["erro"]
    assert (overlay_dir() / "kev.json").is_file()
    assert not (overlay_dir() / "web_retire.json").exists()
    assert data.origem("web_retire.json") == "embarcado"


def test_fonte_desconhecida_e_erro_de_uso() -> None:
    with pytest.raises(ValueError, match="desconhecida"):
        atualizacao.atualizar(["nada"], opener=opener_for({}))


def test_so_baixa_as_fontes_pedidas() -> None:
    chamadas: list[str] = []
    atualizacao.atualizar(
        ["sufixos"], opener=opener_for(ok_routes(), chamadas), hoje=HOJE, saida=None
    )
    assert chamadas == [atualizacao.SUFIXOS_URL]


def test_atualizacao_simultanea_e_recusada() -> None:
    entrou, solto = threading.Event(), threading.Event()

    def lento(url: str, timeout: float = 0.0) -> FakeResponse:
        entrou.set()
        solto.wait(5)
        return FakeResponse(kev_feed(), url)

    thread = threading.Thread(
        target=lambda: atualizacao.atualizar(["kev"], opener=lento, hoje=HOJE), daemon=True
    )
    thread.start()
    assert entrou.wait(5)
    assert atualizacao.ocupado()
    with pytest.raises(RuntimeError, match="andamento"):
        atualizacao.atualizar(["kev"], opener=opener_for({}))
    solto.set()
    thread.join(5)
    assert not atualizacao.ocupado()


# -- validação -----------------------------------------------------------------------------


CORPOS_INVALIDOS = {
    "kev-poucos-itens": ("kev", lambda: kev_feed(999), "1000"),
    "kev-nao-e-json": ("kev", lambda: b"isto nao e json", "JSON"),
    "kev-sem-lista": ("kev", lambda: b'{"vulnerabilities": "x"}', "vulnerabilities"),
    "kev-sem-data": ("kev", lambda: kev_feed(1200, released=""), "data de publicação"),
    "retire-poucas": ("retire", lambda: retire_repo(30), "40"),
    "retire-sem-jquery": (
        "retire",
        lambda: json.dumps(
            {f"x{i}": {"extractors": {}, "vulnerabilities": []} for i in range(60)}
        ).encode(),
        "jquery",
    ),
    "retire-lista": ("retire", lambda: b"[]", "objeto"),
    "sufixos-poucos-icann": ("sufixos", lambda: psl_text(icann=2000), "3000"),
    "sufixos-poucos-privados": ("sufixos", lambda: psl_text(private=10), "1000"),
    "sufixos-nao-utf8": ("sufixos", lambda: bytes([0xFF, 0xFE, 0x20]), "UTF-8"),
}


@pytest.mark.parametrize("caso", CORPOS_INVALIDOS)
def test_dados_invalidos_sao_recusados_e_nada_e_gravado(caso: str) -> None:
    fonte, criar, trecho = CORPOS_INVALIDOS[caso]
    url = atualizacao.FONTES[fonte].url
    [resultado] = rodar({url: criar()}, [fonte])
    assert resultado["ok"] is False
    assert trecho in resultado["erro"]
    assert not overlay_dir().exists() or not list(overlay_dir().iterdir())


def test_sufixos_sem_tlds_basicos_e_recusado() -> None:
    linhas = ["// ===BEGIN ICANN DOMAINS==="]
    linhas += [f"t{i}.example" for i in range(4000)]
    linhas += ["// ===END ICANN DOMAINS===", "// ===BEGIN PRIVATE DOMAINS==="]
    linhas += [f"p{i}.example.net" for i in range(1500)]
    [resultado] = rodar({atualizacao.SUFIXOS_URL: "\n".join(linhas).encode()}, ["sufixos"])
    assert resultado["ok"] is False
    assert "com, br e org" in resultado["erro"]


def test_recusa_arquivo_com_menos_da_metade_do_que_ja_esta_em_uso() -> None:
    assert rodar({atualizacao.KEV_URL: kev_feed(5000)}, ["kev"])[0]["ok"]
    [resultado] = rodar({atualizacao.KEV_URL: kev_feed(2000)}, ["kev"])
    assert resultado["ok"] is False
    assert "incompleto" in resultado["erro"]
    assert len(data.load_json("kev.json")["itens"]) == 5000


def test_dados_mais_antigos_que_os_em_uso_nao_sao_gravados() -> None:
    antigo = kev_feed(1200, released="2020-01-01T00:00:00Z")
    [resultado] = rodar({atualizacao.KEV_URL: antigo}, ["kev"])
    assert resultado["ok"] is True
    assert resultado["gravado"] is False
    assert "mais recentes" in resultado["motivo"]
    assert data.origem("kev.json") == "embarcado"


# -- limites de tamanho e HTTPS ----------------------------------------------------------------


def com_limite(monkeypatch: pytest.MonkeyPatch, nome: str, limite: int) -> None:
    fonte = dataclasses.replace(atualizacao.FONTES[nome], max_bytes=limite)
    monkeypatch.setitem(atualizacao.FONTES, nome, fonte)


def test_corpo_maior_que_o_limite_e_recusado(monkeypatch: pytest.MonkeyPatch) -> None:
    com_limite(monkeypatch, "kev", 5000)
    [resultado] = rodar({atualizacao.KEV_URL: kev_feed()}, ["kev"])
    assert resultado["ok"] is False
    assert "limite" in resultado["erro"]
    assert not (overlay_dir() / "kev.json").exists()


def test_content_length_acima_do_limite_recusa_sem_ler(monkeypatch: pytest.MonkeyPatch) -> None:
    com_limite(monkeypatch, "kev", 5000)
    lido: list[int] = []

    class Gigante(FakeResponse):
        def read(self, size: int = -1) -> bytes:
            lido.append(size)
            return super().read(size)

    def fetch(url: str, timeout: float = 0.0) -> FakeResponse:
        return Gigante(b"{}", url, {"Content-Length": "999999999"})

    [resultado] = atualizacao.atualizar(["kev"], opener=fetch, hoje=HOJE)
    assert resultado["ok"] is False
    assert lido == []


def test_resposta_que_terminou_fora_de_https_e_recusada() -> None:
    def fetch(url: str, timeout: float = 0.0) -> FakeResponse:
        return FakeResponse(kev_feed(), "http://espelho.invalid/kev.json")

    [resultado] = atualizacao.atualizar(["kev"], opener=fetch, hoje=HOJE)
    assert resultado["ok"] is False
    assert "https" in resultado["erro"]


def test_url_que_nao_e_https_nunca_e_aberta() -> None:
    chamadas: list[str] = []
    with pytest.raises(ValueError, match="https"):
        baixar.fetch_bytes("http://exemplo.invalid/x", 5, opener_for({}, chamadas), 1000)
    assert chamadas == []


def test_redirecionamento_para_http_e_recusado() -> None:
    handler = baixar.HttpsOnlyRedirect()
    request = urllib.request.Request("https://exemplo.invalid/kev.json")
    with pytest.raises(urllib.error.URLError, match="HTTPS"):
        handler.redirect_request(request, None, 302, "Found", {}, "http://exemplo.invalid/kev.json")
    novo = handler.redirect_request(
        request, None, 302, "Found", {}, "https://outro.invalid/kev.json"
    )
    assert novo is not None
    assert novo.full_url == "https://outro.invalid/kev.json"


def test_abridor_padrao_so_segue_https_e_identifica_o_programa() -> None:
    abrir = baixar.https_opener()
    director = abrir.__self__  # type: ignore[attr-defined]
    assert any(isinstance(h, baixar.HttpsOnlyRedirect) for h in director.handlers)
    assert dict(director.addheaders)["User-Agent"].startswith("EIGAN")


# -- gravação atômica ------------------------------------------------------------------------------


def test_falha_ao_trocar_o_arquivo_mantem_o_anterior(monkeypatch: pytest.MonkeyPatch) -> None:
    assert rodar(nomes=["kev"])[0]["ok"]
    antes = (overlay_dir() / "kev.json").read_bytes()

    def quebra(*args: object, **kwargs: object) -> None:
        raise OSError("disco cheio")

    with monkeypatch.context() as m:
        m.setattr(os, "replace", quebra)
        [resultado] = rodar({atualizacao.KEV_URL: kev_feed(1300)}, ["kev"])
    assert resultado["ok"] is False
    assert (overlay_dir() / "kev.json").read_bytes() == antes
    assert not list(overlay_dir().glob("*.tmp"))


def test_gravacao_usa_arquivo_temporario_e_troca_de_uma_vez(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trocas: list[tuple[str, str]] = []
    real = os.replace

    def espia(origem: Any, destino: Any) -> None:
        assert Path(origem).read_text(encoding="utf-8").startswith("{")  # completo antes da troca
        trocas.append((Path(origem).name, Path(destino).name))
        real(origem, destino)

    monkeypatch.setattr(os, "replace", espia)
    rodar(nomes=["kev"])
    assert trocas == [("kev.json.tmp", "kev.json")]


# -- --saida (manutenção) ------------------------------------------------------------------------------


def test_saida_grava_no_formato_embarcado_sem_mexer_nos_dados_em_uso(tmp_path: Path) -> None:
    pasta = tmp_path / "saida"
    resultados = rodar(saida=pasta)
    assert all(r["ok"] and r["gravado"] for r in resultados)
    assert sorted(p.name for p in pasta.iterdir()) == [
        "dns_sufixos.json",
        "kev.json",
        "web_retire.json",
    ]
    kev = (pasta / "kev.json").read_text(encoding="utf-8")
    assert kev.startswith('{"fonte":"CISA Known Exploited')  # compacto, como o embarcado
    assert json.loads(kev)["itens"]["CVE-2027-1000"][0] == "Fornecedor 0"
    sufixos = (pasta / "dns_sufixos.json").read_text(encoding="utf-8")
    assert sufixos.startswith('{\n  "fonte"')
    assert '"xn--55qx5d.cn"' in sufixos
    assert not overlay_dir().exists()
    assert data.origem("kev.json") == "embarcado"


# -- a cópia baixada na leitura -----------------------------------------------------------------------


def escrever_copia(nome: str, dados: Any) -> None:
    overlay_dir().mkdir(parents=True, exist_ok=True)
    (overlay_dir() / nome).write_text(
        dados if isinstance(dados, str) else json.dumps(dados), encoding="utf-8"
    )
    data.limpar_cache()


def kev_com(publicado: str, itens: int = 3) -> dict[str, Any]:
    return {
        **data.load_embedded_json("kev.json"),
        "publicado": publicado,
        "itens": {f"CVE-2099-{i}": ["a", "b", "c", "2099-01-01", 0] for i in range(itens)},
    }


def test_copia_baixada_mais_nova_e_preferida() -> None:
    escrever_copia("kev.json", kev_com("2027-01-10T00:00:00Z"))
    assert data.origem("kev.json") == "baixado"
    assert list(data.load_json("kev.json")["itens"]) == ["CVE-2099-0", "CVE-2099-1", "CVE-2099-2"]
    assert vulndb.is_kev("CVE-2099-1")


def test_copia_com_a_mesma_data_do_embarcado_vale() -> None:
    publicado = data.load_embedded_json("kev.json")["publicado"]
    escrever_copia("kev.json", kev_com(publicado))
    assert data.origem("kev.json") == "baixado"


def test_copia_mais_antiga_que_a_embarcada_e_ignorada(caplog: pytest.LogCaptureFixture) -> None:
    escrever_copia("kev.json", kev_com("2020-01-01T00:00:00Z"))
    assert data.origem("kev.json") == "embarcado"
    assert len(data.load_json("kev.json")["itens"]) > 1000


@pytest.mark.parametrize(
    "conteudo",
    [
        "{ isto nao e json",
        "[]",
        '{"publicado": "2099-01-01", "itens": {}}',
        '{"publicado": "ontem", "itens": {"CVE-1": []}}',
        '{"itens": {"CVE-1": []}}',
        "",
    ],
)
def test_copia_corrompida_volta_para_o_embarcado_e_avisa(
    conteudo: str, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.WARNING, logger="eigan.data"):
        escrever_copia("kev.json", conteudo)
        embarcado = data.load_embedded_json("kev.json")
        assert data.load_json("kev.json") == embarcado
    assert data.origem("kev.json") == "embarcado"
    assert any("kev.json" in r.getMessage() for r in caplog.records)


def test_so_os_nomes_permitidos_aceitam_copia_baixada() -> None:
    falso = {**data.load_embedded_json("host_eol.json"), "atualizado": "2099-01-01"}
    escrever_copia("host_eol.json", falso)
    assert data.load_json("host_eol.json") == data.load_embedded_json("host_eol.json")
    assert data.origem("host_eol.json") == "embarcado"


def test_limpar_cache_faz_a_leitura_seguinte_ver_a_mudanca() -> None:
    assert data.origem("kev.json") == "embarcado"
    overlay_dir().mkdir(parents=True, exist_ok=True)
    (overlay_dir() / "kev.json").write_text(
        json.dumps(kev_com("2027-01-10T00:00:00Z")), encoding="utf-8"
    )
    assert data.origem("kev.json") == "embarcado"  # ainda em cache
    data.limpar_cache()
    assert data.origem("kev.json") == "baixado"
    (overlay_dir() / "kev.json").unlink()
    data.limpar_cache()
    assert data.origem("kev.json") == "embarcado"


def test_load_json_continua_em_cache() -> None:
    assert data.load_json("kev.json") is data.load_json("kev.json")


# -- estado e avisos --------------------------------------------------------------------------------------


def test_estado_informa_nome_versao_data_idade_e_origem() -> None:
    linhas = {linha["nome"]: linha for linha in atualizacao.estado(date(2026, 12, 1))}
    kev = linhas["kev"]
    assert kev["arquivo"] == "kev.json"
    assert kev["versao"] == data.load_json("kev.json")["versao"]
    assert kev["data"] == data.load_json("kev.json")["publicado"][:10]
    assert kev["origem"] == "embarcado"
    assert kev["atualizavel"] is True
    assert kev["idade_dias"] == (date(2026, 12, 1) - date.fromisoformat(kev["data"])).days
    assert kev["itens"] > 1000
    assert set(linhas) >= {"kev", "retire", "sufixos"}
    assert set(linhas) >= {m.removesuffix(".json") for m in atualizacao.MANUAIS}
    assert all(linhas[m.removesuffix(".json")]["atualizavel"] is False for m in atualizacao.MANUAIS)


def test_estado_mostra_a_origem_baixada() -> None:
    rodar(nomes=["kev"])
    linhas = {linha["nome"]: linha for linha in atualizacao.estado(HOJE)}
    assert linhas["kev"]["origem"] == "baixado"
    assert linhas["kev"]["idade_dias"] == 5
    assert linhas["retire"]["origem"] == "embarcado"


def test_aviso_aparece_so_depois_de_30_dias_e_diz_a_data_e_como_atualizar() -> None:
    datas = [c["data"] for c in atualizacao.estado() if c["atualizavel"]]
    mais_antiga = date.fromisoformat(min(datas))
    mais_nova = date.fromisoformat(max(datas))
    assert atualizacao.avisos(atualizacao.estado(mais_antiga + timedelta(30))) == []
    velho = atualizacao.avisos(atualizacao.estado(mais_nova + timedelta(31)))
    assert len(velho) == 3  # só os três atualizáveis; a curadoria manual não entra
    kev = date.fromisoformat(data.data_do_catalogo("kev.json", data.load_json("kev.json")))
    assert kev.strftime("%d/%m/%Y") in velho[0]
    assert "eigan atualizar" in velho[0]
    assert "dias" in velho[0]


def test_resumo_tem_o_formato_guardado_na_analise() -> None:
    resumo = atualizacao.resumo()
    assert resumo["limite_dias"] == 30
    assert {c["nome"] for c in resumo["catalogos"]} >= {"kev", "retire", "sufixos", "host_eol"}
    assert isinstance(resumo["avisos"], list)
    json.dumps(resumo)


def test_leitura_e_estado_nao_usam_a_rede(monkeypatch: pytest.MonkeyPatch) -> None:
    def proibido(*args: object, **kwargs: object) -> None:
        raise AssertionError("a auditoria não pode acessar a rede")

    monkeypatch.setattr(baixar, "https_opener", proibido)
    monkeypatch.setattr(baixar, "fetch_bytes", proibido)
    monkeypatch.setattr(urllib.request, "urlopen", proibido)
    monkeypatch.setattr(socket.socket, "connect", proibido)
    data.limpar_cache()
    atualizacao.resumo()
    assert vulndb.catalog_info()["total"] > 1000
    assert data.load_json("web_retire.json")["bibliotecas"]
