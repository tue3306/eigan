"""Camada de acesso ao sistema (sistema.py) e tabela de fim de suporte (host_eol.json)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from eigan.checks.host import comum, info, sistema
from eigan.data import load_json


# -- erros de privilégio ------------------------------------------------------------------------
@pytest.mark.parametrize(
    "texto",
    [
        "Access is denied.",
        "Acesso negado.",
        "Get-X : ... 0x80070005",
        "WMI 0x80041003",
        "CategoryInfo : PermissionDenied: (:) []",
        "UnauthorizedAccessException",
    ],
)
def test_negado_reconhece_recusas_em_qualquer_idioma(texto: str) -> None:
    assert sistema.negado(texto)


def test_negado_ignora_outros_erros() -> None:
    assert not sistema.negado("O termo 'Get-Foo' não é reconhecido")
    assert not sistema.negado("")


def test_powershell_json_com_acesso_negado_levanta(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        sistema,
        "run_powershell",
        lambda s, tempo=40.0: sistema.Resultado(1, "", "Access is denied"),
    )
    with pytest.raises(sistema.AcessoNegado):
        sistema.powershell_json("Get-Algo")


def test_powershell_json_converte_e_tolera_lixo(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        sistema, "run_powershell", lambda s, tempo=40.0: sistema.Resultado(0, '{"a": 1}')
    )
    assert sistema.powershell_json("x") == {"a": 1}
    monkeypatch.setattr(sistema, "run_powershell", lambda s, tempo=40.0: sistema.Resultado(0, "oi"))
    assert sistema.powershell_json("x") is None
    monkeypatch.setattr(sistema, "run_powershell", lambda s, tempo=40.0: None)
    assert sistema.powershell_json("x") is None


def test_powershell_lista_separa_vazio_de_falha(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sistema, "run_powershell", lambda s, tempo=40.0: sistema.Resultado(0, "[]"))
    assert sistema.powershell_lista("x") == []
    monkeypatch.setattr(sistema, "run_powershell", lambda s, tempo=40.0: sistema.Resultado(1, "[]"))
    assert sistema.powershell_lista("x") is None
    monkeypatch.setattr(sistema, "run_powershell", lambda s, tempo=40.0: None)
    assert sistema.powershell_lista("x") is None


# -- comandos e arquivos --------------------------------------------------------------------------
def test_comando_inexistente_devolve_none() -> None:
    assert sistema.run_command(["/nao/existe/programa-eigan"], tempo=2) is None


def test_comando_executa_sem_shell() -> None:
    resultado = sistema.run_command([sys.executable, "-I", "-c", "print('ola')"], tempo=30)
    assert resultado is not None and resultado.codigo == 0 and "ola" in resultado.saida


def test_comando_estourando_o_tempo_devolve_none() -> None:
    assert (
        sistema.run_command([sys.executable, "-I", "-c", "import time; time.sleep(5)"], 0.3) is None
    )


def test_arquivo_inexistente_devolve_none(tmp_path: Path) -> None:
    assert sistema.read_text_file(str(tmp_path / "nada")) is None
    assert sistema.list_dir(str(tmp_path / "nada")) is None
    assert sistema.stat_path(str(tmp_path / "nada")) is None


def test_arquivo_lido_e_pasta_listada(tmp_path: Path) -> None:
    (tmp_path / "b.txt").write_text("conteúdo", encoding="utf-8")
    (tmp_path / "a.txt").write_text("x", encoding="utf-8")
    assert sistema.read_text_file(str(tmp_path / "b.txt")) == "conteúdo"
    assert sistema.list_dir(str(tmp_path)) == ["a.txt", "b.txt"]
    assert sistema.stat_path(str(tmp_path)) is not None


@pytest.mark.skipif(sys.platform == "win32", reason="registro do Windows só existe lá")
def test_registro_fora_do_windows_devolve_none() -> None:
    assert sistema.read_registry_value(r"HKLM\SOFTWARE\X", "Y") is None


# -- utilidades comuns ----------------------------------------------------------------------------
def test_inteiro_aceita_tipos_do_registro() -> None:
    assert comum.inteiro(5) == 5
    assert comum.inteiro("7") == 7
    assert comum.inteiro("0x10") == 16
    assert comum.inteiro(True) == 1
    assert comum.inteiro("abc") is None


def test_verdadeiro_e_como_lista() -> None:
    assert comum.verdadeiro("True") is True
    assert comum.verdadeiro(0) is False
    assert comum.verdadeiro("talvez") is None
    assert comum.como_lista({"a": 1}) == [{"a": 1}]
    assert comum.como_lista([{"a": 1}, 3]) == [{"a": 1}]
    assert comum.como_lista(None) == []


# -- tabela de fim de suporte -----------------------------------------------------------------------
def test_tabela_tem_fontes_licenca_e_data() -> None:
    dados: dict[str, Any] = load_json("host_eol.json")
    for chave in ("fonte", "licenca", "url", "atualizado"):
        assert dados[chave]
    assert all(url.startswith("https://") for lista in dados["_fontes"].values() for url in lista)


def test_tabela_cobre_os_builds_conhecidos_do_windows_11() -> None:
    dados: dict[str, Any] = load_json("host_eol.json")
    builds = {item["build"] for item in dados["windows_cliente"]}
    assert {19045, 22000, 22621, 22631, 26100, 26200} <= builds
    assert {"22000", "22631", "26100", "26200"} <= set(dados["windows_nomes"])


def test_datas_da_tabela_sao_iso_validas() -> None:
    dados: dict[str, Any] = load_json("host_eol.json")
    for item in dados["windows_cliente"]:
        for campo in ("fim_home_pro", "fim_enterprise"):
            info._data(item[campo])
        assert info._data(item["fim_enterprise"]) >= info._data(item["fim_home_pro"])
    for distro in dados["linux"].values():
        for versao in distro["versoes"].values():
            info._data(versao["fim"])


def test_windows_nao_listado_pelo_build_igual_a_zero_nao_e_avaliado() -> None:
    assert info.suporte_windows({"build_number": 0, "edition": "Core", "server": False}) is None


def test_linux_versao_menor_que_a_tabela_e_deduzida() -> None:
    suporte = info.suporte_linux({"distro": "debian", "version": "8", "os": "Debian 8", "name": ""})
    assert suporte is not None and suporte.deducao


@pytest.mark.skipif(sys.platform == "win32", reason="LD_LIBRARY_PATH só existe fora do Windows")
def test_run_command_restaura_ld_library_path_do_pyinstaller(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LD_LIBRARY_PATH", "/tmp/_MEI123")
    monkeypatch.setenv("LD_LIBRARY_PATH_ORIG", "/usr/lib")
    codigo = "import os; print(os.environ.get('LD_LIBRARY_PATH'))"
    resultado = sistema.run_command([sys.executable, "-I", "-c", codigo], tempo=30)
    assert resultado is not None and resultado.saida.strip() == "/usr/lib"


def test_ambiente_filho_sem_original_remove_a_variavel(monkeypatch: pytest.MonkeyPatch) -> None:
    if sys.platform == "win32":
        assert sistema._ambiente_filho(None) is None
        return
    monkeypatch.setenv("LD_LIBRARY_PATH", "/tmp/_MEI123")
    monkeypatch.setenv("LD_LIBRARY_PATH_ORIG", "")
    env = sistema._ambiente_filho(None)
    assert env is not None and "LD_LIBRARY_PATH" not in env
