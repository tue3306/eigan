"""Identificação da máquina e fim de suporte (host.info), contra um sistema falso."""

from __future__ import annotations

from datetime import date
from typing import Any

import pytest
from helpers import CheckOutcome, run_check

from eigan.checks.host import info, sistema
from eigan.core import facts
from eigan.core.models import Confidence, Fact, Severity

HOJE = date(2026, 11, 1)


def _fato(plataforma: str) -> Fact:
    return Fact(kind=facts.LOCAL, key=plataforma, data={"platform": plataforma})


def _windows(monkeypatch: pytest.MonkeyPatch, valores: dict[str, Any], admin: bool = False) -> None:
    monkeypatch.setattr(sistema, "read_registry_value", lambda c, n: valores.get(n))
    monkeypatch.setattr(sistema, "hoje", lambda: HOJE)
    monkeypatch.setattr(sistema, "is_admin", lambda: admin)


def _linux(
    monkeypatch: pytest.MonkeyPatch, os_release: str, apt: dict[str, str] | None = None
) -> None:
    apt = apt or {}

    def ler(caminho: str, limite: int = 0) -> str | None:
        if caminho == "/etc/os-release":
            return os_release
        return apt.get(caminho.rsplit("/", 1)[-1])

    monkeypatch.setattr(sistema, "read_text_file", ler)
    monkeypatch.setattr(sistema, "list_dir", lambda pasta: sorted(apt))
    monkeypatch.setattr(sistema, "hoje", lambda: HOJE)
    monkeypatch.setattr(sistema, "is_admin", lambda: False)


def _rodar(plataforma: str) -> CheckOutcome:
    return run_check("host.info", _fato(plataforma), target="local")


def _win(build: int, edicao: str, versao: str, produto: str = "Windows 10 Pro") -> dict[str, Any]:
    return {
        "ProductName": produto,
        "CurrentBuildNumber": str(build),
        "UBR": 1000,
        "DisplayVersion": versao,
        "EditionID": edicao,
        "InstallationType": "Client",
    }


# -- identificação ---------------------------------------------------------------------------
def test_windows_11_e_detectado_pelo_build(monkeypatch: pytest.MonkeyPatch) -> None:
    _windows(monkeypatch, _win(26200, "Core", "25H2", "Windows 10 Home"), admin=True)
    saida = _rodar("windows")
    dados = saida.facts[0].data
    assert dados["os"] == "Windows 11 Home"
    assert dados["build"] == "26200.1000" and dados["edition"] == "Core"
    assert dados["admin"] is True and dados["hostname"]
    assert saida.ids() == set()  # 25H2 Home/Pro tem suporte até 2027
    assert saida.passed


def test_windows_10_continua_windows_10(monkeypatch: pytest.MonkeyPatch) -> None:
    _windows(monkeypatch, _win(19045, "Professional", "22H2"))
    assert info.coletar_windows()["os"] == "Windows 10 Pro"


def test_sem_privilegio_registra_no_log(monkeypatch: pytest.MonkeyPatch) -> None:
    _windows(monkeypatch, _win(26200, "Core", "25H2"))
    saida = _rodar("windows")
    assert any("sem privilégio" in linha for linha in saida.logs)


def test_nome_da_versao_pelo_build_quando_o_registro_nao_informa(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    valores = _win(22631, "Core", "")
    del valores["DisplayVersion"]
    _windows(monkeypatch, valores)
    assert info.coletar_windows()["version"] == "23H2"


def test_ler_os_release() -> None:
    campos = info.ler_os_release('# x\nNAME="Ubuntu"\nVERSION_ID="22.04"\nID=ubuntu\n')
    assert campos == {"NAME": "Ubuntu", "VERSION_ID": "22.04", "ID": "ubuntu"}


# -- fim de suporte: Windows ---------------------------------------------------------------------
def test_windows_11_24h2_home_acabou_em_outubro_de_2026(monkeypatch: pytest.MonkeyPatch) -> None:
    _windows(monkeypatch, _win(26100, "Core", "24H2", "Windows 10 Home"))
    achado = _rodar("windows").by_id("host.sistema.sem_suporte")[0]
    assert "2026-10-13" in achado.evidence and achado.confidence == Confidence.FIRM


def test_windows_11_24h2_enterprise_ainda_tem_suporte(monkeypatch: pytest.MonkeyPatch) -> None:
    _windows(monkeypatch, _win(26100, "Enterprise", "24H2", "Windows 10 Enterprise"))
    assert _rodar("windows").ids() == set()


def test_windows_11_23h2_enterprise_termina_em_9_dias(monkeypatch: pytest.MonkeyPatch) -> None:
    _windows(monkeypatch, _win(22631, "Enterprise", "23H2", "Windows 10 Enterprise"))
    saida = _rodar("windows")
    assert saida.ids() == {"host.sistema.suporte_acabando"}
    assert "2026-11-10" in saida.findings[0].evidence


def test_windows_10_22h2_sem_suporte(monkeypatch: pytest.MonkeyPatch) -> None:
    _windows(monkeypatch, _win(19045, "Professional", "22H2"))
    saida = _rodar("windows")
    assert saida.ids() == {"host.sistema.sem_suporte"}
    assert "ESU" in saida.findings[0].evidence


def test_build_antigo_e_deduzido(monkeypatch: pytest.MonkeyPatch) -> None:
    _windows(monkeypatch, _win(17763, "Professional", "1809"))
    achado = _rodar("windows").by_id("host.sistema.sem_suporte")[0]
    assert achado.details["deducao"]


def test_build_desconhecido_nao_e_avaliado(monkeypatch: pytest.MonkeyPatch) -> None:
    _windows(monkeypatch, _win(29999, "Professional", ""))
    saida = _rodar("windows")
    assert saida.ids() == set()
    assert any("fora da tabela" in linha for linha in saida.logs)


def test_servidor_2012_r2_sem_suporte_e_esu_encerrado(monkeypatch: pytest.MonkeyPatch) -> None:
    valores = _win(9600, "ServerStandard", "", "Windows Server 2012 R2 Standard")
    valores["InstallationType"] = "Server"
    _windows(monkeypatch, valores)
    achado = _rodar("windows").by_id("host.sistema.sem_suporte")[0]
    assert "também terminou" in achado.evidence


def test_servidor_2022_nao_acusa(monkeypatch: pytest.MonkeyPatch) -> None:
    valores = _win(20348, "ServerStandard", "", "Windows Server 2022 Standard")
    valores["InstallationType"] = "Server"
    _windows(monkeypatch, valores)
    assert _rodar("windows").ids() == set()


# -- fim de suporte: Linux -----------------------------------------------------------------------
def _os(id_: str, nome: str, versao: str) -> str:
    return f'ID={id_}\nNAME="{nome}"\nVERSION_ID="{versao}"\nPRETTY_NAME="{nome} {versao}"\n'


def test_debian_11_terminou_em_agosto_de_2026(monkeypatch: pytest.MonkeyPatch) -> None:
    _linux(monkeypatch, _os("debian", "Debian GNU/Linux", "11"))
    achado = _rodar("linux").by_id("host.sistema.sem_suporte")[0]
    assert "2026-08-31" in achado.evidence and achado.confidence == Confidence.FIRM


def test_debian_12_tem_suporte(monkeypatch: pytest.MonkeyPatch) -> None:
    _linux(monkeypatch, _os("debian", "Debian GNU/Linux", "12"))
    assert _rodar("linux").ids() == set()


def test_ubuntu_2004_com_esm_vira_baixa_e_tentativa(monkeypatch: pytest.MonkeyPatch) -> None:
    _linux(
        monkeypatch,
        _os("ubuntu", "Ubuntu", "20.04"),
        {"ubuntu-esm-infra.sources": "URIs: https://esm.ubuntu.com/infra/ubuntu"},
    )
    achado = _rodar("linux").by_id("host.sistema.sem_suporte")[0]
    assert achado.severity == Severity.LOW and achado.confidence == Confidence.TENTATIVE


def test_ubuntu_2004_sem_esm_e_firme(monkeypatch: pytest.MonkeyPatch) -> None:
    _linux(monkeypatch, _os("ubuntu", "Ubuntu", "20.04"))
    achado = _rodar("linux").by_id("host.sistema.sem_suporte")[0]
    assert achado.confidence == Confidence.FIRM and "Ubuntu Pro" in achado.evidence


def test_centos_stream_e_distro_desconhecida_ficam_fora(monkeypatch: pytest.MonkeyPatch) -> None:
    _linux(monkeypatch, _os("centos", "CentOS Stream", "9"))
    assert _rodar("linux").ids() == set()
    _linux(monkeypatch, _os("arch", "Arch Linux", ""))
    assert _rodar("linux").ids() == set()


def test_rhel_7_menciona_els(monkeypatch: pytest.MonkeyPatch) -> None:
    _linux(monkeypatch, _os("rhel", "Red Hat Enterprise Linux", "7.9"))
    assert "ELS" in _rodar("linux").by_id("host.sistema.sem_suporte")[0].evidence


@pytest.mark.parametrize(
    "apt",
    [
        {"x-esm-infra.list": "# deb https://esm.ubuntu.com/infra/ubuntu focal-infra-security main"},
        {"x-esm-apps.sources": "URIs: https://esm.ubuntu.com/apps/ubuntu"},
        {"x.sources": "Enabled: no\nURIs: https://esm.ubuntu.com/infra/ubuntu"},
    ],
)
def test_esm_comentado_so_apps_ou_desligado_nao_rebaixa(
    monkeypatch: pytest.MonkeyPatch, apt: dict[str, str]
) -> None:
    _linux(monkeypatch, _os("ubuntu", "Ubuntu", "20.04"), apt)
    achado = _rodar("linux").by_id("host.sistema.sem_suporte")[0]
    assert achado.severity == Severity.HIGH and achado.confidence == Confidence.FIRM


@pytest.mark.parametrize("versao", ["23.10", "23.04", "22.10", "21.10", "20.10", "19.10"])
def test_ubuntu_intermediario_antigo_fora_da_tabela_acusa(
    monkeypatch: pytest.MonkeyPatch, versao: str
) -> None:
    _linux(monkeypatch, _os("ubuntu", "Ubuntu", versao))
    achado = _rodar("linux").by_id("host.sistema.sem_suporte")[0]
    assert "9 meses" in achado.evidence


def test_data_deduzida_nao_e_publicada_como_fim_real(monkeypatch: pytest.MonkeyPatch) -> None:
    _linux(monkeypatch, _os("debian", "Debian GNU/Linux", "9"))
    achado = _rodar("linux").by_id("host.sistema.sem_suporte")[0]
    assert achado.details["fim_suporte"] is None
    assert "versão anterior a 10" in achado.evidence


def test_windows_10_22h2_com_esu_possivel_e_tentativo(monkeypatch: pytest.MonkeyPatch) -> None:
    _windows(monkeypatch, _win(19045, "Professional", "22H2"))
    achado = _rodar("windows").by_id("host.sistema.sem_suporte")[0]
    assert achado.confidence == Confidence.TENTATIVE and "ESU" in achado.evidence


@pytest.mark.parametrize(("build", "edicao"), [(17763, "EnterpriseS"), (19044, "IoTEnterpriseS")])
def test_ltsc_fora_da_tabela_ou_na_tabela_nao_quebra(
    monkeypatch: pytest.MonkeyPatch, build: int, edicao: str
) -> None:
    _windows(monkeypatch, _win(build, edicao, "1809"))
    assert _rodar("windows").findings is not None
