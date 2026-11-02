"""Parâmetros do kernel (sysctl) lidos de um /proc/sys falso, com a regra de cada interface."""

from __future__ import annotations

from pathlib import Path

import pytest
from fakes_host_linux import base_segura, rodar

from eigan.core.models import Confidence, Severity

CHECK = "host.linux.kernel"
ASLR = "host.linux.kernel.aslr"
SYNCOOKIES = "host.linux.kernel.syncookies"
KPTR = "host.linux.kernel.ponteiros_expostos"
DMESG = "host.linux.kernel.dmesg_aberto"
LINKS = "host.linux.kernel.links_desprotegidos"
RECEBE = "host.linux.kernel.redirecionamentos_icmp"
ENVIA = "host.linux.kernel.envio_redirecionamentos"
ROTA = "host.linux.kernel.source_route"
IPV4 = "net__ipv4__conf"
IPV6 = "net__ipv6__conf"


def test_kernel_seguro_sem_achados_e_com_pontos_fortes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    resultado = rodar(base_segura(tmp_path), monkeypatch, CHECK)
    assert resultado.ids() == set()
    assert {p.control for p in resultado.passed} >= {
        ASLR,
        SYNCOOKIES,
        KPTR,
        DMESG,
        LINKS,
        RECEBE,
        ROTA,
    }


@pytest.mark.parametrize(("valor", "severidade"), [("0", Severity.MEDIUM), ("1", Severity.LOW)])
def test_aslr_reduzido(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, valor: str, severidade: Severity
) -> None:
    sis = base_segura(tmp_path)
    sis.sysctl(kernel__randomize_va_space=valor)
    achado = rodar(sis, monkeypatch, CHECK).by_id(ASLR)[0]
    assert achado.severity is severidade
    assert achado.confidence is Confidence.CONFIRMED
    assert achado.evidence == f"kernel.randomize_va_space = {valor}"


@pytest.mark.parametrize(
    ("chave", "achado"),
    [
        ("net__ipv4__tcp_syncookies", SYNCOOKIES),
        ("kernel__kptr_restrict", KPTR),
        ("kernel__dmesg_restrict", DMESG),
    ],
)
def test_parametros_que_precisam_estar_ligados(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, chave: str, achado: str
) -> None:
    sis = base_segura(tmp_path)
    sis.sysctl(**{chave: "0"})
    assert rodar(sis, monkeypatch, CHECK).ids() == {achado}
    sis.sysctl(**{chave: "2"})  # tcp_syncookies e kptr_restrict aceitam 2 como valor mais forte
    assert rodar(sis, monkeypatch, CHECK).ids() == set()


@pytest.mark.parametrize("chave", ["fs__protected_symlinks", "fs__protected_hardlinks"])
def test_protecao_de_links(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, chave: str) -> None:
    sis = base_segura(tmp_path)
    sis.sysctl(**{chave: "0"})
    achado = rodar(sis, monkeypatch, CHECK).by_id(LINKS)[0]
    assert achado.details["parametros"] == [chave.replace("__", ".")]


def test_leitura_negada_nao_vira_achado_nem_ponto_forte(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)
    sis.sysctl(fs__protected_symlinks="0")
    sis.negados.update({"/proc/sys/fs/protected_symlinks", "/proc/sys/fs/protected_hardlinks"})
    resultado = rodar(sis, monkeypatch, CHECK)
    assert LINKS not in resultado.ids()
    assert LINKS not in {p.control for p in resultado.passed}
    assert any("fs.protected_symlinks: não verificado" in linha for linha in resultado.logs)


def test_parametro_ausente_nao_vira_achado(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sis = base_segura(tmp_path)
    (sis.caminho("/proc/sys/net/ipv4/tcp_syncookies")).unlink()  # kernel sem CONFIG_SYN_COOKIES
    resultado = rodar(sis, monkeypatch, CHECK)
    assert resultado.ids() == set()
    assert SYNCOOKIES not in {p.control for p in resultado.passed}


def test_redirects_ipv4_sem_encaminhamento_basta_um_ligado(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)
    sis.sysctl(**{f"{IPV4}__all__accept_redirects": "1"})
    achado = rodar(sis, monkeypatch, CHECK).by_id(RECEBE)[0]
    assert achado.details["ipv4"] == ["eth0 (all=1, interface=0)"]
    assert achado.severity is Severity.LOW

    sis.sysctl(**{f"{IPV4}__all__accept_redirects": "0", f"{IPV4}__eth0__accept_redirects": "1"})
    assert rodar(sis, monkeypatch, CHECK).by_id(RECEBE)[0].details["ipv4"] == [
        "eth0 (all=0, interface=1)"
    ]


def test_redirects_ipv4_com_encaminhamento_precisa_dos_dois(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)
    sis.sysctl(
        **{
            f"{IPV4}__all__accept_redirects": "1",
            f"{IPV4}__eth0__accept_redirects": "0",
            f"{IPV4}__eth0__forwarding": "1",
            f"{IPV4}__all__send_redirects": "0",
            f"{IPV4}__eth0__send_redirects": "0",
        }
    )
    assert RECEBE not in rodar(sis, monkeypatch, CHECK).ids()

    sis.sysctl(**{f"{IPV4}__eth0__accept_redirects": "1"})
    assert RECEBE in rodar(sis, monkeypatch, CHECK).ids()


def test_redirects_ipv6_seguem_a_interface(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sis = base_segura(tmp_path)
    sis.sysctl(**{f"{IPV6}__eth0__accept_redirects": "1"})
    assert rodar(sis, monkeypatch, CHECK).by_id(RECEBE)[0].details["ipv6"] == ["eth0"]

    sis.sysctl(**{f"{IPV6}__eth0__forwarding": "1"})  # encaminha: o kernel ignora redirects
    assert RECEBE not in rodar(sis, monkeypatch, CHECK).ids()

    sis.sysctl(**{f"{IPV6}__eth0__forwarding": "0", f"{IPV6}__eth0__disable_ipv6": "1"})
    assert RECEBE not in rodar(sis, monkeypatch, CHECK).ids()


def test_interface_de_loopback_nao_conta(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sis = base_segura(tmp_path)
    sis.sysctl(**{f"{IPV4}__lo__accept_redirects": "1", f"{IPV4}__lo__accept_source_route": "1"})
    assert rodar(sis, monkeypatch, CHECK).ids() == set()


def test_sem_interfaces_avalia_o_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sis = base_segura(tmp_path)
    for pasta in ("net/ipv4/conf/eth0", "net/ipv6/conf/eth0"):
        for arquivo in sis.caminho(f"/proc/sys/{pasta}").iterdir():
            arquivo.unlink()
        sis.caminho(f"/proc/sys/{pasta}").rmdir()
    sis.sysctl(**{f"{IPV4}__default__accept_redirects": "1"})
    assert rodar(sis, monkeypatch, CHECK).by_id(RECEBE)[0].details["ipv4"] == [
        "default (all=0, interface=1)"
    ]


def test_interface_com_ponto_no_nome(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sis = base_segura(tmp_path)
    sis.arquivo("/proc/sys/net/ipv4/conf/eth0.100/accept_redirects", "1\n")
    sis.arquivo("/proc/sys/net/ipv4/conf/eth0.100/forwarding", "0\n")
    assert rodar(sis, monkeypatch, CHECK).by_id(RECEBE)[0].details["ipv4"] == [
        "eth0.100 (all=0, interface=1)"
    ]


def test_envio_de_redirects_so_vale_para_quem_encaminha_pacotes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)  # padrão do kernel: send_redirects=1, sem encaminhamento
    resultado = rodar(sis, monkeypatch, CHECK)
    assert ENVIA not in resultado.ids()
    assert any("não encaminha pacotes" in linha for linha in resultado.logs)

    sis.sysctl(**{f"{IPV4}__eth0__forwarding": "1"})
    assert rodar(sis, monkeypatch, CHECK).by_id(ENVIA)[0].details["interfaces"] == ["eth0"]

    sis.sysctl(**{f"{IPV4}__all__send_redirects": "0", f"{IPV4}__eth0__send_redirects": "0"})
    resultado = rodar(sis, monkeypatch, CHECK)
    assert ENVIA not in resultado.ids()
    assert ENVIA in {p.control for p in resultado.passed}


def test_source_route_exige_all_e_interface(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)
    sis.sysctl(**{f"{IPV4}__eth0__accept_source_route": "1"})  # all=0: o kernel recusa
    assert ROTA not in rodar(sis, monkeypatch, CHECK).ids()

    sis.sysctl(
        **{f"{IPV4}__all__accept_source_route": "1", f"{IPV4}__eth0__accept_source_route": "0"}
    )
    assert ROTA not in rodar(sis, monkeypatch, CHECK).ids()

    sis.sysctl(**{f"{IPV4}__eth0__accept_source_route": "1"})
    assert rodar(sis, monkeypatch, CHECK).by_id(ROTA)[0].details["interfaces"] == ["eth0"]


def test_container_nao_avalia_o_kernel_do_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)
    sis.sysctl(kernel__randomize_va_space="0")
    sis.arquivo("/.dockerenv")
    resultado = rodar(sis, monkeypatch, CHECK)
    assert resultado.ids() == set() and not resultado.passed
    assert any("container" in linha for linha in resultado.logs)
