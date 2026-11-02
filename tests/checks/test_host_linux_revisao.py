"""Regressões da revisão: sudo, firewall, WSL, SSH via PAM, bancos, pacotes e Include circular."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest
from fakes_host_linux import CABECALHO_TCP, base_segura, linha_tcp, rodar

from eigan.checks.host import linux_analise as analise
from eigan.checks.host import linux_sistema, linux_sshd
from eigan.core.models import Confidence, Severity

NOPASSWD = "host.linux.sudo.nopasswd_total"
FIREWALL_OFF = "host.linux.firewall.inativo"
SENHA = "host.linux.ssh.senha_permitida"
ROOT = "host.linux.ssh.root_permitido"
BANCO = "host.linux.rede.banco_exposto"
PENDENTES = "host.linux.atualizacoes.pendentes"
SENHA_VAZIA = "host.linux.contas.senha_vazia"
APT_CHECK = "/usr/lib/update-notifier/apt-check"


def _sudo(regra: str) -> list[analise.RegraSemSenha]:
    sudoers = analise.Sudoers()
    sudoers.linhas.append(analise.LinhaSudo("/etc/sudoers", 1, regra))
    return analise.regras_sem_senha(sudoers)


# -- sudo -----------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "regra",
    [
        "root ALL=(ALL) NOPASSWD: ALL",
        "deploy ALL=(www-data) NOPASSWD: ALL",
        "deploy ALL=(www-data:www-data) NOPASSWD: ALL",
        "deploy ALL=(www-data) NOPASSWD: ALL, (root) PASSWD: ALL",
        "Defaults>www-data !authenticate",
    ],
)
def test_sudo_sem_poder_de_root_nao_e_achado(regra: str) -> None:
    assert _sudo(regra) == []


@pytest.mark.parametrize(
    "regra",
    [
        "deploy ALL=(ALL) NOPASSWD: ALL",
        "deploy ALL=NOPASSWD: ALL",
        "deploy ALL=(root) NOPASSWD: ALL",
        "deploy ALL=(www-data) NOPASSWD: /bin/ls, (ALL) NOPASSWD: ALL",
        "Defaults>root !authenticate",
        "Defaults:deploy !authenticate",
    ],
)
def test_sudo_com_poder_de_root_e_achado(regra: str) -> None:
    assert len(_sudo(regra)) == 1


# -- firewall -------------------------------------------------------------------------------
NFT_F2B = (
    "table inet f2b-table {\n\tchain input {\n"
    "\t\ttype filter hook input priority filter - 1; policy accept;\n"
    "\t\ttcp dport 22 ip saddr @addr-set-sshd reject\n\t}\n}\n"
)
NFT_SO_ACCEPT = (
    "table inet filter {\n\tchain input {\n"
    "\t\ttype filter hook input priority filter; policy accept;\n"
    "\t\ttcp dport 22 accept\n\t}\n}\n"
)
IPT_F2B = (
    "-P INPUT ACCEPT\n-N f2b-sshd\n-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd\n"
    "-A f2b-sshd -s 1.2.3.4/32 -j REJECT --reject-with icmp-port-unreachable\n"
    "-A f2b-sshd -j RETURN\n"
)


def test_firewall_so_com_fail2ban_ou_accept_nao_conta() -> None:
    assert not analise.nft_filtra_entrada(NFT_F2B)
    assert not analise.nft_filtra_entrada(NFT_SO_ACCEPT)
    assert not analise.iptables_filtra_entrada(IPT_F2B)
    assert not analise.iptables_filtra_entrada("-P INPUT ACCEPT\n-A INPUT -j ts-input\n")
    assert not analise.iptables_filtra_entrada(
        "-P INPUT ACCEPT\n-A INPUT -i virbr0 -p udp --dport 53 -j ACCEPT\n"
    )


def test_firewall_com_drop_final_ou_salto_para_cadeia_propria_conta() -> None:
    assert analise.iptables_filtra_entrada("-P INPUT ACCEPT\n-A INPUT -p tcp --dport 23 -j DROP\n")
    assert analise.iptables_filtra_entrada(
        "-P INPUT ACCEPT\n-N meu\n-A INPUT -j meu\n-A meu -p tcp -j REJECT\n"
    )
    assert analise.nft_filtra_entrada(
        "table inet filter {\n chain input {\n type filter hook input priority 0; policy accept;\n"
        " tcp dport 23 drop\n }\n}\n"
    )


def test_host_so_com_fail2ban_tem_firewall_inativo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path, root=True)
    sis.responder("nft", "list", "ruleset", saida=NFT_F2B)
    sis.responder("iptables", "-S", saida=IPT_F2B)
    assert FIREWALL_OFF in rodar(sis, monkeypatch, "host.linux.firewall").ids()


def test_firewall_sem_root_e_so_indicio_leve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)
    sis.servicos(ufw="inactive", firewalld="inactive", nftables="inactive")
    achado = rodar(sis, monkeypatch, "host.linux.firewall").by_id(FIREWALL_OFF)[0]
    assert achado.severity is Severity.LOW
    assert achado.confidence is Confidence.TENTATIVE


# -- WSL ------------------------------------------------------------------------------------
def test_wsl_com_systemd_nao_e_conteiner(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sis = base_segura(tmp_path)
    sis.arquivo("/proc/sys/kernel/osrelease", "6.6.114.1-microsoft-standard-WSL2\n")
    sis.arquivo("/run/systemd/container", "wsl\n")
    assert linux_sistema.em_wsl(sis)
    assert not linux_sistema.em_conteiner(sis)
    sis.sysctl(kernel__dmesg_restrict="0")
    assert "host.linux.kernel.dmesg_aberto" in rodar(sis, monkeypatch, "host.linux.kernel").ids()


def test_conteiner_de_verdade_continua_sendo_conteiner(tmp_path: Path) -> None:
    sis = base_segura(tmp_path)
    sis.arquivo("/run/systemd/container", "podman\n")
    assert linux_sistema.em_conteiner(sis)


# -- SSH -----------------------------------------------------------------------------------
def _ssh(raiz: Path, config: str):  # noqa: ANN202
    sis = base_segura(raiz)
    sis.programa_instalado("sshd", pasta="/usr/sbin")
    sis.arquivo("/etc/ssh/sshd_config", config, 0o644)
    return sis


def test_senha_por_teclado_interativo_com_pam_e_achado(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = _ssh(
        tmp_path,
        "UsePAM yes\nPasswordAuthentication no\nKbdInteractiveAuthentication yes\n"
        "PermitRootLogin no\nMaxAuthTries 3\n",
    )
    resultado = rodar(sis, monkeypatch, "host.linux.ssh")
    achado = resultado.by_id(SENHA)[0]
    assert achado.confidence is Confidence.TENTATIVE
    assert "PAM" in achado.evidence
    assert SENHA not in {p.control for p in resultado.passed}


@pytest.mark.parametrize(
    "extra",
    [
        "UsePAM no\n",
        "UsePAM yes\nKbdInteractiveAuthentication no\n",
        "UsePAM yes\nAuthenticationMethods publickey,keyboard-interactive\n",
    ],
)
def test_sem_senha_por_pam_continua_seguro(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, extra: str
) -> None:
    sis = _ssh(
        tmp_path,
        extra + "PasswordAuthentication no\nPermitRootLogin no\nMaxAuthTries 3\n",
    )
    assert SENHA not in rodar(sis, monkeypatch, "host.linux.ssh").ids()


def test_ssh_parado_reduz_a_gravidade(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sis = _ssh(tmp_path, "PermitRootLogin yes\nPasswordAuthentication yes\n")
    sis.servicos(ssh="inactive", sshd="inactive")
    sis.responder("systemctl", "is-active", "ssh.socket", saida="inactive\n")
    achado = rodar(sis, monkeypatch, "host.linux.ssh").by_id(ROOT)[0]
    assert achado.severity is Severity.MEDIUM
    assert achado.confidence is Confidence.TENTATIVE


def test_sshd_instalado_sem_config_nao_e_avaliado(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)
    sis.programa_instalado("sshd", pasta="/usr/sbin")
    resultado = rodar(sis, monkeypatch, "host.linux.ssh")
    assert resultado.ids() == set()
    assert any("sshd_config" in n for n in resultado.logs)


def test_config_do_fabricante_em_usr_etc(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sis = base_segura(tmp_path)
    sis.programa_instalado("sshd", pasta="/usr/sbin")
    sis.arquivo("/usr/etc/ssh/sshd_config", "PermitRootLogin yes\nPasswordAuthentication yes\n")
    assert ROOT in rodar(sis, monkeypatch, "host.linux.ssh").ids()


def test_include_circular_termina_rapido(tmp_path: Path) -> None:
    sis = base_segura(tmp_path)
    sis.arquivo("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n")
    for nome in ("a", "b", "c"):
        sis.arquivo(
            f"/etc/ssh/sshd_config.d/{nome}.conf",
            "Include /etc/ssh/sshd_config.d/*.conf\nMaxAuthTries 2\n",
        )
    inicio = time.monotonic()
    config = linux_sshd.ler_arquivos(sis)
    assert time.monotonic() - inicio < 2
    assert config is not None
    assert config.efetivo("maxauthtries").valor == "2"


# -- bancos ---------------------------------------------------------------------------------
def test_banco_so_pela_porta_e_tentativo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sis = base_segura(tmp_path)
    sis.arquivo("/proc/net/tcp", CABECALHO_TCP)
    sis.arquivo("/proc/net/tcp6", CABECALHO_TCP + linha_tcp("0" * 32, 5432))
    achado = rodar(sis, monkeypatch, "host.linux.rede").by_id(BANCO)[0]
    assert achado.confidence is Confidence.TENTATIVE
    assert "/proc/net/tcp6" in achado.evidence
    assert "(/proc/net/tcp)" not in achado.evidence


def test_proc_net_tcp_ilegivel_nao_e_ponto_forte(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)
    sis.arquivo("/proc/net/tcp", "lixo\n\n 0: zz:zz\n 1: 00000000:ZZZZ x y 0A\n")
    sis.arquivo("/proc/net/tcp6", "")
    resultado = rodar(sis, monkeypatch, "host.linux.rede")
    assert resultado.ids() == set()
    assert "host.linux.rede.bancos" not in {p.control for p in resultado.passed}


# -- pacotes --------------------------------------------------------------------------------
def _apt(raiz: Path):  # noqa: ANN202
    sis = base_segura(raiz)
    sis.arquivo("/var/lib/apt/lists/archive.ubuntu.com_Packages", "")
    return sis


def test_poucas_pendencias_sao_medias_e_muitas_altas(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = _apt(tmp_path)
    sis.responder(APT_CHECK, erro="12;3\n")
    assert rodar(sis, monkeypatch, "host.linux.atualizacoes").by_id(PENDENTES)[0].severity is (
        Severity.MEDIUM
    )
    sis.responder(APT_CHECK, erro="40;30\n")
    achado = rodar(sis, monkeypatch, "host.linux.atualizacoes").by_id(PENDENTES)[0]
    assert achado.severity is Severity.HIGH


def test_cache_apt_velho_nao_vira_ponto_forte(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = _apt(tmp_path)
    sis.arquivo("/var/lib/apt/periodic/update-success-stamp", "")
    antigo = time.time() - 60 * 86400
    os.utime(sis.caminho("/var/lib/apt/periodic/update-success-stamp"), (antigo, antigo))
    sis.responder(APT_CHECK, erro="0;0\n")
    resultado = rodar(sis, monkeypatch, "host.linux.atualizacoes")
    assert PENDENTES not in {p.control for p in resultado.passed}


def test_dnf_ignora_a_secao_de_obsoletos() -> None:
    saida = (
        "foo.x86_64 1-2 baseos\nbar.noarch 3-4 baseos\nObsoleting Packages\nnovo.x86_64 1-2 repo\n"
    )
    assert analise.dnf_pacotes(saida) == ["foo.x86_64", "bar.noarch"]


def test_dnf_sem_metadados_de_seguranca_nao_e_ponto_forte(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)
    sis.arquivo("/etc/os-release", 'ID="centos"\nID_LIKE="rhel fedora"\nVERSION_ID="9"\n')
    sis.responder("dnf", "-q", "-C", "check-update", "--security", codigo=0)
    sis.responder("dnf", "-q", "-C", "check-update", codigo=100, saida="foo.x86_64 1 2 baseos\n")
    resultado = rodar(sis, monkeypatch, "host.linux.atualizacoes")
    assert PENDENTES not in {p.control for p in resultado.passed}
    assert PENDENTES not in resultado.ids()


# -- contas ---------------------------------------------------------------------------------
def test_senha_vazia_em_conta_sem_login_e_baixa(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)
    sis.arquivo(
        "/etc/passwd",
        "root:x:0:0:root:/root:/bin/bash\nsvc:x:998:998::/:/usr/sbin/nologin\n"
        "ana:x:1000:1000::/home/ana:/bin/bash\n",
        0o644,
    )
    sis.arquivo(
        "/etc/shadow", "root:*:1:::::\nsvc::19000:0:99999:7:::\nana::19000:0:99999:7:::\n", 0o640
    )
    achados = {
        a.details["conta"]: a
        for a in rodar(sis, monkeypatch, "host.linux.contas").by_id(SENHA_VAZIA)
    }
    assert achados["svc"].severity is Severity.LOW
    assert achados["ana"].severity is not Severity.LOW
