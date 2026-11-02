"""Firewall, atualizações, defesas (MAC, auditd, fail2ban) e bancos em escuta, num Linux falso."""

from __future__ import annotations

from pathlib import Path

import pytest
from fakes_host_linux import CABECALHO_TCP, LinuxFalso, base_segura, linha_tcp, rodar
from helpers import CheckOutcome

from eigan.checks.host import linux_analise as analise
from eigan.core.models import Confidence, Severity

FIREWALL = "host.linux.firewall"
FIREWALL_OFF = "host.linux.firewall.inativo"
ATUALIZACOES = "host.linux.atualizacoes"
PENDENTES = "host.linux.atualizacoes.pendentes"
AUTOMATICAS = "host.linux.atualizacoes.automaticas_desligadas"
REINICIO = "host.linux.atualizacoes.reinicio_pendente"
DEFESAS = "host.linux.defesas"
MAC = "host.linux.mac.desligado"
AUDITD = "host.linux.auditoria.auditd_ausente"
FAIL2BAN = "host.linux.auditoria.fail2ban_ausente"
REDE = "host.linux.rede"
BANCO = "host.linux.rede.banco_exposto"

NFT_COM_REGRAS = (
    "table inet filter {\n\tchain input {\n"
    "\t\ttype filter hook input priority filter; policy drop;\n"
    "\t\ttcp dport 22 accept\n\t}\n}\n"
)
NFT_ABERTO = (
    "table inet filter {\n\tchain input {\n"
    "\t\ttype filter hook input priority filter; policy accept;\n"
    "\t}\n}\n"
)


def controles(resultado: CheckOutcome) -> set[str]:
    return {p.control for p in resultado.passed}


# -- firewall --------------------------------------------------------------------------------
def test_firewall_com_root_le_as_regras_do_nftables(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path, root=True)
    sis.responder("nft", "list", "ruleset", saida=NFT_COM_REGRAS)
    resultado = rodar(sis, monkeypatch, FIREWALL)
    assert resultado.ids() == set()
    assert controles(resultado) == {FIREWALL}


def test_firewall_com_root_sem_regras_de_entrada_e_confirmado(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path, root=True)
    sis.responder("nft", "list", "ruleset", saida=NFT_ABERTO)
    sis.responder("iptables", "-S", saida="-P INPUT ACCEPT\n-P FORWARD ACCEPT\n")
    achado = rodar(sis, monkeypatch, FIREWALL).by_id(FIREWALL_OFF)[0]
    assert achado.confidence is Confidence.CONFIRMED
    assert achado.details["regras_lidas"] is True


def test_firewall_iptables_com_politica_drop_conta_como_ativo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path, root=True)
    sis.responder("iptables", "-S", saida="-P INPUT DROP\n")
    assert rodar(sis, monkeypatch, FIREWALL).ids() == set()


def test_firewall_sem_root_ufw_habilitado_e_ativo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)
    sis.arquivo("/etc/ufw/ufw.conf", "# ufw\nENABLED=yes\nLOGLEVEL=low\n")
    sis.servicos(ufw="active")
    resultado = rodar(sis, monkeypatch, FIREWALL)
    assert resultado.ids() == set()
    assert controles(resultado) == {FIREWALL}


def test_firewall_sem_root_tudo_parado_e_indicio_nao_certeza(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)
    sis.arquivo("/etc/ufw/ufw.conf", "ENABLED=no\n")
    sis.servicos(ufw="inactive", firewalld="inactive", nftables="inactive")
    achado = rodar(sis, monkeypatch, FIREWALL).by_id(FIREWALL_OFF)[0]
    assert achado.confidence is Confidence.TENTATIVE
    assert achado.details["regras_lidas"] is False


def test_firewall_sem_root_e_sem_systemctl_nao_e_avaliado(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    resultado = rodar(base_segura(tmp_path), monkeypatch, FIREWALL)
    assert resultado.ids() == set()
    assert not resultado.passed
    assert any("Firewall" in linha for linha in resultado.logs)


def test_firewall_nftables_ativo_com_arquivo_ilegivel_nao_e_achado(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)
    sis.servicos(ufw="inactive", firewalld="inactive", nftables="active")
    sis.arquivo("/etc/nftables.conf", NFT_COM_REGRAS)
    sis.negados.add("/etc/nftables.conf")
    assert rodar(sis, monkeypatch, FIREWALL).ids() == set()


def test_firewall_nftables_conf_sem_filtro_nao_conta(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)
    sis.servicos(ufw="inactive", firewalld="inactive", nftables="active")
    sis.arquivo("/etc/nftables.conf", NFT_ABERTO)
    assert rodar(sis, monkeypatch, FIREWALL).ids() == {FIREWALL_OFF}


# -- atualizações pendentes -------------------------------------------------------------------
APT_CHECK = "/usr/lib/update-notifier/apt-check"


def _apt(raiz: Path, *, com_listas: bool = True) -> LinuxFalso:
    sis = base_segura(raiz)
    if com_listas:
        sis.arquivo("/var/lib/apt/lists/archive.ubuntu.com_Packages", "")
    return sis


def test_apt_check_com_pendencias_de_seguranca(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = _apt(tmp_path)
    sis.responder(APT_CHECK, erro="12;3\n")
    achado = rodar(sis, monkeypatch, ATUALIZACOES).by_id(PENDENTES)[0]
    assert achado.details["seguranca"] == 3
    assert achado.details["total"] == 12
    assert "3 atualizações de segurança" in achado.evidence


def test_apt_check_zerado_vira_ponto_forte(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sis = _apt(tmp_path)
    sis.responder(APT_CHECK, erro="5;0\n")
    resultado = rodar(sis, monkeypatch, ATUALIZACOES)
    assert PENDENTES not in resultado.ids()
    assert PENDENTES in controles(resultado)


def test_apt_simulacao_quando_nao_ha_apt_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = _apt(tmp_path)
    sis.responder(
        "apt-get",
        "-s",
        "dist-upgrade",
        saida=(
            "Inst openssl [3.0.1] (3.0.2 Ubuntu:22.04/jammy-security [amd64])\n"
            "Inst vim [1] (2 Ubuntu:22.04/jammy-updates [amd64])\n"
        ),
    )
    achado = rodar(sis, monkeypatch, ATUALIZACOES).by_id(PENDENTES)[0]
    assert achado.details["seguranca"] == 1
    assert achado.details["pacotes"] == ["openssl"]


def test_sem_listas_do_apt_o_cache_nao_diz_nada(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = _apt(tmp_path, com_listas=False)
    sis.responder(APT_CHECK, erro="9;9\n")
    resultado = rodar(sis, monkeypatch, ATUALIZACOES)
    assert PENDENTES not in resultado.ids()
    assert PENDENTES not in controles(resultado)


def test_dnf_saida_100_tem_pendencias_e_0_nao(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)
    sis.arquivo("/etc/os-release", 'ID="rocky"\nID_LIKE="rhel centos fedora"\n')
    comando = ("dnf", "-q", "-C", "check-update", "--security")
    sis.responder(
        *comando,
        codigo=100,
        saida="openssl.x86_64  3.0.7-1.el9  baseos\nkernel.x86_64  5.14-1  baseos\n",
    )
    achado = rodar(sis, monkeypatch, ATUALIZACOES).by_id(PENDENTES)[0]
    assert achado.details["seguranca"] == 2
    sis.responder(*comando, codigo=0)
    assert PENDENTES not in rodar(sis, monkeypatch, ATUALIZACOES).ids()


def test_analise_de_saidas_de_pacotes() -> None:
    assert analise.apt_check("ruído\n4;2\n") == (4, 2)
    assert analise.apt_check("sem número") is None
    assert analise.dnf_pacotes("Last metadata expires:\nfoo.noarch 1.0 repo\n") == ["foo.noarch"]


# -- atualizações automáticas e reinício ------------------------------------------------------
def test_unattended_upgrades_ausente_e_achado(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    achado = rodar(base_segura(tmp_path), monkeypatch, ATUALIZACOES).by_id(AUTOMATICAS)[0]
    assert "não está instalado" in achado.evidence


def test_unattended_upgrades_ligado_e_ponto_forte(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)
    sis.programa_instalado("unattended-upgrade")
    sis.responder(
        "apt-config",
        "dump",
        saida='APT::Periodic::Unattended-Upgrade "1";\nAPT::Periodic::Enable "1";\n',
    )
    sis.responder("systemctl", "is-enabled", "apt-daily-upgrade.timer", saida="enabled\n")
    resultado = rodar(sis, monkeypatch, ATUALIZACOES)
    assert AUTOMATICAS not in resultado.ids()
    assert "host.linux.atualizacoes.automaticas" in controles(resultado)


def test_unattended_upgrades_com_tarefa_diaria_zerada_e_achado(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)
    sis.programa_instalado("unattended-upgrade")
    sis.responder("apt-config", "dump", saida='APT::Periodic::Unattended-Upgrade "0";\n')
    assert AUTOMATICAS in rodar(sis, monkeypatch, ATUALIZACOES).ids()


def test_automaticas_nao_se_aplicam_a_rhel_nem_a_conteiner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path / "a")
    sis.arquivo("/etc/os-release", 'ID="fedora"\n')
    assert AUTOMATICAS not in rodar(sis, monkeypatch, ATUALIZACOES).ids()
    conteiner = base_segura(tmp_path / "c")
    conteiner.arquivo("/.dockerenv")
    assert AUTOMATICAS not in rodar(conteiner, monkeypatch, ATUALIZACOES).ids()


def test_reinicio_pendente_lista_os_pacotes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)
    sis.arquivo("/var/run/reboot-required", "*** System restart required ***\n")
    sis.arquivo("/var/run/reboot-required.pkgs", "linux-image-6.8.0-41\nlibc6\n")
    achado = rodar(sis, monkeypatch, ATUALIZACOES).by_id(REINICIO)[0]
    assert achado.confidence is Confidence.CONFIRMED
    assert achado.details["pacotes"] == ["linux-image-6.8.0-41", "libc6"]


def test_sem_aviso_de_reinicio_com_criador_presente_e_ponto_forte(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)
    sis.arquivo("/usr/share/update-notifier/notify-reboot-required")
    resultado = rodar(sis, monkeypatch, ATUALIZACOES)
    assert REINICIO not in resultado.ids()
    assert "host.linux.atualizacoes.reinicio" in controles(resultado)


def test_sem_criador_do_aviso_a_ausencia_nao_prova_nada(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    resultado = rodar(base_segura(tmp_path), monkeypatch, ATUALIZACOES)
    assert "host.linux.atualizacoes.reinicio" not in controles(resultado)
    assert REINICIO not in resultado.ids()


def test_rhel_precisa_reiniciar_segundo_needs_restarting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)
    sis.arquivo("/etc/os-release", 'ID="rhel"\n')
    sis.responder("needs-restarting", "-r", codigo=1, saida="Reboot is required to ensure...\n")
    assert REINICIO in rodar(sis, monkeypatch, ATUALIZACOES).ids()
    sis.responder("needs-restarting", "-r", saida="Reboot should not be necessary.\n")
    assert REINICIO not in rodar(sis, monkeypatch, ATUALIZACOES).ids()


# -- SELinux / AppArmor -----------------------------------------------------------------------
def test_apparmor_ativo_e_ponto_forte(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    resultado = rodar(base_segura(tmp_path), monkeypatch, DEFESAS)
    assert MAC not in resultado.ids()
    assert "host.linux.mac" in controles(resultado)


def test_selinux_enforcing_e_ponto_forte(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sis = base_segura(tmp_path)
    sis.arquivo("/sys/module/apparmor/parameters/enabled", "N\n")
    sis.arquivo("/sys/fs/selinux/enforce", "1")
    resultado = rodar(sis, monkeypatch, DEFESAS)
    assert MAC not in resultado.ids()
    assert "host.linux.mac" in controles(resultado)


def test_selinux_permissivo_e_achado_com_titulo_proprio(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)
    sis.arquivo("/sys/module/apparmor/parameters/enabled", "N\n")
    sis.arquivo("/sys/fs/selinux/enforce", "0")
    achado = rodar(sis, monkeypatch, DEFESAS).by_id(MAC)[0]
    assert "permissivo" in achado.title


def test_sem_nenhum_mac_e_achado_e_sem_sys_nao_e_avaliado(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path / "a")
    sis.arquivo("/sys/module/apparmor/parameters/enabled", "N\n")
    assert MAC in rodar(sis, monkeypatch, DEFESAS).ids()
    sem_sys = LinuxFalso(tmp_path / "b")
    sem_sys.arquivo("/etc/os-release", "ID=ubuntu\n")
    assert MAC not in rodar(sem_sys, monkeypatch, DEFESAS).ids()


# -- auditd -----------------------------------------------------------------------------------
def test_auditd_ausente_e_achado(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    achado = rodar(base_segura(tmp_path), monkeypatch, DEFESAS).by_id(AUDITD)[0]
    assert "não encontrado" in achado.evidence


def test_auditd_ativo_e_ponto_forte_e_parado_e_achado(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)
    sis.programa_instalado("auditd", pasta="/usr/sbin")
    sis.servicos(auditd="active")
    resultado = rodar(sis, monkeypatch, DEFESAS)
    assert AUDITD not in resultado.ids()
    assert "host.linux.auditoria.auditd" in controles(resultado)
    sis.servicos(auditd="inactive")
    assert "parado" in rodar(sis, monkeypatch, DEFESAS).by_id(AUDITD)[0].evidence


def test_auditd_sem_resposta_do_systemctl_nao_e_achado(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)
    sis.programa_instalado("auditd", pasta="/usr/sbin")
    assert AUDITD not in rodar(sis, monkeypatch, DEFESAS).ids()


# -- fail2ban ---------------------------------------------------------------------------------
def _ssh_com_senha(raiz: Path, senha: str = "yes") -> LinuxFalso:
    sis = base_segura(raiz)
    sis.programa_instalado("sshd", pasta="/usr/sbin")
    sis.arquivo("/etc/ssh/sshd_config", f"PasswordAuthentication {senha}\n", 0o644)
    return sis


def test_ssh_com_senha_e_sem_fail2ban_e_achado(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    achado = rodar(_ssh_com_senha(tmp_path), monkeypatch, DEFESAS).by_id(FAIL2BAN)[0]
    assert "não encontrados" in achado.evidence


def test_ssh_so_com_chave_nao_exige_fail2ban(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert FAIL2BAN not in rodar(_ssh_com_senha(tmp_path, "no"), monkeypatch, DEFESAS).ids()


def test_fail2ban_ativo_e_ponto_forte_e_parado_e_achado(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = _ssh_com_senha(tmp_path)
    sis.programa_instalado("fail2ban-server")
    sis.servicos(fail2ban="active")
    resultado = rodar(sis, monkeypatch, DEFESAS)
    assert FAIL2BAN not in resultado.ids()
    assert "host.linux.ssh.protecao" in controles(resultado)
    sis.servicos(fail2ban="inactive")
    assert "parado" in rodar(sis, monkeypatch, DEFESAS).by_id(FAIL2BAN)[0].evidence


def test_sem_servidor_ssh_nao_ha_o_que_proteger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert FAIL2BAN not in rodar(base_segura(tmp_path), monkeypatch, DEFESAS).ids()


# -- bancos de dados em escuta ----------------------------------------------------------------
def _tcp(*linhas: str) -> str:
    return CABECALHO_TCP + "".join(linhas)


def test_banco_em_todas_as_interfaces_e_achado(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)
    sis.arquivo("/proc/net/tcp", _tcp(linha_tcp("00000000", 3306), linha_tcp("0100007F", 5432)))
    achados = rodar(sis, monkeypatch, REDE).by_id(BANCO)
    assert [a.details["porta"] for a in achados] == [3306]
    assert "0.0.0.0:3306" in achados[0].evidence


def test_banco_so_no_loopback_e_ponto_forte(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    resultado = rodar(base_segura(tmp_path), monkeypatch, REDE)
    assert resultado.ids() == set()
    assert "host.linux.rede.bancos" in controles(resultado)


def test_banco_ipv6_em_todas_as_interfaces(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sis = base_segura(tmp_path)
    sis.arquivo("/proc/net/tcp6", _tcp(linha_tcp("0" * 32, 6379)))
    achado = rodar(sis, monkeypatch, REDE).by_id(BANCO)[0]
    assert "[::]:6379" in achado.evidence


def test_porta_que_nao_e_banco_ou_nao_escuta_e_ignorada(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)
    sis.arquivo(
        "/proc/net/tcp",
        _tcp(linha_tcp("00000000", 8080), linha_tcp("00000000", 3306, estado="01")),
    )
    assert rodar(sis, monkeypatch, REDE).ids() == set()


def test_firewall_ativo_atenua_a_severidade_do_banco(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sem = base_segura(tmp_path / "a", root=True)
    sem.arquivo("/proc/net/tcp", _tcp(linha_tcp("00000000", 6379)))
    sem.responder("nft", "list", "ruleset", saida=NFT_ABERTO)
    sem.responder("iptables", "-S", saida="-P INPUT ACCEPT\n")
    com = base_segura(tmp_path / "b", root=True)
    com.arquivo("/proc/net/tcp", _tcp(linha_tcp("00000000", 6379)))
    com.responder("nft", "list", "ruleset", saida=NFT_COM_REGRAS)
    pior = rodar(sem, monkeypatch, REDE).by_id(BANCO)[0]
    melhor = rodar(com, monkeypatch, REDE).by_id(BANCO)[0]
    assert melhor.severity is Severity.MEDIUM
    assert pior.severity is not Severity.MEDIUM


def test_conteiner_nao_decide_a_exposicao_e_sem_proc_nao_e_avaliado(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path / "a")
    sis.arquivo("/.dockerenv")
    sis.arquivo("/proc/net/tcp", _tcp(linha_tcp("00000000", 3306)))
    assert rodar(sis, monkeypatch, REDE).ids() == set()
    resultado = rodar(LinuxFalso(tmp_path / "b"), monkeypatch, REDE)
    assert resultado.ids() == set()
    assert not resultado.passed
