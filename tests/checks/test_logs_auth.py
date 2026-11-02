"""Logs de autenticação do Linux: SSH, sudo e criação de contas."""

from __future__ import annotations

from pathlib import Path

from fakes_logs import fato_logs, ssh_aceito, ssh_falha, syslog
from helpers import run_check

ID = "logs.analise"
IP = "203.0.113.5"


def _rodar(tmp_path: Path, linhas: list[str]):
    arq = tmp_path / "auth.log"
    arq.write_text("\n".join(linhas) + "\n", encoding="utf-8")
    return run_check(ID, fato_logs(arq))


def test_forca_bruta_ssh_traz_ip_e_contagem(tmp_path: Path) -> None:
    out = _rodar(tmp_path, [ssh_falha(i * 5, IP, "admin") for i in range(12)])
    achados = [f for f in out.findings if f.check_id == "logs.ssh.forca_bruta"]
    assert len(achados) == 1
    assert IP in achados[0].title
    assert not out.passed


def test_poucas_falhas_nao_geram_forca_bruta(tmp_path: Path) -> None:
    out = _rodar(tmp_path, [ssh_falha(i * 5, IP) for i in range(3)])
    assert "logs.ssh.forca_bruta" not in out.ids()


def test_falhas_espalhadas_por_dias_nao_sao_forca_bruta(tmp_path: Path) -> None:
    out = _rodar(tmp_path, [ssh_falha(i * 20_000, IP) for i in range(6)])
    assert "logs.ssh.forca_bruta" not in out.ids()


def test_sucesso_apos_falhas_e_critico(tmp_path: Path) -> None:
    publico = "93.184.216.34"
    linhas = [ssh_falha(i, publico, "root") for i in range(8)] + [ssh_aceito(30, publico, "root")]
    out = _rodar(tmp_path, linhas)
    achado = next(f for f in out.findings if f.check_id == "logs.ssh.sucesso_apos_falhas")
    assert achado.severity.value == "critical"


def test_sucesso_apos_falhas_de_ip_interno_e_menos_grave(tmp_path: Path) -> None:
    linhas = [ssh_falha(i, "10.0.0.7", "root") for i in range(8)] + [
        ssh_aceito(30, "10.0.0.7", "root")
    ]
    out = _rodar(tmp_path, linhas)
    achado = next(f for f in out.findings if f.check_id == "logs.ssh.sucesso_apos_falhas")
    assert achado.severity.value == "high"


def test_sucesso_de_outro_ip_nao_conta(tmp_path: Path) -> None:
    linhas = [ssh_falha(i, IP, "root") for i in range(8)] + [ssh_aceito(30, "198.51.100.9", "root")]
    out = _rodar(tmp_path, linhas)
    assert "logs.ssh.sucesso_apos_falhas" not in out.ids()


def test_login_normal_gera_ponto_forte(tmp_path: Path) -> None:
    out = _rodar(tmp_path, [ssh_aceito(1, "198.51.100.9", "ana", "publickey"), ssh_falha(9, IP)])
    assert not out.findings
    assert out.passed


def test_usuarios_invalidos_variados(tmp_path: Path) -> None:
    nomes = ["oracle", "ubuntu", "test", "postgres", "git", "ftp"]
    linhas = [
        syslog(i, "sshd", f"Invalid user {n} from {IP} port 40{i}") for i, n in enumerate(nomes)
    ]
    out = _rodar(tmp_path, linhas)
    assert "logs.ssh.usuarios_invalidos" in out.ids()


def test_sudo_falhas_repetidas(tmp_path: Path) -> None:
    linhas = [
        syslog(
            i,
            "sudo",
            "ana : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/ana ; USER=root ; COMMAND=/bin/bash",
        )
        for i in range(3)
    ]
    out = _rodar(tmp_path, linhas)
    assert "logs.sudo.falhas" in out.ids()


def test_sudo_usuario_fora_do_sudoers(tmp_path: Path) -> None:
    linhas = [
        syslog(
            i,
            "sudo",
            "bob : user NOT in sudoers ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/su",
        )
        for i in range(4)
    ]
    out = _rodar(tmp_path, linhas)
    assert "logs.sudo.nao_autorizado" in out.ids()


def test_sudo_bem_sucedido_nao_gera_achado(tmp_path: Path) -> None:
    linhas = [
        syslog(
            i, "sudo", "ana : TTY=pts/0 ; PWD=/home/ana ; USER=root ; COMMAND=/usr/bin/apt update"
        )
        for i in range(10)
    ]
    out = _rodar(tmp_path, linhas)
    assert not [i for i in out.ids() if i.startswith("logs.sudo")]


def test_conta_criada_e_adicionada_ao_sudo(tmp_path: Path) -> None:
    linhas = [
        syslog(
            1,
            "useradd",
            "new user: name=backdoor, UID=1005, GID=1005, home=/home/backdoor, shell=/bin/bash",
        ),
        syslog(2, "usermod", "add 'backdoor' to group 'sudo'"),
    ]
    out = _rodar(tmp_path, linhas)
    assert "logs.linux.novo_usuario" in out.ids()
    assert "logs.linux.grupo_admin" in out.ids()


def test_conta_de_servico_sem_shell_e_grupo_comum_nao_alertam(tmp_path: Path) -> None:
    linhas = [
        syslog(
            1,
            "useradd",
            "new user: name=svc, UID=998, GID=998, home=/var/lib/svc, shell=/usr/sbin/nologin",
        ),
        syslog(2, "usermod", "add 'ana' to group 'audio'"),
    ]
    out = _rodar(tmp_path, linhas)
    assert "logs.linux.grupo_admin" not in out.ids()


def test_uid_zero(tmp_path: Path) -> None:
    out = _rodar(tmp_path, [syslog(1, "usermod", "change user 'joe' UID from '1001' to '0'")])
    assert "logs.linux.admin_uid_zero" in out.ids()
