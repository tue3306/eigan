"""Contas, sudo e permissões de arquivos, com um Linux falso (roda em Windows e em Linux)."""

from __future__ import annotations

import stat
from pathlib import Path

import pytest
from fakes_host_linux import ROOT_E_USUARIO, SHADOW_OK, LinuxFalso, base_segura, rodar

from eigan.checks.host.sistema import InfoArquivo
from eigan.core.models import Confidence, Severity

CONTAS = "host.linux.contas"
SUDO = "host.linux.sudo"
PERMISSOES = "host.linux.permissoes"
UID0 = "host.linux.contas.uid0_extra"
SENHA_VAZIA = "host.linux.contas.senha_vazia"
SHADOW = "host.linux.arquivos.shadow_legivel"
PASSWD = "host.linux.arquivos.passwd_gravavel"
NOPASSWD = "host.linux.sudo.nopasswd_total"
PATH_ID = "host.linux.path.pasta_gravavel"
SUID = "host.linux.suid.binario_arriscado"
CRON = "host.linux.cron.gravavel"
DOCKER = "host.linux.docker.socket_gravavel"


def _permissoes(sis: LinuxFalso, monkeypatch: pytest.MonkeyPatch) -> set[str]:
    return rodar(sis, monkeypatch, PERMISSOES).ids()


# -- contas ------------------------------------------------------------------------------
def test_maquina_segura_sem_achados_de_contas(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    resultado = rodar(base_segura(tmp_path), monkeypatch, CONTAS)
    assert resultado.ids() == set()
    assert {p.control for p in resultado.passed} == {
        "host.linux.contas.uid0",
        "host.linux.contas.senha_vazia",
        "host.linux.arquivos.contas",
    }


def test_outra_conta_com_uid_zero(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sis = base_segura(tmp_path)
    sis.arquivo("/etc/passwd", ROOT_E_USUARIO + "toor:x:0:0::/root:/bin/bash\n", 0o644)
    resultado = rodar(sis, monkeypatch, CONTAS)
    achado = resultado.by_id(UID0)[0]
    assert achado.confidence is Confidence.CONFIRMED
    assert achado.evidence == "Conta toor com UID 0 (/etc/passwd:4)"
    assert achado.title.endswith("toor")


def test_entradas_nis_e_uid_invalido_nao_contam(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)
    sis.arquivo(
        "/etc/passwd",
        ROOT_E_USUARIO + "# comentario:x:0:0\n+::0:0:::\nlixo:x:abc:0::/:/bin/sh\ncurta\n",
    )
    assert UID0 not in rodar(sis, monkeypatch, CONTAS).ids()


def test_senha_vazia_no_shadow_sem_expor_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)
    sis.arquivo("/etc/shadow", SHADOW_OK + "teste::19000:0:99999:7:::\n", 0o640)
    resultado = rodar(sis, monkeypatch, CONTAS)
    assert [f.details["conta"] for f in resultado.by_id(SENHA_VAZIA)] == ["teste"]
    achado = resultado.by_id(SENHA_VAZIA)[0]
    assert achado.evidence == "Campo de senha vazio em /etc/shadow (conta teste)"
    assert "resumo" not in str(achado.to_dict() if hasattr(achado, "to_dict") else achado.details)


def test_senha_vazia_no_passwd_nao_depende_do_shadow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)
    sis.arquivo("/etc/passwd", ROOT_E_USUARIO + "velha::1001:1001::/home/velha:/bin/sh\n", 0o644)
    sis.negados.add("/etc/shadow")
    resultado = rodar(sis, monkeypatch, CONTAS)
    assert resultado.by_id(SENHA_VAZIA)[0].details == {
        "conta": "velha",
        "arquivo": "/etc/passwd",
        "sem_login_interativo": False,
    }


def test_contas_bloqueadas_nao_sao_senha_vazia(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)
    sis.arquivo("/etc/shadow", "a:!:1:0:::::\nb:*:1:0:::::\nc:!!:1:0:::::\nd:!*:1:0:::::\n", 0o640)
    assert SENHA_VAZIA not in rodar(sis, monkeypatch, CONTAS).ids()


def test_shadow_negado_fica_nao_verificado(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sis = base_segura(tmp_path)
    sis.negados.add("/etc/shadow")
    resultado = rodar(sis, monkeypatch, CONTAS)
    assert SENHA_VAZIA not in resultado.ids()
    assert "host.linux.contas.senha_vazia" not in {p.control for p in resultado.passed}
    assert any("/etc/shadow: não verificado" in linha for linha in resultado.logs)


@pytest.mark.parametrize("caminho", ["/etc/shadow", "/etc/gshadow"])
def test_arquivo_de_senhas_legivel_por_todos(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caminho: str
) -> None:
    sis = base_segura(tmp_path)
    sis.arquivo(caminho, "root:*::\n", 0o644)
    achado = rodar(sis, monkeypatch, CONTAS).by_id(SHADOW)[0]
    assert achado.details == {"arquivo": caminho, "modo": "0644"}
    assert achado.severity is Severity.HIGH


@pytest.mark.parametrize("caminho", ["/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow"])
def test_arquivo_de_contas_gravavel_por_todos(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caminho: str
) -> None:
    sis = base_segura(tmp_path)
    sis.modos[caminho] = InfoArquivo(stat.S_IFREG | 0o646)
    achado = rodar(sis, monkeypatch, CONTAS).by_id(PASSWD)[0]
    assert achado.severity is Severity.CRITICAL
    assert achado.details["arquivo"] == caminho


def test_permissoes_normais_dos_arquivos_de_contas(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)
    sis.modos["/etc/shadow"] = InfoArquivo(stat.S_IFREG | 0o000)  # padrão do RHEL
    sis.modos["/etc/passwd"] = InfoArquivo(stat.S_IFREG | 0o644)
    assert rodar(sis, monkeypatch, CONTAS).ids() == set()


# -- sudo --------------------------------------------------------------------------------
def _com_sudoers(raiz: Path, conteudo: str) -> LinuxFalso:
    sis = base_segura(raiz)
    sis.arquivo("/etc/sudoers", conteudo, 0o440)
    return sis


@pytest.mark.parametrize(
    "regra",
    [
        "ana ALL=(ALL) NOPASSWD: ALL",
        "ana ALL=(ALL:ALL) NOPASSWD:ALL",
        "%wheel ALL = (ALL) NOPASSWD: ALL",
        "ana,bia ALL=NOPASSWD: ALL",
        "ana ALL=NOPASSWD: /usr/bin/apt, ALL",
        "ana ALL=(ALL) NOEXEC: NOPASSWD: ALL",
        "ana serv1=(ALL) ALL : serv2=(ALL) NOPASSWD: ALL",
        "ana ALL = \\\n  NOPASSWD: ALL",
        "Defaults:ana !authenticate",
    ],
)
def test_regras_que_liberam_tudo_sem_senha(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, regra: str
) -> None:
    resultado = rodar(_com_sudoers(tmp_path, f"root ALL=(ALL) ALL\n{regra}\n"), monkeypatch, SUDO)
    achado = resultado.by_id(NOPASSWD)[0]
    assert achado.severity is Severity.MEDIUM
    assert achado.details["origem"] == "/etc/sudoers:2"
    assert achado.confidence is Confidence.CONFIRMED


@pytest.mark.parametrize(
    "regra",
    [
        "ana ALL=(ALL) ALL",
        "ana ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart app",
        "ana ALL=(ALL) NOPASSWD: /usr/bin/apt, PASSWD: ALL",
        "ana ALL=(ALL) PASSWD: ALL",
        "# ana ALL=(ALL) NOPASSWD: ALL",
        "Cmnd_Alias TUDO = NOPASSWD: ALL",
        "Defaults env_reset",
        "Defaults@serv1 !authenticate",
        "Defaults!/usr/bin/apt !authenticate",
        "ana ALL=(ALL) ALL # NOPASSWD: ALL",
    ],
)
def test_regras_que_nao_liberam_tudo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, regra: str
) -> None:
    resultado = rodar(_com_sudoers(tmp_path, f"root ALL=(ALL) ALL\n{regra}\n"), monkeypatch, SUDO)
    assert resultado.ids() == set()
    assert {p.control for p in resultado.passed} == {SUDO}


def test_regra_para_todos_os_usuarios_e_mais_grave(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    resultado = rodar(_com_sudoers(tmp_path, "ALL ALL=(ALL) NOPASSWD: ALL\n"), monkeypatch, SUDO)
    assert resultado.by_id(NOPASSWD)[0].severity is Severity.HIGH
    resultado = rodar(_com_sudoers(tmp_path, "Defaults !authenticate\n"), monkeypatch, SUDO)
    assert resultado.by_id(NOPASSWD)[0].severity is Severity.HIGH


def test_inclusoes_do_sudo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sis = _com_sudoers(tmp_path, "root ALL=(ALL) ALL\n@includedir /etc/sudoers.d\n#include extra\n")
    sis.arquivo("/etc/sudoers.d/90-nuvem", "ubuntu ALL=(ALL) NOPASSWD:ALL\n", 0o440)
    sis.arquivo("/etc/sudoers.d/ignorado.bak", "bia ALL=(ALL) NOPASSWD: ALL\n", 0o440)
    sis.arquivo("/etc/sudoers.d/antigo~", "cida ALL=(ALL) NOPASSWD: ALL\n", 0o440)
    sis.arquivo("/etc/extra", "deia ALL=(ALL) NOPASSWD: ALL\n", 0o440)
    achados = rodar(sis, monkeypatch, SUDO).by_id(NOPASSWD)
    assert {f.details["origem"] for f in achados} == {"/etc/sudoers.d/90-nuvem:1", "/etc/extra:1"}


def test_sudoers_negado_ou_ausente_nao_vira_achado(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = _com_sudoers(tmp_path, "ana ALL=(ALL) NOPASSWD: ALL\n")
    sis.negados.add("/etc/sudoers")
    resultado = rodar(sis, monkeypatch, SUDO)
    assert resultado.ids() == set() and not resultado.passed
    assert any("não verificado" in linha for linha in resultado.logs)

    sem_sudo = base_segura(tmp_path / "sem-sudo")
    sem_sudo.caminho("/etc/sudoers").unlink()
    resultado = rodar(sem_sudo, monkeypatch, SUDO)
    assert resultado.ids() == set() and not resultado.passed


def test_inclusao_negada_nao_da_ponto_forte(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = _com_sudoers(tmp_path, "root ALL=(ALL) ALL\n@includedir /etc/sudoers.d\n")
    sis.pasta("/etc/sudoers.d")
    sis.negados.add("/etc/sudoers.d")
    resultado = rodar(sis, monkeypatch, SUDO)
    assert resultado.ids() == set() and not resultado.passed


# -- PATH --------------------------------------------------------------------------------
def test_pasta_gravavel_no_path_do_processo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path, path="/usr/bin:/opt/ferramentas:/bin")
    sis.pasta("/opt/ferramentas", 0o777)
    achado = rodar(sis, monkeypatch, PERMISSOES).by_id(PATH_ID)[0]
    assert achado.details["pasta"] == "/opt/ferramentas"
    assert achado.details["modo"] == "0777"
    assert achado.details["origens"] == ["PATH do processo da auditoria"]


@pytest.mark.parametrize(
    ("arquivo", "conteudo", "origem"),
    [
        ("/etc/environment", 'PATH="/usr/bin:/opt/x"\n', "/etc/environment"),
        ("/etc/login.defs", "ENV_SUPATH\tPATH=/usr/sbin:/opt/x\n", "/etc/login.defs"),
        ("/etc/login.defs", "ENV_PATH /usr/bin:/opt/x\n", "/etc/login.defs"),
        ("/etc/sudoers", 'Defaults secure_path="/usr/sbin:/opt/x"\n', "secure_path do sudo"),
    ],
)
def test_pasta_gravavel_em_outras_fontes_de_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arquivo: str, conteudo: str, origem: str
) -> None:
    sis = base_segura(tmp_path)
    sis.pasta("/opt/x", 0o1777)
    sis.arquivo(arquivo, conteudo)
    assert rodar(sis, monkeypatch, PERMISSOES).by_id(PATH_ID)[0].details["origens"] == [origem]


def test_mesma_pasta_em_varias_fontes_vira_um_achado(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path, path="/opt/x:/atalho")
    sis.pasta("/opt/x", 0o777)
    sis.pasta("/atalho", 0o777)
    sis.reais["/atalho"] = "/opt/x"
    sis.arquivo("/etc/environment", 'PATH="/opt/x"\n')
    achados = rodar(sis, monkeypatch, PERMISSOES).by_id(PATH_ID)
    assert len(achados) == 1
    assert achados[0].details["origens"] == ["PATH do processo da auditoria", "/etc/environment"]


def test_path_sem_problema(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # relativo, vazio, inexistente, arquivo comum e pasta sem escrita para outros
    sis = base_segura(tmp_path, path=".::relativa:/nao/existe:/etc/passwd:/usr/bin:/opt/grupo")
    sis.pasta("/opt/grupo", 0o775)
    resultado = rodar(sis, monkeypatch, PERMISSOES)
    assert PATH_ID not in resultado.ids()
    assert "host.linux.path" in {p.control for p in resultado.passed}


def test_unidades_do_windows_no_wsl_nao_contam(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path, path="/usr/bin:/mnt/c/WINDOWS/system32")
    sis.pasta("/mnt/c/WINDOWS/system32", 0o777)
    sis.arquivo("/proc/self/mounts", "/dev/sdb / ext4 rw 0 0\nC:\\134 /mnt/c 9p rw 0 0\n")
    assert PATH_ID not in rodar(sis, monkeypatch, PERMISSOES).ids()


# -- SUID --------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "programa",
    [
        "/usr/bin/find",
        "/bin/bash",
        "/usr/bin/python3",
        "/usr/local/bin/python3.12",
        "/sbin/vim.basic",
    ],
)
def test_suid_em_programa_arriscado(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, programa: str
) -> None:
    sis = base_segura(tmp_path)
    sis.arquivo(programa, "", 0o4755)
    achado = rodar(sis, monkeypatch, PERMISSOES).by_id(SUID)[0]
    assert achado.details["programa"] == programa
    assert achado.details["modo"] == "4755"
    assert achado.confidence is Confidence.CONFIRMED


def test_suid_sem_falso_positivo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sis = base_segura(tmp_path)
    sis.arquivo("/usr/bin/sudo", "", 0o4755)  # feito para ter SUID
    sis.arquivo("/usr/bin/passwd", "", 0o4755)
    sis.arquivo("/usr/bin/find", "", 0o755)  # sem SUID
    sis.arquivo("/usr/bin/bash", "", 0o4755, uid=1000)  # SUID de outra conta, não de root
    sis.arquivo("/usr/bin/vim", "", 0o4644)  # sem permissão de execução
    sis.arquivo("/home/ana/bash", "", 0o4755)  # fora das pastas padrão
    sis.pasta("/usr/bin/awk", 0o4755)  # pasta com esse nome
    resultado = rodar(sis, monkeypatch, PERMISSOES)
    assert SUID not in resultado.ids()
    assert "host.linux.suid" in {p.control for p in resultado.passed}


def test_suid_no_mesmo_arquivo_por_links_vira_um_achado(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)
    sis.arquivo("/usr/bin/bash", "", 0o4755)
    sis.arquivo("/bin/bash", "", 0o4755)
    sis.reais["/bin/bash"] = "/usr/bin/bash"
    assert len(rodar(sis, monkeypatch, PERMISSOES).by_id(SUID)) == 1


def test_pasta_de_programas_negada_fica_nao_verificada(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)
    sis.arquivo("/usr/bin/find", "", 0o4755)
    sis.negados.add("/usr/bin")
    resultado = rodar(sis, monkeypatch, PERMISSOES)
    assert SUID not in resultado.ids()
    assert any("/usr/bin: não verificado" in linha for linha in resultado.logs)


# -- cron --------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "caminho",
    [
        "/etc/crontab",
        "/etc/anacrontab",
        "/etc/cron.d/backup",
        "/etc/cron.hourly/x",
        "/etc/cron.daily/x",
        "/etc/cron.weekly/x",
        "/etc/cron.monthly/x",
        "/var/spool/cron/root",
        "/var/spool/cron/crontabs/root",
    ],
)
def test_arquivo_do_cron_gravavel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caminho: str
) -> None:
    sis = base_segura(tmp_path)
    sis.arquivo(caminho, "* * * * * root /bin/true\n", 0o666)
    achado = rodar(sis, monkeypatch, PERMISSOES).by_id(CRON)[0]
    assert achado.details["arquivos"] == {caminho: "0666"}
    assert achado.severity is Severity.HIGH


def test_pasta_do_cron_gravavel(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sis = base_segura(tmp_path)
    sis.pasta("/etc/cron.daily", 0o777)
    assert rodar(sis, monkeypatch, PERMISSOES).by_id(CRON)[0].details["arquivos"] == {
        "/etc/cron.daily": "0777"
    }


def test_cron_com_permissoes_normais(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sis = base_segura(tmp_path)
    sis.arquivo("/etc/crontab", "", 0o644)
    sis.arquivo("/etc/cron.d/x", "", 0o664)  # escrita para o grupo não é escrita para todos
    sis.pasta("/var/spool/cron/crontabs", 0o1730)
    sis.arquivo("/home/ana/crontab", "", 0o666)  # fora das pastas do cron
    resultado = rodar(sis, monkeypatch, PERMISSOES)
    assert CRON not in resultado.ids()
    assert "host.linux.cron" in {p.control for p in resultado.passed}


def test_pasta_do_cron_negada_nao_impede_o_resto(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)
    sis.pasta("/var/spool/cron/crontabs")
    sis.negados.add("/var/spool/cron/crontabs")
    sis.arquivo("/etc/cron.d/x", "", 0o666)
    resultado = rodar(sis, monkeypatch, PERMISSOES)
    assert list(resultado.by_id(CRON)[0].details["arquivos"]) == ["/etc/cron.d/x"]
    assert any("crontabs: não verificado" in linha for linha in resultado.logs)


def test_sem_cron_nao_ha_ponto_forte(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    resultado = rodar(base_segura(tmp_path), monkeypatch, PERMISSOES)
    assert "host.linux.cron" not in {p.control for p in resultado.passed}


# -- socket do Docker -------------------------------------------------------------------
def test_socket_do_docker_aberto(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sis = base_segura(tmp_path)
    sis.socket("/var/run/docker.sock", 0o666)
    achado = rodar(sis, monkeypatch, PERMISSOES).by_id(DOCKER)[0]
    assert achado.details == {"socket": "/var/run/docker.sock", "modo": "0666"}


def test_socket_do_docker_no_padrao(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sis = base_segura(tmp_path)
    sis.socket("/var/run/docker.sock", 0o660)
    resultado = rodar(sis, monkeypatch, PERMISSOES)
    assert DOCKER not in resultado.ids()
    assert "host.linux.docker.socket" in {p.control for p in resultado.passed}


def test_arquivo_comum_com_nome_de_socket_nao_conta(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)
    sis.arquivo("/run/docker.sock", "", 0o666)
    resultado = rodar(sis, monkeypatch, PERMISSOES)
    assert DOCKER not in resultado.ids()
    assert "host.linux.docker.socket" not in {p.control for p in resultado.passed}


def test_dois_caminhos_do_mesmo_socket_viram_um_achado(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = base_segura(tmp_path)
    sis.socket("/run/docker.sock", 0o666)
    sis.socket("/var/run/docker.sock", 0o666)
    sis.reais["/var/run/docker.sock"] = "/run/docker.sock"
    assert len(rodar(sis, monkeypatch, PERMISSOES).by_id(DOCKER)) == 1


def test_estado_negado_no_socket_fica_nao_verificado(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Negado(LinuxFalso):
        def estado(self, alvo: str) -> InfoArquivo | None:
            if "docker" in alvo:
                from eigan.checks.host.sistema import AcessoNegado

                raise AcessoNegado(alvo)
            return super().estado(alvo)

    sis = Negado(tmp_path)
    sis.arquivo("/etc/passwd", ROOT_E_USUARIO, 0o644)
    resultado = rodar(sis, monkeypatch, PERMISSOES)
    assert DOCKER not in resultado.ids()
    assert any("Socket do Docker: não verificado" in linha for linha in resultado.logs)
