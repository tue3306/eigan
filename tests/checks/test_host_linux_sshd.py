"""SSH: configuração efetiva do sshd lida de um Linux falso (roda em Windows e em Linux)."""

from __future__ import annotations

from pathlib import Path

import pytest
from fakes_host_linux import LinuxFalso, base_segura, rodar

from eigan.checks.host import linux_sshd
from eigan.checks.host.sistema import AcessoNegado
from eigan.core.models import Confidence, Severity

CHECK = "host.linux.ssh"
ROOT = "host.linux.ssh.root_permitido"
SENHA = "host.linux.ssh.senha_permitida"
VAZIA = "host.linux.ssh.senha_vazia"
X11 = "host.linux.ssh.x11_forwarding"
TENTATIVAS = "host.linux.ssh.tentativas_excessivas"
SEGURO = (
    "PermitRootLogin no\nPasswordAuthentication no\nPermitEmptyPasswords no\n"
    "X11Forwarding no\nMaxAuthTries 3\n"
)
INSEGURO = (
    "PermitRootLogin yes\nPasswordAuthentication yes\nPermitEmptyPasswords yes\n"
    "X11Forwarding yes\nMaxAuthTries 6\n"
)


def maquina(raiz: Path, config: str = SEGURO, *, root: bool = False) -> LinuxFalso:
    sis = base_segura(raiz, root=root)
    sis.programa_instalado("sshd", pasta="/usr/sbin")
    sis.arquivo("/etc/ssh/sshd_config", config, 0o644)
    return sis


def test_configuracao_insegura_gera_os_cinco_achados(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    resultado = rodar(maquina(tmp_path, INSEGURO), monkeypatch, CHECK)
    assert resultado.ids() == {ROOT, SENHA, VAZIA, X11, TENTATIVAS}
    assert not resultado.passed
    raiz = resultado.by_id(ROOT)[0]
    assert raiz.evidence == "PermitRootLogin yes (/etc/ssh/sshd_config:1)."
    assert raiz.severity is Severity.HIGH  # root com senha ligada é mais grave
    assert raiz.confidence is Confidence.FIRM
    assert "openssh" in raiz.tech and "debian" in raiz.tech
    assert raiz.details["fonte"] == "arquivos"


def test_configuracao_segura_vira_pontos_fortes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    resultado = rodar(maquina(tmp_path), monkeypatch, CHECK)
    assert resultado.ids() == set()
    assert {p.control for p in resultado.passed} == {ROOT, SENHA, VAZIA, X11, TENTATIVAS}


def test_root_com_chave_nao_e_achado(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for valor in ("prohibit-password", "without-password", "forced-commands-only"):
        sis = maquina(tmp_path, f"PermitRootLogin {valor}\nPasswordAuthentication no\n")
        assert ROOT not in rodar(sis, monkeypatch, CHECK).ids(), valor


def test_root_sem_senha_ligada_fica_com_a_severidade_padrao(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    resultado = rodar(
        maquina(tmp_path, "PermitRootLogin yes\nPasswordAuthentication no\n"), monkeypatch, CHECK
    )
    assert resultado.by_id(ROOT)[0].severity is Severity.MEDIUM


def test_valores_padrao_do_openssh_quando_nada_foi_definido(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    resultado = rodar(maquina(tmp_path, "# tudo comentado\n"), monkeypatch, CHECK)
    # padrão: senha ligada e 6 tentativas; root só com chave, X11 e senha vazia desligados
    assert resultado.ids() == {SENHA, TENTATIVAS}
    assert "padrão do OpenSSH" in resultado.by_id(SENHA)[0].evidence


def test_a_primeira_ocorrencia_vale_com_include_no_topo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\n" + SEGURO
    sis = maquina(tmp_path, config)
    sis.arquivo("/etc/ssh/sshd_config.d/50-cloud.conf", "PasswordAuthentication no\n")
    assert rodar(sis, monkeypatch, CHECK).ids() == set()


def test_a_primeira_ocorrencia_vale_com_include_no_fim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = "PasswordAuthentication yes\nInclude /etc/ssh/sshd_config.d/*.conf\n" + SEGURO
    sis = maquina(tmp_path, config)
    sis.arquivo("/etc/ssh/sshd_config.d/50-cloud.conf", "PasswordAuthentication no\n")
    resultado = rodar(sis, monkeypatch, CHECK)
    assert resultado.ids() == {SENHA}
    assert "/etc/ssh/sshd_config:1" in resultado.by_id(SENHA)[0].evidence


def test_include_em_ordem_lexica_e_caminho_relativo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = maquina(tmp_path, "Include sshd_config.d/*.conf\n" + SEGURO)
    sis.arquivo("/etc/ssh/sshd_config.d/20-depois.conf", "X11Forwarding no\n")
    sis.arquivo("/etc/ssh/sshd_config.d/10-antes.conf", "X11Forwarding yes\n")
    sis.arquivo("/etc/ssh/sshd_config.d/.oculto.conf", "PermitRootLogin yes\n")
    sis.arquivo("/etc/ssh/sshd_config.d/ignorado.txt", "PermitEmptyPasswords yes\n")
    resultado = rodar(sis, monkeypatch, CHECK)
    assert resultado.ids() == {X11}
    assert "10-antes.conf:1" in resultado.by_id(X11)[0].evidence


def test_bloco_match_condicional_e_ignorado(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = SEGURO + "Match User ana\n  PasswordAuthentication yes\n  PermitRootLogin yes\n"
    resultado = rodar(maquina(tmp_path, config), monkeypatch, CHECK)
    assert resultado.ids() == set()
    config_sem_global = "Match Address 10.0.0.0/8\n  PermitRootLogin yes\n  X11Forwarding yes\n"
    resultado = rodar(maquina(tmp_path, config_sem_global), monkeypatch, CHECK)
    assert ROOT not in resultado.ids() and X11 not in resultado.ids()
    assert resultado.by_id(SENHA)[0].details["blocos_match_ignorados"] == ["/etc/ssh/sshd_config:1"]


def test_match_all_vale_para_todas_as_conexoes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    resultado = rodar(
        maquina(tmp_path, SEGURO + "Match all\n  X11Forwarding yes\n"), monkeypatch, CHECK
    )
    assert resultado.ids() == {X11}


def test_match_de_arquivo_incluido_termina_no_fim_do_arquivo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = maquina(tmp_path, "Include /etc/ssh/extra.conf\nX11Forwarding yes\n")
    sis.arquivo("/etc/ssh/extra.conf", "Match User ana\n  X11Forwarding no\n")
    resultado = rodar(sis, monkeypatch, CHECK)
    assert X11 in resultado.ids()
    assert "/etc/ssh/sshd_config:2" in resultado.by_id(X11)[0].evidence


def test_match_all_incluido_de_dentro_de_match_condicional_nao_vale_sempre(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = maquina(tmp_path, SEGURO + "Match User ana\n  Include /etc/ssh/extra.conf\n")
    sis.arquivo("/etc/ssh/extra.conf", "Match all\n  X11Forwarding yes\n")
    assert rodar(sis, monkeypatch, CHECK).ids() == set()


def test_sintaxes_aceitas_pelo_sshd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config = (
        '  permitrootlogin=YES\nPasswordAuthentication = "yes"\n'
        "X11Forwarding yes # comentário\nMaxAuthTries\t4\n# PermitEmptyPasswords yes\n"
    )
    resultado = rodar(maquina(tmp_path, config), monkeypatch, CHECK)
    assert resultado.ids() == {ROOT, SENHA, X11}


def test_include_recursivo_nao_trava(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sis = maquina(tmp_path, "Include /etc/ssh/sshd_config\n" + SEGURO)
    assert rodar(sis, monkeypatch, CHECK).ids() == set()


def test_sshd_t_so_com_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    saida = (
        "port 22\npermitrootlogin yes\npasswordauthentication no\npermitemptypasswords no\n"
        "x11forwarding no\nmaxauthtries 4\n"
    )
    sis = maquina(tmp_path, SEGURO, root=True)
    sis.responder("sshd", "-T", saida=saida)
    resultado = rodar(sis, monkeypatch, CHECK)
    assert resultado.ids() == {ROOT}
    achado = resultado.by_id(ROOT)[0]
    assert achado.confidence is Confidence.CONFIRMED
    assert achado.details["fonte"] == "sshd -T"
    assert "sshd -T" in achado.evidence

    sem_root = maquina(tmp_path, SEGURO)
    sem_root.responder("sshd", "-T", saida=saida)
    assert rodar(sem_root, monkeypatch, CHECK).ids() == set()
    assert ("sshd", "-T") not in sem_root.executados


def test_sshd_t_que_falha_usa_os_arquivos(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sis = maquina(tmp_path, "X11Forwarding yes\n" + SEGURO, root=True)
    sis.responder("sshd", "-T", codigo=255, erro="sshd: no hostkeys available -- exiting.\n")
    resultado = rodar(sis, monkeypatch, CHECK)
    assert resultado.ids() == {X11}
    assert resultado.by_id(X11)[0].details["fonte"] == "arquivos"


def test_sshd_config_negado_fica_nao_verificado(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = maquina(tmp_path, INSEGURO)
    sis.negados.add("/etc/ssh/sshd_config")
    resultado = rodar(sis, monkeypatch, CHECK)
    assert resultado.ids() == set() and not resultado.passed
    assert any("não verificado" in linha for linha in resultado.logs)


def test_include_ilegivel_deixa_o_resultado_incerto(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = maquina(
        tmp_path, "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\nX11Forwarding no\n"
    )
    sis.negados.add("/etc/ssh/sshd_config.d")
    resultado = rodar(sis, monkeypatch, CHECK)
    # o que vem depois do arquivo ilegível pode ter sido definido nele: só indício, sem pontos fortes
    achado = resultado.by_id(ROOT)[0]
    assert achado.confidence is Confidence.TENTATIVE
    assert achado.details["arquivos_ilegiveis"] == ["/etc/ssh/sshd_config.d/*.conf"]
    assert not resultado.passed
    assert any("não verificado" in linha for linha in resultado.logs)


def test_valores_antes_do_arquivo_ilegivel_continuam_certos(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = maquina(tmp_path, "PermitRootLogin yes\nInclude /etc/ssh/sshd_config.d/*.conf\n")
    sis.negados.add("/etc/ssh/sshd_config.d")
    assert rodar(sis, monkeypatch, CHECK).by_id(ROOT)[0].confidence is Confidence.FIRM


def test_sem_servidor_ssh_nao_ha_o_que_avaliar(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # sshd_config de um pacote removido, sem o programa
    sis = base_segura(tmp_path)
    sis.arquivo("/etc/ssh/sshd_config", INSEGURO)
    resultado = rodar(sis, monkeypatch, CHECK)
    assert resultado.ids() == set() and not resultado.passed

    # programa sem nenhum arquivo de configuração
    sem_config = base_segura(tmp_path / "outra")
    sem_config.programa_instalado("sshd", pasta="/usr/sbin")
    assert rodar(sem_config, monkeypatch, CHECK).ids() == set()


def test_servico_parado_aparece_na_evidencia(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sis = maquina(tmp_path, "X11Forwarding yes\n" + SEGURO)
    sis.responder("systemctl", "is-active", "ssh", codigo=3, saida="inactive\n")
    sis.responder("systemctl", "is-active", "sshd", codigo=3, saida="inactive\n")
    sis.responder("systemctl", "is-active", "ssh.socket", codigo=3, saida="inactive\n")
    assert "parado" in rodar(sis, monkeypatch, CHECK).by_id(X11)[0].evidence


def test_leitor_expoe_configuracao_e_tokens(tmp_path: Path) -> None:
    sis = maquina(tmp_path, 'Banner "/etc/meu banner"\nMaxAuthTries 2 # x\n')
    config = linux_sshd.ler_arquivos(sis)
    assert config is not None
    assert config.valores["banner"].valor == "/etc/meu banner"
    assert config.efetivo("MAXAUTHTRIES").valor == "2"
    assert config.arquivos == ["/etc/ssh/sshd_config"]
    assert linux_sshd.tokens("   # comentário") == []
    assert linux_sshd.tokens("") == []
    assert linux_sshd.ler_arquivos(base_segura(tmp_path / "vazia")) is None
    sis.negados.add("/etc/ssh/sshd_config")
    with pytest.raises(AcessoNegado):
        linux_sshd.ler_arquivos(sis)
