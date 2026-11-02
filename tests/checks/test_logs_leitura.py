"""Leitura de logs: pasta, .gz, UTF-16, limites e arquivos binários."""

from __future__ import annotations

import gzip
from pathlib import Path

from fakes_logs import fato_logs, ssh_falha
from helpers import run_check

from eigan.core.settings import Settings

ID = "logs.analise"


def _brute(n: int, ip: str = "203.0.113.5") -> str:
    return "\n".join(ssh_falha(i, ip) for i in range(n)) + "\n"


def test_arquivo_simples(tmp_path: Path) -> None:
    arq = tmp_path / "auth.log"
    arq.write_text(_brute(12), encoding="utf-8")
    out = run_check(ID, fato_logs(arq))
    assert "logs.ssh.forca_bruta" in out.ids()


def test_gzip_detectado_pela_assinatura_e_nao_pela_extensao(tmp_path: Path) -> None:
    arq = tmp_path / "auth.log.1"
    arq.write_bytes(gzip.compress(_brute(12).encode()))
    out = run_check(ID, fato_logs(arq))
    assert "logs.ssh.forca_bruta" in out.ids()


def test_utf16_com_bom(tmp_path: Path) -> None:
    arq = tmp_path / "auth.log"
    arq.write_bytes(_brute(12).encode("utf-16"))
    assert "logs.ssh.forca_bruta" in run_check(ID, fato_logs(arq)).ids()


def test_pasta_recursiva_e_arquivo_binario_ignorado(tmp_path: Path) -> None:
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "secure").write_text(_brute(12), encoding="utf-8")
    (tmp_path / "btmp").write_bytes(b"\x00\x01\x02" * 100)
    (tmp_path / "dados.log").write_bytes(b"\x00\x01\xff\x00\x02" * 200)
    out = run_check(ID, fato_logs(tmp_path))
    assert "logs.ssh.forca_bruta" in out.ids()
    assert any("binário" in linha for linha in out.logs)


def test_limite_de_linhas_marca_resultado_parcial(tmp_path: Path) -> None:
    arq = tmp_path / "auth.log"
    arq.write_text(_brute(50), encoding="utf-8")
    out = run_check(ID, fato_logs(arq), settings=Settings(max_log_lines=5))
    assert any("parcial" in linha for linha in out.logs)
    assert not out.passed


def test_formato_desconhecido_nao_gera_achado_nem_ponto_forte(tmp_path: Path) -> None:
    arq = tmp_path / "app.log"
    arq.write_text("hello world\nsegunda linha\n", encoding="utf-8")
    out = run_check(ID, fato_logs(arq))
    assert not out.findings and not out.passed
    assert any("nenhum formato" in linha for linha in out.logs)


def test_caminho_inexistente_nao_quebra(tmp_path: Path) -> None:
    out = run_check(ID, fato_logs(tmp_path / "nao_existe"))
    assert not out.findings


def test_gzip_corrompido_vira_aviso(tmp_path: Path) -> None:
    arq = tmp_path / "auth.log.2"
    arq.write_bytes(gzip.compress(_brute(12).encode())[:-20])
    out = run_check(ID, fato_logs(arq))
    assert isinstance(out.logs, list)  # não levanta exceção
