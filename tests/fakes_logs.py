"""Geradores de linhas de log para os testes da família logs (tudo sintético, sem rede)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from eigan.core.models import Fact

BASE = datetime(2026, 11, 1, 10, 0, 0, tzinfo=UTC)
MESES = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def momento(segundos: int) -> datetime:
    return BASE + timedelta(seconds=segundos)


def syslog(segundos: int, programa: str, mensagem: str, host: str = "srv01") -> str:
    t = momento(segundos)
    return f"{MESES[t.month - 1]} {t.day:2d} {t:%H:%M:%S} {host} {programa}[1234]: {mensagem}"


def ssh_falha(segundos: int, ip: str, usuario: str = "root") -> str:
    return syslog(segundos, "sshd", f"Failed password for {usuario} from {ip} port 4242 ssh2")


def ssh_aceito(segundos: int, ip: str, usuario: str = "root", metodo: str = "password") -> str:
    return syslog(segundos, "sshd", f"Accepted {metodo} for {usuario} from {ip} port 4243 ssh2")


def clf(
    segundos: int,
    ip: str,
    uri: str,
    status: int = 200,
    agente: str = "Mozilla/5.0",
    tamanho: int = 512,
) -> str:
    t = momento(segundos)
    data = f"{t.day:02d}/{MESES[t.month - 1]}/{t.year}:{t:%H:%M:%S} +0000"
    return f'{ip} - - [{data}] "GET {uri} HTTP/1.1" {status} {tamanho} "-" "{agente}"'


def w3c(linhas: list[tuple[int, str, str, str, int]]) -> str:
    """Log IIS: (segundos, ip, caminho, consulta, status)."""
    cab = [
        "#Software: Microsoft Internet Information Services 10.0",
        "#Version: 1.0",
        "#Fields: date time c-ip cs-method cs-uri-stem cs-uri-query sc-status sc-bytes cs(User-Agent)",
    ]
    corpo = []
    for seg, ip, caminho, consulta, status in linhas:
        t = momento(seg)
        corpo.append(
            f"{t:%Y-%m-%d %H:%M:%S} {ip} GET {caminho} {consulta or '-'} {status} 900 Mozilla/5.0"
        )
    return "\n".join([*cab, *corpo]) + "\n"


def evento_xml(
    id: int,
    segundos: int,
    dados: dict[str, str],
    *,
    provedor: str = "Microsoft-Windows-Security-Auditing",
    computador: str = "PC01.corp.local",
) -> str:
    t = momento(segundos)
    itens = "".join(f"<Data Name='{k}'>{v}</Data>" for k, v in dados.items())
    return (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
        f"<Provider Name='{provedor}'/><EventID>{id}</EventID>"
        f"<TimeCreated SystemTime='{t:%Y-%m-%dT%H:%M:%S}.000000000Z'/>"
        f"<Computer>{computador}</Computer></System><EventData>{itens}</EventData></Event>"
    )


def fato_logs(caminho: Path) -> Fact:
    return Fact("logs.source", str(caminho), {"path": str(caminho), "label": str(caminho)})
