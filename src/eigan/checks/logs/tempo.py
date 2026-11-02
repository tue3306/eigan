"""Datas e horas dos formatos de log, convertidas para segundos desde a época.

Cada função devolve ``None`` quando o texto não é uma data válida: linha sem data
continua contando, só não entra nas janelas de tempo. Datas sem fuso (syslog clássico,
exportações do Visualizador de Eventos) são tratadas como se fossem UTC, o que mantém a
comparação entre elas correta.
"""

from __future__ import annotations

import calendar
import re
from datetime import UTC, datetime

_MESES = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}
#: tolerância para o relógio do arquivo: data "futura" além disto é do ano anterior
_FOLGA_ANO_S = 2 * 86_400

_CLF = re.compile(
    r"^(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?: ([+-])(\d{2})(\d{2}))?"
)
_ISO = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,]\d+)?"
    r"(?:\s?(Z|[+-]\d{2}:?\d{2}))?"
)
_NUMERICA = re.compile(
    r"^(\d{1,2})/(\d{1,2})/(\d{4})[ ,]+(\d{1,2}):(\d{2})(?::(\d{2}))?(?:\s*([AaPp])\.?\s?[Mm]\.?)?"
)
_DATA_NUMERICA = re.compile(r"\b(\d{1,2})/(\d{1,2})/\d{4}\b")


def _segundos(ano: int, mes: int, dia: int, hora: int, minuto: int, segundo: int) -> float | None:
    if not (1 <= mes <= 12 and 1 <= dia <= 31 and hora <= 24 and minuto <= 59 and segundo <= 60):
        return None
    if not 1970 <= ano <= 2100:
        return None
    try:
        return float(calendar.timegm((ano, mes, dia, hora, minuto, segundo)))
    except (ValueError, OverflowError):
        return None


def de_syslog(
    mes: str, dia: int, hora: int, minuto: int, segundo: int, referencia: float
) -> float | None:
    """Syslog clássico não traz o ano: vem da data do arquivo (``referencia``)."""
    numero = _MESES.get(mes.lower())
    if numero is None:
        return None
    ano = datetime.fromtimestamp(referencia, UTC).year
    valor = _segundos(ano, numero, dia, hora, minuto, segundo)
    if valor is not None and valor > referencia + _FOLGA_ANO_S:
        return _segundos(ano - 1, numero, dia, hora, minuto, segundo)
    return valor


def de_clf(texto: str) -> float | None:
    """``10/Oct/2000:13:55:36 -0700`` (Apache e nginx)."""
    achado = _CLF.match(texto)
    if achado is None:
        return None
    dia, mes, ano, hora, minuto, segundo, sinal, fuso_h, fuso_m = achado.groups()
    numero = _MESES.get(mes.lower())
    if numero is None:
        return None
    valor = _segundos(int(ano), numero, int(dia), int(hora), int(minuto), int(segundo))
    if valor is not None and sinal:
        deslocamento = int(fuso_h) * 3600 + int(fuso_m) * 60
        valor += -deslocamento if sinal == "+" else deslocamento
    return valor


def de_iso(texto: str) -> float | None:
    """ISO 8601 com qualquer precisão (rsyslog, journalctl, ``SystemTime`` do Windows)."""
    achado = _ISO.match(texto.strip())
    if achado is None:
        return None
    valor = _segundos(*(int(parte) for parte in achado.groups()[:6]))
    fuso = achado.group(7)
    if valor is not None and fuso and fuso != "Z":
        numeros = fuso[1:].replace(":", "")
        deslocamento = int(numeros[:2]) * 3600 + int(numeros[2:]) * 60
        valor += -deslocamento if fuso[0] == "+" else deslocamento
    return valor


def de_w3c(data: str, hora: str) -> float | None:
    """Campos ``date`` e ``time`` do W3C (IIS grava em UTC)."""
    return de_iso(f"{data} {hora}")


def dia_primeiro(amostra: str) -> bool:
    """Descobre a ordem de ``02/11/2026`` olhando o começo do arquivo.

    Componente acima de 12 decide sozinho. Sem isso, AM/PM indica o formato dos EUA
    (mês primeiro) e relógio de 24 horas indica o formato do Brasil (dia primeiro).
    """
    for primeiro, segundo in _DATA_NUMERICA.findall(amostra):
        if int(primeiro) > 12:
            return True
        if int(segundo) > 12:
            return False
    return re.search(r"\b\d{1,2}:\d{2}(?::\d{2})?\s*[AaPp]\.?\s?[Mm]\b", amostra) is None


def de_numerica(texto: str, *, dia_antes: bool) -> float | None:
    """``11/2/2026 10:02:11 AM`` ou ``02/11/2026 10:02:11`` (exportações do Windows)."""
    bruto = texto.strip()
    if "-" in bruto[:5]:
        return de_iso(bruto)
    achado = _NUMERICA.match(bruto)
    if achado is None:
        return de_iso(bruto)
    primeiro, segundo, ano, hora, minuto, seg, periodo = achado.groups()
    dia, mes = (primeiro, segundo) if dia_antes else (segundo, primeiro)
    hora_24 = int(hora)
    if periodo:
        hora_24 = hora_24 % 12 + (12 if periodo.lower() == "p" else 0)
    return _segundos(int(ano), int(mes), int(dia), hora_24, int(minuto), int(seg or 0))


def formatar(valor: float | None) -> str:
    """Segundos para ``2026-11-02 10:02:11`` (vazio quando a linha não tinha data)."""
    if valor is None:
        return ""
    return datetime.fromtimestamp(valor, UTC).strftime("%Y-%m-%d %H:%M:%S")
