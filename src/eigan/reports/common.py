"""Apoio comum aos relatórios: análise garantida, rótulos, links, nomes de pasta e textos.

Tudo que vem do alvo auditado (títulos, ativos, evidências, fatos) é tratado como
hostil: :func:`visible` expõe caracteres invisíveis que poderiam enganar o leitor
(ataques "Trojan Source" com controles de direção do texto) e :func:`web_link` só
transforma em link endereços ``http``/``https`` bem formados.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from collections.abc import Callable
from datetime import datetime
from typing import Any
from urllib.parse import quote, urlsplit

from ..core import fmt
from ..core.models import ScanResult, Severity
from ..core.redact import redact
from ..intel import scoring

SEVERITY_ORDER = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)
#: rótulo no plural para as contagens do veredito
SEVERITY_PLURAL = {
    Severity.CRITICAL: "Críticas",
    Severity.HIGH: "Altas",
    Severity.MEDIUM: "Médias",
    Severity.LOW: "Baixas",
    Severity.INFO: "Informativos",
}
BANDS = ("P1", "P2", "P3", "P4")
_BAND_TEXT = {label: text for _floor, label, text in scoring.PRIORITY_BANDS}
_BAND_TEXT["Info"] = "Informativo: sem ação obrigatória"

STATUS_LABEL = {
    "concluida": "Concluída",
    "cancelada": "Cancelada",
    "erro": "Terminou com erro",
    "em_andamento": "Em andamento",
}
STATUS_NOTE = {
    "cancelada": "A auditoria foi cancelada antes do fim: o resultado é parcial.",
    "erro": "A auditoria terminou com erro: o resultado pode estar incompleto.",
    "em_andamento": "A auditoria ainda estava em andamento: o resultado é parcial.",
}

# Controles invisíveis: C0/C1 (exceto tabulação e quebras de linha), marcas e
# isolamentos de direção (U+202A-202E, U+2066-2069), espaço de largura zero, BOM e
# substitutos soltos (nome de arquivo inválido no Linux: não existem em UTF-8).
_HIDDEN = re.compile(
    "[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u061c\u200b\u200e\u200f"
    "\u202a-\u202e\u2060-\u2064\u2066-\u2069\ud800-\udfff\ufeff]"
)
_ANCHOR_SAFE = re.compile(r"^[A-Za-z0-9._-]+$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_URL_UNSAFE = re.compile(r"[\s\x00-\x1f\x7f]")


def ensure_analysis(result: ScanResult) -> dict[str, Any]:
    """Devolve ``result.analysis``, calculando a análise se ela ainda não existir."""
    if not result.analysis:
        from ..intel.analysis import analyze

        analyze(result)
    return result.analysis


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list | tuple) else []


def as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def severity_of(value: Any) -> Severity:
    """Converte ``"high"``/``Severity`` em ``Severity``; desconhecido vira informativo."""
    try:
        return Severity.parse(value) if value else Severity.INFO
    except (ValueError, TypeError, KeyError):
        return Severity.INFO


def severity_view(value: Any) -> dict[str, str]:
    sev = severity_of(value)
    return {"value": sev.value, "label": sev.label}


def band_text(band: str) -> str:
    return _BAND_TEXT.get(band, "")


def band_view(band: Any, text: str = "") -> dict[str, str]:
    label = str(band) if str(band) in _BAND_TEXT else "Info"
    return {"value": label, "css": label.lower(), "text": text or band_text(label)}


def clip(text: str, limit: int) -> tuple[str, bool]:
    """Corta ``text`` em ``limit`` caracteres; devolve o texto e se houve corte."""
    if len(text) <= limit:
        return text, False
    return text[: max(0, limit - 1)].rstrip() + "…", True


def visible(text: str) -> str:
    """Troca caracteres invisíveis de controle por ``<U+202E>`` (o leitor vê que existem)."""
    return _HIDDEN.sub(lambda m: f"<U+{ord(m.group()):04X}>", text)


def deep_visible(value: Any) -> Any:
    """Aplica :func:`visible` em todo texto de uma estrutura de dicionários e listas."""
    if isinstance(value, str):
        return visible(value)
    if isinstance(value, dict):
        return {key: deep_visible(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [deep_visible(item) for item in value]
    return value


def deep_redact(value: Any) -> Any:
    """Aplica :func:`~eigan.core.redact.redact` em todo texto de dicionários e listas."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {str(key): deep_redact(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [deep_redact(item) for item in value]
    if isinstance(value, set | frozenset):
        return sorted((deep_redact(item) for item in value), key=str)
    return value


_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s?#@]*@")
_AUTH_TOKEN = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,}")
_URL_SECRET_PARAM = re.compile(
    r"(?i)([?&;](?:[a-z0-9_.-]*(?:token|secret|passw(?:or)?d|pwd|apikey|api_key|key|auth|sig))=)[^&\s#\"'<>]+"
)


def scrub(text: str) -> str:
    """Mascara segredos em texto vindo do alvo (título, ativo, nota...).

    Além do :func:`~eigan.core.redact.redact`, tira o usuário e a senha de URLs
    (``https://usuario:senha@host``), tokens ``Bearer``/``Basic`` e parâmetros de URL
    com nome de segredo (``?token=...``).
    """
    text = _AUTH_TOKEN.sub(r"\g<1> ***", text)  # antes do redact, que troca só a palavra Bearer
    text = redact(text)
    text = _USERINFO.sub(r"\1***@", text)
    text = _AUTH_TOKEN.sub(r"\1 ***", text)
    return _URL_SECRET_PARAM.sub(r"\1***", text)


def deep_scrub(value: Any) -> Any:
    """:func:`scrub` em todo texto de uma estrutura; ``nan``/``inf`` viram ``None`` (JSON válido)."""
    if isinstance(value, str):
        return scrub(value)
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, dict):
        return {str(key): deep_scrub(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [deep_scrub(item) for item in value]
    if isinstance(value, set | frozenset):
        return sorted((deep_scrub(item) for item in value), key=str)
    return value


def target_slug(target: str) -> str:
    """Nome de pasta a partir do alvo, sem usuário, senha, caminho nem parâmetros de URL."""
    plain = _USERINFO.sub(r"\1", target.strip())
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", plain):
        plain = re.split(r"[/?#]", plain.split("://", 1)[1], maxsplit=1)[0]
    return slugify(plain)


def json_text(data: Any, default: Callable[[Any], Any] | None = None) -> str:
    """JSON legível que sempre grava em UTF-8 e não esconde nada de quem abre o arquivo.

    Caracteres invisíveis e substitutos soltos (que o UTF-8 não representa) saem como
    ``\\u202e``: o arquivo continua válido e o texto volta igual na leitura.
    """
    text = json.dumps(data, ensure_ascii=False, indent=2, default=default, allow_nan=False)
    return _HIDDEN.sub(lambda m: f"\\u{ord(m.group()):04x}", text) + "\n"


def slugify(text: str, *, limit: int = 50, fallback: str = "alvo") -> str:
    """ASCII minúsculo com ``[a-z0-9-]`` (para nomes de pasta)."""
    plain = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")
    plain = re.sub(r"^[a-z][a-z0-9+.-]*://", "", plain.strip().lower())
    slug = re.sub(r"[^a-z0-9]+", "-", plain).strip("-")
    slug = slug[:limit].strip("-")
    return slug or fallback


def anchor(prefix: str, text: str) -> str:
    """Âncora HTML estável e única: ``tipo-web.hsts.ausente`` (com resumo se precisar limpar)."""
    if _ANCHOR_SAFE.match(text) and len(text) <= 120:
        return f"{prefix}-{text}"
    digest = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:8]
    return f"{prefix}-{slugify(text, limit=60, fallback='item')}-{digest}"


def local_moment(value: str) -> datetime | None:
    moment = fmt.parse_iso(value)
    if moment is None:
        return None
    return moment.astimezone() if moment.tzinfo is not None else moment


def time_of_day(value: str) -> str:
    moment = local_moment(value)
    return moment.strftime("%H:%M:%S") if moment else value


def points(n: int) -> str:
    return fmt.plural(n, "ponto", "pontos")


# -- links --------------------------------------------------------------------------------


def is_web_url(url: str) -> bool:
    """``http``/``https`` com host e sem espaços ou controles (seguro para virar link)."""
    if not url or _URL_UNSAFE.search(url) or _HIDDEN.search(url):
        return False
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    return parts.scheme.lower() in ("http", "https") and bool(parts.hostname)


def web_link(url: str) -> dict[str, str]:
    """Só ``http(s)`` vira link; qualquer outro esquema (``javascript:``...) fica como texto."""
    return {"url": url if is_web_url(url) else "", "text": url}


def cve_url(cve: str) -> str:
    """Página do CVE no NVD (vazio se o identificador não tiver o formato de CVE)."""
    value = cve.strip().upper()
    if not _CVE.match(value):
        return ""
    return f"https://nvd.nist.gov/vuln/detail/{quote(value, safe='-')}"


def cwe_url(cwe: str) -> str:
    number = cwe.upper().removeprefix("CWE-").strip()
    if not number.isdigit():
        return ""
    return f"https://cwe.mitre.org/data/definitions/{number}.html"
