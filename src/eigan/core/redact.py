"""Mascaramento de segredos em evidências, relatórios e telas.

Segredos encontrados no alvo (chaves, tokens, senhas) nunca aparecem inteiros:
mostramos o começo — suficiente para identificar e revogar — e o tamanho.
"""

from __future__ import annotations

import re

_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
    re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,255}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
    re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{20,}\b"),
    re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
    re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
    re.compile(r"\bhf_[A-Za-z0-9]{34,}\b"),
    re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_\-]{20,}\b"),
]

# chave=valor com nome sugestivo de segredo
_KV = re.compile(
    r"(?i)\b([A-Za-z0-9_.\-]*(?:password|passwd|pwd|senha|secret|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|auth)[A-Za-z0-9_.\-]*)(\s*[:=]\s*|\"\s*:\s*\")"
    r"([\"']?)([^\s\"'<>,;&]{4,})"
)


def mask(value: str, keep: int = 4) -> str:
    """``abcd…(40 caracteres)`` — o início ajuda a localizar e revogar o segredo."""
    value = value.strip()
    if len(value) <= keep:
        return "•" * len(value)
    return f"{value[:keep]}…({len(value)} caracteres)"


def redact(text: str) -> str:
    if not text:
        return text
    for pattern in _PATTERNS:
        text = pattern.sub(lambda m: mask(m.group(0)), text)

    def _kv(m: re.Match[str]) -> str:
        value = m.group(4)
        if value.startswith(("$", "{", "%", "<")) or value.lower() in (
            "true",
            "false",
            "null",
            "none",
        ):
            return m.group(0)
        if "…(" in value:
            return m.group(0)
        return f"{m.group(1)}{m.group(2)}{m.group(3)}{mask(value)}"

    return _KV.sub(_kv, text)
