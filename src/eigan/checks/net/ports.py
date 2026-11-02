"""Catálogo de portas (``eigan/data/net_ports.json``) e escolha das portas por perfil.

O catálogo é uma lista ordenada por prioridade de auditoria: as 100 primeiras
formam o perfil ``top100``, as 300 primeiras o ``top300`` e ``todas`` soma a
lista inteira às portas 1-1024. O usuário também pode informar uma lista
explícita (``"22,80,443"`` ou faixas ``"8000-8100"``).
"""

from __future__ import annotations

from functools import lru_cache

from ...data import load_json

#: portas usadas na descoberta de hosts de uma faixa (rápida, só as mais comuns)
DISCOVERY_PORTS = (22, 80, 443, 445, 3389, 8080)
#: limite de portas de uma lista explícita (evita varreduras acidentais de 65535 portas)
MAX_EXPLICIT_PORTS = 65_535


@lru_cache(maxsize=1)
def catalog() -> tuple[tuple[int, str], ...]:
    """Pares (porta, serviço) na ordem de prioridade, sem repetição."""
    try:
        raw = load_json("net_ports.json")
    except (OSError, ValueError):
        return ()
    seen: set[int] = set()
    items: list[tuple[int, str]] = []
    for entry in raw.get("portas", []) if isinstance(raw, dict) else []:
        try:
            port, name = int(entry[0]), str(entry[1])
        except (TypeError, ValueError, IndexError):
            continue
        if 0 < port < 65536 and port not in seen:
            seen.add(port)
            items.append((port, name))
    return tuple(items)


@lru_cache(maxsize=1)
def _names() -> dict[int, str]:
    return dict(catalog())


def service_name(port: int) -> str:
    """Nome provável do serviço pela porta (só uma dica; a confirmação vem das sondas)."""
    return _names().get(port, "")


def parse_port_list(text: str) -> list[int]:
    """Interpreta ``"22,80,443"`` e faixas ``"8000-8010"``. Ignora itens inválidos."""
    ports: list[int] = []
    seen: set[int] = set()
    for part in text.replace(";", ",").replace(" ", ",").split(","):
        part = part.strip()
        if not part:
            continue
        start_text, sep, end_text = part.partition("-")
        try:
            start = int(start_text)
            end = int(end_text) if sep else start
        except ValueError:
            continue
        if start > end:
            start, end = end, start
        for port in range(max(1, start), min(65535, end) + 1):
            if port not in seen:
                seen.add(port)
                ports.append(port)
            if len(ports) >= MAX_EXPLICIT_PORTS:
                return ports
    return ports


def explicit_list_problems(profile: str) -> str:
    """Aviso quando a lista explícita de portas tem itens inválidos (ou nenhum válido)."""
    name = (profile or "").strip().lower()
    if name in ("top100", "top300", "todas", ""):
        return ""
    valid = parse_port_list(name)
    if not valid:
        return (
            f"Lista de portas '{profile}' inválida: usando o perfil padrão (300 portas). "
            "Use 'top100', 'top300', 'todas' ou números como '22,80,8000-8010'."
        )
    items = [p for p in name.replace(";", ",").replace(" ", ",").split(",") if p.strip()]
    ignored = [p for p in items if not _valid_item(p)]
    if ignored:
        return f"Itens da lista de portas ignorados por serem inválidos: {', '.join(ignored[:10])}."
    return ""


def _valid_item(item: str) -> bool:
    start, sep, end = item.strip().partition("-")
    try:
        low = int(start)
        high = int(end) if sep else low
    except ValueError:
        return False
    return 1 <= min(low, high) and max(low, high) <= 65535


def ports_for(profile: str) -> list[int]:
    """Portas a varrer para o perfil de portas (``top100``, ``top300``, ``todas`` ou lista)."""
    ordered = [port for port, _ in catalog()]
    name = (profile or "").strip().lower()
    if name == "top100":
        return ordered[:100]
    if name == "top300":
        return ordered[:300]
    if name == "todas":
        known = set(ordered)
        return ordered + [p for p in range(1, 1025) if p not in known]
    explicit = parse_port_list(name)
    return explicit or ordered[:300]
