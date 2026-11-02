"""Formatação de textos em português (plural, listas, datas e durações)."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime


def plural(n: int, singular: str, plural_form: str) -> str:
    return f"{n} {singular if n == 1 else plural_form}"


def join_pt(items: Iterable[str]) -> str:
    """``["a", "b", "c"]`` → ``"a, b e c"``."""
    values = [i for i in items if i]
    if not values:
        return ""
    if len(values) == 1:
        return values[0]
    return ", ".join(values[:-1]) + " e " + values[-1]


def duration(seconds: float) -> str:
    seconds = max(0.0, float(seconds))
    if seconds < 1:
        return "menos de 1 s"
    if seconds < 60:
        return f"{int(round(seconds))} s"
    minutes, secs = divmod(int(round(seconds)), 60)
    if minutes < 60:
        return f"{minutes} min {secs} s" if secs else f"{minutes} min"
    hours, minutes = divmod(minutes, 60)
    return f"{hours} h {minutes} min" if minutes else f"{hours} h"


def parse_iso(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def date_time(value: str) -> str:
    """ISO 8601 → ``01/11/2026 14:05`` no fuso local."""
    moment = parse_iso(value)
    if moment is None:
        return value or ""
    if moment.tzinfo is not None:
        moment = moment.astimezone()
    return moment.strftime("%d/%m/%Y %H:%M")


def date_only(value: str) -> str:
    moment = parse_iso(value)
    if moment is None:
        return value or ""
    if moment.tzinfo is not None:
        moment = moment.astimezone()
    return moment.strftime("%d/%m/%Y")
