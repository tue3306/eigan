"""Saída de terminal: UTF-8 no Windows, cores ANSI só quando o terminal aceita."""

from __future__ import annotations

import os
import shutil
import sys
import textwrap
from typing import TextIO

SEVERITY_COLOR = {
    "critical": "1;31",
    "high": "31",
    "medium": "33",
    "low": "36",
    "info": "2",
}
GRADE_COLOR = {"A+": "32", "A": "32", "B": "32", "C": "33", "D": "31", "E": "31", "F": "1;31"}


def prepare_streams() -> None:
    """Garante UTF-8 na saída (o console do Windows usa outra página de código)."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                pass
    if sys.platform == "win32":
        _enable_windows_vt()


def _enable_windows_vt() -> None:
    if sys.platform != "win32":  # o mypy em Linux não conhece ctypes.windll
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:  # noqa: BLE001 — sem VT, a saída só fica sem cores
        pass


def use_color(stream: TextIO | None = None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR") or os.environ.get("EIGAN_SEM_CORES"):
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


class Console:
    def __init__(self, stream: TextIO | None = None, *, color: bool | None = None) -> None:
        self.stream = stream or sys.stdout
        self.color = use_color(self.stream) if color is None else color

    @property
    def width(self) -> int:
        return max(60, min(110, shutil.get_terminal_size((100, 24)).columns))

    def paint(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.color and code else text

    def bold(self, text: str) -> str:
        return self.paint(text, "1")

    def dim(self, text: str) -> str:
        return self.paint(text, "2")

    def severity(self, text: str, severity: str) -> str:
        return self.paint(text, SEVERITY_COLOR.get(severity, ""))

    def grade(self, text: str, grade: str) -> str:
        return self.paint(text, GRADE_COLOR.get(grade, ""))

    def line(self, text: str = "") -> None:
        print(text, file=self.stream, flush=True)

    def wrap(self, text: str, indent: str = "", first: str | None = None) -> None:
        if not text:
            return
        width = self.width
        for index, paragraph in enumerate(text.split("\n")):
            lead = first if (first is not None and index == 0) else indent
            wrapped = textwrap.fill(
                paragraph,
                width=width,
                initial_indent=lead,
                subsequent_indent=indent,
                break_long_words=True,
                break_on_hyphens=False,
            )
            self.line(wrapped if paragraph else "")

    def rule(self, title: str = "") -> None:
        if title:
            self.line(self.bold(title))
        else:
            self.line(self.dim("─" * min(self.width, 80)))
