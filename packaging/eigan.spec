# -*- mode: python ; coding: utf-8 -*-
# Spec do PyInstaller: um único executável de console com o painel, a base de
# conhecimento e os relatórios embutidos. Gere com:  python packaging/build.py

import platform
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = Path(SPECPATH).resolve().parent  # noqa: F821 — SPECPATH é injetado pelo PyInstaller
sys.path.insert(0, str(ROOT / "src"))

from eigan import __version__  # noqa: E402

SYSTEM = {"win32": "windows", "darwin": "macos"}.get(sys.platform, "linux")
MACHINE = platform.machine().lower()
ARCH = {"amd64": "x64", "x86_64": "x64", "arm64": "arm64", "aarch64": "arm64"}.get(MACHINE, MACHINE)
NAME = f"eigan-{__version__}-{SYSTEM}-{ARCH}"

datas = collect_data_files("eigan")
hiddenimports = collect_submodules("eigan") + collect_submodules("dns")

a = Analysis(
    [str(ROOT / "packaging" / "entry.py")],
    pathex=[str(ROOT / "src")],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["pytest", "mypy", "ruff", "IPython", "numpy", "pandas", "matplotlib"],
    noarchive=False,
)
pyz = PYZ(a.pure)

icon = None
version_file = None
if SYSTEM == "windows":
    icon = str(ROOT / "packaging" / "eigan.ico")
    version_file = str(ROOT / "build" / "versao-windows.txt")

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name=NAME,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=True,
    icon=icon,
    version=version_file,
)
