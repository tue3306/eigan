"""Gera o executável do EIGAN para o sistema atual (Windows ou Linux) e o testa.

Uso:  python packaging/build.py [--sem-teste]

Saída em ``dist/``: ``eigan-<versão>-<sistema>-<arquitetura>[.exe]`` e o ``.sha256``.
O teste de fumaça roda o executável gerado: versão, uma auditoria de pasta com
relatório JSON e a API do painel com token.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from eigan import __version__  # noqa: E402

WINDOWS_VERSION = """# UTF-8
VSVersionInfo(
  ffi=FixedFileInfo(filevers=({v}, 0), prodvers=({v}, 0), mask=0x3f, flags=0x0, OS=0x40004,
                    fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('041604B0', [
      StringStruct('CompanyName', 'EIGAN'),
      StringStruct('FileDescription', 'EIGAN - auditor de segurança blue team'),
      StringStruct('FileVersion', '{dotted}'),
      StringStruct('InternalName', 'eigan'),
      StringStruct('OriginalFilename', 'eigan.exe'),
      StringStruct('ProductName', 'EIGAN'),
      StringStruct('ProductVersion', '{dotted}'),
      StringStruct('LegalCopyright', 'Apache-2.0')])]),
    VarFileInfo([VarStruct('Translation', [1046, 1200])])
  ]
)
"""


def run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    print("$", " ".join(cmd), flush=True)
    return subprocess.run(cmd, check=True, text=True, **kwargs)  # type: ignore[call-overload]


def write_version_file() -> None:
    parts = [int(p) for p in __version__.split(".")[:3]] + [0]
    target = ROOT / "build" / "versao-windows.txt"
    target.parent.mkdir(parents=True, exist_ok=True)
    text = WINDOWS_VERSION.format(v=", ".join(str(p) for p in parts[:3]), dotted=__version__)
    target.write_text(text, encoding="utf-8")


def ensure_icon() -> None:
    if (ROOT / "packaging" / "eigan.ico").exists():
        return
    run([sys.executable, str(ROOT / "packaging" / "make_icon.py")])


def latest_executable() -> Path:
    windows = sys.platform == "win32"
    candidates = [
        c
        for c in (ROOT / "dist").glob(f"eigan-{__version__}-*")
        if c.is_file() and c.name.endswith(".exe") == windows and not c.name.endswith(".sha256")
    ]
    if not candidates:
        raise SystemExit("Executável não encontrado em dist/.")
    return max(candidates, key=lambda p: p.stat().st_mtime)


def build() -> Path:
    ensure_icon()
    write_version_file()
    run(
        [
            sys.executable,
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            "--distpath",
            str(ROOT / "dist"),
            "--workpath",
            str(ROOT / "build" / "pyinstaller"),
            str(ROOT / "packaging" / "eigan.spec"),
        ],
        cwd=ROOT,
    )
    exe = latest_executable()
    digest = hashlib.sha256(exe.read_bytes()).hexdigest()
    (exe.parent / f"{exe.name}.sha256").write_text(f"{digest}  {exe.name}\n", encoding="utf-8")
    print(f"Gerado: {exe} ({exe.stat().st_size / 1_048_576:.1f} MB)")
    return exe


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _stop(process: subprocess.Popen[str]) -> None:
    """Para o painel e o processo filho do executável (o PyInstaller usa dois no Windows)."""
    try:
        process.wait(timeout=15)
        return
    except subprocess.TimeoutExpired:
        pass
    if sys.platform == "win32":
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(process.pid)], capture_output=True)
    else:
        process.kill()
    process.wait(timeout=10)


def smoke(exe: Path) -> None:
    """Testa o executável de verdade, isolado num diretório de dados temporário."""
    with tempfile.TemporaryDirectory(prefix="eigan-fumaca-", ignore_cleanup_errors=True) as tmp:
        env = {**os.environ, "EIGAN_HOME": str(Path(tmp) / "dados"), "NO_COLOR": "1"}
        out = run([str(exe), "--versao"], capture_output=True, env=env).stdout
        assert f"EIGAN {__version__}" in out, out

        project = Path(tmp) / "projeto"
        project.mkdir()
        (project / "app.py").write_text("DEBUG = True\n", encoding="utf-8")
        result = run(
            [
                str(exe),
                "auditar",
                str(project),
                "--tipo",
                "projeto",
                "--json",
                "--formatos",
                "html,pdf,json,sarif,csv",
            ],
            capture_output=True,
            env=env,
        )
        data = json.loads(result.stdout)
        assert data["status"] == "concluida", data["status"]
        assert data["analysis"]["posture"]["grade"], "análise ausente"
        reports = list((Path(tmp) / "dados" / "relatorios").rglob("eigan-*"))
        assert len(reports) == 5, reports

        port = _free_port()
        base = f"http://127.0.0.1:{port}"
        panel = subprocess.Popen(
            [str(exe), "painel", "--porta", str(port), "--sem-navegador"],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        try:
            html = ""
            for _ in range(60):
                try:
                    with urllib.request.urlopen(f"{base}/", timeout=2) as resp:
                        html = resp.read().decode("utf-8")
                    break
                except OSError:
                    time.sleep(0.5)
            assert 'name="eigan-token"' in html, "painel não respondeu"
            token = html.split('name="eigan-token" content="', 1)[1].split('"', 1)[0]
            headers = {"X-EIGAN-Token": token}
            request = urllib.request.Request(f"{base}/api/info", headers=headers)
            with urllib.request.urlopen(request, timeout=5) as resp:
                info = json.loads(resp.read().decode("utf-8"))
            assert info["version"] == __version__ and info["checks"] > 0, info
            # Encerra pelo próprio painel (o mesmo botão "Encerrar" da tela Sobre).
            request = urllib.request.Request(
                f"{base}/api/encerrar",
                data=b"{}",
                headers={**headers, "Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5) as resp:
                assert resp.status == 202, resp.status
        finally:
            _stop(panel)
    print("Teste de fumaça do executável: OK")


def main() -> None:
    parser = argparse.ArgumentParser(description="Gera e testa o executável do EIGAN.")
    parser.add_argument("--sem-teste", action="store_true", help="não roda o teste de fumaça")
    parser.add_argument(
        "--so-teste", action="store_true", help="só testa o executável já gerado em dist/"
    )
    args = parser.parse_args()
    exe = latest_executable() if args.so_teste else build()
    if not args.sem_teste:
        smoke(exe)


if __name__ == "__main__":
    main()
