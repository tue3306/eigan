"""Apoio aos testes de código: projetos sintéticos, índice do git e tokens de teste.

Os tokens são **montados em tempo de execução** a partir de um gerador com semente
fixa: nenhum valor com formato de credencial fica escrito no código-fonte dos testes
(nem dispara a proteção de push do GitHub, nem o próprio ``code.secrets`` do EIGAN).
"""

from __future__ import annotations

import hashlib
import random
import string
import struct
from collections.abc import Iterable
from pathlib import Path

from eigan.core.models import Fact

ALNUM = string.ascii_letters + string.digits
HEX_LOWER = "0123456789abcdef"
HEX_ANY = HEX_LOWER + "ABCDEF"
BASE32_UP = string.ascii_uppercase + "234567"
BASE64ISH = ALNUM + "+/"
URLSAFE = ALNUM + "-_"


def random_text(size: int, alphabet: str = ALNUM, *, seed: str = "eigan") -> str:
    """Texto pseudoaleatório reprodutível (com alta entropia)."""
    rng = random.Random(f"{seed}:{size}:{alphabet}")
    return "".join(rng.choice(alphabet) for _ in range(size))


def joined(*parts: str) -> str:
    """Junta pedaços: deixa claro que o valor só existe em tempo de execução."""
    return "".join(parts)


def write_tree(root: Path, files: dict[str, str | bytes]) -> Path:
    """Cria os arquivos (caminhos com ``/``) dentro de ``root``."""
    for rel, content in files.items():
        path = root.joinpath(*rel.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8", newline="\n")
    return root


def project_fact(root: Path) -> Fact:
    return Fact("project", str(root), {"path": str(root), "label": str(root)})


def manifest_fact(root: Path, rel: str) -> Fact:
    path = root.joinpath(*rel.split("/"))
    return Fact(
        "code.manifest",
        str(path),
        {"path": str(path), "rel": rel, "project": str(root), "label": rel},
    )


def _pad_to_eight(entry: bytes, name_length: int, fixed: int) -> bytes:
    size = ((fixed + name_length) // 8 + 1) * 8
    return entry + b"\x00" * (size - len(entry))


def _index_entry_fixed(name_length: int, extended: bool = False) -> bytes:
    flags = min(name_length, 0xFFF) | (0x4000 if extended else 0)
    fixed = struct.pack(">10I", 0, 0, 0, 0, 0, 0, 0o100644, 0, 0, 0)
    return fixed + b"\x11" * 20 + struct.pack(">H", flags)


def index_bytes(names: Iterable[str], *, version: int = 2, extensions: bytes = b"") -> bytes:
    """Bytes de um ``.git/index`` com os caminhos dados (formatos 2, 3 e 4)."""
    ordered = sorted(names)
    out = bytearray(b"DIRC" + struct.pack(">II", version, len(ordered)))
    previous = b""
    for text in ordered:
        name = text.encode("utf-8")
        if version == 4:
            common = 0
            for a, b in zip(previous, name, strict=False):
                if a != b:
                    break
                common += 1
            strip = len(previous) - common
            out += _index_entry_fixed(len(name))
            out += _varint(strip) + name[common:] + b"\x00"
            previous = name
        else:
            extended = version == 3
            entry = _index_entry_fixed(len(name), extended)
            fixed = 62
            if extended:
                entry += b"\x00\x00"
                fixed = 64
            out += _pad_to_eight(entry + name, len(name), fixed)
    out += extensions
    out += hashlib.sha1(bytes(out), usedforsecurity=False).digest()
    return bytes(out)


def _varint(value: int) -> bytes:
    """Inteiro de tamanho variável do formato do git (índice v4)."""
    chunks = [value & 0x7F]
    value >>= 7
    while value:
        value -= 1
        chunks.append(0x80 | (value & 0x7F))
        value >>= 7
    return bytes(reversed(chunks))


def init_fake_git(
    root: Path,
    *,
    tracked: Iterable[str] = (),
    gitignore: str | None = None,
    version: int = 2,
    ignorecase: bool = False,
) -> Path:
    """Repositório git mínimo (só ``.git/index``, ``config`` e ``.gitignore``)."""
    git = root / ".git"
    (git / "info").mkdir(parents=True, exist_ok=True)
    (git / "index").write_bytes(index_bytes(tracked, version=version))
    flag = "true" if ignorecase else "false"
    (git / "config").write_text(f"[core]\n\tignorecase = {flag}\n", encoding="utf-8")
    if gitignore is not None:
        (root / ".gitignore").write_text(gitignore, encoding="utf-8", newline="\n")
    return git
