"""O que o git sabe sobre o projeto: arquivos versionados e regras do ``.gitignore``.

Tudo só leitura e sem executar o ``git``: o índice (``.git/index``) é lido
diretamente (formatos 2, 3 e 4) e o ``.gitignore`` é interpretado por um
casador simplificado (negação ``!``, âncora ``/``, só-pasta ``/`` final e ``**``).
Serve para dizer se um ``.env`` foi versionado ou se escaparia num ``git add``.

De propósito, só valem as regras do próprio repositório (``.gitignore`` e
``.git/info/exclude``): o ``core.excludesFile`` global é do usuário desta máquina
e não protege o resto da equipe.
"""

from __future__ import annotations

import re
import struct
import threading
from dataclasses import dataclass, field
from pathlib import Path

from ...core.context import CheckContext

_MAX_INDEX_BYTES = 64 * 1024 * 1024
_MAX_PATTERN_FILE = 1024 * 1024
_MAX_PARENTS = 12
#: extensões do índice que deixam a lista de arquivos incompleta (split index, sparse index)
_PARTIAL_INDEX = (b"link", b"sdir")


@dataclass(frozen=True)
class _Pattern:
    regex: re.Pattern[str]
    negate: bool
    dir_only: bool
    base: str  # pasta (relativa à raiz do git) onde o .gitignore está


@dataclass
class GitInfo:
    """Visão do repositório git que contém o projeto (se houver)."""

    git_root: Path | None = None
    prefix: str = ""  # caminho do projeto relativo à raiz do git ("" se for a raiz)
    tracked: set[str] | None = None
    ignore_case: bool = False  # core.ignorecase (padrão no Windows e no macOS)
    _patterns: list[_Pattern] = field(default_factory=list)
    _loaded_dirs: set[str] = field(default_factory=set)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False, compare=False)

    @property
    def is_repo(self) -> bool:
        return self.git_root is not None

    def repo_path(self, rel: str) -> str:
        """Caminho relativo à raiz do git a partir do caminho relativo ao projeto."""
        return f"{self.prefix}/{rel}" if self.prefix else rel

    def is_tracked(self, rel: str) -> bool | None:
        """``True``/``False`` se o índice foi lido; ``None`` se não dá para saber."""
        if self.tracked is None:
            return None
        path = self.repo_path(rel)
        return (path.lower() if self.ignore_case else path) in self.tracked

    def is_ignored(self, rel: str) -> bool:
        """Se o arquivo casa com as regras de ``.gitignore`` (inclui pastas-pai ignoradas)."""
        if self.git_root is None:
            return False
        path = self.repo_path(rel)
        parts = path.split("/")
        with self._lock:  # as checagens de código rodam em paralelo e compartilham este objeto
            for depth in range(1, len(parts) + 1):
                self._load_dir("/".join(parts[: depth - 1]))
            for depth in range(1, len(parts)):
                if self._match("/".join(parts[:depth]), is_dir=True):
                    return True  # o git não reinclui arquivos de uma pasta ignorada
            return self._match(path, is_dir=False)

    def _match(self, path: str, *, is_dir: bool) -> bool:
        ignored = False
        for pattern in self._patterns:
            if pattern.dir_only and not is_dir:
                continue
            if pattern.base and not path.startswith(pattern.base + "/"):
                continue
            local = path[len(pattern.base) + 1 :] if pattern.base else path
            if pattern.regex.fullmatch(local):
                ignored = not pattern.negate
        return ignored

    def _load_dir(self, rel_dir: str) -> None:
        if rel_dir in self._loaded_dirs or self.git_root is None:
            return
        self._loaded_dirs.add(rel_dir)
        folder = self.git_root / rel_dir if rel_dir else self.git_root
        self._patterns.extend(_read_patterns(folder / ".gitignore", rel_dir, self.ignore_case))


def git_info(ctx: CheckContext, root: str | Path) -> GitInfo:
    """Informações do git do projeto, calculadas uma vez por auditoria."""
    base = Path(root)
    return ctx.memo(f"code.git:{base}", lambda: load_git_info(base))


def load_git_info(root: Path) -> GitInfo:
    git_root = _find_git_root(root)
    if git_root is None:
        return GitInfo()
    try:
        prefix = root.resolve().relative_to(git_root.resolve()).as_posix()
    except (OSError, ValueError):
        prefix = ""
    prefix = "" if prefix == "." else prefix
    info = GitInfo(git_root=git_root, prefix=prefix)
    git_dir = _git_dir(git_root)
    if git_dir is not None:
        common = _common_dir(git_dir)
        info.ignore_case = _ignore_case(common / "config")
        tracked = read_index(git_dir / "index")
        if tracked is not None and info.ignore_case:
            tracked = {name.lower() for name in tracked}
        info.tracked = tracked
        info._patterns.extend(_read_patterns(common / "info" / "exclude", "", info.ignore_case))
    return info


def _common_dir(git_dir: Path) -> Path:
    """Pasta com ``config`` e ``info/`` (numa worktree, é a do repositório principal)."""
    try:
        target = (git_dir / "commondir").read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return git_dir
    return git_dir / target if target else git_dir


def _find_git_root(start: Path) -> Path | None:
    try:
        current = start.resolve()
    except OSError:
        current = start
    for _ in range(_MAX_PARENTS):
        if (current / ".git").exists():
            return current
        if current.parent == current:
            return None
        current = current.parent
    return None


def _git_dir(git_root: Path) -> Path | None:
    marker = git_root / ".git"
    if marker.is_dir():
        return marker
    try:  # worktree/submódulo: ".git" é um arquivo "gitdir: <caminho>"
        text = marker.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None
    if text.startswith("gitdir:"):
        target = Path(text.split(":", 1)[1].strip())
        return target if target.is_absolute() else (git_root / target)
    return None


def _ignore_case(config: Path) -> bool:
    """``core.ignorecase = true`` no ``.git/config`` do repositório."""
    try:
        lines = config.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return False
    section = ""
    for raw in lines:
        line = raw.split("#", 1)[0].split(";", 1)[0].strip()
        if line.startswith("["):
            section = line.strip("[]").strip().lower()
        elif section == "core" and "=" in line:
            key, value = (part.strip().lower() for part in line.split("=", 1))
            if key == "ignorecase":
                return value in ("true", "yes", "on", "1")
    return False


def read_index(path: Path) -> set[str] | None:
    """Caminhos versionados lidos do ``.git/index`` (``None`` se ilegível ou incompleto)."""
    try:
        if path.stat().st_size > _MAX_INDEX_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    try:
        return _parse_index(data)
    except (ValueError, struct.error, IndexError):
        return None


def _parse_index(data: bytes) -> set[str] | None:
    if len(data) < 12 or data[:4] != b"DIRC":
        return None
    version, count = struct.unpack(">II", data[4:12])
    if version not in (2, 3, 4):
        return None
    pos = 12
    previous = b""
    names: set[str] = set()
    for _ in range(count):
        start = pos
        flags = struct.unpack(">H", data[pos + 60 : pos + 62])[0]
        pos += 62
        extended = 2 if version >= 3 and flags & 0x4000 else 0
        pos += extended
        if version == 4:
            strip, pos = _varint(data, pos)
            end = data.index(b"\x00", pos)
            name = previous[: len(previous) - strip] + data[pos:end]
            pos = end + 1
        else:
            end = data.index(b"\x00", pos)
            name = data[pos:end]
            pos = start + ((62 + extended + len(name)) // 8 + 1) * 8
        previous = name
        names.add(name.decode("utf-8", errors="replace"))
    if _index_extensions(data, pos) & set(_PARTIAL_INDEX):
        return None
    return names


def _index_extensions(data: bytes, pos: int) -> set[bytes]:
    """Assinaturas das extensões gravadas depois das entradas do índice."""
    found: set[bytes] = set()
    while pos + 8 <= len(data):
        signature = data[pos : pos + 4]
        if not signature.isalpha():
            break  # chegou ao hash final do arquivo
        size = struct.unpack(">I", data[pos + 4 : pos + 8])[0]
        found.add(signature)
        pos += 8 + size
    return found


def _varint(data: bytes, pos: int) -> tuple[int, int]:
    """Inteiro de tamanho variável do formato do git (índice v4)."""
    byte = data[pos]
    pos += 1
    value = byte & 0x7F
    while byte & 0x80:
        byte = data[pos]
        pos += 1
        value = ((value + 1) << 7) | (byte & 0x7F)
    return value, pos


def _read_patterns(path: Path, base: str, ignore_case: bool = False) -> list[_Pattern]:
    try:
        if path.stat().st_size > _MAX_PATTERN_FILE:
            return []
        lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    except OSError:
        return []
    patterns: list[_Pattern] = []
    for raw in lines:
        parsed = _parse_line(raw, base, ignore_case)
        if parsed is not None:
            patterns.append(parsed)
    return patterns


def _parse_line(raw: str, base: str, ignore_case: bool = False) -> _Pattern | None:
    line = raw.rstrip()
    if line.endswith("\\") and raw.endswith(" "):
        line = line[:-1] + " "
    if not line or line.startswith("#"):
        return None
    negate = line.startswith("!")
    if negate:
        line = line[1:]
    if line.startswith("\\"):
        line = line[1:]
    dir_only = line.endswith("/")
    line = line.rstrip("/")
    if not line:
        return None
    anchored = "/" in line
    line = line.lstrip("/")
    body = _glob_to_regex(line)
    regex = body if anchored else f"(?:.*/)?{body}"
    try:
        compiled = re.compile(regex, re.IGNORECASE if ignore_case else 0)
    except re.error:
        return None  # padrão que o git também não entenderia (ex.: classe [z-a])
    return _Pattern(compiled, negate, dir_only, base)


def _glob_to_regex(glob: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(glob):
        char = glob[i]
        if glob.startswith("**/", i) and (i == 0 or glob[i - 1] == "/"):
            out.append("(?:.*/)?")
            i += 3
            continue
        if glob.startswith("/**", i) and i + 3 == len(glob):
            out.append("/.*")
            i += 3
            continue
        if glob.startswith("**", i):
            out.append("[^/]*")  # fora de "/**/", dois asteriscos valem como um
            i += 2
            continue
        if char == "*":
            out.append("[^/]*")
        elif char == "?":
            out.append("[^/]")
        elif char == "[":
            end = glob.find("]", i + 2)
            if end == -1:
                out.append(re.escape(char))
            else:
                content = glob[i + 1 : end].replace("\\", "\\\\")
                content = re.sub(r"([\[&~|])", r"\\\1", content)  # literais dentro da classe
                if content.startswith("!"):
                    content = "^" + content[1:]
                out.append(f"[{content}]")
                i = end
        else:
            out.append(re.escape(char))
        i += 1
    return "".join(out)
