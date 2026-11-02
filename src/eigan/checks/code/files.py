"""Varredura de projetos: a lista de arquivos compartilhada pelas checagens de código.

A pasta é percorrida uma única vez por auditoria (``ctx.memo``) e o resultado é
reaproveitado por inventário, segredos, IaC, configuração e SAST. Regras:

- nunca segue links simbólicos nem junções do Windows e não visita a mesma pasta
  duas vezes (montagens que formam ciclos);
- pula as pastas de ``settings.skip_dirs`` (``node_modules``, ``.git``...), as de
  controle de versão e caches de ferramentas (``ALWAYS_SKIP``) e ambientes virtuais
  Python com qualquer nome (pasta com ``pyvenv.cfg`` ou ``conda-meta``);
- para em ``settings.max_files`` arquivos e em ``MAX_DEPTH`` níveis de pasta, e não
  lê arquivos maiores que ``settings.max_file_bytes``;
- arquivos binários (byte NUL no começo) são ignorados na leitura.
"""

from __future__ import annotations

import os
import re
import stat
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ...core.context import CheckContext
from ...core.models import Confidence, Severity

BINARY_SNIFF = 8192
MAX_DEPTH = 48
#: pastas que nunca têm código do projeto: controle de versão, caches de ferramentas e
#: bibliotecas de terceiros instaladas (quem as audita é a análise de dependências)
ALWAYS_SKIP = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".bzr",
        "_darcs",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        ".gradle",
        ".terraform",
        ".cache",
        ".eggs",
        ".next",
        ".nuxt",
        ".parcel-cache",
        ".turbo",
        ".angular",
        ".dart_tool",
        ".pnpm-store",
        ".yarn",
        "bower_components",
        "jspm_packages",
        "site-packages",
    }
)
#: arquivos que identificam um ambiente virtual Python (venv/virtualenv/conda)
_VENV_MARKERS = ("pyvenv.cfg", os.path.join("conda-meta", "history"))

#: extensão -> linguagem (para o inventário e para escolher as regras de SAST)
LANGUAGES: dict[str, str] = {
    ".py": "Python",
    ".pyw": "Python",
    ".js": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".mts": "TypeScript",
    ".cts": "TypeScript",
    ".vue": "Vue",
    ".svelte": "Svelte",
    ".php": "PHP",
    ".phtml": "PHP",
    ".java": "Java",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".scala": "Scala",
    ".groovy": "Groovy",
    ".cs": "C#",
    ".vb": "Visual Basic",
    ".fs": "F#",
    ".go": "Go",
    ".rb": "Ruby",
    ".erb": "Ruby",
    ".rs": "Rust",
    ".c": "C",
    ".h": "C/C++",
    ".cpp": "C++",
    ".cc": "C++",
    ".hpp": "C++",
    ".swift": "Swift",
    ".m": "Objective-C",
    ".dart": "Dart",
    ".lua": "Lua",
    ".pl": "Perl",
    ".sh": "Shell",
    ".bash": "Shell",
    ".ps1": "PowerShell",
    ".psm1": "PowerShell",
    ".bat": "Batch",
    ".cmd": "Batch",
    ".sql": "SQL",
    ".html": "HTML",
    ".htm": "HTML",
    ".css": "CSS",
    ".scss": "CSS",
    ".tf": "Terraform",
    ".yaml": "YAML",
    ".yml": "YAML",
}

_TEST_DIRS = frozenset(
    {
        "test",
        "tests",
        "__tests__",
        "spec",
        "specs",
        "testdata",
        "test-data",
        "test_data",
        "fixtures",
        "fixture",
        "__fixtures__",
        "__mocks__",
        "mocks",
        "testing",
        "e2e",
    }
)
_EXAMPLE_DIRS = frozenset(
    {
        "example",
        "examples",
        "sample",
        "samples",
        "demo",
        "demos",
        "docs",
        "doc",
        "exemplo",
        "exemplos",
    }
)
_TEST_SUFFIXES = (
    "_test.py",
    "_test.go",
    "_spec.rb",
    "_test.rb",
    ".test.js",
    ".test.ts",
    ".test.jsx",
    ".test.tsx",
    ".spec.js",
    ".spec.ts",
    ".spec.jsx",
    ".spec.tsx",
)
#: ``UserServiceTest.java``, ``FooTests.cs``, ``bar_test.php`` (mas não ``Latest.java``)
_TEST_CLASS_NAME = re.compile(r"(?:Tests?|(?:^|[._\-])tests?)\.(?:java|kt|scala|cs|php)$")

_SEVERITY_ORDER = (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)


@dataclass(frozen=True)
class SourceFile:
    """Um arquivo do projeto: caminho absoluto, relativo (com ``/``) e tamanho."""

    path: Path
    rel: str
    size: int

    @property
    def name(self) -> str:
        return self.path.name

    @property
    def lname(self) -> str:
        return self.path.name.lower()

    @property
    def ext(self) -> str:
        return self.path.suffix.lower()


@dataclass
class ProjectFiles:
    """Resultado da varredura da pasta do projeto."""

    root: Path
    files: list[SourceFile]
    truncated: bool = False
    skipped_dirs: int = 0
    #: links simbólicos e junções encontrados (nunca seguidos)
    links: int = 0
    #: pastas não visitadas por passar de ``MAX_DEPTH`` níveis
    too_deep: int = 0

    def readable(self, max_bytes: int) -> list[SourceFile]:
        """Arquivos dentro do limite de tamanho de leitura."""
        return [f for f in self.files if f.size <= max_bytes]


def project_files(ctx: CheckContext, root: str | Path) -> ProjectFiles:
    """Lista de arquivos do projeto, calculada uma vez por auditoria."""
    base = Path(root)
    settings = ctx.settings
    skip = {d.strip().lower() for d in settings.skip_dirs.split(",") if d.strip()}
    return ctx.memo(
        f"code.files:{base}",
        lambda: walk(base, skip_dirs=skip, max_files=settings.max_files, check=ctx.check_cancel),
    )


def walk(
    root: Path,
    *,
    skip_dirs: set[str] | frozenset[str],
    max_files: int,
    check: Callable[[], None] | None = None,
    max_depth: int = MAX_DEPTH,
) -> ProjectFiles:
    """Percorre ``root`` (em profundidade, ordem alfabética) sem seguir links."""
    result = ProjectFiles(root, [])
    skip = {d.lower() for d in skip_dirs} | ALWAYS_SKIP
    seen: set[tuple[int, int]] = set()
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        if check is not None:
            check()
        current, depth = stack.pop()
        identity = _identity(current)
        if identity is not None:
            if identity in seen:
                result.skipped_dirs += 1
                continue
            seen.add(identity)
        try:
            with os.scandir(current) as entries:
                ordered = sorted(entries, key=lambda e: e.name)
        except OSError:
            continue
        subdirs: list[Path] = []
        for entry in ordered:
            if _is_link(entry):
                result.links += 1
                continue
            try:
                if entry.is_dir(follow_symlinks=False):
                    if depth + 1 > max_depth:
                        result.too_deep += 1
                    elif _skip_dir(entry, skip):
                        result.skipped_dirs += 1
                    else:
                        subdirs.append(Path(entry.path))
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
                if len(result.files) >= max_files:
                    result.truncated = True
                    return result
                size = entry.stat(follow_symlinks=False).st_size
            except OSError:
                continue
            rel = _printable(Path(entry.path).relative_to(root).as_posix())
            result.files.append(SourceFile(Path(entry.path), rel, size))
        stack.extend((sub, depth + 1) for sub in reversed(subdirs))
    return result


def _identity(folder: Path) -> tuple[int, int] | None:
    """``(dispositivo, inode)`` da pasta, para não visitar a mesma pasta duas vezes."""
    try:
        info = os.stat(folder)
    except OSError:
        return None
    return (info.st_dev, info.st_ino) if info.st_ino else None


def _skip_dir(entry: os.DirEntry[str], skip: set[str]) -> bool:
    """Pasta ignorada pelo nome ou por ser um ambiente virtual Python."""
    if entry.name.lower() in skip:
        return True
    return any(os.path.isfile(os.path.join(entry.path, marker)) for marker in _VENV_MARKERS)


def _is_link(entry: os.DirEntry[str]) -> bool:
    """Link simbólico ou junção do Windows (nunca seguidos)."""
    try:
        return entry.is_symlink() or _is_junction(entry)
    except OSError:
        return True


def _is_junction(entry: os.DirEntry[str]) -> bool:
    """Junção/ponto de montagem do Windows (``DirEntry.is_junction`` só existe no 3.12+)."""
    method = getattr(entry, "is_junction", None)
    if callable(method):
        return bool(method())
    if sys.platform == "win32":
        info = entry.stat(follow_symlinks=False)
        return info.st_reparse_tag == stat.IO_REPARSE_TAG_MOUNT_POINT
    return False


def _printable(text: str) -> str:
    """Nome exibível mesmo com bytes inválidos no nome do arquivo (Linux)."""
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return text.encode("utf-8", "replace").decode("utf-8")
    return text


def read_text(path: Path, max_bytes: int) -> str | None:
    """Conteúdo de texto do arquivo, ou ``None`` se for grande demais, binário ou ilegível."""
    try:
        with path.open("rb") as handle:
            data = handle.read(max_bytes + 1)
    except OSError:
        return None
    if len(data) > max_bytes:
        return None
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            return None
    if b"\x00" in data[:BINARY_SNIFF]:
        return None
    return data.decode("utf-8-sig", errors="replace")


#: documentação: trechos de configuração ali costumam ser ilustrativos
_DOC_EXTS = frozenset({".md", ".markdown", ".mdx", ".rst", ".adoc", ".asciidoc"})
#: ``config.example.json``, ``sample_settings.py``, ``demo-app.yml``...
_EXAMPLE_NAME = re.compile(r"(?:^|[._-])(?:examples?|samples?|exemplos?|demos?)(?:[._-]|$)")
#: modelos de configuração: ``.env.template``, ``phpunit.xml.dist``, ``app.ini.default``
_TEMPLATE_SUFFIX = re.compile(r"\.(?:template|tmpl|dist|defaults?|example|sample)$")


def path_context(rel: str) -> str:
    """``teste`` (testes/fixtures), ``exemplo`` (exemplos/modelos/documentação) ou ``""``."""
    parts = rel.lower().split("/")
    dirs, name = parts[:-1], parts[-1]
    if any(part in _TEST_DIRS for part in dirs) or _is_test_name(rel.rsplit("/", 1)[-1]):
        return "teste"
    if any(part in _EXAMPLE_DIRS for part in dirs) or _EXAMPLE_NAME.search(name):
        return "exemplo"
    if _TEMPLATE_SUFFIX.search(name) and (name.startswith(".") or name.count(".") >= 2):
        return "exemplo"
    if os.path.splitext(name)[1] in _DOC_EXTS:
        return "exemplo"
    return ""


def _is_test_name(name: str) -> bool:
    """Nome de arquivo de teste (recebe o nome original: a caixa separa ``Test`` de ``Latest``)."""
    lowered = name.lower()
    if lowered.startswith("test_") and lowered.endswith(".py"):
        return True
    if lowered == "conftest.py" or lowered.endswith(_TEST_SUFFIXES):
        return True
    return _TEST_CLASS_NAME.search(name) is not None


def asset(rel: str, line: int | None = None) -> str:
    """Ativo de achado de código: ``caminho/relativo:linha``."""
    return f"{rel}:{line}" if line else rel


def line_of(text: str, index: int) -> int:
    """Número da linha (1-based) de uma posição do texto."""
    return text.count("\n", 0, max(0, index)) + 1


def lower_severity(severity: Severity, steps: int = 1) -> Severity:
    """Rebaixa a severidade (nunca abaixo de baixa; informativo continua informativo)."""
    if severity is Severity.INFO:
        return severity
    rank = max(_SEVERITY_ORDER.index(severity) - steps, 1)
    return _SEVERITY_ORDER[rank]


def raise_severity(severity: Severity, steps: int = 1) -> Severity:
    """Eleva a severidade (no máximo crítica)."""
    rank = min(_SEVERITY_ORDER.index(severity) + steps, len(_SEVERITY_ORDER) - 1)
    return _SEVERITY_ORDER[rank]


def context_adjust(
    rel: str, severity: Severity, confidence: Confidence
) -> tuple[Severity, Confidence, str]:
    """Ajusta severidade/confiança de achados em testes e exemplos."""
    where = path_context(rel)
    if where == "teste":
        capped = Severity.LOW if severity.rank > Severity.LOW.rank else severity
        return capped, Confidence.TENTATIVE, where
    if where == "exemplo":
        return lower_severity(severity), Confidence.TENTATIVE, where
    return severity, confidence, where


#: extensão -> tecnologia dos exemplos de correção da base de conhecimento
_TECH_BY_EXT: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".vue": "javascript",
    ".php": "php",
    ".java": "java",
    ".kt": "java",
    ".properties": "java",
    ".cs": "csharp",
    ".go": "go",
    ".rb": "ruby",
    ".tf": "terraform",
}


def tech_of(item: SourceFile) -> list[str]:
    """Tecnologia do arquivo (para escolher o exemplo de correção certo)."""
    name = item.lname
    if name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile"):
        return ["dockerfile"]
    if name in ("web.config", "appsettings.json") or name.startswith("appsettings."):
        return ["csharp"]
    tech = _TECH_BY_EXT.get(item.ext)
    return [tech] if tech else []
