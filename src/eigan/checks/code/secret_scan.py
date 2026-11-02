"""Segredos no código: chaves privadas, tokens, senhas e arquivos .env versionados.

O valor encontrado **nunca** sai inteiro desta checagem: evidência e detalhes
levam só o começo do segredo e o tamanho (``core.redact.mask``). Achados em
testes/fixtures continuam aparecendo, mas com severidade baixa; arquivos que o
``.gitignore`` ignora (e que não estão versionados) perdem um nível.

Uma linha marcada com ``gitleaks:allow``, ``pragma: allowlist secret`` (detect-secrets)
ou ``eigan:ignore`` é ignorada — o mesmo vale para a linha seguinte a
``pragma: allowlist nextline secret``.
"""

from __future__ import annotations

import bisect
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ...core import facts
from ...core.context import CheckContext
from ...core.models import Category, Confidence, Fact, Severity
from ...core.redact import mask
from ...core.registry import check
from . import secret_kb  # noqa: F401  (registra as entradas da base)
from .files import (
    SourceFile,
    asset,
    context_adjust,
    lower_severity,
    project_files,
    read_text,
    tech_of,
)
from .gitmeta import GitInfo, git_info
from .manifests import index_to_line, line_starts
from .secret_rules import (
    CONNECTION,
    ENV_FILE,
    PRIVATE_KEY,
    RULES,
    SECRET_FINDINGS,
    SENSITIVE_FILE,
    SecretRule,
    generic_key_ok,
    generic_value_ok,
    is_config_file,
    is_placeholder,
    jwt_is_valid,
    private_key_encrypted,
    private_key_has_body,
    shannon_entropy,
)

MAX_PER_FILE = 25
#: limite de ocorrências por regra e arquivo (listas de chaves, dumps) e janela de busca da linha
MAX_HITS_PER_RULE = 200
_LINE_WINDOW = 2000
MAX_TOTAL = 300

_SKIP_EXTS = frozenset(
    ".png .jpg .jpeg .gif .bmp .ico .webp .tif .tiff .psd .svg .svgz .woff .woff2 .ttf .otf .eot "
    ".zip .gz .tgz .bz2 .xz .7z .rar .jar .war .ear .exe .dll .so .dylib .bin .o .a .lib .class "
    ".pyc .pyo .whl .egg .mp3 .mp4 .avi .mov .wav .flac .ogg .webm .pdf .doc .docx .xls .xlsx "
    ".ppt .pptx .db .sqlite .sqlite3 .pfx .p12 .jks .keystore .bks .der".split()
)
_LOCKFILES = frozenset(
    "package-lock.json npm-shrinkwrap.json yarn.lock pnpm-lock.yaml poetry.lock pipfile.lock "
    "uv.lock composer.lock gemfile.lock cargo.lock go.sum packages.lock.json gradle.lockfile".split()
)
_MINIFIED = (".min.js", ".min.css", ".map", ".bundle.js", ".chunk.js")
_ALLOW_MARKERS = ("gitleaks:allow", "pragma: allowlist secret", "eigan:ignore", "eigan: ignore")
_ALLOW_NEXT = "pragma: allowlist nextline secret"
_ENV_NAME = re.compile(r"^(?:\.env(?:\.[\w.\-]+)?|[\w.\-]+\.env)$")
_ENV_TEMPLATE = (
    ".example", ".sample", ".template", ".tmpl", ".tpl", ".dist", ".default", ".defaults",
    ".schema", ".test", ".testing", ".ci",
)  # fmt: skip
_ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.\-]*)\s*=\s*(.*?)\s*$")
#: DSN do Sentry e strings de conexão: o nome não termina em substantivo de segredo
_DSN_KEY = re.compile(r"(?i)(?:^|_)dsn$|conn(?:ection)?_?str(?:ing)?$")
_TRIVIAL_VALUES = frozenset("true false yes no on off null none nil enabled disabled".split())
_PUBLIC_PREFIXES = (
    "NEXT_PUBLIC_",
    "VITE_",
    "REACT_APP_",
    "NUXT_PUBLIC_",
    "PUBLIC_",
    "EXPO_PUBLIC_",
)
#: servidores locais: credencial de ambiente de desenvolvimento
_ANY_ADDRESS = ".".join("0000")  # endereço "qualquer interface" (só comparado, nunca usado em bind)
_LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1", _ANY_ADDRESS, "host.docker.internal"})
#: senhas-padrão de imagens e instalações locais (``postgres:postgres@localhost``)
_DEFAULT_PASSWORDS = frozenset("admin root guest postgres mysql pass secret toor sa".split())
_PLACEHOLDER_HOSTS = frozenset(
    "host hostname server domain myhost yourhost your-host dbhost db-host".split()
)
_SENSITIVE_FILES: dict[str, str] = {
    ".pfx": "certificado com chave privada (PKCS#12)",
    ".p12": "certificado com chave privada (PKCS#12)",
    ".jks": "keystore Java",
    ".keystore": "keystore Java/Android",
    ".bks": "keystore BouncyCastle",
    "terraform.tfstate": "estado do Terraform (guarda senhas em texto puro)",
    "terraform.tfstate.backup": "cópia do estado do Terraform (guarda senhas em texto puro)",
    ".git-credentials": "senhas/tokens do Git em texto puro",
    ".pgpass": "senhas do PostgreSQL em texto puro",
    ".netrc": "senhas de FTP/HTTP em texto puro",
    "_netrc": "senhas de FTP/HTTP em texto puro",
    ".htpasswd": "hashes de senha do Apache",
}
_GIT_TEXT = {
    "versionado": "versionado no Git: o segredo também está no histórico do repositório",
    "ignorado": "ignorado pelo .gitignore e fora do Git (só no disco desta pasta)",
    "fora": "fora do Git, mas NÃO está no .gitignore: pode entrar no próximo commit",
}


@dataclass(frozen=True)
class SecretHit:
    """Um segredo encontrado: regra, valor e posição (índices no texto)."""

    rule: SecretRule
    secret: str
    start: int
    end: int
    key: str = ""
    severity: Severity | None = None  # ajuste da regra (chave cifrada, servidor local...)
    note: str = ""


@check(
    id="code.secrets",
    name="Segredos no código",
    category=Category.CODE,
    consumes=facts.PROJECT,
    description=(
        "Procura chaves privadas, credenciais de nuvem, tokens de serviços, senhas no código e "
        "arquivos .env versionados. O valor encontrado nunca é exibido inteiro."
    ),
    findings=SECRET_FINDINGS,
    order=30,
)
def check_secrets(ctx: CheckContext, fact: Fact) -> None:
    root = Path(str(fact.data.get("path") or fact.key))
    if not root.is_dir():
        return
    listing = project_files(ctx, root)
    git = git_info(ctx, root)
    max_bytes = ctx.settings.max_file_bytes
    scanned = 0
    pending: list[_Report] = []
    for item in listing.files:
        ctx.check_cancel()
        status = git_status(git, item.rel)
        _check_special_file(ctx, item, status, max_bytes)
        if item.ext in _SKIP_EXTS or item.lname in _LOCKFILES or item.size > max_bytes:
            continue
        text = read_text(item.path, max_bytes)
        if text is None:
            continue
        scanned += 1
        found = _relevant(scan_text(text, item.lname, ctx.check_cancel), item, status)
        starts = line_starts(text) if found else []
        reports = [_build_report(item, text, starts, hit, status, found) for hit in found]
        reports.sort(key=lambda r: -r.severity.rank)  # os mais graves primeiro (estável)
        pending.extend(reports[:MAX_PER_FILE])
    reported, skipped = _emit(ctx, pending)
    ctx.log(f"Segredos: {scanned} arquivos de texto analisados, {reported} ocorrência(s).")
    if skipped:
        ctx.log(
            f"Mais {skipped} ocorrências de segredos de menor gravidade não foram detalhadas "
            f"(limite de {MAX_TOTAL})."
        )
    if not reported and scanned:
        ctx.passed(
            "code.segredos", f"Nenhum segredo encontrado em {scanned} arquivos de texto", str(root)
        )


def _emit(ctx: CheckContext, pending: list[_Report]) -> tuple[int, int]:
    """Relata por gravidade (críticos primeiro); chaves privadas passam por cima do limite."""
    ordered = sorted(pending, key=lambda r: -r.severity.rank)
    reported = skipped = 0
    for report in ordered:
        if reported >= MAX_TOTAL and report.finding != PRIVATE_KEY:
            skipped += 1
            continue
        ctx.report(report.finding, **report.fields)
        reported += 1
    return reported, skipped


def git_status(git: GitInfo, rel: str) -> str:
    """``versionado``, ``ignorado``, ``fora`` (nem versionado nem ignorado) ou ``""``."""
    if not git.is_repo:
        return ""
    tracked = git.is_tracked(rel)
    if tracked:
        return "versionado"
    if git.is_ignored(rel):
        return "ignorado"
    return "fora" if tracked is False else ""


def _relevant(hits: list[SecretHit], item: SourceFile, status: str) -> list[SecretHit]:
    """Num ``.env`` ignorado pelo git, senhas e conexões são a configuração local esperada."""
    if status != "ignorado" or not is_env_file(item.lname):
        return hits
    return [h for h in hits if not h.rule.generic and h.rule.finding != CONNECTION]


# -- varredura de texto ------------------------------------------------------------


def scan_text(text: str, lname: str, cancel: Callable[[], None] | None = None) -> list[SecretHit]:
    """Todos os segredos de um texto (sem sobreposição: a regra mais específica vence)."""
    lowered = text.lower()
    minified = is_minified(text, lname)
    config = is_config_file(lname)
    hits: list[SecretHit] = []
    starts: list[int] = []  # intervalos já usados, ordenados e sem sobreposição
    ends: list[int] = []
    for rule in RULES:
        if rule.files and lname not in rule.files:
            continue
        if rule.generic and minified:
            continue
        if rule.id == "atribuicao-config" and not config:
            continue
        if not any(word in lowered for word in rule.keywords):
            continue
        if rule.requires is not None and not rule.requires.search(text):
            continue
        found = 0
        for number, match in enumerate(rule.pattern.finditer(text)):
            if cancel is not None and number % 256 == 0:
                cancel()
            hit = _accept(rule, match, text, lowered)
            if hit is None or _overlaps(starts, ends, hit):
                continue
            position = bisect.bisect_left(starts, hit.start)
            starts.insert(position, hit.start)
            ends.insert(position, hit.end)
            hits.append(hit)
            found += 1
            if found >= MAX_HITS_PER_RULE:
                break
    allowed = [h for h in hits if not _allowlisted(lowered, h.start)]
    return sorted(allowed, key=lambda h: h.start)


def _overlaps(starts: list[int], ends: list[int], hit: SecretHit) -> bool:
    """O trecho do achado cruza algum intervalo já aceito? (busca binária, sem varrer a lista)"""
    position = bisect.bisect_left(starts, hit.start)
    if position > 0 and ends[position - 1] > hit.start:
        return True
    return position < len(starts) and starts[position] < hit.end


def _allowlisted(lowered: str, index: int) -> bool:
    """A linha tem um comentário de exceção (ou a linha anterior pede exceção para ela)."""
    low = max(index - _LINE_WINDOW, 0)
    found = lowered.rfind("\n", low, index)
    start = found + 1 if found >= 0 else low
    end = lowered.find("\n", index, index + _LINE_WINDOW)
    line = lowered[start : index + _LINE_WINDOW if end < 0 else end]
    if any(marker in line for marker in _ALLOW_MARKERS):
        return True
    before = max(start - 1, 0)
    previous = lowered[max(lowered.rfind("\n", 0, before) + 1, before - _LINE_WINDOW) : before]
    return start > 0 and _ALLOW_NEXT in previous


def is_minified(text: str, lname: str) -> bool:
    if lname.endswith(_MINIFIED):
        return True
    return len(text) > 5000 and text.count("\n") < len(text) / 1000


def _accept(rule: SecretRule, match: re.Match[str], text: str, lowered: str) -> SecretHit | None:
    secret = match.group(rule.group)
    start, end = match.span(rule.group)
    if rule.finding == PRIVATE_KEY:
        if rule.id == "chave-privada" and not private_key_has_body(text, match.end()):
            return None
        if private_key_encrypted(secret, text, match.end()):
            note = "chave protegida por senha (cifrada): ainda é preciso trocá-la"
            return SecretHit(rule, secret, start, end, severity=Severity.HIGH, note=note)
        return SecretHit(rule, secret, start, end)
    if rule.generic:
        key = match.group("key")
        if not generic_key_ok(key) or _django_secret_key(key, lowered):
            return None
        if is_placeholder(secret, strict=True) or not generic_value_ok(secret, rule.min_entropy):
            return None
        return SecretHit(rule, secret, start, end, key)
    if rule.finding == CONNECTION:
        return _connection_hit(rule, match, secret, start, end)
    if rule.min_entropy and shannon_entropy(secret) < rule.min_entropy:
        return None
    if is_placeholder(secret, strict=False):
        return None
    if rule.id == "jwt" and not jwt_is_valid(secret):
        return None
    return SecretHit(rule, secret, start, end)


def _connection_hit(
    rule: SecretRule, match: re.Match[str], secret: str, start: int, end: int
) -> SecretHit | None:
    """Senha em URL/string de conexão, descartando exemplos e servidores locais com senha-padrão."""
    if is_placeholder(secret, strict=True) or (secret.isdigit() and len(secret) <= 5):
        return None
    if rule.id != "url-credenciais":
        return SecretHit(rule, secret, start, end)
    if match.group("user").lower() == secret.lower():
        return None  # usuário e senha iguais (guest:guest, anonymous:anonymous): padrão da imagem
    host = match.group("host").lower().strip("[]")
    if "example" in host or host in _PLACEHOLDER_HOSTS:
        return None
    if host in _LOOPBACK or host.startswith("127."):
        if secret.lower() in _DEFAULT_PASSWORDS:
            return None
        note = "servidor local (ambiente de desenvolvimento)"
        return SecretHit(rule, secret, start, end, severity=Severity.LOW, note=note)
    return SecretHit(rule, secret, start, end)


def _django_secret_key(key: str, lowered: str) -> bool:
    """``SECRET_KEY`` do Django é tratado pela checagem de configuração (evita achado duplo)."""
    return key == "SECRET_KEY" and "django" in lowered


# -- relato ------------------------------------------------------------------------


@dataclass(frozen=True)
class _Report:
    """Achado já montado (a ordem de relato é decidida depois, por gravidade)."""

    finding: str
    severity: Severity
    fields: dict[str, Any]


def _build_report(
    item: SourceFile,
    text: str,
    starts: list[int],
    hit: SecretHit,
    status: str,
    hits: list[SecretHit],
) -> _Report:
    rule = hit.rule
    if rule.finding == PRIVATE_KEY:
        confidence = Confidence.CONFIRMED
    elif rule.generic:
        confidence = Confidence.TENTATIVE
    else:
        confidence = Confidence.FIRM
    base = hit.severity or rule.severity
    severity, confidence, where = context_adjust(item.rel, base, confidence)
    if status == "ignorado":
        severity = lower_severity(severity)
    line = index_to_line(starts, hit.start)
    column = hit.start - starts[line - 1] + 1
    fields: dict[str, Any] = {
        "asset": asset(item.rel, line),
        "title": rule.label,
        "severity": severity,
        "evidence": _evidence(text, hit, hits),
        "details": _details(hit, status, where),
        "confidence": confidence,
        "discriminator": f"{rule.id}@{column}",
        "tech": tech_of(item),
    }
    return _Report(rule.finding, severity, fields)


def masked(secret: str) -> str:
    """Máscara proporcional: segredos curtos (senhas) mostram menos caracteres."""
    keep = 4 if len(secret) >= 20 else 2 if len(secret) >= 12 else 0
    return mask(secret, keep=keep)


def _evidence(text: str, hit: SecretHit, hits: list[SecretHit] | None = None) -> str:
    """A linha do achado com **todos** os segredos dela mascarados (cortada em ~200 caracteres)."""
    if hit.rule.finding == PRIVATE_KEY:
        header = hit.secret.strip("-").strip()
        return f"{header} (cabeçalho da chave; o conteúdo foi omitido)"
    line_start = text.rfind("\n", 0, hit.start) + 1
    line_end = text.find("\n", hit.end)
    line_end = len(text) if line_end < 0 else line_end
    pieces: list[str] = []
    cursor = line_start
    for other in sorted({hit, *(hits or [])}, key=lambda h: h.start):
        if other.start < cursor or other.end > line_end or other.start < line_start:
            continue
        pieces.append(text[cursor : other.start])
        pieces.append(masked(other.secret))
        cursor = other.end
    pieces.append(text[cursor:line_end])
    shown = "".join(pieces).strip()
    return shown if len(shown) <= 220 else shown[:220] + "…"


def _details(hit: SecretHit, status: str, where: str) -> dict[str, Any]:
    details: dict[str, Any] = {
        "regra": hit.rule.id,
        "tipo": hit.rule.label,
        "como_revogar": hit.rule.revoke,
    }
    if hit.rule.finding != PRIVATE_KEY:
        details["segredo"] = masked(hit.secret)
        details["entropia"] = round(shannon_entropy(hit.secret), 2)
    if hit.key:
        details["variavel"] = hit.key
    if hit.note:
        details["observacao"] = hit.note
    if status:
        details["git"] = _GIT_TEXT[status]
    if where:
        details["contexto"] = (
            f"arquivo de {where}: severidade reduzida (confira se é só dado de teste)"
        )
    return details


# -- arquivos especiais (.env, keystores, tfstate...) -------------------------------


def is_env_file(lname: str) -> bool:
    """``.env``, ``.env.production``, ``prod.env``... (modelos como ``.env.example`` não)."""
    if not _ENV_NAME.match(lname) or lname.endswith(_ENV_TEMPLATE):
        return False
    return not lname.startswith(("example", "sample", "template"))


def _env_secret(name: str, value: str) -> bool:
    """Nome de segredo (termina em senha/token/chave...) com valor que não é flag, número ou caminho."""
    if not (generic_key_ok(name) or _DSN_KEY.search(name)):
        return False
    if value.lower() in _TRIVIAL_VALUES or value.replace(".", "").isdigit():
        return False
    return not is_placeholder(value, strict=True)


def env_secret_names(text: str) -> tuple[int, list[str], int]:
    """Variáveis definidas, as que têm nome de segredo com valor real e a linha da primeira."""
    total = first = 0
    names: list[str] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        match = _ENV_LINE.match(raw)
        if not match or raw.lstrip().startswith("#"):
            continue
        name, value = match.group(1), match.group(2).strip().strip("'\"")
        total += 1
        if not value or name.upper().startswith(_PUBLIC_PREFIXES):
            continue
        if _env_secret(name, value):
            names.append(name)
            first = first or number
    return total, names, first


def _check_special_file(ctx: CheckContext, item: SourceFile, status: str, max_bytes: int) -> None:
    if status not in ("versionado", "fora"):
        return  # sem git, ou já ignorado: não há risco de ir para o repositório
    if is_env_file(item.lname):
        _report_env(ctx, item, status, max_bytes)
        return
    kind = _SENSITIVE_FILES.get(item.lname) or _SENSITIVE_FILES.get(item.ext)
    if kind is None:
        return
    base = Severity.HIGH if status == "versionado" else Severity.MEDIUM
    severity, confidence, where = context_adjust(item.rel, base, Confidence.FIRM)
    details: dict[str, Any] = {"tipo": kind, "git": _GIT_TEXT[status]}
    if where:
        details["contexto"] = f"arquivo de {where}: severidade reduzida"
    ctx.report(
        SENSITIVE_FILE,
        asset=asset(item.rel),
        title=f"Arquivo de credenciais no projeto: {item.name}",
        severity=severity,
        evidence=f"{item.rel} ({kind}; {item.size} bytes)",
        details=details,
        confidence=confidence,
        discriminator="arquivo",
        tech=["git"],
    )


def _report_env(ctx: CheckContext, item: SourceFile, status: str, max_bytes: int) -> None:
    text = read_text(item.path, max_bytes)
    if text is None:
        return
    total, names, first = env_secret_names(text)
    if not names:
        return  # só configuração pública (URLs, portas, flags)
    base = Severity.HIGH if status == "versionado" else Severity.MEDIUM
    severity, confidence, where = context_adjust(item.rel, base, Confidence.CONFIRMED)
    shown = ", ".join(names[:10]) + (" ..." if len(names) > 10 else "")
    details: dict[str, Any] = {
        "variaveis": total,
        "com_nome_de_segredo": names[:30],
        "git": _GIT_TEXT[status],
    }
    if where:
        details["contexto"] = f"arquivo de {where}: severidade reduzida"
    situation = "versionado no Git" if status == "versionado" else "fora do .gitignore"
    ctx.report(
        ENV_FILE,
        asset=asset(item.rel, first),
        title=f"Arquivo {item.name} {situation}",
        severity=severity,
        evidence=f"{item.rel}: {total} variáveis; com nome de segredo: {shown}",
        details=details,
        confidence=confidence,
        discriminator="env",
        tech=["git"],
    )
