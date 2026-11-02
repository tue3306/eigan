"""Checagem de padrões inseguros no código (SAST por regras).

Lê os arquivos Python, JavaScript/TypeScript, PHP, Java, C#, Go e Ruby do projeto e
aplica as regras de ``sast_rules_*``. Cada regra acha o ponto perigoso por expressão
regular sobre o texto sem comentários nem conteúdo de strings (``sast_mask``) e depois
confirma olhando os argumentos: constante é ignorada; variável ou texto montado vira
um pedido de revisão; entrada direta da requisição vira achado de severidade alta.
Nada é executado nem importado.

Contenção de ruído: testes e exemplos têm severidade e confiança reduzidas, arquivos
minificados, gerados, de bibliotecas de terceiros ou enormes são ignorados e há tetos
por arquivo, por regra e por projeto.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from functools import cache
from pathlib import Path

from ...core import facts, redact
from ...core.context import CheckContext
from ...core.models import Category, Confidence, Fact, Severity
from ...core.registry import check
from . import kb_sast  # noqa: F401  (registra as entradas da base)
from .files import SourceFile, asset, context_adjust, line_of, project_files, read_text, tech_of
from .sast_common import SAST_FINDINGS, Hit, SastRule, Verdict, tainted_names
from .sast_mask import CSHARP, GO, JAVA, JAVASCRIPT, PHP, PYTHON, RUBY, MaskedSource, mask_source
from .sast_rules_compiled import COMPILED_RULES
from .sast_rules_script import SCRIPT_RULES
from .sast_rules_web import WEB_RULES

#: tetos de contenção
MAX_PER_FILE = 15
MAX_PER_RULE = 25
MAX_TOTAL = 400
#: casamentos examinados por regra em um arquivo (evita custo quadratico em arquivos absurdos)
MAX_MATCHES_PER_RULE = 300
#: arquivos acima disto não são analisados (código escrito por pessoas raramente passa)
MAX_SOURCE_BYTES = 1_000_000

_LANGUAGE_BY_EXT: dict[str, str] = {
    ".py": PYTHON,
    ".pyw": PYTHON,
    ".js": JAVASCRIPT,
    ".mjs": JAVASCRIPT,
    ".cjs": JAVASCRIPT,
    ".jsx": JAVASCRIPT,
    ".ts": JAVASCRIPT,
    ".tsx": JAVASCRIPT,
    ".vue": JAVASCRIPT,
    ".php": PHP,
    ".inc": PHP,
    ".php3": PHP,
    ".php4": PHP,
    ".php5": PHP,
    ".php7": PHP,
    ".phps": PHP,
    ".phtml": PHP,
    ".java": JAVA,
    ".cs": CSHARP,
    ".go": GO,
    ".rb": RUBY,
    ".rake": RUBY,
}
_VENDOR_DIRS = frozenset(
    {
        "vendor",
        "vendors",
        "third_party",
        "third-party",
        "thirdparty",
        "node_modules",
        "bower_components",
        "jspm_packages",
        "site-packages",
        "dist-packages",
    }
)
_GENERATED = re.compile(
    r"(?:\.min\.[a-z]+|\.bundle\.js|\.chunk\.js|\.map|\.pb\.go|_pb2(?:_grpc)?\.py|\.designer\.cs|\.g\.cs|\.generated\.\w+|"
    r"-min\.js)$"
)
_GENERATED_HEADER = re.compile(
    r"(?i)(?:@generated|code generated.{0,80}do not edit|auto-?generated (?:file|code)|this file (?:is|was) (?:auto-?)?generated)"
)


@cache
def rules_for(language: str) -> tuple[SastRule, ...]:
    """Regras que valem para a linguagem."""
    return tuple(
        rule for rule in (*SCRIPT_RULES, *WEB_RULES, *COMPILED_RULES) if language in rule.languages
    )


def language_of(item: SourceFile) -> str:
    return _LANGUAGE_BY_EXT.get(item.ext, "")


def is_vendored(rel: str) -> bool:
    """O caminho passa por uma pasta de bibliotecas de terceiros."""
    return any(part.lower() in _VENDOR_DIRS for part in rel.split("/")[:-1])


def is_skippable(item: SourceFile, text: str) -> bool:
    """Arquivo minificado, gerado ou de terceiros: o achado não seria do projeto."""
    if is_vendored(item.rel) or _GENERATED.search(item.lname):
        return True
    if _GENERATED_HEADER.search(text[:400]):
        return True
    return len(text) > 5000 and text.count("\n") < len(text) / 1000


@dataclass(frozen=True)
class RawHit:
    """Uma ocorrência já confirmada, antes do ajuste de contexto."""

    rule: SastRule
    index: int
    verdict: Verdict


_CONFIDENCE_ORDER = {Confidence.CONFIRMED: 0, Confidence.FIRM: 1, Confidence.TENTATIVE: 2}


@check(
    id="code.sast",
    name="Padrões inseguros no código",
    category=Category.CODE,
    consumes=facts.PROJECT,
    description=(
        "Procura no código-fonte (Python, JavaScript/TypeScript, PHP, Java, C#, Go e Ruby) "
        "execução de comandos e de código dinâmico, desserialização insegura, SQL montado "
        "com texto, TLS sem validação, hashes fracos para senhas, aleatoriedade previsível, "
        "XSS, JWT sem verificação e parsers XML vulneráveis. Só lê os arquivos: nada é executado."
    ),
    findings=SAST_FINDINGS,
    order=36,
)
def check_sast(ctx: CheckContext, fact: Fact) -> None:
    root = Path(str(fact.data.get("path") or fact.key))
    if not root.is_dir():
        return
    listing = project_files(ctx, root)
    limit = min(ctx.settings.max_file_bytes, MAX_SOURCE_BYTES)
    scanned = reported = omitted = 0
    per_rule: dict[str, int] = defaultdict(int)
    collected: list[tuple[SourceFile, str, str, RawHit, Severity, Confidence]] = []
    for item in listing.files:
        ctx.check_cancel()
        language = language_of(item)
        if not language or item.size > limit:
            continue
        text = read_text(item.path, limit)
        if text is None or is_skippable(item, text):
            continue
        scanned += 1
        for raw in scan_text(text, language):
            severity, confidence = grade(raw.rule, raw.verdict)
            severity, confidence, _where = context_adjust(item.rel, severity, confidence)
            collected.append((item, text, language, raw, severity, confidence))
    # os tetos valem depois de ordenar por gravidade: o que é grave nunca perde vaga para o leve
    collected.sort(
        key=lambda row: (-row[4].rank, _CONFIDENCE_ORDER[row[5]], row[0].rel, row[3].index)
    )
    per_file: dict[str, int] = defaultdict(int)
    for item, text, language, raw, _severity, _confidence in collected:
        if (
            reported >= MAX_TOTAL
            or per_rule[raw.rule.id] >= MAX_PER_RULE
            or per_file[item.rel] >= MAX_PER_FILE
        ):
            omitted += 1
            continue
        per_rule[raw.rule.id] += 1
        per_file[item.rel] += 1
        reported += 1
        _report(ctx, item, text, language, raw)
    ctx.log(f"SAST: {scanned} arquivos de código analisados, {reported} ocorrência(s).")
    if omitted:
        ctx.log(
            f"SAST: mais {omitted} ocorrências (as menos graves) além dos limites não foram "
            "detalhadas; corrija as listadas e rode de novo."
        )
    if scanned and not reported:
        ctx.passed(
            "code.sast",
            f"Nenhum padrão inseguro conhecido em {scanned} arquivos de código",
            str(root),
        )


# -- análise de um arquivo ------------------------------------------------------------------


def scan_text(text: str, language: str, *, dedupe: bool = True) -> list[RawHit]:
    """Aplica as regras da linguagem ao texto e devolve as ocorrências em ordem de posição."""
    candidates = [rule for rule in rules_for(language) if _applies(rule, text)]
    if not candidates:
        return []
    source = mask_source(text, language)
    tainted = cache_tainted(source, language)
    found: dict[tuple[str, int], RawHit] = {}
    for rule in candidates:
        view = source.code if rule.view == "code" else source.nostr
        for count, match in enumerate(rule.pattern.finditer(view)):
            if count >= MAX_MATCHES_PER_RULE:
                break
            hit = Hit(source, match, language, tainted)
            verdict = rule.confirm(hit) if rule.confirm is not None else Verdict()
            if verdict is None:
                continue
            index = verdict.index if verdict.index is not None else match.start()
            line = line_of(text, index)
            key = (rule.finding if dedupe else rule.id, line)
            previous = found.get(key)
            if previous is None or _better(verdict, previous.verdict):
                found[key] = RawHit(rule, index, verdict)
    return sorted(found.values(), key=lambda raw: raw.index)


def _applies(rule: SastRule, text: str) -> bool:
    if not any(keyword in text for keyword in rule.keywords):
        return False
    if rule.requires is not None and rule.requires.search(text) is None:
        return False
    return rule.unless is None or rule.unless.search(text) is None


def _better(new: Verdict, old: Verdict) -> bool:
    order = {"direta": 2, "indireta": 1, "": 0}
    return order[new.input_kind] > order[old.input_kind]


def cache_tainted(source: MaskedSource, language: str) -> Callable[[], dict[str, int]]:
    """Função preguiçosa dos nomes que recebem entrada externa (calculada na primeira consulta)."""
    holder: dict[str, int] | None = None

    def get() -> dict[str, int]:
        nonlocal holder
        if holder is None:
            holder = tainted_names(source, language)
        return holder

    return get


# -- relato -----------------------------------------------------------------------------------


def grade(rule: SastRule, verdict: Verdict) -> tuple[Severity, Confidence]:
    """Severidade e confiança: entrada externa sobe os dois; sem ela é pedido de revisão."""
    severity = verdict.severity or rule.severity
    confidence = verdict.confidence or rule.confidence
    if verdict.input_kind:
        indirect = verdict.input_kind != "direta"
        raised = (
            min(rule.severity_input, Severity.HIGH, key=lambda s: s.rank)
            if indirect
            else rule.severity_input
        )
        if raised.rank > severity.rank:
            severity = raised
        if not indirect:
            confidence = Confidence.FIRM
        elif confidence is Confidence.FIRM and verdict.confidence is None:
            confidence = Confidence.TENTATIVE  # fluxo indireto é inferência por nome
    return severity, confidence


def _report(ctx: CheckContext, item: SourceFile, text: str, language: str, raw: RawHit) -> None:
    rule = raw.rule
    line = line_of(text, raw.index)
    severity, confidence = grade(rule, raw.verdict)
    severity, confidence, where = context_adjust(item.rel, severity, confidence)
    details: dict[str, object] = {
        "arquivo": item.rel,
        "linha": line,
        "linguagem": language,
        "regra": rule.id,
        "cwe": rule.cwe,
    }
    if raw.verdict.input_kind:
        details["entrada_externa"] = raw.verdict.input_kind
    if raw.verdict.interpolated:
        details["valor_montado_com_variaveis"] = True
    if where:
        details["contexto"] = where
    ctx.report(
        rule.finding,
        asset=asset(item.rel, line),
        title=rule.title,
        severity=severity,
        confidence=confidence,
        evidence=_snippet(text, raw.index),
        details=details,
        discriminator=rule.id,
        tech=tech_of(item),
    )


def _snippet(text: str, index: int) -> str:
    start = text.rfind("\n", 0, index) + 1
    end = text.find("\n", index)
    line = text[start : len(text) if end < 0 else end].strip()
    return redact.redact(_mask_literals(line[:240]))


_USERINFO = re.compile(r"(://[^/:@\s\"']+:)[^@/\s\"']+(@)")
_LONG_LITERAL = re.compile(r"""(["'])([^"'\s]{12,})(?:\1)""")
_AUTH_LITERAL = re.compile(r"""(?i)((?:bearer|basic|token)\s+)[A-Za-z0-9._~+/=-]{12,}""")


def _mask_literals(line: str) -> str:
    """Esconde senha em URL, tokens Authorization e literais longos sem espaço (chaves)."""
    line = _USERINFO.sub(lambda m: m.group(1) + "***" + m.group(2), line)
    line = _AUTH_LITERAL.sub(lambda m: m.group(1) + "***", line)
    return _LONG_LITERAL.sub(lambda m: m.group(1) + redact.mask(m.group(2)) + m.group(1), line)
