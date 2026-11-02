"""Versões vulneráveis e sem suporte: cruza os fatos ``tech`` com ``net_vulns.json``.

``web.fingerprint`` e ``net.services`` ensinam produto e versão lidos em cabeçalhos e
banners. Aqui a versão é comparada com regras curadas (CVEs famosos e ramos sem
suporte), cada uma com a fonte oficial. Nada é explorado: a conclusão vem da versão
anunciada, no máximo com um ``OPTIONS`` comum para saber se o WebDAV está ativo.

A versão anunciada nem sempre conta toda a história. Distribuições corrigem falhas
sem mudar o número, então um banner com marca de distribuição (``(Ubuntu)``,
``-fips``, OpenSSH sem o sufixo ``p``) rebaixa o achado para indício. CVE no catálogo
CISA KEV sempre vira severidade crítica.
"""

from __future__ import annotations

import calendar
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from functools import lru_cache
from typing import Any

from ...core import facts, vulndb
from ...core import versions as versioning
from ...core.context import CheckContext
from ...core.http import Response
from ...core.models import Category, Confidence, Fact, Severity
from ...core.registry import check
from ...data import load_json
from . import kb_versions
from .common import service_asset
from .services import add_tech

DATA_FILE = "net_vulns.json"
MAX_VERSION = 40  # versão vem de banner: limita o que entra em títulos e evidências
MAX_OPTIONS = 4  # sites do mesmo host consultados para saber se o WebDAV está ativo

COND_WINDOWS = "windows"
COND_WEBDAV = "webdav"
#: tecnologias que revelam Windows no host (a regra do PHP-CGI depende disso)
WINDOWS_TECHS = frozenset({"windows", "iis", "iis-ftp"})
PRODUCT_LABEL = {"apache": "Apache httpd", "iis": "IIS", "php": "PHP", "openssh": "OpenSSH"}

_NUMBERS = re.compile(r"^v?(\d+(?:\.\d+)*)", re.I)
_PRERELEASE = re.compile(r"^[-._]?(alpha|beta|rc|dev|pre|preview|snapshot)[-._]?(\d*)", re.I)
_SUFFIX_LETTER = re.compile(r"^([a-z]{1,2})(?![a-z0-9])", re.I)
_PORTABLE = re.compile(r"^p(\d+)", re.I)
_OPENSSH_PORTABLE = re.compile(r"^\d+(?:\.\d+)*p\d+", re.I)
_VENDOR_MARK = re.compile(
    r"ubuntu|debian|\bdeb\d+u\d+|red\s?hat|\brhel|centos|rocky|almalinux|fedora|suse|\bsles"
    r"|amzn|amazon linux|oracle linux|raspbian|gentoo|\.el\d|-fips",
    re.I,
)
_WINDOWS_TEXT = re.compile(r"\bwin(?:32|64)\b|for_windows|microsoft-(?:iis|httpapi)", re.I)
_JENKINS_VERSION = re.compile(r"^\d+(?:\.\d+)+")


# -- regras ----------------------------------------------------------------------


@dataclass(frozen=True)
class VersionRange:
    """``introduced <= versão < fixed`` (ou ``<= last_affected``); ``parts`` limita o formato."""

    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    parts: int | None = None


@dataclass(frozen=True)
class Branch:
    """Ramo com data de fim de suporte e o texto que descreve a situação depois dela."""

    branch: str
    end: date
    status: str


@dataclass(frozen=True)
class Rule:
    """Uma regra curada de ``net_vulns.json``."""

    id: str
    finding: str
    product: str
    severity: Severity
    confidence: Confidence
    title: str
    summary: str
    references: tuple[str, ...]
    cves: tuple[str, ...] = ()
    ranges: tuple[VersionRange, ...] = ()
    branches: tuple[Branch, ...] = ()
    letters: bool = False
    condition: str = ""


def _end_date(text: str) -> date:
    """``AAAA-MM-DD``, ``AAAA-MM`` ou ``AAAA``: datas parciais valem até o fim do período."""
    pieces = [int(piece) for piece in text.split("-")]
    year = pieces[0]
    month = pieces[1] if len(pieces) > 1 else 12
    day = pieces[2] if len(pieces) > 2 else calendar.monthrange(year, month)[1]
    return date(year, month, day)


def _parse_branch(item: Mapping[str, Any]) -> Branch:
    end = _end_date(str(item["fim"]))
    status = str(item.get("texto") or f"sem atualizações de segurança desde {end:%d/%m/%Y}")
    return Branch(str(item["ramo"]), end, status)


def _parse_range(item: Mapping[str, Any]) -> VersionRange:
    return VersionRange(
        introduced=item.get("introduzida"),
        fixed=item.get("corrigida"),
        last_affected=item.get("ultima_afetada"),
        parts=item.get("partes"),
    )


def _parse_rule(item: Mapping[str, Any]) -> Rule:
    return Rule(
        id=str(item["id"]),
        finding=str(item["achado"]),
        product=str(item["produto"]),
        severity=Severity.parse(str(item["severidade"])),
        confidence=Confidence(str(item["confianca"])),
        title=str(item["titulo"]),
        summary=str(item["resumo"]),
        references=tuple(item["referencias"]),
        cves=tuple(item.get("cves", ())),
        ranges=tuple(_parse_range(part) for part in item.get("faixas", ())),
        branches=tuple(_parse_branch(part) for part in item.get("ramos", ())),
        letters=bool(item.get("letras")),
        condition=str(item.get("condicao") or ""),
    )


@lru_cache(maxsize=1)
def load_rules() -> tuple[Rule, ...]:
    return tuple(_parse_rule(item) for item in load_json(DATA_FILE)["regras"])


@lru_cache(maxsize=1)
def _aliases() -> dict[str, str]:
    table: dict[str, str] = {}
    for canonical, names in load_json(DATA_FILE)["apelidos"].items():
        table.update({str(name).lower(): str(canonical) for name in names})
    return table


def canonical_product(name: object) -> str:
    """Nome canônico do produto: minúsculas e apelidos (``httpd``, ``microsoft-iis``...)."""
    text = str(name or "").strip().lower()
    return _aliases().get(text, text)


def rules_for(product: str) -> tuple[Rule, ...]:
    return tuple(rule for rule in load_rules() if rule.product == product)


@lru_cache(maxsize=1)
def _relevant_products() -> frozenset[str]:
    return frozenset(rule.product for rule in load_rules()) | WINDOWS_TECHS


# -- comparação de versões ---------------------------------------------------------


def _letter_value(letters: str) -> int:
    """Sufixo de letra como número: ``a`` = 1, ``g`` = 7, ``za`` = 27 (OpenSSL 1.0.2za)."""
    value = 0
    for char in letters.lower():
        value = value * 26 + ord(char) - ord("a") + 1
    return value


def normalize_version(raw: str, *, letters: bool = False) -> str:
    """Só o que importa para comparar, sem a revisão do pacote.

    ``7.4.3-4ubuntu2.20`` → ``7.4.3``; ``4.90_1`` → ``4.90``; ``2.4.51-dev`` → ``2.4.51-dev``.
    Com ``letters``, a letra vem depois do número (``1.0.1e-fips`` → ``1.0.1.5``): no
    comparador do núcleo, ``a``, ``b`` e ``c`` seriam pré-lançamentos.
    """
    text = raw.strip()
    match = _NUMBERS.match(text)
    if match is None:
        return ""
    numbers, rest = match.group(1), text[match.end() :]
    prerelease = _PRERELEASE.match(rest)
    if prerelease:
        return f"{numbers}-{prerelease[1].lower()}{prerelease[2]}"
    if letters:
        letter = _SUFFIX_LETTER.match(rest)
        return f"{numbers}.{_letter_value(letter[1])}" if letter else numbers
    portable = _PORTABLE.match(rest)
    return f"{numbers}p{portable[1]}" if portable else numbers


def _bound(rule: Rule, value: str | None) -> str | None:
    return normalize_version(value, letters=rule.letters) if value else None


def _part_count(version: str) -> int:
    match = _NUMBERS.match(version)
    return len(match.group(1).split(".")) if match else 0


def matches_range(rule: Rule, version: str) -> bool:
    """A versão cai em alguma faixa afetada da regra?"""
    current = normalize_version(version, letters=rule.letters)
    if not current:
        return False
    for item in rule.ranges:
        if item.parts and _part_count(current) != item.parts:
            continue
        if versioning.in_range(
            current,
            introduced=_bound(rule, item.introduced),
            fixed=_bound(rule, item.fixed),
            last_affected=_bound(rule, item.last_affected),
        ):
            return True
    return False


def find_branch(rule: Rule, version: str) -> Branch | None:
    """Ramo da versão (``7.4`` casa com ``7.4.33``, mas não com ``7.40.1``)."""
    match = _NUMBERS.match(version.strip())
    if match is None:
        return None
    numbers = match.group(1).split(".")
    for item in rule.branches:
        parts = item.branch.split(".")
        if numbers[: len(parts)] == parts:
            return item
    return None


def vendor_marked(product: str, version: str, origin: str) -> bool:
    """O banner sugere pacote de distribuição, que pode ter a correção sem mudar o número?"""
    if _VENDOR_MARK.search(f"{version} {origin}"):
        return True
    return product == "openssh" and _OPENSSH_PORTABLE.match(version) is None


def today() -> date:
    """Data atual (função à parte para os testes de fim de suporte)."""
    return date.today()


# -- checagem ----------------------------------------------------------------------


@dataclass(frozen=True)
class Seen:
    """Uma tecnologia com versão vista em um host."""

    host: str
    port: int | None
    product: str
    version: str
    origin: str

    @property
    def asset(self) -> str:
        return service_asset(self.host, self.port) if self.port else self.host

    @property
    def label(self) -> str:
        return PRODUCT_LABEL.get(self.product, self.product)


@dataclass(frozen=True)
class Proof:
    """Resultado da condição extra de uma regra: vale? em que base? com dúvida?"""

    applies: bool
    note: str = ""
    doubtful: bool = False


def _is_relevant(fact: Fact) -> bool:
    return canonical_product(fact.data.get("name")) in _relevant_products()


@check(
    id="net.versions",
    name="Versões vulneráveis e sem suporte",
    category=Category.NETWORK,
    consumes=facts.TECH,
    when=_is_relevant,
    description=(
        "Compara as versões anunciadas em banners e cabeçalhos com uma lista curada de falhas "
        "famosas (Apache, OpenSSL, vsftpd, ProFTPD, Exim, PHP, IIS, Jenkins) e de ramos sem "
        "suporte. Não explora nada: uma versão com marca de distribuição vira só indício."
    ),
    findings=kb_versions.FINDINGS,
    order=40,
)
def check_versions(ctx: CheckContext, fact: Fact) -> None:
    seen = _seen(fact)
    if seen is not None:
        for rule in rules_for(seen.product):
            ctx.check_cancel()
            _apply(ctx, rule, seen)
    _recheck_windows_rules(ctx, fact)


@check(
    id="net.versions.jenkins",
    name="Versão do Jenkins no cabeçalho",
    category=Category.NETWORK,
    consumes=facts.HTTP_SERVICE,
    description=(
        "Lê o cabeçalho X-Jenkins da página inicial de cada site e ensina o produto e a versão "
        "para a checagem de versões vulneráveis."
    ),
    facts=(facts.TECH,),
    order=6,
)
def check_jenkins_header(ctx: CheckContext, fact: Fact) -> None:
    url = str(fact.data.get("url") or fact.key)
    resp = ctx.http.get(url, max_bytes=4096)
    value = (resp.header("x-jenkins") or "").strip() if resp is not None else ""
    if not _JENKINS_VERSION.match(value):
        return
    add_tech(
        ctx,
        str(fact.data.get("host") or ""),
        int(fact.data.get("port") or 0),
        "jenkins",
        value[:MAX_VERSION],
        "service",
        f"X-Jenkins: {value[:MAX_VERSION]}",
    )


def _seen(fact: Fact) -> Seen | None:
    data = fact.data
    product = canonical_product(data.get("name"))
    raw = "".join(ch for ch in str(data.get("version") or "") if ch.isprintable())
    version = raw.strip()[:MAX_VERSION]
    host = str(data.get("host") or fact.key.rsplit(":", 1)[0])
    if not product or not version or not host:
        return None
    try:
        port = int(data.get("port") or 0) or None
    except (TypeError, ValueError):
        port = None
    return Seen(host, port, product, version, str(data.get("evidence") or ""))


def _reveals_windows(fact: Fact) -> bool:
    """A tecnologia (``iis``, ``windows``) ou o banner dela (``(Win64)``) revelam Windows?"""
    if canonical_product(fact.data.get("name")) in WINDOWS_TECHS:
        return True
    return _WINDOWS_TEXT.search(str(fact.data.get("evidence") or "")) is not None


def _recheck_windows_rules(ctx: CheckContext, fact: Fact) -> None:
    """O sinal de Windows pode chegar depois do PHP: reavalia as regras que dependem dele."""
    if not _reveals_windows(fact):
        return
    host = fact.data.get("host")
    for other in ctx.facts(facts.TECH):
        seen = _seen(other) if other.data.get("host") == host else None
        if seen is None:
            continue
        for rule in rules_for(seen.product):
            if rule.condition == COND_WINDOWS:
                _apply(ctx, rule, seen)


def _apply(ctx: CheckContext, rule: Rule, seen: Seen) -> None:
    if rule.branches:
        _apply_branches(ctx, rule, seen)
    elif matches_range(rule, seen.version):
        proof = _proof(ctx, rule, seen)
        if proof.applies:
            _report(ctx, rule, seen, proof)


def _apply_branches(ctx: CheckContext, rule: Rule, seen: Seen) -> None:
    branch = find_branch(rule, seen.version)
    if branch is None:
        return
    if today() > branch.end:
        _report(ctx, rule, seen, Proof(True), status=branch.status, branch=branch.branch)
    else:
        ctx.log(
            f"{seen.label} {seen.version}: ramo {branch.branch} com suporte até "
            f"{branch.end:%d/%m/%Y} (o patch instalado não é verificado pelo banner)."
        )


def _proof(ctx: CheckContext, rule: Rule, seen: Seen) -> Proof:
    if rule.condition == COND_WINDOWS:
        return _windows_proof(ctx, seen)
    if rule.condition == COND_WEBDAV:
        return _webdav_proof(ctx, seen)
    return Proof(True)


def _windows_proof(ctx: CheckContext, seen: Seen) -> Proof:
    for item in ctx.facts(facts.TECH):
        if item.data.get("host") == seen.host and _reveals_windows(item):
            return Proof(True, f"O host foi identificado como Windows ({item.data.get('label')}).")
    return Proof(False)


def _webdav_signal(resp: Response) -> str:
    """Trecho da resposta ao OPTIONS que anuncia WebDAV (vazio se não anuncia)."""
    dav = resp.header("dav")
    if dav:
        return f"DAV: {dav}"
    for name in ("allow", "public"):
        value = resp.header(name) or ""
        if "PROPFIND" in value.upper():
            return f"{name.capitalize()}: {value}"
    return ""


def _http_urls(ctx: CheckContext, seen: Seen) -> list[str]:
    urls = [
        str(item.data.get("url") or item.key)
        for item in ctx.facts(facts.HTTP_SERVICE)
        if item.data.get("host") == seen.host
        and (not seen.port or item.data.get("port") == seen.port)
    ]
    return urls[:MAX_OPTIONS]


def _webdav_proof(ctx: CheckContext, seen: Seen) -> Proof:
    answered = False
    for url in _http_urls(ctx, seen):
        ctx.check_cancel()
        resp = ctx.http.options(url, follow_redirects=False)
        if resp is None:
            continue
        answered = True
        signal = _webdav_signal(resp)
        if signal:
            return Proof(True, f"OPTIONS {url} anuncia WebDAV ({signal}).")
    if answered:
        return Proof(False)  # o site respondeu sem WebDAV: esta falha não se aplica
    return Proof(
        True, "Não foi possível confirmar se o WebDAV está ativo (OPTIONS sem resposta).", True
    )


def _kev_lines(cves: tuple[str, ...]) -> list[str]:
    lines = []
    for cve in cves:
        entry = vulndb.kev_entry(cve)
        if entry is not None:
            extra = ", com uso conhecido em ransomware" if entry.ransomware else ""
            lines.append(f"{cve} está no catálogo CISA KEV desde {entry.date_added}{extra}.")
    return lines


def _evidence(rule: Rule, seen: Seen, proof: Proof, marked: bool) -> str:
    source = f" ({seen.origin})" if seen.origin else ""
    lines = [f"{seen.label} {seen.version}{source}."]
    if proof.note:
        lines.append(proof.note)
    if marked:
        lines.append(
            "O banner sugere um pacote de distribuição: o fornecedor pode ter aplicado a correção "
            "sem mudar o número da versão. Confira o pacote instalado."
        )
    lines.extend(_kev_lines(rule.cves))
    return "\n".join(lines)


def _report(
    ctx: CheckContext,
    rule: Rule,
    seen: Seen,
    proof: Proof,
    *,
    status: str = "",
    branch: str = "",
) -> None:
    marked = vendor_marked(seen.product, seen.version, seen.origin)
    cves = list(rule.cves)
    kev = vulndb.any_kev(cves)
    details: dict[str, Any] = {
        "produto": seen.product,
        "versao": seen.version,
        "regra": rule.id,
        "resumo": rule.summary,
        "referencias": list(rule.references),
    }
    if branch:
        details.update({"ramo": branch, "situacao": status})
    confidence = Confidence.TENTATIVE if marked or proof.doubtful else rule.confidence
    ctx.report(
        rule.finding,
        asset=seen.asset,
        title=rule.title.format(versao=seen.version, situacao=status),
        severity=Severity.CRITICAL
        if kev and confidence is not Confidence.TENTATIVE
        else rule.severity,
        evidence=_evidence(rule, seen, proof, marked),
        details=details,
        confidence=confidence,
        cves=cves,
        kev=kev,
        discriminator=rule.id,
        tech=[seen.product],
    )
