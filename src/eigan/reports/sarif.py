"""SARIF 2.1.0: os achados para GitHub code scanning, Azure DevOps e IDEs.

Achados de código apontam para o arquivo (``uri`` relativa à raiz do projeto, com
``region.startLine`` quando há linha). Achados web apontam para a URL; os de rede e de
host, para um local lógico (host e porta). Todo texto que vem do alvo sai com os
caracteres invisíveis à mostra e a evidência sai com os segredos mascarados.
"""

from __future__ import annotations

import posixpath
import re
from datetime import UTC
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

from .. import __version__
from ..core import fmt
from ..core.kb import Fix, KBEntry
from ..core.models import (
    Confidence,
    Exposure,
    Finding,
    ScanResult,
    Severity,
    TargetKind,
    TriageStatus,
)
from ..core.redact import redact
from ..intel import scoring
from ..intel.remediation import entry_for
from .common import as_dict, as_list, clip, ensure_analysis, is_web_url, json_text, scrub, visible
from .view_annex import RUN_STATUS

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
INFORMATION_URI = "https://github.com/tue3306/eigan"
SRCROOT = "SRCROOT"
FINGERPRINT_KEY = "eiganFingerprint/v1"

SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.5",
    Severity.INFO: "0.0",
}
PRECISION = {
    Confidence.CONFIRMED: "very-high",
    Confidence.FIRM: "high",
    Confidence.TENTATIVE: "medium",
}
_PRECISION_RANK = {"very-high": 3, "high": 2, "medium": 1}
_SUPPRESSED = (TriageStatus.ACCEPTED, TriageStatus.FALSE_POSITIVE, TriageStatus.FIXED)
# caminho/relativo:linha[:coluna] (convenção dos achados de código)
_CODE_LOCATION = re.compile(r"^(?P<path>[^\r\n]+?):(?P<line>\d{1,9})(?::\d{1,9})?$")
_WINDOWS_PATH = re.compile(r"^[A-Za-z]:/")
_LONE_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")
# Separadores que podem ficar como estão numa URI (sem aspas, espaços nem < >).
_URI_SAFE = "!$&()*+,;=:@%-._~"
MAX_EVIDENCE = 1000
MAX_TEXT = 2000
MAX_FIX = 6000


def _quote(text: str, safe: str = "/") -> str:
    """Codifica para URI; substituto solto (nome de arquivo inválido) também vira ``%XX``."""
    return quote(text, safe=safe, errors="surrogatepass")


def render_sarif(result: ScanResult) -> str:
    """O resultado em SARIF 2.1.0 (calcula a análise se ainda não existir)."""
    analysis = ensure_analysis(result)
    by_rule: dict[str, list[Finding]] = {}
    for finding in result.findings:
        by_rule.setdefault(finding.check_id, []).append(finding)
    rule_index = {check_id: index for index, check_id in enumerate(by_rule)}
    rules = [_rule(check_id, findings) for check_id, findings in by_rule.items()]
    baseline = _baseline_states(analysis.get("diff"))
    code_scan = result.kind is TargetKind.PROJECT
    project = _project_path(result) if code_scan else ""
    results = [
        _result(finding, rule_index[finding.check_id], code_scan, baseline, project)
        for finding in result.findings
    ]
    posture = as_dict(analysis.get("posture"))
    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "EIGAN",
                "version": __version__,
                "semanticVersion": __version__,
                "informationUri": INFORMATION_URI,
                "language": "pt-BR",
                "rules": rules,
            }
        },
        "automationDetails": {"id": f"eigan/{result.kind.value}/{_text(result.id, 200)}"},
        "invocations": [_invocation(result)],
        "results": results,
        "properties": {
            "target": _text(result.target),
            "targetKind": result.kind.value,
            "profile": _text(result.profile, 100),
            "scanId": _text(result.id, 200),
            "evaluated": bool(analysis.get("evaluated")),
            "score": posture.get("score"),
            "grade": posture.get("grade"),
        },
    }
    root = _source_root(project)
    if root:
        run["originalUriBaseIds"] = {SRCROOT: {"uri": root}}
    sarif = {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}
    return json_text(sarif)


# -- regras -----------------------------------------------------------------------------------


def _rule(check_id: str, findings: list[Finding]) -> dict[str, Any]:
    entry = entry_for(findings[0])
    worst = max((f.severity for f in findings), key=lambda s: s.rank)
    precision = min((PRECISION[f.confidence] for f in findings), key=lambda p: _PRECISION_RANK[p])
    title = _text(entry.title or findings[0].title or check_id, 300)
    rule: dict[str, Any] = {
        "id": check_id,
        "name": _rule_name(check_id),
        "shortDescription": {"text": title},
        "fullDescription": {"text": _text(entry.summary or title)},
        "help": {"text": _help_text(entry, title), "markdown": _help_markdown(entry, title)},
        "defaultConfiguration": {"level": SARIF_LEVEL[entry.severity]},
        "properties": {
            "tags": _tags(entry),
            "security-severity": SECURITY_SEVERITY[worst],
            "precision": precision,
        },
    }
    links = _references(entry)
    if links:
        rule["helpUri"] = links[0]
    return rule


def _rule_name(check_id: str) -> str:
    """``web.https.sem_redirecionamento`` vira ``WebHttpsSemRedirecionamento``."""
    parts = [p for p in re.split(r"[^0-9A-Za-z]+", check_id) if p]
    return "".join(p[:1].upper() + p[1:] for p in parts) or "Regra"


def _tags(entry: KBEntry) -> list[str]:
    tags = ["security", entry.category.value]
    if entry.cwe:
        tags.append(entry.cwe.upper())
        number = entry.cwe.upper().removeprefix("CWE-").strip()
        if number.isdigit():
            tags.append(f"external/cwe/cwe-{number}")
    if entry.owasp:
        tags.append(f"OWASP-{entry.owasp}")
    tags += [f"CIS-v8-{control}" for control in entry.cis]
    if entry.lgpd:
        tags.append("LGPD")
    return list(dict.fromkeys(visible(tag) for tag in tags))  # sem repetição (uniqueItems)


def _references(entry: KBEntry) -> list[str]:
    """Só referências ``http(s)`` bem formadas viram link (``javascript:`` fica de fora)."""
    return [safe_url(url) for url in entry.references if is_web_url(url)]


def _help_text(entry: KBEntry, title: str) -> str:
    lines = [f"{n}. {_text(step)}" for n, step in enumerate(entry.steps, 1)]
    if entry.verify:
        lines.append(f"Como verificar: {_text(entry.verify)}")
    return "\n".join(lines) or _text(entry.summary) or title


def _help_markdown(entry: KBEntry, title: str) -> str:
    parts = [f"**{_md(title)}**"]
    if entry.summary and entry.summary != entry.title:
        parts.append(_md(entry.summary))
    if entry.risk:
        parts.append(f"**Risco:** {_md(entry.risk)}")
    if entry.steps:
        steps = "\n".join(f"{n}. {_md(step)}" for n, step in enumerate(entry.steps, 1))
        parts.append(f"**Como corrigir**\n\n{steps}")
    if entry.verify:
        parts.append(f"**Como verificar:** {_md(entry.verify)}")
    for fix in entry.examples:
        parts.append(f"**Exemplo de correção: {_md(fix.label or fix.tech)}**\n\n{_fenced(fix)}")
    links = _references(entry)
    if links:
        parts.append("**Referências**\n\n" + "\n".join(f"- <{url}>" for url in links))
    return "\n\n".join(parts)


def _fenced(fix: Fix) -> str:
    """Bloco de código Markdown com cerca mais longa que qualquer crase do próprio exemplo."""
    code = _text(fix.code, MAX_FIX)
    longest = max((len(run) for run in re.findall(r"`+", code)), default=0)
    fence = "`" * max(3, longest + 1)
    lang = re.sub(r"[^0-9A-Za-z_+-]", "", fix.lang)
    return f"{fence}{lang}\n{code}\n{fence}"


# -- resultados ---------------------------------------------------------------------------------


def _result(
    finding: Finding,
    index: int,
    code_scan: bool,
    baseline: dict[str, str],
    project: str = "",
) -> dict[str, Any]:
    title = _text(finding.title, 500)
    asset = _text(finding.asset, 500)
    evidence = _text(redact(finding.evidence.strip("\r\n")), MAX_EVIDENCE)
    item: dict[str, Any] = {
        "ruleId": finding.check_id,
        "ruleIndex": index,
        "level": SARIF_LEVEL[finding.severity],
        "message": {"text": f"{title} — {asset}" if asset else title or finding.check_id},
        "locations": [location(finding, code_scan, project)],
        "partialFingerprints": {FINGERPRINT_KEY: finding.fingerprint},
        "properties": {
            "priority": finding.priority,
            "band": finding.priority_label or scoring.priority_band(finding.priority)[0],
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "exposure": finding.exposure.value,
            "cves": [_text(cve, 100) for cve in finding.cves],
            "kev": finding.kev,
            "status": finding.status.value,
            "firstSeen": finding.first_seen,
            "evidence": evidence,
        },
    }
    state = baseline.get(finding.fingerprint)
    if state:
        item["baselineState"] = state
    if finding.status in _SUPPRESSED:
        item["suppressions"] = [
            {
                "kind": "external",
                "status": "accepted",
                "justification": _text(
                    finding.status_note
                    or (
                        "Marcado como corrigido; a próxima auditoria confirma."
                        if finding.status is TriageStatus.FIXED
                        else finding.status.label
                    ),
                    1000,
                ),
            }
        ]
    return item


def location(finding: Finding, code_scan: bool = False, project: str = "") -> dict[str, Any]:
    """Onde o achado está: arquivo e linha, URL, ou um local lógico (host, porta...)."""
    asset = scrub(finding.asset.strip())
    if code_scan or finding.check_id.startswith("code.") or finding.exposure is Exposure.CODE:
        physical = _code_location(asset, project)
        if physical:
            return {"physicalLocation": physical}
    logical = [{"name": _text(asset, 500) or finding.check_id, "kind": "resource"}]
    if is_web_url(asset):
        return {
            "physicalLocation": {"artifactLocation": {"uri": safe_url(asset)}},
            "logicalLocations": logical,
        }
    return {"logicalLocations": logical}


def _code_location(asset: str, project: str = "") -> dict[str, Any] | None:
    """``src/app.py:12`` vira arquivo + ``region.startLine``; ``requirements.txt``, só o arquivo."""
    if not asset or is_web_url(asset):
        return None
    match = _CODE_LOCATION.match(asset)
    path = match.group("path") if match else asset
    if any(ch in path for ch in "\r\n\t") or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", path):
        return None
    path = _relative_to(path, project)
    if not path:  # o achado é sobre a pasta do projeto, não sobre um arquivo dela
        return None
    physical: dict[str, Any] = {"artifactLocation": _artifact(path)}
    if match and int(match.group("line")) >= 1:
        physical["region"] = {"startLine": int(match.group("line"))}
    return physical


def _artifact(path: str) -> dict[str, str]:
    """``src\\app.py`` vira ``src/app.py`` relativo à raiz (``SRCROOT``), como pede o SARIF."""
    uri = path.strip().replace("\\", "/")
    while uri.startswith("./"):
        uri = uri[2:]
    if _WINDOWS_PATH.match(uri):
        return {"uri": "file:///" + _quote(uri, safe="/:")}
    if uri.startswith("//"):  # caminho de rede (\\servidor\pasta)
        return {"uri": "file:" + _quote(uri, safe="/")}
    if uri.startswith("/"):
        return {"uri": "file://" + _quote(uri, safe="/")}
    normal = posixpath.normpath(uri) if uri else ""
    if normal in ("", ".") or normal == ".." or normal.startswith("../"):
        # sai da raiz do projeto: sem SRCROOT, o uri não finge estar dentro dele
        return {"uri": _quote(uri, safe="/")}
    return {"uri": _quote(normal, safe="/"), "uriBaseId": SRCROOT}


def _project_path(scan: ScanResult) -> str:
    """Pasta do projeto auditado com barras normais e sem a barra final."""
    return scan.target.strip().replace("\\", "/").rstrip("/")


def _relative_to(path: str, project: str) -> str:
    """Caminho dentro do projeto vira relativo (no Windows, sem diferenciar maiúsculas)."""
    plain = path.strip().replace("\\", "/").rstrip("/")
    if not project:
        return path
    windows = bool(_WINDOWS_PATH.match(project + "/"))
    same = plain.lower() == project.lower() if windows else plain == project
    if same:
        return ""
    prefix = project + "/"
    inside = plain[: len(prefix)].lower() == prefix.lower() if windows else plain.startswith(prefix)
    return plain[len(prefix) :] if inside else path


def _source_root(path: str) -> str:
    """Raiz dos caminhos relativos quando o alvo é um projeto local (``file:///.../``)."""
    if _WINDOWS_PATH.match(path + "/"):
        return "file:///" + _quote(path, safe="/:") + "/"
    if path.startswith("/") and not path.startswith("//"):
        return "file://" + _quote(path, safe="/") + "/"
    return ""


def safe_url(url: str) -> str:
    """URL de link com aspas, espaços, ``< >`` e não ASCII codificados (``%22``, ``%3C``...)."""
    parts = urlsplit(_LONE_PERCENT.sub("%25", url))
    return urlunsplit(
        (
            parts.scheme.lower(),
            _quote(parts.netloc, safe=_URI_SAFE + "[]"),
            _quote(parts.path, safe=_URI_SAFE + "/"),
            _quote(parts.query, safe=_URI_SAFE + "/?"),
            _quote(parts.fragment, safe=_URI_SAFE + "/?"),
        )
    )


# -- execução e comparação ------------------------------------------------------------------------


def _invocation(result: ScanResult) -> dict[str, Any]:
    invocation: dict[str, Any] = {"executionSuccessful": result.status == "concluida"}
    start, end = _utc(result.started_at), _utc(result.finished_at)
    if start:
        invocation["startTimeUtc"] = start
    if end:
        invocation["endTimeUtc"] = end
    notes = [str(error) for error in result.errors]
    notes += [
        f"{run.name or run.check_id}: {RUN_STATUS.get(run.status, run.status)}"
        + (f" ({run.message})" if run.message else "")
        for run in result.runs
        if run.status != "ok"
    ]
    if notes:
        invocation["toolExecutionNotifications"] = [
            {"level": "warning", "message": {"text": _text(redact(note))}} for note in notes
        ]
    return invocation


def _baseline_states(diff: Any) -> dict[str, str]:
    states: dict[str, str] = {}
    data = as_dict(diff)
    for key, state in (("new", "new"), ("persisting", "unchanged")):
        for item in as_list(data.get(key)):
            fingerprint = as_dict(item).get("fingerprint")
            if fingerprint:
                states[str(fingerprint)] = state
    return states


def _utc(value: str) -> str:
    moment = fmt.parse_iso(value)
    if moment is None:
        return ""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# -- texto ----------------------------------------------------------------------------------------


def _text(value: object, limit: int = MAX_TEXT) -> str:
    """Texto do alvo com os caracteres invisíveis à mostra e tamanho limitado."""
    return clip(visible(scrub(str(value))), limit)[0]


def _md(value: object) -> str:
    """Texto para Markdown sem virar HTML, link ou código (``<``, ``[``, crase...)."""
    text = _text(value).replace("\\", "\\\\").replace("&", "&amp;")
    text = text.replace("<", "&lt;").replace(">", "&gt;")
    for ch in "[]`*_":
        text = text.replace(ch, "\\" + ch)
    return text
