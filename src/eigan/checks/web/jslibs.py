"""Bibliotecas JavaScript com vulnerabilidades conhecidas (base do retire.js).

A identificação é a do retire.js (Apache-2.0), com a base embarcada em
``eigan/data/web_retire.json``. Para cada ``<script>`` da página:

1. o endereço passa pelos extratores ``uri`` e ``filename`` (sem baixar nada);
2. o conteúdo passa por ``filecontent``, ``filecontentreplace`` e ``hashes``: scripts da
   mesma origem conforme o perfil e, só no perfil completo, os de CDN.

O conteúdo tem prioridade: uma pasta chamada ``/1.2.3/`` pode ser a versão da aplicação,
não a da biblioteca. A versão encontrada é comparada com as faixas ``below`` e
``atOrAbove`` da base, com a mesma regra do retire.js. Os CVEs são cruzados com o
catálogo CISA KEV embarcado. Nenhuma consulta externa é feita sobre o que foi achado.
"""

from __future__ import annotations

import hashlib
import importlib
import re
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any
from urllib.parse import urlsplit

from ...core import facts, vulndb
from ...core.context import CheckContext
from ...core.http import Response
from ...core.models import Category, Confidence, Fact, Severity
from ...core.registry import check
from ...data import load_json
from . import kb_jslibs  # noqa: F401 — registra a entrada da base
from .common import (
    fetch_script,
    hints,
    load_page,
    page_doc,
    profile_level,
    run_parallel,
    same_origin,
    skip_reason,
)
from .htmlscan import HtmlDoc

DATA_FILE = "web_retire.json"

#: o que o retire.js coloca no lugar de ``§§version§§``
VERSION_PATTERN = r"[0-9][0-9.a-z_\-]+"
_PLACEHOLDER = "§§version§§"
#: JavaScript aceita lookbehind de largura variável; o ``re`` do Python não. A única
#: ocorrência da base (lodash) exige x.y.z com até dois dígitos, e é o que este grupo faz.
_JS_ONLY = (
    (
        f"({_PLACEHOLDER})(?<=[0-9]{{1,2}}\\.[0-9]{{1,2}}\\.[0-9]{{1,2}})",
        r"([0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2})",
    ),
)
_NAMED_GROUP = re.compile(r"\(\?<([A-Za-z_]\w*)>")
_BUILD_SUFFIX = re.compile(
    r"(?:[.-](?:min|slim|bundle|esm|umd|cjs|module|pack|custom|prod|production|compat))+$", re.I
)
#: ``\s`` (ou classe com ``\s``) seguido de ``+``/``*`` sem limite: quadrático em texto hostil
_OPEN_SPACE_RUN = re.compile(r"(\[(?:\\.|[^\]\\])*\\s(?:\\.|[^\]\\])*\]|\\s)([+*])")
_RUN_LIMIT = 100
#: padrões maiores que isto (a base embarcada não chega perto) são descartados
_PATTERN_MAX = 1000
#: o começo do arquivo basta para banners e versões; o resto só custaria tempo
SCAN_MAX_CHARS = 400_000
#: pacotes npm sem ``npmname`` na base, cujo nome na base é o mesmo do pacote
_NPM_FALLBACK = {
    n: n
    for n in ("lodash", "bootstrap", "handlebars", "axios", "vue", "react", "marked", "knockout")
}
#: extratores do EIGAN por cima da base: o lodash minificado só traz a versão em ``X.VERSION``
_EXTRA_CONTENT = {
    "lodash": (r"\.VERSION\s*=\s*\"(§§version§§)\"\s*,\s*[\w$]{1,6}\(\s*\"bind bindKey curry",),
}
_REPLACE_SPEC = re.compile(r"^/(.*[^\\])/([^/]+)/$", re.S)
_DOLLAR_GROUP = re.compile(r"\$(\d)")
_NUMERIC = re.compile(r"[0-9]+")
_PARTS = re.compile(r"[.-]")
#: ``below`` a partir daqui significa "sem versão corrigida" (regra do repositório retire.js)
_NO_FIX = re.compile(r"(?:^|\.)999(?:\.|$)")

_SEVERITIES = {
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}
_SEVERITY_TEXT = {
    Severity.LOW: "baixa",
    Severity.MEDIUM: "média",
    Severity.HIGH: "alta",
    Severity.CRITICAL: "crítica",
}
#: o tipo de falha em português (o resumo da base é em inglês); o resto mostra só o CWE
_CWE_TEXT = {
    "CWE-20": "validação de entrada incorreta",
    "CWE-22": "acesso a arquivos fora da pasta permitida",
    "CWE-74": "injeção de conteúdo",
    "CWE-79": "XSS (execução de script no navegador)",
    "CWE-94": "injeção de código",
    "CWE-200": "exposição de informação",
    "CWE-201": "envio de informação sensível",
    "CWE-285": "autorização incorreta",
    "CWE-352": "CSRF (requisição forjada)",
    "CWE-400": "negação de serviço por consumo de recursos",
    "CWE-407": "negação de serviço por complexidade do algoritmo",
    "CWE-409": "negação de serviço por dados muito comprimidos",
    "CWE-434": "envio de arquivo perigoso",
    "CWE-502": "desserialização insegura",
    "CWE-601": "redirecionamento aberto",
    "CWE-674": "negação de serviço por recursão sem limite",
    "CWE-770": "negação de serviço por alocação sem limite",
    "CWE-918": "SSRF (requisição forjada pelo servidor)",
    "CWE-1321": "poluição de protótipo",
    "CWE-1333": "negação de serviço por expressão regular (ReDoS)",
    "CWE-1395": "dependência de componente vulnerável",
}
_METHOD_TEXT = {
    "uri": "pelo endereço do script",
    "filename": "pelo nome do arquivo",
    "filecontent": "pelo conteúdo do arquivo",
    "filecontentreplace": "pelo conteúdo do arquivo",
    "hash": "pelo hash do arquivo",
}
_CONTENT_METHODS = frozenset({"filecontent", "filecontentreplace", "hash"})

#: scripts da mesma origem lidos por perfil (rápido, padrão, completo)
SAME_ORIGIN_LIMITS = (5, 15, 30)
#: scripts de CDN lidos no perfil completo
CDN_LIMIT = 10
#: orçamento para aplicar as expressões em um único script e na auditoria de uma página
_SCRIPT_SECONDS = 20.0
_MAX_EVIDENCE_LINES = 10


# -- base embarcada ------------------------------------------------------------------------


@dataclass(frozen=True)
class Vulnerability:
    """Uma faixa vulnerável da base."""

    below: str | None
    at_or_above: str | None
    excludes: tuple[str, ...]
    severity: Severity
    cves: tuple[str, ...]
    cwes: tuple[str, ...]
    summary: str
    advisory: str
    info: tuple[str, ...]

    def affects(self, version: str) -> bool:
        if self.below is not None and is_at_or_above(version, self.below):
            return False
        if self.at_or_above is not None and not is_at_or_above(version, self.at_or_above):
            return False
        return version not in self.excludes

    @property
    def has_fix(self) -> bool:
        return self.below is not None and _NO_FIX.search(self.below) is None


@dataclass(frozen=True)
class Library:
    """Extratores já compilados e vulnerabilidades de uma biblioteca."""

    name: str
    uri: tuple[re.Pattern[str], ...] = ()
    filename: tuple[re.Pattern[str], ...] = ()
    filecontent: tuple[re.Pattern[str], ...] = ()
    replace: tuple[tuple[re.Pattern[str], str], ...] = ()
    hashes: Mapping[str, str] = field(default_factory=dict)
    vulnerabilities: tuple[Vulnerability, ...] = ()
    npm: str = ""


@dataclass(frozen=True)
class Repository:
    libraries: tuple[Library, ...]
    by_name: Mapping[str, Library]
    hashes: Mapping[str, tuple[str, str]]  # sha1 -> (biblioteca, versão)
    skipped_patterns: tuple[str, ...]  # padrões que o ``re`` não aceitou
    info: Mapping[str, str]


@dataclass(frozen=True)
class Detection:
    """Uma biblioteca identificada: nome, versão e como foi reconhecida."""

    library: str
    version: str
    method: str  # uri | filename | filecontent | filecontentreplace | hash

    @property
    def by_content(self) -> bool:
        return self.method in _CONTENT_METHODS


def _to_python(pattern: str) -> str:
    """Troca o marcador de versão e o que só existe na sintaxe do JavaScript."""
    for js_only, portable in _JS_ONLY:
        pattern = pattern.replace(js_only, portable)
    pattern = pattern.replace(_PLACEHOLDER, VERSION_PATTERN)
    pattern = _OPEN_SPACE_RUN.sub(_bounded_run, pattern)
    return _NAMED_GROUP.sub(r"(?P<\1>", pattern)


def _bounded_run(match: re.Match[str]) -> str:
    low = 1 if match.group(2) == "+" else 0
    return f"{match.group(1)}{{{low},{_RUN_LIMIT}}}"


_REPETICOES = ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT")


def _repeticao_aninhada(itens: Any, dentro: bool, maxrepeat: int) -> bool:
    """Há repetição sem teto dentro de outra repetição sem teto (backtracking exponencial)?"""
    lista = list(itens)
    for posicao, (operacao, valor) in enumerate(lista):
        nome = str(operacao)
        if nome in _REPETICOES:
            _, maximo, corpo = valor
            sem_teto = maximo >= maxrepeat or maximo > _RUN_LIMIT
            # ``(.*\n)*``: o ``.`` não atravessa a quebra de linha que fecha cada volta,
            # então não há mais de uma divisão possível (padrões da base do jQuery UI).
            seguinte = lista[posicao + 1] if posicao + 1 < len(lista) else None
            por_linha = [str(o) for o, _ in corpo] == ["ANY"] and (
                seguinte is not None and str(seguinte[0]) == "LITERAL" and seguinte[1] == 10
            )
            if sem_teto and dentro and not por_linha:
                return True
            if _repeticao_aninhada(corpo, dentro or sem_teto, maxrepeat):
                return True
        elif nome == "SUBPATTERN":
            if _repeticao_aninhada(valor[-1], dentro, maxrepeat):
                return True
        elif nome == "BRANCH":
            if any(_repeticao_aninhada(ramo, dentro, maxrepeat) for ramo in valor[1]):
                return True
        elif nome == "ATOMIC_GROUP" and _repeticao_aninhada(valor, dentro, maxrepeat):
            return True
    return False


def padrao_perigoso(pattern: str) -> bool:
    """Padrão que não compila ou que tem repetições sem teto aninhadas, como ``(a+)+``.

    O Python não interrompe uma busca no meio de um padrão; o orçamento de tempo só é
    conferido entre um padrão e outro. Por isso um padrão assim, vindo de uma cópia
    baixada que ninguém revisou, é descartado em vez de compilado.
    """
    analisador = importlib.import_module("re._parser")
    try:
        arvore = analisador.parse(_to_python(pattern), re.ASCII)
    except (re.error, RecursionError, OverflowError):
        return True
    return bool(_repeticao_aninhada(arvore, False, int(analisador.MAXREPEAT)))


def padrao_suspeito(extractors: Mapping[str, Any]) -> str | None:
    """O primeiro padrão de uma biblioteca da base que ``padrao_perigoso`` recusa."""
    for campo in ("uri", "filename", "filecontent"):
        for pattern in extractors.get(campo) or ():
            if len(pattern) > _PATTERN_MAX or padrao_perigoso(pattern):
                return str(pattern)
    for spec in extractors.get("filecontentreplace") or ():
        partes = _REPLACE_SPEC.match(spec)
        if partes and (len(spec) > _PATTERN_MAX or padrao_perigoso(partes.group(1))):
            return str(spec)
    return None


def _compile(pattern: str, skipped: list[str]) -> re.Pattern[str] | None:
    if len(pattern) > _PATTERN_MAX or padrao_perigoso(pattern):
        skipped.append(pattern)
        return None
    try:
        compiled = re.compile(_to_python(pattern), re.ASCII)
    except re.error:
        skipped.append(pattern)
        return None
    if compiled.groups < 1:  # sem grupo não há de onde tirar a versão
        skipped.append(pattern)
        return None
    return compiled


def _compile_all(patterns: Iterable[str], skipped: list[str]) -> tuple[re.Pattern[str], ...]:
    compiled = (_compile(item, skipped) for item in patterns)
    return tuple(item for item in compiled if item is not None)


def _compile_replace(
    specs: Iterable[str], skipped: list[str]
) -> tuple[tuple[re.Pattern[str], str], ...]:
    found: list[tuple[re.Pattern[str], str]] = []
    for spec in specs:
        parts = _REPLACE_SPEC.match(spec)
        compiled = _compile(parts.group(1), skipped) if parts else None
        if parts and compiled is not None:
            found.append((compiled, parts.group(2)))
    return tuple(found)


def _vulnerability(raw: Mapping[str, Any]) -> Vulnerability:
    identifiers = raw.get("identifiers") or {}
    return Vulnerability(
        below=raw.get("below"),
        at_or_above=raw.get("atOrAbove"),
        excludes=tuple(raw.get("excludes") or ()),
        severity=_SEVERITIES.get(str(raw.get("severity")).lower(), Severity.MEDIUM),
        cves=tuple(identifiers.get("CVE") or ()),
        cwes=tuple(raw.get("cwe") or ()),
        summary=str(identifiers.get("summary") or ""),
        advisory=str(identifiers.get("githubID") or ""),
        info=tuple(raw.get("info") or ()),
    )


def _npm_uri(npm: str) -> tuple[str, ...]:
    """CDNs de pacotes npm (jsDelivr, unpkg): ``/npm/jquery@3.4.1/dist/...`` traz a versão."""
    if not npm:
        return ()
    return (rf"/(?:npm/)?{re.escape(npm)}@({_PLACEHOLDER})(?:[/?#]|$)",)


def _library(name: str, raw: Mapping[str, Any], skipped: list[str]) -> Library:
    extractors = raw.get("extractors") or {}
    npm = str(raw.get("npmname") or _NPM_FALLBACK.get(name, ""))
    uris = [*(extractors.get("uri") or ()), *_npm_uri(npm)]
    contents = [*(extractors.get("filecontent") or ()), *_EXTRA_CONTENT.get(name, ())]
    return Library(
        name=name,
        uri=_compile_all(uris, skipped),
        filename=_compile_all(extractors.get("filename") or (), skipped),
        filecontent=_compile_all(contents, skipped),
        replace=_compile_replace(extractors.get("filecontentreplace") or (), skipped),
        hashes=dict(extractors.get("hashes") or {}),
        vulnerabilities=tuple(_vulnerability(v) for v in raw.get("vulnerabilities") or ()),
        npm=npm,
    )


@lru_cache(maxsize=1)
def repository() -> Repository:
    """A base compilada: calculada uma vez por processo, na primeira página analisada."""
    data = load_json(DATA_FILE)
    skipped: list[str] = []
    libraries = tuple(_library(n, raw, skipped) for n, raw in data["bibliotecas"].items())
    hashes = {
        digest: (library.name, version)
        for library in libraries
        for digest, version in library.hashes.items()
    }
    info = {k: str(v) for k, v in data.items() if k != "bibliotecas"}
    return Repository(libraries, {lib.name: lib for lib in libraries}, hashes, tuple(skipped), info)


# -- comparação de versões (mesma regra do retire.js) --------------------------------------


def _comparable(part: str | None) -> int | str:
    if part is None:
        return 0
    return int(part) if _NUMERIC.fullmatch(part) else part


def is_at_or_above(version: str, other: str) -> bool:
    """``version >= other`` como no retire.js: número vence texto (``1.0.0 >= 1.0.0-rc``)."""
    left, right = _PARTS.split(version), _PARTS.split(other)
    for index in range(max(len(left), len(right))):
        a = _comparable(left[index] if index < len(left) else None)
        b = _comparable(right[index] if index < len(right) else None)
        if isinstance(a, int) != isinstance(b, int):
            return isinstance(a, int)
        if a == b:
            continue
        return a > b  # type: ignore[operator]  # os dois têm o mesmo tipo aqui
    return True


def vulnerabilities_of(library: str, version: str) -> list[Vulnerability]:
    """Vulnerabilidades da base que atingem esta versão da biblioteca."""
    item = repository().by_name.get(library)
    if item is None:
        return []
    return [v for v in item.vulnerabilities if v.affects(version)]


# -- extratores ----------------------------------------------------------------------------


def _clean_version(version: str) -> str:
    return _BUILD_SUFFIX.sub("", version)  # ``.min``, ``.slim``, ``.bundle``... não são versão


def _unique(items: Iterable[Detection]) -> list[Detection]:
    seen: dict[tuple[str, str], Detection] = {}
    for item in items:
        seen.setdefault((item.library, item.version), item)
    return list(seen.values())


def _file_name(url: str) -> str:
    try:
        path = urlsplit(url).path
    except ValueError:
        return ""
    return path.rsplit("/", 1)[-1]


def scan_url(url: str) -> list[Detection]:
    """Identifica pelo endereço completo (``uri``) e pelo nome do arquivo (``filename``)."""
    found: list[Detection] = []
    name = _file_name(url)
    for library in repository().libraries:
        for pattern in library.uri:
            for match in pattern.finditer(url):
                if match.group(1):
                    found.append(Detection(library.name, _clean_version(match.group(1)), "uri"))
        for pattern in library.filename if name else ():
            whole = pattern.fullmatch(name)
            if whole is not None and whole.group(1):
                found.append(Detection(library.name, _clean_version(whole.group(1)), "filename"))
    return _unique(found)


def _expand(template: str, match: re.Match[str]) -> str:
    def group(ref: re.Match[str]) -> str:
        number = int(ref.group(1))
        return (match.group(number) or "") if number <= (match.re.groups) else ""

    return _DOLLAR_GROUP.sub(group, template)


def _scan_library(library: Library, text: str, deadline: float | None = None) -> list[Detection]:
    found: list[Detection] = []
    for pattern in library.filecontent:
        if deadline is not None and time.monotonic() > deadline:
            return found
        for match in pattern.finditer(text):
            if match.group(1):
                found.append(Detection(library.name, _clean_version(match.group(1)), "filecontent"))
    if found:
        return found
    for pattern, template in library.replace:
        if deadline is not None and time.monotonic() > deadline:
            return found
        for match in pattern.finditer(text):
            version = _clean_version(_expand(template, match))
            if version:
                found.append(Detection(library.name, version, "filecontentreplace"))
    return found


def scan_content(
    text: str, *, raw: bytes | None = None, budget: float | None = None
) -> list[Detection]:
    """Identifica pelo conteúdo do script.

    Diferente do retire.js, ``filecontentreplace`` roda por biblioteca (um pacote com várias
    bibliotecas não esconde a que só esse extrator reconhece). O hash SHA-1 fica por último
    e só vale para o arquivo inteiro (``raw``). ``budget`` limita o tempo em segundos.
    """
    normalized = text[:SCAN_MAX_CHARS].replace("\r\n", "\n").replace("\r", "\n")
    deadline = None if budget is None else time.monotonic() + budget
    found: list[Detection] = []
    for library in repository().libraries:
        if deadline is not None and time.monotonic() > deadline:
            break
        found.extend(_scan_library(library, normalized, deadline))
    if not found and raw is not None:
        found.extend(_scan_hash(raw))
    return _unique(found)


def _scan_hash(raw: bytes) -> list[Detection]:
    normalized = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    digest = hashlib.sha1(normalized, usedforsecurity=False).hexdigest()
    hit = repository().hashes.get(digest)
    return [Detection(hit[0], hit[1], "hash")] if hit else []


# -- a página ------------------------------------------------------------------------------


@dataclass
class _Sighting:
    """Uma biblioteca em uma versão, com os lugares onde apareceu."""

    detection: Detection
    sources: list[str] = field(default_factory=list)
    unconfirmed: bool = False  # o endereço sugere a versão, mas o conteúdo lido não confirma


def _scripts_to_read(
    ctx: CheckContext, urls: list[str], known: Mapping[str, list[Detection]], origin: str
) -> list[str]:
    """Quais scripts ler: mesma origem conforme o perfil; CDN só no perfil completo."""
    level = profile_level(ctx)
    local = [u for u in urls if same_origin(u, origin)]
    if level == 0:  # rápido: o endereço já disse o que era, não precisa baixar
        local = [u for u in local if not known[u]]
    chosen = local[: SAME_ORIGIN_LIMITS[level]]
    if level >= 2:
        chosen += [u for u in urls if not same_origin(u, origin)][:CDN_LIMIT]
    return chosen


def _read(ctx: CheckContext, url: str) -> tuple[str, Response] | None:
    script = fetch_script(ctx, url)
    return (url, script) if script is not None else None


def _scan_script(resp: Response) -> list[Detection]:
    raw = None if resp.truncated else resp.body
    return scan_content(resp.text, raw=raw, budget=_SCRIPT_SECONDS)


def _detect_scripts(
    ctx: CheckContext, page_origin: str, doc: HtmlDoc
) -> dict[tuple[str, str], _Sighting]:
    urls = doc.script_urls()
    by_url = {url: scan_url(url) for url in urls}
    wanted = _scripts_to_read(ctx, urls, by_url, page_origin)
    contents = dict(run_parallel(ctx, wanted, lambda url: _read(ctx, url)))
    attempted = set(wanted)
    sightings: dict[tuple[str, str], _Sighting] = {}
    for url in urls:
        ctx.check_cancel()
        resp = contents.get(url)
        from_content = _scan_script(resp) if resp is not None else []
        confirmed = {d.library for d in from_content}
        for detection in from_content:
            _note(sightings, detection, url)
        for detection in by_url[url]:
            if detection.library not in confirmed:
                # lido e sem confirmação (ou sumiu/não é JavaScript): o endereço sozinho é indício
                _note(sightings, detection, url, unconfirmed=url in attempted)
    return sightings


def _detect_inline(
    ctx: CheckContext, page_url: str, doc: HtmlDoc, sightings: dict[tuple[str, str], _Sighting]
) -> None:
    for text in doc.inline_scripts():
        ctx.check_cancel()
        for detection in scan_content(text, budget=_SCRIPT_SECONDS):
            _note(sightings, detection, page_url)


def _note(
    sightings: dict[tuple[str, str], _Sighting],
    detection: Detection,
    source: str,
    *,
    unconfirmed: bool = False,
) -> None:
    key = (detection.library, detection.version)
    current = sightings.get(key)
    if current is None:
        current = _Sighting(detection, unconfirmed=unconfirmed)
        sightings[key] = current
    elif detection.by_content and not current.detection.by_content:
        current.detection = detection  # o conteúdo é prova melhor que o endereço
    if not unconfirmed:
        current.unconfirmed = False
    if source not in current.sources:
        current.sources.append(source)


def _fixed_version(vulns: Iterable[Vulnerability]) -> tuple[str | None, bool]:
    """Menor versão acima de todas as faixas encontradas e se alguma faixa não tem correção."""
    best: str | None = None
    no_fix = False
    for vuln in vulns:
        if not vuln.has_fix or vuln.below is None:
            no_fix = True
            continue
        if best is None or is_at_or_above(vuln.below, best):
            best = vuln.below
    return best, no_fix


def _kind_of(vuln: Vulnerability) -> str:
    labels = [_CWE_TEXT.get(cwe, cwe) for cwe in vuln.cwes]
    return "; ".join(labels) if labels else "tipo não informado"


def _advice_line(vuln: Vulnerability) -> str:
    name = ", ".join(vuln.cves) or vuln.advisory or "sem CVE"
    fixed = f"corrigida na {vuln.below}" if vuln.has_fix else "sem versão corrigida"
    return f"- {name} (severidade {_SEVERITY_TEXT[vuln.severity]}; {fixed}): {_kind_of(vuln)}"


def _evidence(sighting: _Sighting, vulns: list[Vulnerability]) -> str:
    det = sighting.detection
    fixed, no_fix = _fixed_version(vulns)
    how = _METHOD_TEXT.get(det.method, det.method)
    lines = [f"{det.library} {det.version} em {sighting.sources[0]} (identificada {how})."]
    if sighting.unconfirmed:
        lines.append("O conteúdo lido não confirma a versão do endereço: vale conferir o arquivo.")
    if fixed:
        lines.append(
            f"{len(vulns)} vulnerabilidade(s) conhecida(s); atualize para {fixed} ou mais recente."
        )
    if no_fix:
        lines.append("Parte das falhas não tem versão corrigida: avalie trocar a biblioteca.")
    ordered = sorted(vulns, key=lambda v: v.severity.rank, reverse=True)
    lines.extend(_advice_line(v) for v in ordered[:_MAX_EVIDENCE_LINES])
    if len(ordered) > _MAX_EVIDENCE_LINES:
        lines.append(
            f"... e mais {len(ordered) - _MAX_EVIDENCE_LINES} (lista completa nos detalhes)."
        )
    return "\n".join(lines)


def _details(sighting: _Sighting, vulns: list[Vulnerability]) -> dict[str, Any]:
    det = sighting.detection
    fixed, no_fix = _fixed_version(vulns)
    library = repository().by_name.get(det.library)
    return {
        "biblioteca": det.library,
        "versao": det.version,
        "pacote_npm": library.npm if library else "",
        "identificacao": det.method,
        "fontes": sighting.sources[:20],
        "versao_corrigida": fixed,
        "sem_correcao": no_fix,
        "base": repository().info.get("atualizado", ""),
        "vulnerabilidades": [
            {
                "cves": list(v.cves),
                "aviso": v.advisory,
                "severidade": v.severity.value,
                "tipo": _kind_of(v),
                "cwe": list(v.cwes),
                "abaixo_de": v.below,
                "a_partir_de": v.at_or_above,
                "descricao_original_em_ingles": v.summary,
                "referencias": list(v.info)[:5],
            }
            for v in vulns
        ],
    }


def _confidence(sighting: _Sighting) -> Confidence:
    if sighting.detection.by_content:
        return Confidence.CONFIRMED
    return Confidence.TENTATIVE if sighting.unconfirmed else Confidence.FIRM


def _report(
    ctx: CheckContext, sighting: _Sighting, vulns: list[Vulnerability], tech: list[str]
) -> None:
    det = sighting.detection
    cves = sorted({cve for v in vulns for cve in v.cves})
    kev = vulndb.any_kev(cves)
    severity = max((v.severity for v in vulns), key=lambda s: s.rank)
    ctx.report(
        "web.biblioteca.vulneravel",
        asset=sighting.sources[0],
        title=f"Biblioteca JavaScript vulnerável: {det.library} {det.version}",
        severity=Severity.CRITICAL if kev else severity,
        evidence=_evidence(sighting, vulns),
        details=_details(sighting, vulns),
        confidence=_confidence(sighting),
        cves=cves,
        kev=kev,
        discriminator=f"{det.library}@{det.version}",
        tech=tech,
    )


@check(
    id="web.jslibs",
    name="Bibliotecas JavaScript vulneráveis",
    category=Category.WEB,
    consumes=facts.HTTP_SERVICE,
    description=(
        "Identifica as bibliotecas JavaScript da página (pelo endereço e pelo conteúdo dos "
        "scripts) e compara as versões com a base embarcada do retire.js e com o catálogo CISA KEV."
    ),
    findings=("web.biblioteca.vulneravel",),
    facts=(facts.TECH,),
    order=45,
)
def check_jslibs(ctx: CheckContext, fact: Fact) -> None:
    url = str(fact.data["url"])
    page = load_page(ctx, url)
    if page is None:
        ctx.log(f"{url} não respondeu.")
        return
    reason = skip_reason(ctx, page)
    if reason:
        ctx.log(reason)
        return
    doc = page_doc(ctx, page)
    if doc is None:
        return
    sightings = _detect_scripts(ctx, page.origin, doc)
    _detect_inline(ctx, page.final.url, doc, sightings)
    _conclude(ctx, page.host, page.origin, sightings, hints(ctx, page))


def _conclude(
    ctx: CheckContext,
    host: str,
    origin: str,
    sightings: Mapping[tuple[str, str], _Sighting],
    tech: list[str],
) -> None:
    clean: list[str] = []
    for sighting in sightings.values():
        det = sighting.detection
        ctx.add_tech(
            host,
            det.library,
            version=det.version,
            kind="js-lib",
            evidence=f"{sighting.sources[0]} ({_METHOD_TEXT.get(det.method, det.method)})",
        )
        vulns = vulnerabilities_of(det.library, det.version)
        if vulns:
            _report(ctx, sighting, vulns, tech)
        else:
            clean.append(f"{det.library} {det.version}")
    if clean and len(clean) == len(sightings):
        ctx.passed(
            "web.biblioteca",
            "Bibliotecas JavaScript sem vulnerabilidades conhecidas na base embarcada: "
            + ", ".join(sorted(clean)[:10]),
            origin,
        )
