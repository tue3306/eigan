"""Apoio aos testes de relatórios: resultados de auditoria prontos e leitura de HTML e PDF.

Tudo é local: nada de rede. Os achados usam ids que sempre existem na base de
conhecimento (``web.https.*`` e ``web.hsts.*``) e outros fora dela, para exercitar a
entrada mínima de :func:`eigan.intel.remediation.entry_for`.
"""

from __future__ import annotations

import base64
import re
import zlib
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any

from eigan.core import kb
from eigan.core.models import (
    CheckRun,
    Confidence,
    Decision,
    Fact,
    Finding,
    PassedControl,
    ScanResult,
    Severity,
    TargetKind,
    TriageStatus,
)
from eigan.core.registry import load_builtin_checks
from eigan.intel.analysis import analyze

load_builtin_checks()

SITE = "https://exemplo.com.br/"
STARTED = "2026-11-01T10:00:00+00:00"
FINISHED = "2026-11-01T10:04:12+00:00"

SCRIPT = "<script>alert(1)</script>"
IMG = '"><img src=x onerror=alert(1)>'
JS_URL = "javascript:alert(1)"
SECRET = "AKIAABCDEFGHIJKLMNOP"
#: payloads hostis: o texto precisa aparecer escapado e nunca virar elemento
PAYLOADS = (
    SCRIPT,
    IMG,
    "<svg/onload=alert(1)>",
    "<a href=javascript:alert(1)>clique</a>",
    "</style><script>alert(2)</script>",
    "'\"><iframe src=//mal.example></iframe>",
    "<b>negrito</b> & <i>x</i> &amp; &#60;script&#62;",
    "{{ 7*7 }} {% include 'x' %}",
)


def make(
    check_id: str = "web.hsts.ausente",
    asset: str = SITE,
    *,
    severity: Severity | None = None,
    title: str = "",
    **extra: Any,
) -> Finding:
    """Achado com o título e a severidade da base de conhecimento, quando o id existe."""
    entry = kb.get(check_id)
    extra.setdefault("source", "web.transport")
    extra.setdefault("first_seen", STARTED)
    return Finding(
        check_id=check_id,
        title=title or (entry.title if entry else check_id),
        severity=severity or (entry.severity if entry else Severity.MEDIUM),
        asset=asset,
        **extra,
    )


def scan(findings: list[Finding] | None = None, **extra: Any) -> ScanResult:
    """Resultado concluído (ainda sem análise) com padrões razoáveis."""
    defaults: dict[str, Any] = {
        "id": "abc123",
        "target": "https://exemplo.com.br",
        "kind": TargetKind.URL,
        "profile": "padrao",
        "started_at": STARTED,
        "finished_at": FINISHED,
        "status": "concluida",
        "app_version": "0.0.0",
    }
    defaults.update(extra)
    return ScanResult(findings=findings or [], **defaults)


def analyzed(result: ScanResult, previous: ScanResult | None = None) -> ScanResult:
    analyze(result, previous)
    return result


def sample_findings() -> list[Finding]:
    """Achados variados: KEV, triados, hostis, informativo, código e rede."""
    return [
        make(
            "net.servico.vulneravel",
            "loja.exemplo.com.br:8443/tcp",
            severity=Severity.CRITICAL,
            title='Log4j 2.14.1 "vulnerável" <b>Log4Shell</b>',
            cves=["CVE-2021-44228", "CVE-2021-45046"],
            kev=True,
            confidence=Confidence.FIRM,
            evidence="Banner HTTP: Apache Tomcat/9.0.50\nArquivo: log4j-core-2.14.1.jar",
            details={"produto": "log4j-core", "versao": "2.14.1", "corrigida": ["2.17.1"]},
            tech=["java"],
        ),
        make(
            "web.https.sem_redirecionamento",
            "http://exemplo.com.br/",
            confidence=Confidence.CONFIRMED,
            evidence="GET http://exemplo.com.br/ respondeu 200 sem redirecionar.",
            tech=["nginx"],
        ),
        make(
            "web.hsts.ausente",
            SITE,
            confidence=Confidence.CONFIRMED,
            evidence=f"Resposta com {SCRIPT} e sem Strict-Transport-Security.",
            details={"hostil": IMG, "<chave>": "valor"},
            tech=["nginx"],
        ),
        make(
            "web.hsts.fraco",
            'https://api.exemplo.com.br/"><b>x</b>',
            evidence="Strict-Transport-Security: max-age=86400",
            details={"max_age": 86400, "inclui_subdominios": False, "nada": None},
        ),
        make(
            "web.hsts.fraco",
            "https://legado.exemplo.com.br/",
            evidence="=SOMA(1;1)",
            status=TriageStatus.ACCEPTED,
            status_note="Subdomínio legado, desligamento previsto para dezembro.",
        ),
        make(
            "web.hsts.fraco",
            "https://teste.exemplo.com.br/",
            status=TriageStatus.FALSE_POSITIVE,
            status_note="",
        ),
        make(
            "web.tecnologia.identificada",
            SITE,
            severity=Severity.INFO,
            title="Tecnologia identificada: nginx 1.18.0",
            confidence=Confidence.CONFIRMED,
            evidence="Server: nginx/1.18.0",
        ),
    ]


def sample_result() -> ScanResult:
    """Resultado realista: achados, controles, fatos, decisões, execuções e erros."""
    result = scan(
        sample_findings(),
        passed=[
            PassedControl("tls.protocolos", "Só aceita TLS 1.2 e TLS 1.3", "exemplo.com.br:443"),
            PassedControl(
                "tls.protocolos", "Só aceita TLS 1.2 e TLS 1.3", "api.exemplo.com.br:443"
            ),
            PassedControl("web.metodos", "Métodos perigosos recusados", SITE),
        ],
        facts=[
            Fact(
                "http.service",
                SITE,
                {"url": SITE, "host": "exemplo.com.br", "port": 443, "scheme": "https"},
                source="web.discovery",
            ),
            Fact(
                "tech",
                "exemplo.com.br:nginx",
                {"host": "exemplo.com.br", "name": "nginx", "version": "1.18.0", "kind": "server"},
                source="web.fingerprint",
            ),
        ],
        decisions=[
            Decision("2026-11-01T10:00:01+00:00", "Iniciar pelas verificações de HTTPS."),
            Decision("2026-11-01T10:00:04+00:00", "Porta 8443 aberta: consultar o catálogo KEV."),
        ],
        runs=[
            CheckRun("web.transport", "Transporte", SITE, "ok", 1.2),
            CheckRun("web.headers", "Cabeçalhos", SITE, "ok", 0.8),
            CheckRun(
                "web.cookies", "Cookies", SITE, "tempo_esgotado", 30.0, "Sem resposta em 30 s"
            ),
            CheckRun("net.portas", "Portas", "exemplo.com.br", "erro", 0.1, "Conexão recusada"),
        ],
        errors=["Cookies em https://exemplo.com.br/: tempo esgotado após 30 s."],
    )
    return analyzed(result)


def previous_result() -> ScanResult:
    """Auditoria anterior do mesmo alvo, para a seção de comparação."""
    return analyzed(
        scan(
            [
                make("web.https.ausente", "http://antigo.exemplo.com.br/", source="web.transport"),
                make("web.hsts.ausente", SITE),
                make("web.hsts.fraco", "https://outro.exemplo.com.br/", source="checagem.profunda"),
            ],
            id="anterior1",
            started_at="2026-10-01T10:00:00+00:00",
            finished_at="2026-10-01T10:03:00+00:00",
        )
    )


def sample_with_diff() -> ScanResult:
    result = sample_result()
    return analyzed(result, previous_result())


def not_evaluated() -> ScanResult:
    """Nenhuma verificação respondeu: o estado "não foi possível avaliar"."""
    return analyzed(
        scan(
            runs=[CheckRun("web.transport", "Transporte", SITE, "erro", 0.2, "Conexão recusada")],
            errors=["Não foi possível conectar ao alvo."],
        )
    )


def clean_result() -> ScanResult:
    """Avaliado e sem nenhum problema: nota máxima e só pontos fortes."""
    return analyzed(scan(passed=[PassedControl("tls.protocolos", "Só aceita TLS 1.2+", SITE)]))


def many_findings(count: int) -> ScanResult:
    """Centenas de achados do mesmo tipo e de tipos diferentes."""
    findings = [
        make(
            "web.hsts.ausente" if n % 2 else "web.https.sem_redirecionamento",
            f"https://host-{n:04d}.exemplo.com.br/caminho/muito/comprido/{n}",
            evidence=f"Evidência da ocorrência {n}: coração, ação e não.",
            severity=Severity.HIGH if n % 7 == 0 else None,
        )
        for n in range(count)
    ]
    return analyzed(scan(findings))


# -- leitura de HTML ------------------------------------------------------------------------


@dataclass
class ParsedHtml:
    """O que um navegador veria: elementos, atributos e texto já sem escape."""

    tags: list[str] = field(default_factory=list)
    attrs: list[tuple[str, str, str]] = field(default_factory=list)
    text: list[str] = field(default_factory=list)
    style: str = ""

    def hrefs(self) -> list[str]:
        return [value for tag, name, value in self.attrs if tag == "a" and name == "href"]

    def ids(self) -> list[str]:
        return [value for _tag, name, value in self.attrs if name == "id"]

    def plain(self) -> str:
        return "".join(self.text)


class _Parser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parsed = ParsedHtml()
        self._in_style = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.parsed.tags.append(tag)
        for name, value in attrs:
            self.parsed.attrs.append((tag, name, value or ""))
        self._in_style = tag == "style"

    def handle_endtag(self, tag: str) -> None:
        if tag == "style":
            self._in_style = False

    def handle_data(self, data: str) -> None:
        if self._in_style:
            self.parsed.style += data
        else:
            self.parsed.text.append(data)


def parse_html(document: str) -> ParsedHtml:
    parser = _Parser()
    parser.feed(document)
    parser.close()
    return parser.parsed


# -- leitura de PDF -------------------------------------------------------------------------

_STREAM = re.compile(rb"stream\r?\n(.*?)\s*endstream", re.S)
_LITERAL = re.compile(rb"\((?:\\.|[^\\()])*\)", re.S)
_ESCAPES = {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"\b", b"f": b"\f"}


def _unescape_literal(raw: bytes) -> bytes:
    def replace(match: re.Match[bytes]) -> bytes:
        token = match.group(1)
        if token[:1].isdigit():
            return bytes([int(token, 8) & 0xFF])
        return _ESCAPES.get(token, token)

    return re.sub(rb"\\([0-7]{1,3}|.)", replace, raw, flags=re.S)


def _decoded_streams(pdf: bytes) -> list[bytes]:
    streams = []
    for raw in _STREAM.findall(pdf):
        data = raw.strip().removesuffix(b"~>")
        try:
            streams.append(zlib.decompress(base64.a85decode(data)))
        except (ValueError, zlib.error):
            streams.append(data)
    return streams


def pdf_page_text(pdf: bytes) -> list[str]:
    """Texto de cada conteúdo do PDF (só para testes: basta para os PDFs do reportlab)."""
    pages = []
    for stream in _decoded_streams(pdf):
        if b" Tj" not in stream and b"TJ" not in stream:
            continue
        pieces = [
            _unescape_literal(item[1:-1]).decode("cp1252", "replace")
            for item in _LITERAL.findall(stream)
        ]
        pages.append(" ".join(pieces))
    return pages


def pdf_text_of(pdf: bytes) -> str:
    """Todo o texto do PDF numa string só, sem as quebras de linha do desenho."""
    return " ".join(pdf_page_text(pdf))


def pdf_pages(pdf: bytes) -> int:
    return len(re.findall(rb"/Type\s*/Page\b", pdf))
