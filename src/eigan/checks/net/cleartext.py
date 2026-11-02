"""Protocolos em texto puro: Telnet, FTP (TLS e login anônimo) e e-mail (STARTTLS).

Só os comandos que qualquer cliente envia ao começar: ``FEAT``/``AUTH TLS`` no
FTP, ``EHLO`` no SMTP, ``CAPA`` (ou ``STLS``) no POP3 e ``CAPABILITY`` no IMAP.
O teste de FTP anônimo faz login com o usuário público ``anonymous`` e sai em
seguida (``QUIT``), sem listar nem transferir arquivos.

Resposta ausente ou inesperada nunca vira achado nem ponto forte: fica no
registro como inconclusiva.
"""

from __future__ import annotations

import re
import time

from ...core import facts
from ...core.context import CheckContext
from ...core.models import Category, Confidence, Fact, Severity
from ...core.registry import check
from . import kb_servicos  # noqa: F401 — registra as entradas da base
from .banners import clean_text
from .common import Connection, by_exposure, host_port, open_service, service_asset, where

ANONYMOUS_PASSWORD = "auditoria@eigan.invalid"
SUBMISSION_PORTS = frozenset({587, 2525})
_REPLY = re.compile(r"^(\d{3})([ -])(.*)$")
#: recusa do anônimo só por falta de criptografia (o anônimo pode existir sobre TLS)
_NEEDS_TLS = re.compile(r"tls|ssl|encrypt", re.I)


def read_reply(conn: Connection, limit: int = 16) -> tuple[int, list[str]]:
    """Resposta FTP/SMTP (``123-...`` continua, ``123 ...`` encerra). Código 0 = sem resposta."""
    lines: list[str] = []
    deadline = time.monotonic() + max(conn.timeout, 1.0) * 2
    for _ in range(limit * 8):
        if time.monotonic() > deadline:
            break
        raw = conn.read_until(b"\n", limit=4096)
        if not raw:
            break
        line = clean_text(raw.decode("utf-8", errors="replace").rstrip("\r\n"), 500)
        lines.append(line)
        match = _REPLY.match(line)
        if match and match.group(2) == " ":
            return int(match.group(1)), lines
    first = _REPLY.match(lines[0]) if lines else None
    return (int(first.group(1)) if first else 0), lines


def command(conn: Connection, text: str) -> tuple[int, list[str]]:
    if not conn.send(text.encode("ascii") + b"\r\n"):
        return 0, []
    return read_reply(conn)


def _definitive_refusal(code: int) -> bool:
    """Código 5xx: recusa definitiva. 4xx (limite de conexões...) não prova nada."""
    return 500 <= code < 600


# -- Telnet --------------------------------------------------------------------------
@check(
    id="net.telnet",
    name="Telnet",
    category=Category.NETWORK,
    consumes=facts.SERVICE,
    when=lambda fact: fact.data.get("service") == "telnet",
    description="Aponta servidores Telnet, que transmitem login e senha sem criptografia.",
    findings=("net.telnet.ativo",),
    order=30,
)
def check_telnet(ctx: CheckContext, fact: Fact) -> None:
    host, port = host_port(fact)
    if fact.data.get("tls"):
        return
    confirmed = bool(fact.data.get("confirmed"))
    how = "respondeu com negociação Telnet" if confirmed else "aberta (porta padrão do Telnet)"
    banner = str(fact.data.get("banner") or "")
    ctx.report(
        "net.telnet.ativo",
        asset=service_asset(host, port),
        severity=by_exposure(
            host, internet=Severity.HIGH, internal=Severity.HIGH, local=Severity.MEDIUM
        ),
        evidence=f"Porta {port}/tcp {where(host)} {how}" + (f": {banner}" if banner else "."),
        confidence=Confidence.CONFIRMED if confirmed else Confidence.TENTATIVE,
    )


# -- FTP -----------------------------------------------------------------------------
@check(
    id="net.ftp",
    name="FTP: criptografia e acesso anônimo",
    category=Category.NETWORK,
    consumes=facts.SERVICE,
    when=lambda fact: fact.data.get("service") == "ftp",
    description="Verifica se o FTP oferece TLS (AUTH TLS) e se aceita login anônimo.",
    findings=("net.ftp.sem_tls", "net.ftp.anonimo"),
    order=30,
)
def check_ftp(ctx: CheckContext, fact: Fact) -> None:
    host, port = host_port(fact)
    tls = bool(fact.data.get("tls"))
    asset = service_asset(host, port)
    tech = [str(fact.data.get("product"))] if fact.data.get("product") else []
    if tls:
        ctx.passed("net.ftp.tls", "FTP com TLS implícito (FTPS)", asset)
    else:
        _ftp_tls(ctx, host, port, asset, tech)
    ctx.check_cancel()
    _ftp_anonymous(ctx, host, port, tls, asset, tech)


def ftp_tls_support(conn: Connection) -> tuple[bool | None, str]:
    """(suporta TLS?, evidência) usando ``FEAT`` e, se preciso, ``AUTH TLS``.

    None = inconclusivo (sem saudação 220 ou sem resposta aos comandos).
    """
    code, _ = read_reply(conn)
    if code != 220:
        return None, ""
    code, lines = command(conn, "FEAT")
    features = [line.strip().upper() for line in lines[1:-1]] if code == 211 else []
    if any(item.startswith(("AUTH TLS", "AUTH SSL")) for item in features):
        return True, "FEAT anuncia AUTH TLS"
    code, lines = command(conn, "AUTH TLS")
    if code == 234:
        return True, "AUTH TLS aceito (234)"
    if not _definitive_refusal(code):  # sem resposta ou recusa temporária (ex.: 421)
        return None, ""
    return False, f"FEAT sem AUTH TLS; 'AUTH TLS' respondeu: {lines[-1]}"


def _ftp_tls(ctx: CheckContext, host: str, port: int, asset: str, tech: list[str]) -> None:
    conn = open_service(ctx, host, port)
    if conn is None:
        return
    with conn:
        supported, evidence = ftp_tls_support(conn)
    if supported is None:
        ctx.log(f"{asset}: o servidor FTP não respondeu como esperado (TLS não avaliado).")
        return
    if supported:
        ctx.passed("net.ftp.tls", f"FTP oferece TLS ({evidence})", asset)
        return
    ctx.report(
        "net.ftp.sem_tls",
        asset=asset,
        severity=by_exposure(host, internet=Severity.MEDIUM, internal=Severity.LOW),
        evidence=f"{evidence} ({where(host)}).",
        confidence=Confidence.CONFIRMED,
        tech=tech,
    )


def ftp_anonymous_login(conn: Connection) -> tuple[bool | None, list[str]]:
    """Tenta ``USER anonymous``; devolve (entrou?, respostas). Sai com ``QUIT``.

    None = inconclusivo: sem saudação, sem resposta ou recusa só por falta de TLS.
    """
    code, greeting = read_reply(conn)
    if code != 220:
        return None, greeting[-1:]
    code, user_reply = command(conn, "USER anonymous")
    transcript = greeting[-1:] + [f"USER anonymous -> {user_reply[-1] if user_reply else ''}"]
    replies = list(user_reply)
    if code == 331:
        code, pass_reply = command(conn, f"PASS {ANONYMOUS_PASSWORD}")
        transcript.append(f"PASS (e-mail fictício) -> {pass_reply[-1] if pass_reply else ''}")
        replies += pass_reply
    conn.send(b"QUIT\r\n")
    if code == 230:
        return True, transcript
    if not _definitive_refusal(code) or _NEEDS_TLS.search(" ".join(replies)):
        return None, transcript
    return False, transcript


def _ftp_anonymous(
    ctx: CheckContext, host: str, port: int, tls: bool, asset: str, tech: list[str]
) -> None:
    conn = open_service(ctx, host, port, tls=tls)
    if conn is None:
        return
    with conn:
        accepted, transcript = ftp_anonymous_login(conn)
    if accepted is None:
        ctx.log(
            f"{asset}: login anônimo não avaliado ({' | '.join(transcript) or 'sem resposta'})."
        )
        return
    if not accepted:
        ctx.passed("net.ftp.anonimo", "FTP recusa login anônimo", asset)
        return
    ctx.report(
        "net.ftp.anonimo",
        asset=asset,
        severity=by_exposure(
            host, internet=Severity.HIGH, internal=Severity.MEDIUM, local=Severity.LOW
        ),
        evidence="\n".join(transcript) + f"\nLogin anônimo aceito ({where(host)}).",
        confidence=Confidence.CONFIRMED,
        tech=tech,
    )


# -- e-mail --------------------------------------------------------------------------
@check(
    id="net.correio",
    name="E-mail: STARTTLS no SMTP, POP3 e IMAP",
    category=Category.NETWORK,
    consumes=facts.SERVICE,
    when=lambda fact: fact.data.get("service") in ("smtp", "pop3", "imap"),
    description="Verifica se os serviços de e-mail oferecem criptografia (STARTTLS/STLS ou TLS implícito).",
    findings=("net.smtp.sem_starttls", "net.correio.sem_tls"),
    order=30,
)
def check_mail(ctx: CheckContext, fact: Fact) -> None:
    host, port = host_port(fact)
    service = str(fact.data.get("service"))
    asset = service_asset(host, port)
    if fact.data.get("tls"):
        ctx.passed("net.correio.tls", f"{service.upper()} com TLS implícito", asset)
        return
    conn = open_service(ctx, host, port)
    if conn is None:
        return
    with conn:
        offered, evidence = _PROBES[service](conn)
    if offered is None:
        ctx.log(f"{asset}: o servidor {service.upper()} não respondeu como esperado.")
        return
    if offered:
        ctx.passed("net.correio.tls", f"{service.upper()} oferece STARTTLS", asset)
        return
    tech = [str(fact.data.get("product"))] if fact.data.get("product") else []
    if service == "smtp":
        submission = port in SUBMISSION_PORTS
        severity = by_exposure(
            host,
            internet=Severity.HIGH if submission else Severity.MEDIUM,
            internal=Severity.MEDIUM if submission else Severity.LOW,
        )
        ctx.report(
            "net.smtp.sem_starttls",
            asset=asset,
            severity=severity,
            evidence=evidence,
            confidence=Confidence.CONFIRMED,
            tech=tech,
        )
        return
    ctx.report(
        "net.correio.sem_tls",
        asset=asset,
        severity=by_exposure(host, internet=Severity.MEDIUM, internal=Severity.LOW),
        evidence=evidence,
        confidence=Confidence.CONFIRMED,
        tech=tech,
    )


def smtp_starttls(conn: Connection) -> tuple[bool | None, str]:
    """STARTTLS na resposta ao ``EHLO``. None se o servidor não cumprimentar ou não responder."""
    code, _ = read_reply(conn)
    if code != 220:
        return None, ""
    code, lines = command(conn, "EHLO eigan.invalid")
    conn.send(b"QUIT\r\n")
    if code in (500, 502):  # servidor sem ESMTP: STARTTLS depende do EHLO (RFC 3207)
        return False, f"EHLO não reconhecido ({lines[-1]}): o servidor não oferece STARTTLS."
    if code != 250:  # recusa da conexão, limite de conexões ou sem resposta
        return None, ""
    keywords = [line[4:].strip().upper() for line in lines]
    if any(word.startswith("STARTTLS") for word in keywords):
        return True, "EHLO anuncia STARTTLS"
    return False, "Resposta ao EHLO sem STARTTLS: " + ", ".join(keywords[1:])[:300]


def pop3_stls(conn: Connection) -> tuple[bool | None, str]:
    """STLS anunciado no ``CAPA`` (RFC 2449/2595); sem CAPA, tenta o próprio ``STLS``."""
    greeting = conn.read_until(b"\n", limit=2048)
    if not greeting.startswith(b"+OK"):
        return None, ""
    conn.send(b"CAPA\r\n")
    first = conn.read_until(b"\n", limit=2048)
    if not first:
        return None, ""
    if first.startswith(b"+OK"):
        body = conn.read_until(b"\r\n.\r\n", limit=8192).decode("ascii", "replace")
        caps = [c.strip().upper() for c in body.splitlines() if c.strip() not in ("", ".")]
        conn.send(b"QUIT\r\n")
        if "STLS" in caps:
            return True, "CAPA anuncia STLS"
        return False, f"POP3 sem STLS (capacidades: {', '.join(caps)[:300] or 'nenhuma'})."
    conn.send(b"STLS\r\n")
    reply = conn.read_until(b"\n", limit=2048)
    if reply.startswith(b"+OK"):
        return True, "STLS aceito (servidor sem CAPA)"
    if not reply:
        return None, ""
    conn.send(b"QUIT\r\n")
    return False, "POP3 sem CAPA e sem STLS: " + reply.decode("ascii", "replace").strip()[:200]


def imap_starttls(conn: Connection) -> tuple[bool | None, str]:
    """STARTTLS na saudação ou na resposta ao ``CAPABILITY`` (exige o ``a1 OK`` final)."""
    greeting = conn.read_until(b"\n", limit=4096)
    if not greeting.startswith((b"* OK", b"* PREAUTH")):
        return None, ""
    conn.send(b"a1 CAPABILITY\r\n")
    reply = conn.read_until(b"a1 ", limit=8192) + conn.read_until(b"\n", limit=1024)
    conn.send(b"a2 LOGOUT\r\n")
    text = (greeting + reply).decode("ascii", "replace").upper()
    if "STARTTLS" in text:
        return True, "CAPABILITY anuncia STARTTLS"
    if "A1 OK" not in text:
        return None, ""
    caps = re.findall(r"\* CAPABILITY ([^\r\n]*)", text)
    shown = (caps[0] if caps else "não informadas")[:300]
    return False, f"IMAP sem STARTTLS (capacidades: {shown})."


_PROBES = {"smtp": smtp_starttls, "pop3": pop3_stls, "imap": imap_starttls}
