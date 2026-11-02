"""Interpretação de banners: protocolos em que o SERVIDOR fala primeiro.

SSH, FTP, SMTP, POP3, IMAP, VNC, Telnet e MySQL se apresentam assim que a
conexão abre. Aqui só há interpretação de bytes (sem E/S): o resultado é um
``Identified`` com serviço, produto e versão quando o banner os revela.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ...core.versions import extract_version


def clean_text(text: object, limit: int = 300) -> str:
    """Texto vindo do alvo sem bytes de controle (impede sequências de escape no terminal)."""
    raw = str(text)[:limit]
    return "".join(ch if ch.isprintable() else " " for ch in raw).strip()


@dataclass
class Identified:
    """Serviço reconhecido numa porta."""

    service: str
    product: str = ""
    version: str = ""
    banner: str = ""
    tls: bool = False
    confirmed: bool = True  # False = só pela porta (sem resposta do protocolo)
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.banner = clean_text(self.banner, 600)
        self.product = clean_text(self.product, 80)
        self.version = clean_text(self.version, 80)


SMTP_PORTS = frozenset({25, 465, 587, 2525})
FTP_PORTS = frozenset({21, 990, 2121})

_SSH = re.compile(r"^SSH-(\d+\.\d+)-(\S+)(?:[ \t]+(.*))?$")
_RFB = re.compile(rb"^RFB (\d{3})\.(\d{3})\n")
_TELNET_CMDS = frozenset({0xFB, 0xFC, 0xFD, 0xFE})

_FTP_PRODUCTS = (
    (re.compile(r"vsFTPd (\d[\w.]*)", re.I), "vsftpd"),
    (re.compile(r"ProFTPD (\d[\w.]*)", re.I), "proftpd"),
    (re.compile(r"FileZilla Server(?: version)? (\d[\w.]*)", re.I), "filezilla-server"),
    (re.compile(r"Pure-FTPd()", re.I), "pure-ftpd"),
    (re.compile(r"Microsoft FTP Service()", re.I), "iis-ftp"),
)
_SMTP_PRODUCTS = (
    (re.compile(r"Exim (\d[\w.]*)", re.I), "exim"),
    (re.compile(r"Sendmail (\d[\w.]*)", re.I), "sendmail"),
    (re.compile(r"Postfix()", re.I), "postfix"),
    (re.compile(r"Microsoft ESMTP()", re.I), "exchange"),
    (re.compile(r"OpenSMTPD()", re.I), "opensmtpd"),
)
_MAILBOX_PRODUCTS = (
    (re.compile(r"Dovecot()", re.I), "dovecot"),
    (re.compile(r"Courier()", re.I), "courier"),
    (re.compile(r"Cyrus IMAP(?: v)?(\d[\w.]*)?", re.I), "cyrus"),
    (re.compile(r"Microsoft Exchange()", re.I), "exchange"),
)
_FTP_WORDS = ("ftp", "filezilla")
_SMTP_WORDS = ("smtp", "esmtp", "postfix", "exim", "sendmail", "mail service", " mta")


def _product(text: str, table: tuple[tuple[re.Pattern[str], str], ...]) -> tuple[str, str]:
    for pattern, name in table:
        match = pattern.search(text)
        if match:
            return name, (match.group(1) or "")
    return "", ""


def parse_ssh_banner(line: str) -> Identified | None:
    """``SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10`` → openssh 8.9p1 (com o comentário)."""
    match = _SSH.match(line.strip())
    if not match:
        return None
    proto, software, comment = match.group(1), match.group(2), match.group(3) or ""
    product, version, extra = ssh_product(software)
    extra.update({"protocolo": proto, "software": software, "comentario": comment.strip()})
    return Identified("ssh", product, version, banner=line.strip(), extra=extra)


_SSH_RULES: tuple[tuple[str, str, dict[str, Any]], ...] = (
    (r"OpenSSH_for_Windows_([\w.]+)", "openssh", {"plataforma": "windows"}),
    (r"OpenSSH_([\w.]+)", "openssh", {}),
    (r"dropbear_([\w.]+)", "dropbear", {}),
    (r"libssh[_-]([\w.]+)", "libssh", {}),
)


def ssh_product(software: str) -> tuple[str, str, dict[str, Any]]:
    """Produto e versão a partir do campo ``softwareversion`` do banner SSH."""
    for pattern, name, extra in _SSH_RULES:
        match = re.match(pattern, software, re.I)
        if match:
            return name, match.group(1), dict(extra)
    name = re.split(r"[_\-/]", software, maxsplit=1)[0].lower()
    return name, extract_version(software) or "", {}


def parse_mysql_greeting(data: bytes) -> Identified | None:
    """Saudação do MySQL/MariaDB (protocolo 10) ou pacote de erro inicial (0xFF)."""
    if len(data) < 6 or data[3] != 0:
        return None
    length = int.from_bytes(data[0:3], "little")
    body = data[4 : 4 + length]
    if not 1 < length <= 0xFFFF or len(body) < 2:
        return None
    if body[0] == 0x0A:
        end = body.find(b"\x00", 1)
        raw = body[1:end] if end > 1 else b""
        text = raw.decode("ascii", errors="replace")
        if not re.match(r"\d+\.\d+", text):
            return None
        product, version = mysql_product(text)
        return Identified("mysql", product, version, banner=text)
    if body[0] == 0xFF and len(body) >= 4:
        code = int.from_bytes(body[1:3], "little")
        message = body[3:].decode("utf-8", errors="replace").lstrip("#")
        if 1000 <= code < 5000:
            return Identified("mysql", "mysql", banner=message[:200], extra={"erro": code})
    return None


def mysql_product(server_version: str) -> tuple[str, str]:
    """``5.5.5-10.6.12-MariaDB-0ubuntu0.22.04.1`` → (mariadb, 10.6.12); ``8.0.35`` → (mysql, 8.0.35)."""
    if "mariadb" in server_version.lower():
        match = re.search(r"(?:5\.5\.5-)?(\d+\.\d+\.\d+)-MariaDB", server_version, re.I)
        return "mariadb", match.group(1) if match else ""
    match = re.match(r"(\d+\.\d+\.\d+)", server_version)
    return "mysql", match.group(1) if match else ""


def is_telnet(data: bytes) -> bool:
    """Negociação Telnet (IAC + DO/DONT/WILL/WONT) logo no início da conexão."""
    return len(data) >= 2 and data[0] == 0xFF and data[1] in _TELNET_CMDS


def rfb_version(data: bytes) -> tuple[int, int] | None:
    """Versão do protocolo RFB (VNC) anunciada pelo servidor (``RFB 003.008``)."""
    match = _RFB.match(data)
    return (int(match.group(1)), int(match.group(2))) if match else None


def classify_banner(data: bytes, port: int) -> Identified | None:
    """Reconhece o serviço pelo que o servidor envia ao abrir a conexão."""
    if not data:
        return None
    text = data.decode("latin-1")
    first = text.split("\n", 1)[0].strip()
    if first.startswith("SSH-"):
        return parse_ssh_banner(first)
    rfb = rfb_version(data)
    if rfb is not None:  # a versão do protocolo RFB não é a versão do produto
        return Identified("vnc", "vnc", banner=first, extra={"rfb": f"{rfb[0]}.{rfb[1]}"})
    if is_telnet(data):
        return Identified("telnet", banner="negociação Telnet (IAC)")
    greeting = parse_mysql_greeting(data)
    if greeting is not None:
        return greeting
    return _classify_text(text, first, port)


def _classify_text(text: str, first: str, port: int) -> Identified | None:
    lower = text.lower()
    if first.startswith("220"):
        return classify_220(text, port)
    if first.startswith("+OK"):
        product, version = _product(text, _MAILBOX_PRODUCTS)
        return Identified("pop3", product, version, banner=first)
    if first.startswith(("* OK", "* PREAUTH")):
        product, version = _product(text, _MAILBOX_PRODUCTS)
        return Identified("imap", product, version, banner=first)
    if first.startswith("HTTP/1."):
        return Identified("http", banner=first)
    if first.startswith(("-NOAUTH", "-DENIED")):
        return Identified("redis", "redis", banner=first)
    if port in (23, 2323) and any(w in lower for w in ("login:", "username:", "password:")):
        return Identified("telnet", banner=first)
    return None


def classify_220(text: str, port: int) -> Identified:
    """Banner ``220``: FTP ou SMTP.

    Ordem de decisão: produto reconhecido (vsFTPd, Postfix...), palavras de um só
    protocolo e, se o banner citar os dois (ex.: ``220 ftp.empresa.com ESMTP``) ou
    nenhum, a porta. Sem pista nenhuma, fica ``ftp-ou-smtp`` para desempatar com EHLO.
    """
    first = text.split("\n", 1)[0].strip()
    service = _service_by_product(text) or _service_by_words(text.lower())
    if not service:
        if port in SMTP_PORTS:
            service = "smtp"
        elif port in FTP_PORTS:
            service = "ftp"
        else:
            return Identified("ftp-ou-smtp", banner=first, confirmed=False)
    table = _FTP_PRODUCTS if service == "ftp" else _SMTP_PRODUCTS
    product, version = _product(text, table)
    return Identified(service, product, version, banner=first)


def _service_by_product(text: str) -> str:
    if _product(text, _FTP_PRODUCTS)[0]:
        return "ftp"
    if _product(text, _SMTP_PRODUCTS)[0]:
        return "smtp"
    return ""


def _service_by_words(lower: str) -> str:
    ftp = any(word in lower for word in _FTP_WORDS)
    smtp = any(word in lower for word in _SMTP_WORDS)
    if ftp != smtp:
        return "ftp" if ftp else "smtp"
    return ""
