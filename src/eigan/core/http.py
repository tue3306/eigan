"""Cliente HTTP das checagens (stdlib ``http.client``).

Controle total do que é enviado e recebido: redirecionamentos só quando pedido,
limite de bytes lidos, cabeçalhos repetidos preservados (vários ``Set-Cookie``),
limite de conexões simultâneas por host e nunca leitura de endereços de
metadados de nuvem. O certificado do ALVO não é validado aqui (é auditado à
parte pelas checagens TLS) — assim um certificado vencido não impede o resto da
auditoria.
"""

from __future__ import annotations

import http.client
import logging
import ssl
import threading
import time
import zlib
from dataclasses import dataclass, field
from email.message import Message
from typing import Any
from urllib.parse import urljoin, urlsplit

from .netutil import is_metadata_address
from .settings import Settings

log = logging.getLogger("eigan.http")

_REDIRECTS = {301, 302, 303, 307, 308}


def insecure_context() -> ssl.SSLContext:
    """Contexto TLS tolerante (só para conversar com o alvo, nunca para baixar dados)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        pass
    return ctx


@dataclass
class Response:
    url: str
    status: int
    reason: str
    headers: list[tuple[str, str]]
    body: bytes
    elapsed: float
    redirects: list[tuple[int, str]] = field(default_factory=list)
    truncated: bool = False
    _text: str | None = field(default=None, repr=False)

    def header(self, name: str) -> str | None:
        lname = name.lower()
        for key, value in self.headers:
            if key.lower() == lname:
                return value
        return None

    def headers_all(self, name: str) -> list[str]:
        lname = name.lower()
        return [value for key, value in self.headers if key.lower() == lname]

    def has_header(self, name: str) -> bool:
        return self.header(name) is not None

    @property
    def content_type(self) -> str:
        value = self.header("content-type") or ""
        return value.split(";", 1)[0].strip().lower()

    @property
    def charset(self) -> str:
        msg = Message()
        msg["content-type"] = self.header("content-type") or "text/plain"
        return str(msg.get_param("charset") or "utf-8")

    @property
    def text(self) -> str:
        if self._text is None:
            try:
                self._text = self.body.decode(self.charset, errors="replace")
            except LookupError:
                self._text = self.body.decode("utf-8", errors="replace")
        return self._text

    @property
    def location(self) -> str | None:
        value = self.header("location")
        return urljoin(self.url, value) if value else None

    @property
    def is_html(self) -> bool:
        return "html" in self.content_type or self.text.lstrip()[:15].lower().startswith(
            ("<!doctype html", "<html")
        )


class HttpClient:
    """Cliente usado por todas as checagens web."""

    def __init__(self, settings: Settings, cancel: threading.Event | None = None) -> None:
        self.settings = settings
        self.cancel = cancel or threading.Event()
        self._ctx = insecure_context()
        self._sem_lock = threading.Lock()
        self._semaphores: dict[str, threading.BoundedSemaphore] = {}
        self.requests_made = 0

    def _semaphore(self, host: str) -> threading.BoundedSemaphore:
        with self._sem_lock:
            sem = self._semaphores.get(host)
            if sem is None:
                sem = threading.BoundedSemaphore(self.settings.http_per_host)
                self._semaphores[host] = sem
            return sem

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | str | None = None,
        timeout: float | None = None,
        max_bytes: int | None = None,
        follow_redirects: bool = False,
        max_redirects: int = 5,
    ) -> Response | None:
        """Faz a requisição. Devolve None se não houver resposta HTTP (rede/TLS/tempo)."""
        redirects: list[tuple[int, str]] = []
        current = url
        current_method = method.upper()
        current_body = body
        started = time.monotonic()
        for _ in range(max_redirects + 1):
            if self.cancel.is_set():
                return None
            resp = self._single(current_method, current, headers, current_body, timeout, max_bytes)
            if resp is None:
                return None
            if not follow_redirects or resp.status not in _REDIRECTS or not resp.location:
                resp.redirects = redirects
                resp.elapsed = time.monotonic() - started
                return resp
            nxt = resp.location
            if urlsplit(nxt).scheme not in ("http", "https"):
                resp.redirects = redirects
                return resp
            redirects.append((resp.status, nxt))
            if resp.status == 303 or (resp.status in (301, 302) and current_method == "POST"):
                current_method, current_body = "GET", None
            current = nxt
        log.debug("redirecionamentos demais em %s", url)
        return None

    def _single(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None,
        body: bytes | str | None,
        timeout: float | None,
        max_bytes: int | None,
    ) -> Response | None:
        parts = urlsplit(url)
        host = parts.hostname or ""
        if not host or parts.scheme not in ("http", "https"):
            return None
        if is_metadata_address(host):
            log.warning("bloqueado acesso a endereço de metadados: %s", host)
            return None
        port = parts.port or (443 if parts.scheme == "https" else 80)
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        send_headers = {
            "User-Agent": self.settings.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
        }
        if headers:
            send_headers.update(headers)
        payload = body.encode("utf-8") if isinstance(body, str) else body
        limit = max_bytes if max_bytes is not None else self.settings.http_max_bytes
        wait = timeout if timeout is not None else self.settings.http_timeout
        conn: http.client.HTTPConnection
        if parts.scheme == "https":
            conn = http.client.HTTPSConnection(host, port, timeout=wait, context=self._ctx)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=wait)
        sem = self._semaphore(host)
        with sem:
            if self.settings.http_delay > 0:
                time.sleep(self.settings.http_delay)
            started = time.monotonic()
            try:
                conn.request(method, path, body=payload, headers=send_headers)
                raw = conn.getresponse()
                data = raw.read(limit + 1) if method != "HEAD" else b""
                header_list = [(k, v) for k, v in raw.getheaders()]
                status, reason = raw.status, raw.reason
            except (TimeoutError, OSError, ssl.SSLError, http.client.HTTPException) as exc:
                log.debug("%s %s falhou: %s", method, url, exc)
                return None
            finally:
                conn.close()
                self.requests_made += 1
        truncated = len(data) > limit
        data = data[:limit]
        resp = Response(
            url=url,
            status=status,
            reason=reason or "",
            headers=header_list,
            body=data,
            elapsed=time.monotonic() - started,
            truncated=truncated,
        )
        encoding = (resp.header("content-encoding") or "").lower()
        if data and encoding in ("gzip", "deflate"):
            inflated = _inflate(data, encoding, limit * 4)
            if inflated is not None:
                resp.body = inflated
        return resp

    def get(self, url: str, **kwargs: Any) -> Response | None:
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> Response | None:
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> Response | None:
        return self.request("OPTIONS", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Response | None:
        return self.request("POST", url, **kwargs)


def _inflate(data: bytes, encoding: str, max_out: int) -> bytes | None:
    """Descomprime com teto de saída (resposta do alvo pode ser uma "bomba" de gzip)."""
    attempts = [16 + zlib.MAX_WBITS] if encoding == "gzip" else [zlib.MAX_WBITS, -zlib.MAX_WBITS]
    for wbits in attempts:
        try:
            return zlib.decompressobj(wbits).decompress(data, max_out)
        except zlib.error:
            continue
    return None
