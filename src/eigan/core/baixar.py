"""Download HTTPS com limites, usado só nos comandos de atualização.

Nunca é chamado durante uma auditoria. O abridor valida o certificado, segue
redirecionamentos apenas para ``https://`` e o corpo é lido em pedaços com teto de
tamanho, então uma resposta gigante (ou infinita) não enche a memória nem o disco.
"""

from __future__ import annotations

import io
import ssl
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any, BinaryIO
from urllib.parse import urlsplit

Opener = Callable[..., Any]

USER_AGENT = "EIGAN (atualizacao de catalogos; https://github.com/tue3306/EIGAN)"
CHUNK = 1 << 20
#: o relógio do prazo total (os testes o substituem)
_agora = time.monotonic


class HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    """Segue redirecionamentos apenas para endereços https://."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        if urlsplit(newurl).scheme != "https":
            raise urllib.error.URLError(f"redirecionamento para fora de HTTPS recusado: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def https_opener() -> Opener:
    """Abridor com certificado validado e redirecionamentos só para HTTPS."""
    handler = urllib.request.HTTPSHandler(context=ssl.create_default_context())
    director = urllib.request.build_opener(HttpsOnlyRedirect(), handler)
    director.addheaders = [("User-Agent", USER_AGENT)]
    return director.open


def fetch_stream(
    url: str,
    out: BinaryIO,
    timeout: float,
    fetch: Opener,
    max_bytes: int,
    total: float | None = None,
) -> int:
    """Copia a resposta para ``out`` respeitando o limite de tamanho; devolve os bytes lidos.

    ``timeout`` vale para cada leitura do socket; ``total`` (segundos) é o prazo da
    transferência inteira, conferido a cada pedaço recebido. Sem ele, um servidor que
    manda 1 byte a cada ``timeout`` segundos seguraria o download para sempre.
    """
    if not url.startswith("https://"):
        raise ValueError("só downloads https:// são permitidos")
    lidos = 0
    prazo = None if total is None else _agora() + total
    with fetch(url, timeout=timeout) as response:
        final = str(getattr(response, "geturl", lambda: url)() or url)
        if not final.startswith("https://"):
            raise ValueError("a resposta veio de um endereço que não é https://")
        declared = (getattr(response, "headers", None) or {}).get("Content-Length")
        if declared and str(declared).isdigit() and int(declared) > max_bytes:
            raise ValueError("arquivo maior que o limite de download")
        # read1 devolve o que chegou numa leitura, sem esperar encher o pedaço
        ler = getattr(response, "read1", response.read)
        while chunk := ler(CHUNK):
            lidos += len(chunk)
            if lidos > max_bytes:
                raise ValueError("arquivo maior que o limite de download")
            out.write(chunk)
            if prazo is not None and _agora() > prazo:
                raise TimeoutError("o download passou do prazo total")
    return lidos


def fetch_to(url: str, target: Path, timeout: float, fetch: Opener, max_bytes: int) -> int:
    """Grava a resposta em ``target`` respeitando o limite de tamanho."""
    if not url.startswith("https://"):
        raise ValueError("só downloads https:// são permitidos")
    with target.open("wb") as out:
        return fetch_stream(url, out, timeout, fetch, max_bytes)


def fetch_bytes(
    url: str, timeout: float, fetch: Opener, max_bytes: int, total: float | None = None
) -> bytes:
    """Baixa para a memória (arquivos pequenos, com teto de tamanho e prazo total opcional)."""
    buffer = io.BytesIO()
    fetch_stream(url, buffer, timeout, fetch, max_bytes, total)
    return buffer.getvalue()
