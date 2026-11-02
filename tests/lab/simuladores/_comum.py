"""Base comum dos SIMULADORES do EIGAN Lab.

SIMULADO: nada aqui e o software de verdade. Cada simulador reproduz apenas o que um
cliente enxerga ao conectar (bytes de handshake/banner/cabecalhos), com layouts
tirados da documentacao do protocolo. Nao ha codigo vulneravel nem execucao de
comandos: os simuladores nunca fazem nada alem de responder com texto/bytes fixos.

Portas vem de variaveis de ambiente PORT_* (ver ../portas.env). Tudo escuta em 127.0.0.1.
"""

from __future__ import annotations

import json
import os
import signal
import socketserver
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"
SIMULADO = "simulado"


def porta(nome: str) -> int:
    return int(os.environ[nome])


class _Tcp(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def contexto_tls(
    cert: str, chave: str, ca: str | None = None, exigir_cliente: bool = False
) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, chave)
    if exigir_cliente and ca:
        ctx.load_verify_locations(ca)
        ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def certs() -> dict[str, str]:
    base = os.environ.get("CERTS", "")
    return {
        "cert": os.path.join(base, "ok-cadeia.pem"),
        "chave": os.path.join(base, "ok.key"),
        "ca": os.path.join(base, "ca.pem"),
        "auto_cert": os.path.join(base, "autoassinado.pem"),
        "auto_chave": os.path.join(base, "autoassinado.key"),
    }


def servidor_tcp(
    numero: int, handler: type[socketserver.BaseRequestHandler], tls: ssl.SSLContext | None = None
):
    srv = _Tcp((HOST, numero), handler)
    if tls is not None:
        srv.socket = tls.wrap_socket(srv.socket, server_side=True)
    return srv


class _Http(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def servidor_http(numero: int, rotas, servidor_hdr: str = "", tls: ssl.SSLContext | None = None):
    """``rotas(metodo, caminho, cabecalhos) -> (status, cabecalhos_extra, corpo_bytes)``."""

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def version_string(self) -> str:  # cabecalho Server
            return servidor_hdr

        def log_message(self, *a) -> None:  # silencioso
            return

        def _resp(self) -> None:
            n = int(self.headers.get("Content-Length") or 0)
            if n:
                self.rfile.read(min(n, 65536))
            status, extra, corpo = rotas(self.command, self.path, self.headers)
            if isinstance(corpo, (dict, list)):
                corpo = json.dumps(corpo).encode()
                extra = {"Content-Type": "application/json", **extra}
            elif isinstance(corpo, str):
                corpo = corpo.encode()
            self.send_response(status)
            for k, v in extra.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(corpo)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(corpo)

        do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = do_OPTIONS = _resp  # noqa: N815

    srv = _Http((HOST, numero), H)
    if tls is not None:
        srv.socket = tls.wrap_socket(srv.socket, server_side=True)
    return srv


def rodar(servidores) -> None:
    """Sobe todos e bloqueia ate SIGTERM/SIGINT."""
    parar = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: parar.set())
    for s in servidores:
        threading.Thread(target=s.serve_forever, daemon=True).start()
        print(f"[{SIMULADO}] escutando em {HOST}:{s.server_address[1]}", flush=True)
    parar.wait()
    for s in servidores:
        s.shutdown()
    sys.exit(0)
