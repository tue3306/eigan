"""Servidor SSH falso e pacotes montados à mão para os testes de ``net.ssh``.

Fala só o começo do protocolo: manda o banner, lê o do cliente, manda os pacotes
combinados e guarda tudo o que recebeu, para os testes confirmarem que a checagem
não enviou nada além do próprio banner.
"""

from __future__ import annotations

import socket
import struct
import threading
from collections.abc import Sequence
from typing import Any

from eigan.core.models import Fact

MODERN_KEX = ("mlkem768x25519-sha256", "curve25519-sha256", "kex-strict-s-v00@openssh.com")
MODERN_HOSTKEY = ("ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256")
MODERN_CIPHERS = ("chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-ctr")
MODERN_MACS = ("hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com")

SSH_MSG_IGNORE = 2


def name_list(names: Sequence[str]) -> bytes:
    text = ",".join(names).encode("ascii")
    return struct.pack(">I", len(text)) + text


def kexinit_payload(
    *,
    kex: Sequence[str] = MODERN_KEX,
    hostkey: Sequence[str] = MODERN_HOSTKEY,
    ciphers: Sequence[str] = MODERN_CIPHERS,
    macs: Sequence[str] = MODERN_MACS,
    ciphers_s2c: Sequence[str] | None = None,
    macs_s2c: Sequence[str] | None = None,
) -> bytes:
    """Payload do SSH_MSG_KEXINIT: tipo, cookie, dez listas, flag e campo reservado."""
    lists = (
        kex,
        hostkey,
        ciphers,
        ciphers if ciphers_s2c is None else ciphers_s2c,
        macs,
        macs if macs_s2c is None else macs_s2c,
        ("none", "zlib@openssh.com"),
        ("none", "zlib@openssh.com"),
        (),
        (),
    )
    body = b"".join(name_list(item) for item in lists)
    return bytes([20]) + b"\x11" * 16 + body + b"\x00" + b"\x00\x00\x00\x00"


def packet(payload: bytes) -> bytes:
    """Pacote binário sem criptografia (RFC 4253 §6): tamanho, padding, payload, padding."""
    padding = 8 - (len(payload) + 5) % 8
    if padding < 4:
        padding += 8
    return struct.pack(">IB", len(payload) + padding + 1, padding) + payload + b"\x00" * padding


def ignore_packet() -> bytes:
    return packet(bytes([SSH_MSG_IGNORE]) + struct.pack(">I", 3) + b"abc")


class FakeSshServer:
    """Atende conexões em 127.0.0.1 e guarda em ``received`` o que cada cliente mandou."""

    def __init__(
        self,
        banner: bytes = b"SSH-2.0-OpenSSH_9.9p1\r\n",
        packets: Sequence[bytes] = (),
        *,
        pre_lines: Sequence[bytes] = (),
    ) -> None:
        self.banner = banner
        self.packets = packets
        self.pre_lines = pre_lines
        self.received: list[bytes] = []
        self._stop = threading.Event()
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(5)
        self._listener.settimeout(0.1)
        self.port: int = self._listener.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with conn:
                self._handle(conn)

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(3.0)
        data = b""
        try:
            conn.sendall(b"".join(self.pre_lines) + self.banner)
            if self.packets:
                while b"\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                conn.sendall(b"".join(self.packets))
            while True:  # espera o cliente fechar, guardando o que mais ele mandar
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
        except OSError:
            pass
        self.received.append(data)

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)
        self._listener.close()


def service_fact(port: int, host: str = "127.0.0.1", **extra: Any) -> Fact:
    """Fato ``service`` igual ao que ``net.services`` produz para uma porta SSH."""
    data: dict[str, Any] = {
        "host": host,
        "port": port,
        "service": "ssh",
        "tls": False,
        "label": f"{host}:{port}",
    }
    data.update(extra)
    return Fact("service", f"{host}:{port}", data)
