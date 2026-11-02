"""SIMULADO: Telnet (RFC 854/857/858/1073) - apenas inseguro (o endurecido e "nao ter Telnet").

Negocia ECHO/SGA (IAC WILL ECHO, IAC WILL SGA), mostra banner e prompt de login em texto claro.
Nenhuma credencial e aceita e nenhum shell existe: qualquer tentativa recebe "Login incorrect".
"""

from __future__ import annotations

import socketserver

import _comum as c

IAC, WILL, DO, ECHO, SGA = 255, 251, 253, 1, 3


class H(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        r = self.request
        r.settimeout(10)
        try:
            r.sendall(
                bytes([IAC, WILL, ECHO, IAC, WILL, SGA, IAC, DO, 31])
            )  # DO NAWS tambem, como roteadores
            r.sendall(b"\r\nUbuntu 14.04.6 LTS\r\neigan-lab login: ")
            r.recv(256)
            r.sendall(b"Password: ")
            r.recv(256)
            r.sendall(b"\r\nLogin incorrect\r\n")
        except OSError:
            return


if __name__ == "__main__":
    c.rodar([c.servidor_tcp(c.porta("PORT_SIM_TELNET_INS"), H)])
