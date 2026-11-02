"""SIMULADO: VNC (protocolo RFB 3.8, RFC 6143 secoes 7.1 e 7.2).

inseguro   : oferece apenas o tipo de seguranca 1 (None) e responde SecurityResult OK -> sem senha
endurecido : oferece apenas o tipo 2 (VNC Authentication) e envia o desafio de 16 bytes; qualquer
             resposta recebe SecurityResult 1 (falha). Nenhum desktop e exposto.
"""

from __future__ import annotations

import os
import socketserver
import struct

import _comum as c


def tela_inicial() -> bytes:
    pixel = struct.pack(">BBBBHHHBBBxxx", 32, 24, 0, 1, 255, 255, 255, 16, 8, 0)
    nome = b"EIGAN Lab (simulado)"
    return struct.pack(">HH", 800, 600) + pixel + struct.pack(">I", len(nome)) + nome


def fabrica(modo: str):
    class H(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            r = self.request
            r.settimeout(5)
            try:
                r.sendall(b"RFB 003.008\n")
                r.recv(12)  # versao do cliente
                if modo == "inseguro":
                    r.sendall(bytes([1, 1]))  # 1 tipo: None
                    r.recv(1)
                    r.sendall(struct.pack(">I", 0))  # SecurityResult OK
                    r.recv(1)  # ClientInit
                    r.sendall(tela_inicial())
                else:
                    r.sendall(bytes([1, 2]))  # 1 tipo: VNC Authentication
                    r.recv(1)
                    r.sendall(os.urandom(16))  # desafio
                    r.recv(16)
                    motivo = b"Authentication failed"
                    r.sendall(struct.pack(">I", 1) + struct.pack(">I", len(motivo)) + motivo)
            except OSError:
                return

    return H


if __name__ == "__main__":
    c.rodar(
        [
            c.servidor_tcp(c.porta("PORT_SIM_VNC_INS"), fabrica("inseguro")),
            c.servidor_tcp(c.porta("PORT_SIM_VNC_END"), fabrica("endurecido")),
        ]
    )
