"""SIMULADO: Microsoft SQL Server (TDS 7.x, resposta ao PRELOGIN).

Layout: MS-TDS 2.2.6.5 (PRELOGIN). Pacote tipo 0x12 de entrada, resposta tipo 0x04.
  inseguro   : versao 11.0.2100 (SQL Server 2012 sem service pack), ENCRYPT_NOT_SUP (0x02)
  endurecido : versao 16.0.1000 (SQL Server 2022), ENCRYPT_REQ (0x03)
A versao e apenas o texto numerico do PRELOGIN; nao ha banco de dados nem login.
"""

from __future__ import annotations

import socketserver
import struct

import _comum as c


def prelogin(major: int, minor: int, build: int, sub: int, cripto: int) -> bytes:
    # Tabela de opcoes: token(1) offset(2) tamanho(2) ... 0xFF ; depois os dados
    dados = [
        (0x00, struct.pack(">BBHH", major, minor, build, sub)),  # VERSION (6 bytes)
        (0x01, bytes([cripto])),  # ENCRYPTION
        (0x02, b"\x00"),  # INSTOPT
        (0x03, b""),  # THREADID
        (0x04, b"\x00"),  # MARS
    ]
    tabela_len = len(dados) * 5 + 1
    off = tabela_len
    tabela = b""
    corpo = b""
    for token, d in dados:
        tabela += struct.pack(">BHH", token, off, len(d))
        corpo += d
        off += len(d)
    payload = tabela + b"\xff" + corpo
    return struct.pack(">BBHHBB", 0x04, 0x01, 8 + len(payload), 0, 1, 0) + payload


def fabrica(resposta: bytes):
    class H(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            self.request.settimeout(5)
            try:
                dados = self.request.recv(4096)
            except OSError:
                return
            if dados[:1] == b"\x12":
                self.request.sendall(resposta)

    return H


if __name__ == "__main__":
    c.rodar(
        [
            c.servidor_tcp(c.porta("PORT_SIM_MSSQL_INS"), fabrica(prelogin(11, 0, 2100, 0, 0x02))),
            c.servidor_tcp(c.porta("PORT_SIM_MSSQL_END"), fabrica(prelogin(16, 0, 1000, 6, 0x03))),
        ]
    )
