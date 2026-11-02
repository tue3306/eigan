"""SIMULADO: RDP (X.224 Connection Confirm com RDP Negotiation Response).

Layout: MS-RDPBCGR 2.2.1.2 (Server X.224 Connection Confirm PDU) + 2.2.1.2.1 (RDP_NEG_RSP).
  inseguro   : selectedProtocol = 0x00000000 (PROTOCOL_RDP, seguranca RDP padrao, sem NLA)
  endurecido : selectedProtocol = 0x00000002 (PROTOCOL_HYBRID = TLS + CredSSP/NLA)
Nao ha sessao RDP: depois do Confirm a conexao e encerrada.
"""

from __future__ import annotations

import socketserver
import struct

import _comum as c


def confirmacao(selecionado: int) -> bytes:
    neg = struct.pack(
        "<BBHI", 0x02, 0x00, 8, selecionado
    )  # TYPE_RDP_NEG_RSP, flags, length, protocolo
    x224 = (
        bytes([6 + len(neg), 0xD0]) + b"\x00\x00" + b"\x12\x34" + b"\x00" + neg
    )  # LI, CC, dst, src, classe
    return b"\x03\x00" + struct.pack(">H", 4 + len(x224)) + x224


def fabrica(selecionado: int):
    class H(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            self.request.settimeout(5)
            try:
                dados = self.request.recv(4096)
            except OSError:
                return
            if dados[:2] == b"\x03\x00":  # TPKT valido
                self.request.sendall(confirmacao(selecionado))

    return H


if __name__ == "__main__":
    c.rodar(
        [
            c.servidor_tcp(c.porta("PORT_SIM_RDP_INS"), fabrica(0x00000000)),
            c.servidor_tcp(c.porta("PORT_SIM_RDP_END"), fabrica(0x00000002)),
        ]
    )
