"""Protocolos de rede do Windows: negociação RDP (X.224) e SMB (NEGOTIATE).

Só a primeira troca de cada protocolo — a mesma que qualquer cliente faz antes
de pedir usuário e senha:

* RDP: ``X.224 Connection Request`` com ``RDP_NEG_REQ`` ([MS-RDPBCGR] 2.2.1.1);
  a resposta diz quais protocolos de segurança o servidor aceita.
* SMB: ``NEGOTIATE`` do SMB1 ([MS-CIFS] 2.2.4.52) e do SMB2 ([MS-SMB2] 2.2.3);
  a resposta revela se o SMBv1 está ativo e se a assinatura é obrigatória.

Nada aqui faz E/S: são os bytes dos pedidos e a interpretação das respostas.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

# -- RDP -------------------------------------------------------------------------
PROTOCOL_RDP = 0x00  # segurança RDP padrão (sem TLS, sem NLA)
PROTOCOL_SSL = 0x01  # TLS
PROTOCOL_HYBRID = 0x02  # CredSSP (NLA)
PROTOCOL_HYBRID_EX = 0x08  # CredSSP com Early User Authorization

#: códigos de RDP_NEG_FAILURE ([MS-RDPBCGR] 2.2.1.2.2)
HYBRID_REQUIRED_BY_SERVER = 5
RDP_FAILURES = {
    1: "SSL_REQUIRED_BY_SERVER",
    2: "SSL_NOT_ALLOWED_BY_SERVER",
    3: "SSL_CERT_NOT_ON_SERVER",
    4: "INCONSISTENT_FLAGS",
    5: "HYBRID_REQUIRED_BY_SERVER",
    6: "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER",
    7: "ENTRA_AUTH_REQUIRED_BY_SERVER",
}
#: falhas que provam autenticação ANTES da sessão gráfica (NLA, certificado ou Entra ID)
PREAUTH_FAILURES = frozenset({5, 6, 7})
RDP_PROTOCOL_NAMES = {
    0: "RDP padrão",
    1: "TLS",
    2: "CredSSP (NLA)",
    4: "RDSTLS",
    8: "CredSSP-EX (NLA)",
    16: "RDSAAD",
}


@dataclass(frozen=True)
class RdpNegotiation:
    """Resultado de uma negociação: protocolo escolhido OU código de falha."""

    selected: int | None = None
    failure: int | None = None
    legacy: bool = False  # servidor antigo: confirmou sem bloco de negociação (só RDP padrão)

    @property
    def accepted(self) -> bool:
        return self.selected is not None

    def describe(self) -> str:
        if self.legacy:
            return "confirmou a conexão sem negociação (servidor antigo: só segurança RDP padrão)"
        if self.selected is not None:
            name = RDP_PROTOCOL_NAMES.get(self.selected, f"0x{self.selected:x}")
            return f"aceitou o protocolo {name}"
        code = self.failure if self.failure is not None else -1
        return f"recusou com {RDP_FAILURES.get(code, f'código {code}')}"


def rdp_request(protocols: int) -> bytes:
    """TPKT + X.224 Connection Request + cookie + RDP_NEG_REQ pedindo ``protocols``."""
    negotiation = struct.pack("<BBHI", 0x01, 0x00, 8, protocols)
    body = b"\xe0\x00\x00\x00\x00\x00" + b"Cookie: mstshash=eigan\r\n" + negotiation
    tpdu = bytes([len(body)]) + body
    return struct.pack(">BBH", 3, 0, 4 + len(tpdu)) + tpdu


def parse_rdp(data: bytes) -> RdpNegotiation | None:
    """Interpreta o X.224 Connection Confirm (código 0xD0) e o bloco de negociação.

    Deslocamentos: TPKT (4) + LI (1) + código (1) + DST-REF (2) + SRC-REF (2) + classe
    (1); a negociação começa no byte 11 (tipo, flags, tamanho e o valor em 15..19).
    """
    if len(data) < 11 or data[0] != 3 or data[5] & 0xF0 != 0xD0:
        return None
    length = int.from_bytes(data[2:4], "big")
    if len(data) < length:
        return None  # resposta incompleta: não dá para dizer que não houve negociação
    if len(data) >= 19:
        kind = data[11]
        value = int.from_bytes(data[15:19], "little")
        if kind == 0x02:
            return RdpNegotiation(selected=value)
        if kind == 0x03:
            return RdpNegotiation(failure=value)
    if length != 11:
        return None
    return RdpNegotiation(selected=PROTOCOL_RDP, legacy=True)


# -- SMB -------------------------------------------------------------------------
SMB1_DIALECT = "NT LM 0.12"
SMB2_DIALECTS = (0x0202, 0x0210, 0x0300, 0x0302)
SMB2_DIALECT_NAMES = {
    0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0", 0x0302: "3.0.2", 0x0311: "3.1.1", 0x02FF: "2.x",
}  # fmt: skip
#: resposta do NEGOTIATE do SMB1 para o dialeto NT LM 0.12: 17 palavras de parâmetros
SMB1_NTLM_WORDCOUNT = 0x11


@dataclass(frozen=True)
class SmbNegotiation:
    version: int  # 1 ou 2
    dialect: str
    signing_enabled: bool
    signing_required: bool


def _netbios(payload: bytes) -> bytes:
    """Cabeçalho de sessão NetBIOS (tipo 0x00 + tamanho em 24 bits) usado na porta 445."""
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


def smb1_negotiate(dialects: tuple[str, ...] = (SMB1_DIALECT,)) -> bytes:
    """SMB_COM_NEGOTIATE (0x72) oferecendo ``dialects`` (por padrão só o SMBv1)."""
    header = (
        b"\xffSMB"
        + b"\x72"  # comando NEGOTIATE
        + b"\x00\x00\x00\x00"  # status
        + b"\x18"  # flags: caminhos canônicos, sem diferenciar maiúsculas
        + struct.pack("<H", 0xC801)  # flags2: unicode, NT status, segurança estendida, nomes longos
        + b"\x00" * 12  # PIDHigh + SecurityFeatures + reservado
        + b"\x00\x00"  # TID
        + struct.pack("<H", 0xFEFF)  # PIDLow
        + b"\x00\x00\x00\x00"  # UID + MID
    )
    names = b"".join(b"\x02" + d.encode("ascii") + b"\x00" for d in dialects)
    return _netbios(header + b"\x00" + struct.pack("<H", len(names)) + names)


def smb2_negotiate() -> bytes:
    """SMB2 NEGOTIATE (comando 0) oferecendo os dialetos 2.0.2 a 3.0.2.

    O 3.1.1 fica de fora porque exige contextos de negociação; servidores que só
    aceitam 3.1.1 recusam este pedido e a assinatura fica sem avaliação.
    """
    header = (
        b"\xfeSMB"
        + struct.pack("<H", 64)  # StructureSize
        + b"\x00\x00"  # CreditCharge
        + b"\x00\x00\x00\x00"  # Status
        + b"\x00\x00"  # NEGOTIATE
        + struct.pack("<H", 1)  # CreditRequest
        + b"\x00" * 4  # Flags
        + b"\x00" * 4  # NextCommand
        + b"\x00" * 8  # MessageId
        + b"\x00" * 4  # Reserved
        + b"\x00" * 4  # TreeId
        + b"\x00" * 8  # SessionId
        + b"\x00" * 16  # Signature
    )
    # tamanho da estrutura, nº de dialetos, SecurityMode (assinatura habilitada), reservado
    fixed = struct.pack("<HHHH", 36, len(SMB2_DIALECTS), 0x0001, 0)
    body = (
        fixed
        + b"\x00\x00\x00\x00"  # Capabilities
        + os.urandom(16)  # ClientGuid
        + b"\x00" * 8  # ClientStartTime
        + b"".join(struct.pack("<H", d) for d in SMB2_DIALECTS)
    )
    return _netbios(header + body)


def parse_smb(data: bytes) -> SmbNegotiation | None:
    """Resposta ao NEGOTIATE (SMB1 ou SMB2). None se não for SMB ou se nenhum dialeto servir."""
    if len(data) < 8 or data[0] != 0x00:
        return None
    payload = data[4:]
    if payload.startswith(b"\xfeSMB"):
        return _parse_smb2(payload)
    if payload.startswith(b"\xffSMB"):
        return _parse_smb1(payload)
    return None


def _parse_smb1(payload: bytes) -> SmbNegotiation | None:
    """Cabeçalho SMB1 de 32 bytes; depois WordCount (32), DialectIndex (33) e SecurityMode (35).

    SMBv1 ativo = status de sucesso, WordCount 0x11 e DialectIndex diferente de 0xFFFF
    (0xFFFF significa "nenhum dialeto oferecido serve").
    """
    if len(payload) < 36 or payload[4] != 0x72:
        return None
    status = int.from_bytes(payload[5:9], "little")
    if status != 0 or payload[32] != SMB1_NTLM_WORDCOUNT:
        return None
    if int.from_bytes(payload[33:35], "little") == 0xFFFF:
        return None
    mode = payload[35]
    return SmbNegotiation(1, SMB1_DIALECT, bool(mode & 0x04), bool(mode & 0x08))


def _parse_smb2(payload: bytes) -> SmbNegotiation | None:
    """Cabeçalho SMB2 de 64 bytes; SecurityMode em 66 e DialectRevision em 68."""
    if len(payload) < 64 + 6:
        return None
    command = int.from_bytes(payload[12:14], "little")
    status = int.from_bytes(payload[8:12], "little")
    if command != 0 or status != 0:
        return None
    mode = int.from_bytes(payload[66:68], "little")
    dialect = int.from_bytes(payload[68:70], "little")
    name = SMB2_DIALECT_NAMES.get(dialect, f"0x{dialect:04x}")
    return SmbNegotiation(2, name, bool(mode & 0x01), bool(mode & 0x02))
