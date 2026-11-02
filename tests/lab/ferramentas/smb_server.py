#!/usr/bin/env python3
"""Servidor SMB REAL (impacket SimpleSMBServer) do laboratorio EIGAN.

  --modo inseguro    SMBv1 apenas (sem SMB2), compartilhamento anonimo, sem assinatura
  --modo endurecido  SMB2/3 habilitado, exige usuario e senha

Limite honesto do impacket: nao ha opcao para desligar o SMBv1 nem para exigir assinatura
no modo endurecido; por isso o catalogo marca o gemeo endurecido com essa ressalva.
"""

from __future__ import annotations

import argparse
import logging

from impacket import smbserver


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--modo", choices=("inseguro", "endurecido"), required=True)
    ap.add_argument("--porta", type=int, required=True)
    ap.add_argument("--raiz", required=True)
    ap.add_argument("--senha", default="")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO)

    server = smbserver.SimpleSMBServer(listenAddress="127.0.0.1", listenPort=args.porta)
    server.addShare("PUBLICO" if args.modo == "inseguro" else "PRIVADO", args.raiz, "Lab EIGAN")
    if args.modo == "inseguro":
        server.setSMB2Support(False)
    else:
        server.setSMB2Support(True)
        # hash NT calculado em tempo de execucao (a senha FALSA vem do lab)
        from impacket.ntlm import compute_nthash

        nt = compute_nthash(args.senha).hex()
        server.addCredential("labuser", 1001, "aad3b435b51404eeaad3b435b51404ee", nt)
    server.setLogFile("")
    server.start()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
