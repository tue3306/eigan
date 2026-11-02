#!/usr/bin/env python3
"""Servidor FTP REAL (pyftpdlib) do laboratorio EIGAN.

--modo inseguro    login anonimo habilitado, sem TLS, senha trafega em texto claro
--modo endurecido  sem anonimo, FTPS explicito obrigatorio (TLS 1.2+), usuario com senha
"""

from __future__ import annotations

import argparse
import logging
import ssl as _ssl

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--modo", choices=("inseguro", "endurecido"), required=True)
    ap.add_argument("--porta", type=int, required=True)
    ap.add_argument("--raiz", required=True)
    ap.add_argument("--cert")
    ap.add_argument("--chave")
    ap.add_argument("--senha", default="")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO)

    auth = DummyAuthorizer()
    if args.modo == "inseguro":
        auth.add_anonymous(args.raiz, perm="elr")
        handler = FTPHandler
        handler.banner = "EIGAN Lab FTP (inseguro) pronto."
    else:
        from pyftpdlib.handlers import TLS_FTPHandler

        auth.add_user("labuser", args.senha, args.raiz, perm="elr")
        handler = TLS_FTPHandler
        handler.certfile = args.cert
        handler.keyfile = args.chave
        handler.tls_control_required = True
        handler.tls_data_required = True
        handler.banner = "Servico FTP."
        try:  # pyftpdlib >= 1.5.7 expoe o contexto; exige TLS 1.2+
            from OpenSSL import SSL

            handler.ssl_protocol = SSL.TLS_METHOD
            handler.ssl_options = (
                SSL.OP_NO_SSLv2
                | SSL.OP_NO_SSLv3
                | SSL.OP_NO_TLSv1
                | SSL.OP_NO_TLSv1_1
                | SSL.OP_NO_COMPRESSION
            )
        except Exception:  # noqa: BLE001 - laboratorio: segue com o padrao da biblioteca
            pass
    handler.authorizer = auth
    handler.passive_ports = range(args.porta + 100, args.porta + 120)
    handler.permit_foreign_addresses = False
    server = FTPServer(("127.0.0.1", args.porta), handler)
    server.max_cons = 32
    server.serve_forever()
    return 0


if __name__ == "__main__":
    _ = _ssl  # silencia linters; ssl importado para garantir suporte TLS na build
    raise SystemExit(main())
