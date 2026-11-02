"""SIMULADO: SMTP (RFC 5321).

inseguro   : sem STARTTLS, aceita qualquer RCPT TO (retransmissao aberta aparente) e responde VRFY/EXPN.
             NADA e entregue: o DATA e descartado.
endurecido : anuncia STARTTLS (TLS real com certificado do laboratorio), nega RCPT externo com 554 5.7.1,
             VRFY responde 252 (sem revelar usuarios)
"""

from __future__ import annotations

import socketserver
import ssl

import _comum as c

K = c.certs()


def fabrica(modo: str):
    class H(socketserver.StreamRequestHandler):
        def enviar(self, texto: str) -> None:
            self.wfile.write(texto.encode() + b"\r\n")
            self.wfile.flush()

        def handle(self) -> None:
            self.request.settimeout(15)
            ctx = c.contexto_tls(K["cert"], K["chave"]) if modo == "endurecido" else None
            self.enviar(
                "220 mail.lab.test ESMTP Postfix"
                if modo == "endurecido"
                else "220 mail.lab.test ESMTP Sendmail 8.13.8"
            )
            tls = False
            dados = False
            try:
                while True:
                    linha = self.rfile.readline(2048)
                    if not linha:
                        return
                    cmd = linha.decode("latin-1").strip()
                    up = cmd.upper()
                    if dados:
                        dados = up != "."
                        if not dados:
                            self.enviar("250 2.0.0 Ok (descartado pelo laboratorio)")
                        continue
                    if up.startswith(("EHLO", "HELO")):
                        if modo == "endurecido":
                            ext = ["250-mail.lab.test", "250-PIPELINING", "250-SIZE 10240000"]
                            if not tls:
                                ext.append("250-STARTTLS")
                            ext.append("250 8BITMIME")
                            self.enviar("\r\n".join(ext))
                        else:
                            self.enviar(
                                "250-mail.lab.test\r\n250-SIZE\r\n250-VRFY\r\n250-EXPN\r\n250 8BITMIME"
                            )
                    elif up == "STARTTLS" and modo == "endurecido" and not tls:
                        self.enviar("220 2.0.0 Ready to start TLS")
                        self.request = ctx.wrap_socket(self.request, server_side=True)
                        self.rfile = self.request.makefile("rb")
                        self.wfile = self.request.makefile("wb")
                        tls = True
                    elif up.startswith("MAIL FROM"):
                        self.enviar("250 2.1.0 Ok")
                    elif up.startswith("RCPT TO"):
                        if modo == "inseguro" or "@lab.test" in cmd.lower():
                            self.enviar("250 2.1.5 Ok")
                        else:
                            self.enviar("554 5.7.1 Relay access denied")
                    elif up == "DATA":
                        self.enviar("354 End data with <CR><LF>.<CR><LF>")
                        dados = True
                    elif up.startswith(("VRFY", "EXPN")):
                        self.enviar(
                            "250 2.1.5 root@lab.test"
                            if modo == "inseguro"
                            else "252 2.0.0 Cannot VRFY user"
                        )
                    elif up == "QUIT":
                        self.enviar("221 2.0.0 Bye")
                        return
                    else:
                        self.enviar(
                            "250 2.0.0 Ok"
                            if up in ("RSET", "NOOP")
                            else "502 5.5.2 Error: command not recognized"
                        )
            except (OSError, ssl.SSLError):
                return

    return H


if __name__ == "__main__":
    c.rodar(
        [
            c.servidor_tcp(c.porta("PORT_SIM_SMTP_INS"), fabrica("inseguro")),
            c.servidor_tcp(c.porta("PORT_SIM_SMTP_END"), fabrica("endurecido")),
        ]
    )
