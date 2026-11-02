"""SIMULADO: servidor de banners antigos, para testar as REGRAS DE VERSAO do EIGAN.

Cada porta so DIZ ser um software antigo (banner/cabecalho); nao existe o software por tras e
nenhum codigo vulneravel e executado. Em particular o "vsFTPd 2.3.4" aqui NAO tem a porta
dos fundos historica: so repete a string do banner e recusa qualquer login.

  HTTP   Apache/2.4.49 (Unix)                           porta PORT_BANNER_HTTP_APACHE
  HTTP   nginx/1.16.1                                   porta PORT_BANNER_HTTP_NGINX
  FTP    (vsFTPd 2.3.4)                                 porta PORT_BANNER_FTP_VSFTPD
  FTP    ProFTPD 1.3.5 Server (Debian)                  porta PORT_BANNER_FTP_PROFTPD
  SSH    SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10 (+KEXINIT legado)  porta PORT_BANNER_SSH_OLD
  SMTP   Exim 4.87 / Postfix                            portas PORT_BANNER_SMTP_EXIM / _POSTFIX
  MySQL  handshake v10 com versao 5.1.73                porta PORT_BANNER_MYSQL_OLD
  Redis  INFO com redis_version:2.8.19                  porta PORT_BANNER_REDIS_OLD
"""

from __future__ import annotations

import os
import socketserver
import struct

import _comum as c


# ------------------------------------------------------------------ HTTP
def rotas_http(corpo: str):
    def r(metodo, caminho, cab):
        return (
            200,
            {"Content-Type": "text/html"},
            f"<html><body><h1>{corpo}</h1><!-- banner simulado --></body></html>",
        )

    return r


# ------------------------------------------------------------------ FTP
def ftp(banner: str):
    class H(socketserver.StreamRequestHandler):
        def handle(self) -> None:
            self.request.settimeout(10)
            w = lambda s: (self.wfile.write(s.encode() + b"\r\n"), self.wfile.flush())  # noqa: E731
            try:
                w(banner)
                while True:
                    linha = self.rfile.readline(512)
                    if not linha:
                        return
                    cmd = linha.decode("latin-1").strip().upper()
                    if cmd.startswith("USER"):
                        w("331 Please specify the password.")
                    elif cmd.startswith("PASS"):
                        w("530 Login incorrect.")
                    elif cmd.startswith("QUIT"):
                        w("221 Goodbye.")
                        return
                    elif cmd.startswith("FEAT"):
                        w("211-Features:\r\n UTF8\r\n211 End")
                    else:
                        w("530 Please login with USER and PASS.")
            except OSError:
                return

    return H


# ------------------------------------------------------------------ SSH legado
def _lista(itens: list[str]) -> bytes:
    s = ",".join(itens).encode()
    return struct.pack(">I", len(s)) + s


def kexinit_openssh_72() -> bytes:
    kex = [
        "curve25519-sha256@libssh.org",
        "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
        "diffie-hellman-group-exchange-sha256",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group1-sha1",
    ]
    hostkeys = ["ssh-rsa", "ssh-dss", "ecdsa-sha2-nistp256", "ssh-ed25519"]
    ciph = [
        "aes128-ctr",
        "aes192-ctr",
        "aes256-ctr",
        "aes128-cbc",
        "3des-cbc",
        "blowfish-cbc",
        "cast128-cbc",
        "aes192-cbc",
        "aes256-cbc",
        "arcfour",
    ]
    macs = [
        "hmac-md5-etm@openssh.com",
        "hmac-sha1-etm@openssh.com",
        "umac-64-etm@openssh.com",
        "hmac-md5",
        "hmac-sha1",
        "umac-64@openssh.com",
        "hmac-sha2-256",
        "hmac-sha2-512",
    ]
    corpo = bytes([20]) + os.urandom(16)
    for lst in (
        kex,
        hostkeys,
        ciph,
        ciph,
        macs,
        macs,
        ["none", "zlib@openssh.com"],
        ["none", "zlib@openssh.com"],
        [],
        [],
    ):
        corpo += _lista(lst)
    corpo += b"\x00" + struct.pack(">I", 0)
    pad = 8 - ((len(corpo) + 5) % 8)
    pad = pad + 8 if pad < 4 else pad
    pacote = bytes([pad]) + corpo + os.urandom(pad)
    return struct.pack(">I", len(pacote)) + pacote


class SshVelho(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        r = self.request
        r.settimeout(8)
        try:
            r.sendall(b"SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10\r\n")
            r.sendall(kexinit_openssh_72())
            r.recv(4096)
        except OSError:
            return


# ------------------------------------------------------------------ SMTP
def smtp(banner: str):
    class H(socketserver.StreamRequestHandler):
        def handle(self) -> None:
            self.request.settimeout(10)
            w = lambda s: (self.wfile.write(s.encode() + b"\r\n"), self.wfile.flush())  # noqa: E731
            try:
                w(banner)
                while True:
                    linha = self.rfile.readline(512)
                    if not linha:
                        return
                    up = linha.decode("latin-1").strip().upper()
                    if up.startswith("EHLO"):
                        w("250-lab.test\r\n250-SIZE 52428800\r\n250 8BITMIME")
                    elif up.startswith("HELO"):
                        w("250 lab.test")
                    elif up.startswith("QUIT"):
                        w("221 Bye")
                        return
                    else:
                        w("502 Command not implemented")
            except OSError:
                return

    return H


# ------------------------------------------------------------------ MySQL antigo
class MysqlVelho(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        versao = b"5.1.73-lab"
        s1, s2 = os.urandom(8), os.urandom(12)
        corpo = (
            b"\x0a"
            + versao
            + b"\x00"
            + struct.pack("<I", 1)
            + s1
            + b"\x00"
            + struct.pack("<H", 0xF7FF)
            + b"\x21"
            + struct.pack("<H", 2)
            + struct.pack("<H", 0x000F)
            + bytes([21])
            + b"\x00" * 10
            + s2
            + b"\x00"
            + b"mysql_native_password\x00"
        )
        try:
            self.request.sendall(struct.pack("<I", len(corpo))[:3] + b"\x00" + corpo)
            self.request.settimeout(5)
            self.request.recv(1024)
        except OSError:
            return


# ------------------------------------------------------------------ Redis antigo
class RedisVelho(socketserver.BaseRequestHandler):
    INFO = (
        "# Server\r\nredis_version:2.8.19\r\nredis_mode:standalone\r\nos:Linux 3.16.0 x86_64\r\n"
        "tcp_port:6379\r\n# Keyspace\r\n"
    )

    def handle(self) -> None:
        r = self.request
        r.settimeout(8)
        try:
            while True:
                d = r.recv(2048).upper()
                if not d:
                    return
                if b"PING" in d:
                    r.sendall(b"+PONG\r\n")
                elif b"INFO" in d:
                    r.sendall(b"$%d\r\n%s\r\n" % (len(self.INFO), self.INFO.encode()))
                elif b"QUIT" in d:
                    r.sendall(b"+OK\r\n")
                    return
                else:
                    r.sendall(b"-ERR unknown command\r\n")
        except OSError:
            return


if __name__ == "__main__":
    P = c.porta
    c.rodar(
        [
            c.servidor_http(
                P("PORT_BANNER_HTTP_APACHE"), rotas_http("It works!"), "Apache/2.4.49 (Unix)"
            ),
            c.servidor_http(
                P("PORT_BANNER_HTTP_NGINX"), rotas_http("Welcome to nginx!"), "nginx/1.16.1"
            ),
            c.servidor_tcp(P("PORT_BANNER_FTP_VSFTPD"), ftp("220 (vsFTPd 2.3.4)")),
            c.servidor_tcp(
                P("PORT_BANNER_FTP_PROFTPD"),
                ftp("220 ProFTPD 1.3.5 Server (Debian) [::ffff:127.0.0.1]"),
            ),
            c.servidor_tcp(P("PORT_BANNER_SSH_OLD"), SshVelho),
            c.servidor_tcp(
                P("PORT_BANNER_SMTP_EXIM"),
                smtp("220 lab.test ESMTP Exim 4.87 Mon, 02 Nov 2026 10:00:00 +0000"),
            ),
            c.servidor_tcp(
                P("PORT_BANNER_SMTP_POSTFIX"), smtp("220 lab.test ESMTP Postfix (Ubuntu)")
            ),
            c.servidor_tcp(P("PORT_BANNER_MYSQL_OLD"), MysqlVelho),
            c.servidor_tcp(P("PORT_BANNER_REDIS_OLD"), RedisVelho),
        ]
    )
