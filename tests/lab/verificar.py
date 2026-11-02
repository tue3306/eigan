#!/usr/bin/env python3
"""Teste de fumaca do laboratorio: confirma que cada servico responde COMO O MODO PROMETE.

So biblioteca padrao (roda no Windows, no Linux e no WSL). Fala os protocolos na mao, sem
exploracao: uma conexao, um pedido, leitura da resposta.

    python verificar.py                  # tudo
    python verificar.py --so nginx redis # filtra por trecho do id
    python verificar.py --json
    python verificar.py --certs <pasta com ca.pem>   # para classificar certificados (expirado, autoassinado...)

Codigo de saida: 0 se todas as verificacoes passaram; 1 se alguma falhou; 2 se nada respondeu.
"""

from __future__ import annotations

import argparse
import http.client as httpclient
import json
import os
import socket
import ssl
import struct
import sys
import time
import warnings
from pathlib import Path

warnings.filterwarnings("ignore", category=DeprecationWarning)
AQUI = Path(__file__).resolve().parent
HOST = "127.0.0.1"
SENHA = os.environ.get("LAB_PASS", "Lab-Endurecido-9xK2mQ4v")


def carregar_portas() -> dict[str, int]:
    portas: dict[str, int] = {}
    for linha in (AQUI / "portas.env").read_text(encoding="utf-8").splitlines():
        linha = linha.strip()
        if linha.startswith("PORT_") and "=" in linha:
            k, v = linha.split("=", 1)
            portas[k] = int(v.split("#")[0].strip())
    return portas


P = carregar_portas()
CA: str | None = None


# ----------------------------------------------------------------------------- helpers
def conectar(porta: int, timeout: float = 5.0) -> socket.socket:
    return socket.create_connection((HOST, porta), timeout)


def ler(s: socket.socket, n: int = 4096) -> bytes:
    try:
        return s.recv(n)
    except OSError:
        return b""


def http(
    porta: int,
    caminho: str = "/",
    metodo: str = "GET",
    tls: bool = False,
    headers: dict | None = None,
):
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        con = httpclient.HTTPSConnection(HOST, porta, timeout=6, context=ctx)
    else:
        con = httpclient.HTTPConnection(HOST, porta, timeout=6)
    con.request(metodo, caminho, headers=headers or {})
    r = con.getresponse()
    corpo = r.read(65536)
    cab = {k.lower(): v for k, v in r.getheaders()}
    cab["__set-cookie"] = "\n".join(v for k, v in r.getheaders() if k.lower() == "set-cookie")
    con.close()
    return r.status, cab, corpo


def tls_aceita(porta: int, versao: ssl.TLSVersion, cifras: str | None = None) -> bool | None:
    """True/False se o servidor aceita aquela versao; None se este cliente nao consegue testar."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = versao
        ctx.maximum_version = versao
        if cifras:
            ctx.set_ciphers(cifras)
    except (ssl.SSLError, ValueError, AttributeError):
        return None
    try:
        with conectar(porta) as s, ctx.wrap_socket(s, server_hostname="localhost"):
            return True
    except ssl.SSLError as e:
        txt = str(e).lower()
        if any(
            k in txt
            for k in (
                "version",
                "alert",
                "handshake failure",
                "no protocols",
                "unsupported protocol",
                "wrong_version",
                "no_protocols_available",
                "unknown protocol",
            )
        ):
            return False
        return None
    except OSError:
        return False


def tls_erro_cert(porta: int, host: str = "localhost") -> str:
    """Classifica o certificado: ok, expirado, autoassinado, hostname, ou outro texto."""
    ctx = ssl.create_default_context()
    if CA and Path(CA).exists():
        ctx.load_verify_locations(CA)
    try:
        with conectar(porta) as s, ctx.wrap_socket(s, server_hostname=host):
            return "ok"
    except ssl.SSLCertVerificationError as e:
        t = (e.verify_message or str(e)).lower()
        if "expired" in t:
            return "expirado"
        if "self-signed certificate" in t or "self signed certificate" in t:
            return "autoassinado"
        if "hostname" in t or "ip address mismatch" in t:
            return "hostname"
        return "outro: " + t[:60]
    except (ssl.SSLError, OSError) as e:
        return "erro: " + str(e)[:60]


def ssh_kexinit(porta: int) -> dict:
    s = conectar(porta)
    banner = b""
    while not banner.endswith(b"\n"):
        c = s.recv(1)
        if not c:
            break
        banner += c
    s.sendall(b"SSH-2.0-EIGANLabCheck\r\n")
    dados = b""
    while len(dados) < 5 or len(dados) < 4 + struct.unpack(">I", dados[:4])[0]:
        c = s.recv(65536)
        if not c:
            break
        dados += c
    s.close()
    tam = struct.unpack(">I", dados[:4])[0]
    corpo = dados[5 : 4 + tam]  # tira tamanho + padding_length
    pos = 1 + 16
    nomes = [
        "kex",
        "hostkey",
        "cifras_cs",
        "cifras_sc",
        "mac_cs",
        "mac_sc",
        "comp_cs",
        "comp_sc",
        "lang_cs",
        "lang_sc",
    ]
    out: dict = {"banner": banner.decode(errors="replace").strip()}
    for n in nomes:
        (ln,) = struct.unpack(">I", corpo[pos : pos + 4])
        out[n] = corpo[pos + 4 : pos + 4 + ln].decode().split(",") if ln else []
        pos += 4 + ln
    return out


def dns_consulta(porta: int, nome: str, tipo: int = 1, tcp: bool = False) -> tuple[int, int, int]:
    """Retorna (flags, rcode, ancount)."""
    q = (
        b"".join(bytes([len(p)]) + p.encode() for p in nome.split("."))
        + b"\x00"
        + struct.pack(">HH", tipo, 1)
    )
    msg = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + q
    if tcp:
        with conectar(porta) as s:
            s.sendall(struct.pack(">H", len(msg)) + msg)
            cab = b""
            while len(cab) < 2:
                cab += s.recv(2 - len(cab))
            (n,) = struct.unpack(">H", cab)
            r = b""
            while len(r) < min(n, 14):
                c = s.recv(4096)
                if not c:
                    break
                r += c
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
            u.settimeout(5)
            u.sendto(msg, (HOST, porta))
            r, _ = u.recvfrom(4096)
    _, flags, _, an, _, _ = struct.unpack(">HHHHHH", r[:12])
    return flags, flags & 0xF, an


def mongo_msg(cmd_bson: bytes, req: int = 1) -> bytes:
    corpo = struct.pack("<I", 0) + b"\x00" + cmd_bson
    return struct.pack("<iiii", 16 + len(corpo), req, 0, 2013) + corpo


def bson(**campos) -> bytes:
    corpo = b""
    for k, v in campos.items():
        if isinstance(v, int):
            corpo += b"\x10" + k.encode() + b"\x00" + struct.pack("<i", v)
        else:
            vb = str(v).encode()
            corpo += b"\x02" + k.encode() + b"\x00" + struct.pack("<i", len(vb) + 1) + vb + b"\x00"
    return struct.pack("<i", len(corpo) + 5) + corpo + b"\x00"


# ----------------------------------------------------------------------------- verificacoes
Resultado = tuple[bool, str]


def v_web(porta_http, porta_tls=None, ins=True):
    def f() -> list[tuple[str, Resultado]]:
        r: list[tuple[str, Resultado]] = []
        st, cab, corpo = http(porta_http, "/")
        if ins:
            r.append(
                (
                    "cabecalho Server revela versao",
                    (
                        "/" in cab.get("server", "")
                        and any(ch.isdigit() for ch in cab.get("server", "")),
                        cab.get("server", "-"),
                    ),
                )
            )
            r.append(
                (
                    "sem cabecalhos de seguranca",
                    (
                        not any(
                            h in cab
                            for h in (
                                "strict-transport-security",
                                "content-security-policy",
                                "x-frame-options",
                                "x-content-type-options",
                            )
                        ),
                        "ok",
                    ),
                )
            )
            r.append(
                (
                    "cookie sem Secure/HttpOnly",
                    (
                        "httponly" not in cab["__set-cookie"].lower()
                        and "secure" not in cab["__set-cookie"].lower()
                        and cab["__set-cookie"] != "",
                        cab["__set-cookie"][:60],
                    ),
                )
            )
            for caminho, marca in [
                ("/.git/HEAD", b"ref: refs/"),
                ("/.env", b"DB_PASSWORD="),
                ("/backup.sql", b"CREATE TABLE"),
                ("/phpinfo.php", b"phpinfo()"),
            ]:
                s2, _, c2 = http(porta_http, caminho)
                r.append((f"{caminho} exposto", (s2 == 200 and marca in c2, str(s2))))
            s2, _, c2 = http(porta_http, "/listing/")
            r.append(("listagem de diretorio", (s2 == 200 and b"Index of" in c2, str(s2))))
            _, cab2, _ = http(porta_http, "/", headers={"Origin": "https://evil.test"})
            _, cab3, _ = http(porta_http, "/api/x", headers={"Origin": "https://evil.test"})
            refl = (
                cab2.get("access-control-allow-origin") == "https://evil.test"
                or cab3.get("access-control-allow-origin") == "https://evil.test"
            )
            r.append(
                (
                    "CORS espelha Origin",
                    (
                        refl,
                        cab3.get(
                            "access-control-allow-origin",
                            cab2.get("access-control-allow-origin", "-"),
                        ),
                    ),
                )
            )
        else:
            r.append(
                (
                    "redireciona para HTTPS",
                    (
                        st in (301, 302, 308) and cab.get("location", "").startswith("https://"),
                        f"{st} {cab.get('location', '')}",
                    ),
                )
            )
        return r

    return f


def v_nginx_ins():
    base = v_web(P["PORT_NGINX_INS_HTTP"])
    r = base()
    s, _, c = http(P["PORT_NGINX_INS_HTTP"], "/nginx_status")
    r.append(("stub_status exposto", (s == 200 and b"Active connections" in c, str(s))))
    s, _, c = http(P["PORT_NGINX_INS_HTTP"], "/actuator")
    r.append(("actuator exposto", (s == 200 and b"heapdump" in c, str(s))))
    for nome, var, versao in [
        ("TLS 1.0", "PORT_NGINX_INS_TLS_LEGADO", ssl.TLSVersion.TLSv1),
        ("TLS 1.1", "PORT_NGINX_INS_TLS_LEGADO", ssl.TLSVersion.TLSv1_1),
    ]:
        a = tls_aceita(P[var], versao, "ALL:@SECLEVEL=0")
        r.append(
            (
                f"{nome} aceito (legado)",
                (True, "nao testavel neste cliente") if a is None else (a, str(a)),
            )
        )
    for nome, var in [
        ("expirado", "PORT_NGINX_INS_TLS_EXPIRADO"),
        ("autoassinado", "PORT_NGINX_INS_TLS_AUTOASSINADO"),
        ("hostname", "PORT_NGINX_INS_TLS_HOSTERRADO"),
    ]:
        e = tls_erro_cert(P[var])
        r.append((f"certificado {nome}", (e == nome or (CA is None and e != "ok"), e)))
    s, _, c = http(P["PORT_NGINX_INS_SOFT404"], "/.git/HEAD")
    r.append(
        (
            "soft-404: .git/HEAD devolve 200 com HTML",
            (s == 200 and b"<html" in c.lower() and b"ref:" not in c, str(s)),
        )
    )
    return r


def v_nginx_end():
    r = v_web(P["PORT_NGINX_END_HTTP"], ins=False)()
    st, cab, _ = http(P["PORT_NGINX_END_TLS"], "/", tls=True)
    r.append(
        (
            "HSTS + CSP + XFO + nosniff",
            (
                all(
                    h in cab
                    for h in (
                        "strict-transport-security",
                        "content-security-policy",
                        "x-frame-options",
                        "x-content-type-options",
                    )
                ),
                "ok",
            ),
        )
    )
    r.append(("Server sem versao", ("/" not in cab.get("server", ""), cab.get("server", "-"))))
    c = cab["__set-cookie"].lower()
    r.append(
        (
            "cookie Secure+HttpOnly+SameSite",
            ("secure" in c and "httponly" in c and "samesite" in c, c[:70]),
        )
    )
    for caminho in ("/.git/HEAD", "/.env", "/backup.sql", "/phpinfo.php", "/nginx_status"):
        s2, _, _ = http(P["PORT_NGINX_END_TLS"], caminho, tls=True)
        r.append((f"{caminho} nao exposto", (s2 in (403, 404), str(s2))))
    s2, _, _ = http(P["PORT_NGINX_END_TLS"], "/", metodo="TRACE", tls=True)
    r.append(("TRACE bloqueado", (s2 in (405, 403, 501), str(s2))))
    for nome, v in [("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)]:
        a = tls_aceita(P["PORT_NGINX_END_TLS"], v, "ALL:@SECLEVEL=0")
        r.append(
            (
                f"{nome} recusado",
                (True, "nao testavel neste cliente") if a is None else (a is False, str(a)),
            )
        )
    e = tls_erro_cert(P["PORT_NGINX_END_TLS"])
    r.append(
        (
            "certificado valido (CA do lab)",
            (e == "ok" if CA else True, e if CA else "sem --certs: nao classificado"),
        )
    )
    return r


def v_apache_ins():
    r = v_web(P["PORT_APACHE_INS_HTTP"])()
    p = P["PORT_APACHE_INS_HTTP"]
    s, _, c = http(p, "/server-status")
    r.append(("server-status exposto", (s == 200 and b"Apache Server Status" in c, str(s))))
    s, _, c = http(p, "/server-info")
    r.append(("server-info exposto", (s == 200 and b"Apache Server Information" in c, str(s))))
    s, _, c = http(p, "/", metodo="TRACE", headers={"X-Lab": "1"})
    r.append(("TRACE habilitado", (s == 200 and b"X-Lab" in c, str(s))))
    for nome, v in [("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)]:
        a = tls_aceita(P["PORT_APACHE_INS_TLS"], v, "ALL:@SECLEVEL=0")
        r.append(
            (f"{nome} aceito", (True, "nao testavel neste cliente") if a is None else (a, str(a)))
        )
    return r


def v_apache_end():
    r = v_web(P["PORT_APACHE_END_HTTP"], ins=False)()
    p = P["PORT_APACHE_END_TLS"]
    st, cab, _ = http(p, "/", tls=True)
    r.append(
        (
            "HSTS + CSP + XFO + nosniff",
            (
                all(
                    h in cab
                    for h in (
                        "strict-transport-security",
                        "content-security-policy",
                        "x-frame-options",
                        "x-content-type-options",
                    )
                ),
                "ok",
            ),
        )
    )
    r.append(
        (
            "Server = Apache (sem versao)",
            (cab.get("server", "") == "Apache", cab.get("server", "-")),
        )
    )
    for caminho in ("/server-status", "/.git/HEAD", "/.env"):
        s2, _, _ = http(p, caminho, tls=True)
        r.append((f"{caminho} nao exposto", (s2 in (403, 404), str(s2))))
    s2, _, _ = http(p, "/", metodo="TRACE", tls=True)
    r.append(("TRACE bloqueado", (s2 in (403, 405), str(s2))))
    for nome, v in [("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)]:
        a = tls_aceita(p, v, "ALL:@SECLEVEL=0")
        r.append(
            (
                f"{nome} recusado",
                (True, "nao testavel neste cliente") if a is None else (a is False, str(a)),
            )
        )
    return r


def ajp_cping(porta: int) -> bool:
    try:
        with conectar(porta, 3) as s:
            s.sendall(bytes.fromhex("12340001") + b"\x0a")
            return ler(s, 16).startswith(bytes.fromhex("41420001"))
    except OSError:
        return False


def v_tomcat_ins():
    s, cab, c = http(P["PORT_TOMCAT_INS_HTTP"], "/inexistente")
    r = [("pagina de erro revela Apache Tomcat/x.y", (b"Apache Tomcat/" in c, str(s)))]
    s2, _, _ = http(P["PORT_TOMCAT_INS_HTTP"], "/examples/servlets/")
    r.append(("aplicacoes de exemplo instaladas", (s2 == 200, str(s2))))
    s3, _, _ = http(P["PORT_TOMCAT_INS_HTTP"], "/manager/html")
    r.append(("Manager acessivel (pede login)", (s3 in (401, 403), str(s3))))
    r.append(
        (
            "AJP 1.3 aberto e respondendo CPing (sem segredo)",
            (ajp_cping(P["PORT_TOMCAT_INS_AJP"]), "CPONG"),
        )
    )
    return r


def v_tomcat_end():
    s, cab, c = http(P["PORT_TOMCAT_END_HTTP"], "/inexistente")
    r = [("erro sem versao do Tomcat", (b"Apache Tomcat/" not in c, str(s)))]
    s2, _, _ = http(P["PORT_TOMCAT_END_HTTP"], "/examples/")
    r.append(("sem apps de exemplo", (s2 == 404, str(s2))))
    try:
        conectar(P["PORT_TOMCAT_INS_AJP"] + 1, 1).close()
        r.append(("AJP desligado", (False, "porta aberta")))
    except OSError:
        r.append(("AJP desligado", (True, "recusado")))
    return r


def v_ssh(porta, ins):
    def f():
        k = ssh_kexinit(porta)
        r = [("banner SSH-2.0", (k["banner"].startswith("SSH-2.0-OpenSSH"), k["banner"]))]
        fracos_kex = {
            "diffie-hellman-group1-sha1",
            "diffie-hellman-group14-sha1",
            "diffie-hellman-group-exchange-sha1",
        }
        fracos_cif = {"3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc"}
        fracos_mac = {"hmac-md5", "hmac-sha1", "hmac-md5-96", "hmac-sha1-96"}
        tem = lambda lst, fr: sorted(set(lst) & fr)  # noqa: E731
        if ins:
            r.append(
                (
                    "KEX legado (sha1)",
                    (bool(tem(k["kex"], fracos_kex)), ",".join(tem(k["kex"], fracos_kex))),
                )
            )
            r.append(
                (
                    "cifras CBC/3DES",
                    (
                        bool(tem(k["cifras_cs"], fracos_cif)),
                        ",".join(tem(k["cifras_cs"], fracos_cif)),
                    ),
                )
            )
            r.append(
                (
                    "MAC md5/sha1",
                    (bool(tem(k["mac_cs"], fracos_mac)), ",".join(tem(k["mac_cs"], fracos_mac))),
                )
            )
            r.append(
                ("host key ssh-rsa oferecida", ("ssh-rsa" in k["hostkey"], ",".join(k["hostkey"])))
            )
        else:
            r.append(
                ("sem KEX legado", (not tem(k["kex"], fracos_kex), ",".join(k["kex"][:3]) + "..."))
            )
            r.append(
                ("sem CBC/3DES", (not tem(k["cifras_cs"], fracos_cif), ",".join(k["cifras_cs"])))
            )
            r.append(
                ("sem MAC md5/sha1", (not tem(k["mac_cs"], fracos_mac), ",".join(k["mac_cs"])))
            )
            r.append(
                (
                    "sem ssh-rsa (sha1) no host key",
                    ("ssh-rsa" not in k["hostkey"], ",".join(k["hostkey"])),
                )
            )
        return r

    return f


def resp_redis(porta, cmd: bytes) -> bytes:
    with conectar(porta) as s:
        s.sendall(cmd)
        time.sleep(0.15)
        return ler(s)


def v_redis_ins():
    r1 = resp_redis(P["PORT_REDIS_INS"], b"PING\r\n")
    r2 = resp_redis(P["PORT_REDIS_INS"], b"INFO server\r\n")
    r3 = resp_redis(P["PORT_REDIS_INS"], b"CONFIG GET dir\r\n")
    return [
        ("PING sem senha", (r1.startswith(b"+PONG"), r1[:20].decode(errors="replace"))),
        ("INFO revela versao", (b"redis_version:" in r2, "ok")),
        ("CONFIG GET permitido", (b"dir" in r3, "ok")),
    ]


def v_redis_end():
    r1 = resp_redis(P["PORT_REDIS_END"], b"PING\r\n")
    r2 = resp_redis(P["PORT_REDIS_END"], f"AUTH {SENHA}\r\nPING\r\n".encode())
    return [
        ("PING exige autenticacao", (b"NOAUTH" in r1, r1[:30].decode(errors="replace").strip())),
        ("autentica e responde", (b"+OK" in r2 and b"+PONG" in r2, "ok")),
    ]


def v_memcached_ins():
    with conectar(P["PORT_MEMCACHED_INS"]) as s:
        s.sendall(b"stats\r\n")
        time.sleep(0.2)
        tcp = ler(s)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
        u.settimeout(3)
        u.sendto(b"\x00\x01\x00\x00\x00\x01\x00\x00stats\r\n", (HOST, P["PORT_MEMCACHED_INS"]))
        try:
            udp, _ = u.recvfrom(4096)
        except OSError:
            udp = b""
    return [
        (
            "stats sem autenticacao (TCP)",
            (tcp.startswith(b"STAT"), tcp[:30].decode(errors="replace").strip()),
        ),
        ("responde por UDP (amplificacao)", (b"STAT" in udp, f"{len(udp)} bytes")),
    ]


def v_memcached_end():
    with conectar(P["PORT_MEMCACHED_END"]) as s:
        s.sendall(b"stats\r\n")
        time.sleep(0.2)
        tcp = ler(s)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
        u.settimeout(2)
        u.sendto(b"\x00\x01\x00\x00\x00\x01\x00\x00stats\r\n", (HOST, P["PORT_MEMCACHED_END"]))
        try:
            udp, _ = u.recvfrom(4096)
        except OSError:
            udp = b""
    return [
        (
            "stats NAO devolvido sem autenticar (SASL)",
            (not tcp.startswith(b"STAT"), tcp[:30].decode(errors="replace").strip() or "(fechou)"),
        ),
        ("UDP desligado", (udp == b"", "sem resposta")),
    ]


def pg_probe(porta):
    with conectar(porta) as s:
        s.sendall(struct.pack(">II", 8, 80877103))
        ssl_resp = ler(s, 1)
    with conectar(porta) as s:
        corpo = struct.pack(">I", 196608) + b"user\x00postgres\x00database\x00postgres\x00\x00"
        s.sendall(struct.pack(">I", len(corpo) + 4) + corpo)
        r = ler(s)
    auth = struct.unpack(">I", r[5:9])[0] if r[:1] == b"R" and len(r) >= 9 else -1
    return ssl_resp, auth


def v_pg_ins():
    ssl_r, auth = pg_probe(P["PORT_POSTGRES_INS"])
    return [
        ("TLS nao suportado", (ssl_r == b"N", ssl_r.decode(errors="replace"))),
        ("auth trust: AuthenticationOk sem senha", (auth == 0, f"auth={auth}")),
    ]


def v_pg_end():
    ssl_r, auth = pg_probe(P["PORT_POSTGRES_END"])
    return [
        ("TLS suportado", (ssl_r == b"S", ssl_r.decode(errors="replace"))),
        ("exige SCRAM-SHA-256 (auth=10)", (auth == 10, f"auth={auth}")),
    ]


def mysql_greeting(porta):
    with conectar(porta) as s:
        d = ler(s)
    if len(d) < 10:
        return None
    ver = d[5 : d.index(b"\x00", 5)].decode()
    i = d.index(b"\x00", 5) + 1 + 4 + 8 + 1
    caps = struct.unpack("<H", d[i : i + 2])[0]
    return ver, bool(caps & 0x0800)


def v_mysql(porta, ins):
    g = mysql_greeting(porta)
    if g is None:
        return [("greeting recebido", (False, "vazio"))]
    return [
        ("greeting v10 com versao", (True, g[0])),
        ("anuncia suporte a TLS", (g[1] if not ins else True, f"ssl={g[1]}")),
    ]


def v_mongo(porta, ins):
    with conectar(porta) as s:
        s.sendall(mongo_msg(bson(listDatabases=1, **{"$db": "admin"})))
        time.sleep(0.2)
        r = ler(s, 65536)
    if ins:
        return [("listDatabases sem credenciais", (b"databases" in r and b"admin" in r, "ok"))]
    return [
        (
            "listDatabases exige autenticacao",
            (b"requires authentication" in r or b"Unauthorized" in r, "401"),
        )
    ]


def v_etcd_ins():
    s, _, c = http(P["PORT_ETCD_INS_CLIENT"], "/version")
    return [
        (
            "/version sem TLS e sem auth",
            (s == 200 and b"etcdserver" in c, c[:40].decode(errors="replace")),
        )
    ]


def v_etcd_end():
    try:
        http(P["PORT_ETCD_END_CLIENT"], "/version", tls=True)
        return [("exige certificado de cliente", (False, "respondeu sem certificado"))]
    except (ssl.SSLError, OSError, httpclient.HTTPException):
        return [("exige certificado de cliente", (True, "handshake recusado"))]


def v_ftp_ins():
    import ftplib

    f = ftplib.FTP()
    f.connect(HOST, P["PORT_FTP_INS"], timeout=5)
    f.login()
    lista = f.nlst()
    f.quit()
    return [("login anonimo aceito", (True, ",".join(lista)))]


def v_ftp_end():
    import ftplib

    f = ftplib.FTP_TLS()
    f.connect(HOST, P["PORT_FTP_END"], timeout=5)
    try:
        f.login("anonymous", "a@b")
        anon = True
    except ftplib.error_perm:
        anon = False
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    g = ftplib.FTP_TLS(context=ctx)
    g.connect(HOST, P["PORT_FTP_END"], timeout=5)
    g.auth()
    ver = g.sock.version()
    g.login("labuser", SENHA)
    g.prot_p()
    g.quit()
    return [
        ("anonimo recusado", (not anon, "530")),
        ("FTPS explicito (AUTH TLS) com TLS 1.2+", (ver in ("TLSv1.2", "TLSv1.3"), ver)),
    ]


def smb1_negociar(porta) -> bytes:
    hdr = (
        b"\xffSMB"
        + b"\x72"
        + b"\x00" * 4
        + b"\x18"
        + struct.pack("<H", 0xC843)
        + b"\x00\x00"
        + b"\x00" * 8
        + b"\x00\x00"
        + struct.pack("<HHHH", 0xFFFF, 0xFEFF, 0, 0)
    )
    dial = b"\x02NT LM 0.12\x00"
    corpo = hdr + b"\x00" + struct.pack("<H", len(dial)) + dial
    with conectar(porta) as s:
        s.sendall(b"\x00" + struct.pack(">I", len(corpo))[1:] + corpo)
        return ler(s)


def smb2_negociar(porta) -> bytes:
    hdr = (
        b"\xfeSMB"
        + struct.pack("<HHIHHIIQI", 64, 0, 0, 0, 31, 0, 0, 0, 0)
        + b"\x00" * 4
        + b"\x00" * 16
    )
    corpo = (
        hdr
        + struct.pack("<HHHHI", 36, 1, 1, 0, 0)
        + b"\x00" * 16
        + struct.pack("<IHH", 0, 0, 0)
        + struct.pack("<H", 0x0202)
    )
    with conectar(porta) as s:
        s.sendall(b"\x00" + struct.pack(">I", len(corpo))[1:] + corpo)
        return ler(s)


def v_smb_ins():
    r = smb1_negociar(P["PORT_SMB_INS"])
    return [("aceita negociar SMBv1 (NT LM 0.12)", (r[4:8] == b"\xffSMB", r[4:8].hex()))]


def v_smb_end():
    r = smb2_negociar(P["PORT_SMB_END"])
    return [("negocia SMB2/3", (r[4:8] == b"\xfeSMB", r[4:8].hex()))]


def v_dns_ins():
    p = P["PORT_DNS_INS"]
    fl, rc, _ = dns_consulta(p, "www.exemplo-externo.test", 1)
    fa, ra_rc, an = dns_consulta(p, "lab-inseguro.test", 252, tcp=True)
    fv, _, vn = dns_consulta(p, "lab-inseguro.test", 16)
    return [
        ("recursao aberta (flag RA)", (bool(fl & 0x0080), f"flags={fl:#06x}")),
        (
            "AXFR permitido para qualquer cliente",
            (ra_rc == 0 and an > 0, f"rcode={ra_rc} respostas={an}"),
        ),
        ("zona responde (TXT SPF)", (vn > 0, f"respostas={vn}")),
    ]


def v_dns_end():
    p = P["PORT_DNS_END"]
    fl, rc, _ = dns_consulta(p, "www.exemplo-externo.test", 1)
    fa, ra_rc, _ = dns_consulta(p, "lab-endurecido.test", 252, tcp=True)
    _, _, caa = dns_consulta(p, "lab-endurecido.test", 257)
    _, _, key = dns_consulta(p, "lab-endurecido.test", 48)
    return [
        ("recursao recusada (REFUSED, sem RA)", (rc == 5 and not (fl & 0x0080), f"rcode={rc}")),
        ("AXFR recusado", (ra_rc == 5, f"rcode={ra_rc}")),
        ("CAA publicado", (caa > 0, str(caa))),
        ("DNSKEY (DNSSEC) publicado", (key > 0, str(key))),
    ]


def mqtt_conn(porta, usuario=None, senha=None):
    flags = 0x02
    cid = b"lab"
    payload = struct.pack(">H", len(cid)) + cid
    if usuario:
        flags |= 0xC0
        payload += struct.pack(">H", len(usuario)) + usuario + struct.pack(">H", len(senha)) + senha
    corpo = b"\x00\x04MQTT\x04" + bytes([flags]) + b"\x00\x3c" + payload
    with conectar(porta, 3) as s:
        s.sendall(b"\x10" + bytes([len(corpo)]) + corpo)
        r = ler(s, 4)
    return r[3] if len(r) >= 4 else -1


def v_mqtt_ins():
    rc = mqtt_conn(P["PORT_MQTT_INS"])
    return [("CONNECT anonimo aceito (rc=0)", (rc == 0, f"rc={rc}"))]


def v_mqtt_end():
    try:
        rc = mqtt_conn(P["PORT_MQTT_END"])
        return [("anonimo/texto-claro recusado", (rc != 0, f"rc={rc}"))]
    except OSError:
        return [("anonimo/texto-claro recusado", (True, "listener so aceita TLS"))]


# --- simuladores
def v_rdp(porta, ins):
    req = bytes.fromhex(
        "0300001308e00000000000010008000b000000"
    )  # X.224 CR + RDP_NEG_REQ (SSL|HYBRID|HYBRID_EX)
    with conectar(porta) as s:
        s.sendall(req)
        r = ler(s)
    sel = struct.unpack("<I", r[15:19])[0] if len(r) >= 19 else -1
    return [
        ("X.224 Connection Confirm (SIMULADO)", (r[:2] == b"\x03\x00", r.hex())),
        (
            "NLA nao exigido (PROTOCOL_RDP)" if ins else "NLA/CredSSP selecionado",
            (sel == (0 if ins else 2), f"selectedProtocol={sel}"),
        ),
    ]


def v_mssql(porta, ins):
    opts = [
        (0, b"\x00\x00\x00\x00\x00\x00"),
        (1, b"\x00"),
        (2, b"\x00"),
        (3, b"\x00\x00\x00\x00"),
        (4, b"\x00"),
    ]
    off = len(opts) * 5 + 1
    tabela, dados = b"", b""
    for t, d in opts:
        tabela += struct.pack(">BHH", t, off, len(d))
        dados += d
        off += len(d)
    payload = tabela + b"\xff" + dados
    pkt = struct.pack(">BBHHBB", 0x12, 1, 8 + len(payload), 0, 1, 0) + payload
    with conectar(porta) as s:
        s.sendall(pkt)
        r = ler(s)
    ok = r[:1] == b"\x04"
    major = minor = cripto = -1
    if ok:
        corpo = r[8:]
        major, minor = corpo[corpo[1] * 256 + corpo[2]], corpo[corpo[1] * 256 + corpo[2] + 1]
        cripto = corpo[corpo[6] * 256 + corpo[7]]
    return [
        ("PRELOGIN response (SIMULADO)", (ok, r[:8].hex())),
        (
            "sem criptografia (ENCRYPT_NOT_SUP) e versao 11.x"
            if ins
            else "criptografia exigida (ENCRYPT_REQ) e versao 16.x",
            (
                cripto == (2 if ins else 3) and major == (11 if ins else 16),
                f"v{major}.{minor} enc={cripto}",
            ),
        ),
    ]


def v_vnc(porta, ins):
    with conectar(porta) as s:
        v = s.recv(12)
        s.sendall(b"RFB 003.008\n")
        tipos = ler(s, 8)
    return [
        (
            "handshake RFB 003.008 (SIMULADO)",
            (v == b"RFB 003.008\n", v.decode(errors="replace").strip()),
        ),
        (
            "seguranca None (sem senha)" if ins else "seguranca VNC Authentication",
            (tipos[:2] == (b"\x01\x01" if ins else b"\x01\x02"), tipos.hex()),
        ),
    ]


def v_docker_ins():
    s, cab, c = http(P["PORT_SIM_DOCKER_INS"], "/version")
    return [("Docker API em HTTP sem auth (SIMULADO)", (s == 200 and b"ApiVersion" in c, str(s)))]


def v_docker_end():
    try:
        http(P["PORT_SIM_DOCKER_END"], "/version", tls=True)
        return [("exige certificado de cliente", (False, "respondeu"))]
    except (ssl.SSLError, OSError, httpclient.HTTPException):
        return [("exige certificado de cliente", (True, "handshake recusado"))]


def v_k8s_ins():
    s, _, c = http(P["PORT_SIM_K8S_INS"], "/version", tls=True)
    s2, _, c2 = http(P["PORT_SIM_K8S_INS"], "/api/v1/namespaces", tls=True)
    return [
        ("/version anonimo", (s == 200 and b"gitVersion" in c, str(s))),
        ("namespaces anonimo", (s2 == 200 and b"kube-system" in c2, str(s2))),
    ]


def v_k8s_end():
    s, _, c = http(P["PORT_SIM_K8S_END"], "/version", tls=True)
    return [("anonimo recebe 401", (s == 401, str(s)))]


def v_telnet():
    with conectar(P["PORT_SIM_TELNET_INS"]) as s:
        time.sleep(0.4)
        d = ler(s)
    return [
        (
            "negociacao IAC + login em texto claro (SIMULADO)",
            (d[:1] == b"\xff" and b"login:" in d, d[-24:].decode(errors="replace").strip()),
        )
    ]


def smtp_dialogo(porta, cmds):
    with conectar(porta) as s:
        s.settimeout(5)
        saida = ler(s).decode(errors="replace")
        for c in cmds:
            s.sendall(c.encode() + b"\r\n")
            time.sleep(0.15)
            saida += ler(s).decode(errors="replace")
    return saida


def v_smtp_ins():
    o = smtp_dialogo(
        P["PORT_SIM_SMTP_INS"],
        ["EHLO lab", "MAIL FROM:<a@externo.test>", "RCPT TO:<b@outro.test>", "VRFY root", "QUIT"],
    )
    return [
        ("sem STARTTLS", ("STARTTLS" not in o, "ok")),
        ("RCPT externo aceito (relay aberto)", ("250 2.1.5 Ok" in o, "ok")),
        ("VRFY habilitado", ("250 2.1.5 root" in o, "ok")),
    ]


def v_smtp_end():
    o = smtp_dialogo(
        P["PORT_SIM_SMTP_END"],
        ["EHLO lab", "MAIL FROM:<a@externo.test>", "RCPT TO:<b@outro.test>", "VRFY root", "QUIT"],
    )
    return [
        ("anuncia STARTTLS", ("STARTTLS" in o, "ok")),
        ("RCPT externo negado (554)", ("554 5.7.1" in o, "ok")),
        ("VRFY nao revela (252)", ("252" in o, "ok")),
    ]


def v_elastic_ins():
    s, _, c = http(P["PORT_SIM_ELASTIC_INS"], "/")
    return [
        ("raiz sem autenticacao revela versao (SIMULADO)", (s == 200 and b"7.10.0" in c, str(s)))
    ]


def v_elastic_end():
    s, cab, _ = http(P["PORT_SIM_ELASTIC_END"], "/")
    return [
        (
            "401 com WWW-Authenticate",
            (s == 401 and "basic" in cab.get("www-authenticate", "").lower(), str(s)),
        )
    ]


def v_winrm():
    s, cab, _ = http(P["PORT_SIM_WINRM_INS"], "/wsman", metodo="POST")
    return [
        (
            "Basic anunciado em HTTP puro (SIMULADO)",
            (
                s == 401 and "basic" in cab.get("www-authenticate", "").lower(),
                cab.get("www-authenticate", "-"),
            ),
        )
    ]


def v_banners():
    r = []
    s, cab, _ = http(P["PORT_BANNER_HTTP_APACHE"], "/")
    r.append(
        (
            "HTTP Server: Apache/2.4.49",
            (cab.get("server", "").startswith("Apache/2.4.49"), cab.get("server", "-")),
        )
    )
    s, cab, _ = http(P["PORT_BANNER_HTTP_NGINX"], "/")
    r.append(
        (
            "HTTP Server: nginx/1.16.1",
            (cab.get("server", "") == "nginx/1.16.1", cab.get("server", "-")),
        )
    )
    for nome, var, esperado in [
        ("FTP vsFTPd", "PORT_BANNER_FTP_VSFTPD", b"220 (vsFTPd 2.3.4)"),
        ("FTP ProFTPD", "PORT_BANNER_FTP_PROFTPD", b"220 ProFTPD 1.3.5"),
    ]:
        with conectar(P[var]) as c:
            b = ler(c)
        r.append((f"{nome} banner", (b.startswith(esperado), b.decode(errors="replace").strip())))
    k = ssh_kexinit(P["PORT_BANNER_SSH_OLD"])
    r.append(
        (
            "SSH OpenSSH_7.2p2 + KEX legado",
            (
                k["banner"].startswith("SSH-2.0-OpenSSH_7.2p2")
                and "diffie-hellman-group1-sha1" in k["kex"],
                k["banner"],
            ),
        )
    )
    for nome, var, esperado in [
        ("SMTP Exim", "PORT_BANNER_SMTP_EXIM", "Exim 4.87"),
        ("SMTP Postfix", "PORT_BANNER_SMTP_POSTFIX", "Postfix"),
    ]:
        with conectar(P[var]) as c:
            b = ler(c).decode(errors="replace")
        r.append((f"{nome} banner", (esperado in b, b.strip()[:50])))
    g = mysql_greeting(P["PORT_BANNER_MYSQL_OLD"])
    r.append(("MySQL 5.1.73 no handshake", (g is not None and g[0].startswith("5.1.73"), str(g))))
    o = resp_redis(P["PORT_BANNER_REDIS_OLD"], b"INFO\r\n")
    r.append(("Redis 2.8.19 no INFO", (b"redis_version:2.8.19" in o, "ok")))
    return r


CHECKS: list[tuple[str, str, object]] = [
    ("nginx-inseguro", "real", v_nginx_ins),
    ("nginx-endurecido", "real", v_nginx_end),
    ("apache-inseguro", "real", v_apache_ins),
    ("apache-endurecido", "real", v_apache_end),
    ("tomcat-inseguro", "real", v_tomcat_ins),
    ("tomcat-endurecido", "real", v_tomcat_end),
    ("sshd-inseguro", "real", v_ssh(P["PORT_SSHD_INS"], True)),
    ("sshd-endurecido", "real", v_ssh(P["PORT_SSHD_END"], False)),
    ("redis-inseguro", "real", v_redis_ins),
    ("redis-endurecido", "real", v_redis_end),
    ("memcached-inseguro", "real", v_memcached_ins),
    ("memcached-endurecido", "real", v_memcached_end),
    ("postgres-inseguro", "real", v_pg_ins),
    ("postgres-endurecido", "real", v_pg_end),
    ("mysql-inseguro", "real", lambda: v_mysql(P["PORT_MYSQL_INS"], True)),
    ("mysql-endurecido", "real", lambda: v_mysql(P["PORT_MYSQL_END"], False)),
    ("mongo-inseguro", "real", lambda: v_mongo(P["PORT_MONGO_INS"], True)),
    ("mongo-endurecido", "real", lambda: v_mongo(P["PORT_MONGO_END"], False)),
    ("etcd-inseguro", "real", v_etcd_ins),
    ("etcd-endurecido", "real", v_etcd_end),
    ("ftp-inseguro", "real", v_ftp_ins),
    ("ftp-endurecido", "real", v_ftp_end),
    ("smb-inseguro", "real", v_smb_ins),
    ("smb-endurecido", "real", v_smb_end),
    ("dns-inseguro", "real", v_dns_ins),
    ("dns-endurecido", "real", v_dns_end),
    ("mqtt-inseguro", "real", v_mqtt_ins),
    ("mqtt-endurecido", "real", v_mqtt_end),
    ("sim-rdp-inseguro", "simulado", lambda: v_rdp(P["PORT_SIM_RDP_INS"], True)),
    ("sim-rdp-endurecido", "simulado", lambda: v_rdp(P["PORT_SIM_RDP_END"], False)),
    ("sim-mssql-inseguro", "simulado", lambda: v_mssql(P["PORT_SIM_MSSQL_INS"], True)),
    ("sim-mssql-endurecido", "simulado", lambda: v_mssql(P["PORT_SIM_MSSQL_END"], False)),
    ("sim-vnc-inseguro", "simulado", lambda: v_vnc(P["PORT_SIM_VNC_INS"], True)),
    ("sim-vnc-endurecido", "simulado", lambda: v_vnc(P["PORT_SIM_VNC_END"], False)),
    ("sim-docker-inseguro", "simulado", v_docker_ins),
    ("sim-docker-endurecido", "simulado", v_docker_end),
    ("sim-k8s-inseguro", "simulado", v_k8s_ins),
    ("sim-k8s-endurecido", "simulado", v_k8s_end),
    ("sim-telnet-inseguro", "simulado", v_telnet),
    ("sim-smtp-inseguro", "simulado", v_smtp_ins),
    ("sim-smtp-endurecido", "simulado", v_smtp_end),
    ("sim-elastic-inseguro", "simulado", v_elastic_ins),
    ("sim-elastic-endurecido", "simulado", v_elastic_end),
    ("sim-winrm-inseguro", "simulado", v_winrm),
    ("sim-banners", "simulado", v_banners),
]


def main() -> int:
    global CA
    ap = argparse.ArgumentParser()
    ap.add_argument("--so", nargs="*", default=[])
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--certs", help="pasta com ca.pem (classifica certificados)")
    a = ap.parse_args()
    if a.certs and (Path(a.certs) / "ca.pem").exists():
        CA = str(Path(a.certs) / "ca.pem")
    elif (Path.home() / ".eigan-lab/run/certs/ca.pem").exists():
        CA = str(Path.home() / ".eigan-lab/run/certs/ca.pem")
    saida, falhas, sem_resposta, total = [], 0, 0, 0
    for sid, tipo, fn in CHECKS:
        if a.so and not any(t in sid for t in a.so):
            continue
        try:
            itens = fn()
        except Exception as e:  # noqa: BLE001 - relatorio de laboratorio
            itens = [("conexao/protocolo", (False, f"{type(e).__name__}: {e}"[:90]))]
            sem_resposta += 1
        for nome, (ok, det) in itens:
            total += 1
            falhas += 0 if ok else 1
            saida.append(
                {
                    "servico": sid,
                    "tipo": tipo,
                    "verificacao": nome,
                    "ok": bool(ok),
                    "detalhe": " ".join(str(det).split()),
                }
            )
            if not a.json:
                print(f"{'OK  ' if ok else 'FALHA'} {sid:24} {nome:58} {str(det)[:60]}")
    if a.json:
        print(json.dumps(saida, ensure_ascii=False, indent=1))
    else:
        print(
            f"--- {total - falhas}/{total} verificacoes ok"
            + (f", {sem_resposta} servico(s) sem resposta" if sem_resposta else "")
        )
    if total and sem_resposta == len(
        [1 for c in CHECKS if not a.so or any(t in c[0] for t in a.so)]
    ):
        return 2
    return 0 if falhas == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
