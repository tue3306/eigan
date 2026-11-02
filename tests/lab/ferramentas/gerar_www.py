#!/usr/bin/env python3
"""Gera, em tempo de execucao, as raizes web do laboratorio EIGAN (nada disso vai para o git).

    gerar_www.py <destino>

Cria tres arvores:
  inseguro/   conteudo que NAO deveria estar publico (.git, .env, dump SQL, phpinfo...)
  endurecido/ site comum, sem nada sensivel
  soft404/    SPA que responde 200 para qualquer caminho (guarda contra falso positivo)

Todos os segredos sao FALSOS: carregam a palavra FAKE/LAB e nao dao acesso a nada.
"""

from __future__ import annotations

import json
import struct
import subprocess
import sys
import zlib
from pathlib import Path


def w(root: Path, rel: str, data: str | bytes) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode() if isinstance(data, str) else data)


INDEX_INS = """<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<title>Intranet Lab (inseguro)</title></head><body>
<h1>Intranet Lab</h1><p>Alvo de teste do EIGAN: <b>modo inseguro</b>. Nada aqui e real.</p>
<form action="/login" method="post"><input name="user"><input name="pass" type="password"></form>
<a href="/listing/">arquivos</a>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/1.12.4/jquery.min.js"></script>
</body></html>
"""

INDEX_END = """<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Site Lab (endurecido)</title></head><body>
<h1>Site Lab</h1><p>Alvo de teste do EIGAN: <b>modo endurecido</b>.</p>
</body></html>
"""

GIT_CONFIG = """[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
[remote "origin"]
\turl = https://lab-user:FAKE-lab-Pa55w0rd-NaoUse@git.lab.invalid/equipe/intranet.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
"""

DOTENV = """APP_ENV=production
APP_DEBUG=true
DB_HOST=db.lab.invalid
DB_USER=app
DB_PASSWORD=FAKE-lab-Pa55w0rd!x9
APP_SECRET_KEY=FAKE_lab_secret_key_0123456789abcdef
JWT_SECRET=FAKE-lab-jwt-Secret-ZXCVBN-12345
SMTP_PASSWORD=FAKE-lab-Smtp#Pass-7788
"""

SQL_DUMP = """-- MySQL dump 10.13  Distrib 8.0.36, for Linux (x86_64)
--
-- Host: localhost    Database: intranet
-- Servidor de TESTE do EIGAN: todos os dados abaixo sao ficticios.
DROP TABLE IF EXISTS `usuarios`;
CREATE TABLE `usuarios` (
  `id` int NOT NULL AUTO_INCREMENT,
  `email` varchar(120) NOT NULL,
  `senha_hash` varchar(80) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB;
LOCK TABLES `usuarios` WRITE;
INSERT INTO `usuarios` VALUES (1,'fulano@lab.invalid','$2y$10$FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFA'),(2,'ciclana@lab.invalid','$2y$10$FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFB');
UNLOCK TABLES;
"""

PHPINFO = """<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"><html><head>
<title>phpinfo()</title></head><body><div class="center">
<table><tr class="h"><td><a href="http://www.php.net/"><img border="0" src="x" alt="PHP logo" /></a>
<h1 class="p">PHP Version 7.4.3</h1></td></tr></table>
<table><tr><td class="e">System </td><td class="v">Linux lab 5.15.0 #1 SMP x86_64 </td></tr>
<tr><td class="e">Server API </td><td class="v">Apache 2.0 Handler </td></tr>
<tr><td class="e">Zend Engine</td><td class="v">v3.4.0 with Zend OPcache</td></tr>
<tr><td class="e">PHP Extension</td><td class="v">20190902</td></tr></table>
<!-- PAGINA ESTATICA DO LAB: nao ha PHP aqui (simulado) -->
</div></body></html>
"""

ACTUATOR_INDEX = {
    "_links": {
        "self": {"href": "http://127.0.0.1/actuator", "templated": False},
        "health": {"href": "http://127.0.0.1/actuator/health", "templated": False},
        "env": {"href": "http://127.0.0.1/actuator/env", "templated": False},
        "heapdump": {"href": "http://127.0.0.1/actuator/heapdump", "templated": False},
        "configprops": {"href": "http://127.0.0.1/actuator/configprops", "templated": False},
    }
}
ACTUATOR_ENV = {
    "activeProfiles": ["prod"],
    "propertySources": [
        {"name": "systemEnvironment", "properties": {"JAVA_HOME": {"value": "/opt/java"}}},
        {
            "name": "applicationConfig",
            "properties": {"spring.datasource.password": {"value": "******"}},
        },
    ],
}
SWAGGER = {
    "openapi": "3.0.1",
    "info": {"title": "API Lab (simulada)", "version": "1.0"},
    "paths": {"/api/users": {"get": {"responses": {"200": {"description": "ok"}}}}},
}
CROSSDOMAIN = (
    '<?xml version="1.0"?>\n<cross-domain-policy>\n'
    '  <allow-access-from domain="*" />\n</cross-domain-policy>\n'
)
WEBCONFIG = """<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <appSettings><add key="ApiKey" value="FAKE-lab-api-key-0000" /></appSettings>
  <connectionStrings><add name="Db" connectionString="Server=db.lab.invalid;User Id=app;Password=FAKE-lab-Pa55w0rd!x9;" /></connectionStrings>
  <system.web><compilation debug="true" targetFramework="4.8" /></system.web>
</configuration>
"""
HTPASSWD = "admin:$apr1$FAKElab1$FAKEFAKEFAKEFAKEFAKEFA\n"
COMPOSE = (
    "services:\n  db:\n    image: mysql:5.7\n    environment:\n"
    '      MYSQL_ROOT_PASSWORD: FAKE-lab-root-Pa55\n    ports:\n      - "3306:3306"\n'
)
PKG = json.dumps(
    {
        "name": "intranet",
        "version": "1.0.0",
        "dependencies": {"lodash": "4.17.15", "express": "4.16.0"},
    },
    indent=2,
)


def git_index() -> bytes:
    """Cabecalho real de um indice do git v2 com 3 entradas (conteudo minimo)."""
    return b"DIRC" + struct.pack(">II", 2, 3) + b"\x00" * 64


def make_private_key() -> str:
    """Chave RSA descartavel gerada agora (nunca versionada, sem uso em lugar nenhum)."""
    try:
        out = subprocess.run(
            ["openssl", "genrsa", "2048"], capture_output=True, check=True, timeout=30
        )
        return out.stdout.decode()
    except Exception:
        return "-----BEGIN RSA PRIVATE KEY-----\nRkFLRS1MQUItTkFPLUUtVU1BLUNIQVZFLVJFQUw=\n-----END RSA PRIVATE KEY-----\n"


def inseguro(root: Path) -> None:
    w(root, "index.html", INDEX_INS)
    w(
        root,
        "robots.txt",
        "User-agent: *\nDisallow: /admin/\nDisallow: /backup.sql\nDisallow: /.git/\n",
    )
    for n in ("relatorio-2024.txt", "senhas-antigas.txt", "notas.md"):
        w(root, f"listing/{n}", f"arquivo de teste {n}\n")
    w(root, ".git/HEAD", "ref: refs/heads/main\n")
    w(root, ".git/config", GIT_CONFIG)
    w(root, ".git/index", git_index())
    w(root, ".env", DOTENV)
    w(root, "backup.sql", SQL_DUMP)
    w(root, "phpinfo.php", PHPINFO)
    w(root, "info.php", PHPINFO)
    w(root, "actuator/index.json", json.dumps(ACTUATOR_INDEX))
    w(root, "actuator/env", json.dumps(ACTUATOR_ENV))
    w(root, "swagger.json", json.dumps(SWAGGER))
    w(root, "crossdomain.xml", CROSSDOMAIN)
    w(root, "web.config", WEBCONFIG)
    w(root, ".htpasswd", HTPASSWD)
    w(root, "docker-compose.yml", COMPOSE)
    w(root, "package.json", PKG)
    w(root, ".DS_Store", b"\x00\x00\x00\x01Bud1" + b"\x00" * 32)
    w(root, "backup.zip", b"PK\x03\x04" + zlib.compress(b"conteudo falso do lab"))
    w(root, "id_rsa", make_private_key())
    w(
        root,
        "error.log",
        "[Mon Nov 02 10:00:01 2026] [error] [client 10.0.0.9] PHP Fatal error: "
        "Uncaught Exception in /var/www/html/app.php:42\n",
    )
    w(
        root,
        "admin/index.html",
        "<html><title>Painel administrativo</title><body>Login admin (lab)</body></html>",
    )


def endurecido(root: Path) -> None:
    w(root, "index.html", INDEX_END)
    w(root, "robots.txt", "User-agent: *\nAllow: /\n")
    w(
        root,
        ".well-known/security.txt",
        "Contact: mailto:seguranca@lab.invalid\nExpires: 2027-12-31T23:59:59.000Z\nPreferred-Languages: pt-BR\n",
    )
    w(root, "404.html", "<!doctype html><title>Nao encontrado</title><h1>404</h1>")


def soft404(root: Path) -> None:
    w(
        root,
        "index.html",
        '<!doctype html><html><head><title>App SPA</title></head><body><div id="root">Carregando...</div>'
        '<script src="/static/app.js"></script></body></html>',
    )


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    base = Path(sys.argv[1])
    inseguro(base / "inseguro")
    endurecido(base / "endurecido")
    soft404(base / "soft404")
    print(f"raizes web geradas em {base}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
