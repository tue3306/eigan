#!/usr/bin/env python3
"""Gera os alvos ESTATICOS de codigo do laboratorio EIGAN (deterministico).

    gerar_alvos.py              escreve alvos/projeto-vulneravel e alvos/projeto-limpo (versionados)
    gerar_alvos.py --segredos   escreve alvos/_gerado/segredos (NAO versionado: segredos FALSOS com
                                formato de token real, montados em tempo de execucao para nao
                                disparar a protecao de push do GitHub)

Tudo e FICTICIO e proposital. Nenhum segredo daqui funciona em lugar nenhum.
Os pacotes vulneraveis usam versoes publicas e antigas escolhidas por terem avisos de seguranca
conhecidos; o estagio de testes confirma os identificadores (CVE/GHSA) contra a base vendorizada.
"""

from __future__ import annotations

import json
import random
import string
import subprocess
import sys
from pathlib import Path

AQUI = Path(__file__).resolve().parent.parent / "alvos"
LEIAME_VULN = (
    "# ALVO DE TESTE DO EIGAN - INSEGURO DE PROPOSITO\n\n"
    "Nada aqui deve ser usado em producao. Dependencias antigas, codigo com falhas e segredos FALSOS.\n"
)
LEIAME_LIMPO = (
    "# ALVO DE TESTE DO EIGAN - GEMEO LIMPO\n\n"
    "Mesma estrutura do projeto-vulneravel, sem as falhas plantadas. O EIGAN nao deve reportar achados\n"
    "de dependencias, segredos, codigo ou infraestrutura aqui (guarda contra falso positivo).\n"
)


def escreve(raiz: Path, arquivos: dict[str, str]) -> None:
    for rel, conteudo in arquivos.items():
        p = raiz / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(conteudo, encoding="utf-8", newline="\n")


# =========================================================================== VULNERAVEL
def npm_lock(deps: dict[str, str]) -> str:
    pk = {"": {"name": "app-lab", "version": "1.0.0", "dependencies": dict(deps)}}
    for nome, ver in deps.items():
        pk[f"node_modules/{nome}"] = {
            "version": ver,
            "resolved": f"https://registry.npmjs.org/{nome}/-/{nome}-{ver}.tgz",
        }
    return (
        json.dumps(
            {
                "name": "app-lab",
                "version": "1.0.0",
                "lockfileVersion": 3,
                "requires": True,
                "packages": pk,
            },
            indent=2,
        )
        + "\n"
    )


NPM_VULN = {
    "lodash": "4.17.15",
    "minimist": "1.2.0",
    "express": "4.16.0",
    "jquery": "3.3.1",
    "moment": "2.19.2",
    "axios": "0.18.0",
    "handlebars": "4.0.11",
}
NPM_LIMPO = {"lodash": "4.17.21", "minimist": "1.2.8", "express": "4.21.2", "axios": "1.7.9"}

CODIGO_VULN = {
    "src/python/app.py": r"""import hashlib
import os
import pickle
import subprocess
import tempfile

import requests
import yaml
from flask import Flask, request

app = Flask(__name__)
SECRET_KEY = "lab-fake-secret-key-do-not-use-123456"   # segredo fixo no codigo (FALSO)
DB_URL = "postgres://app:FAKE-lab-Pa55w0rd@db.lab.invalid:5432/app"


@app.route("/calc")
def calc():
    return str(eval(request.args["expr"]))                      # eval com entrada do usuario


@app.route("/ping")
def ping():
    return subprocess.check_output("ping -c1 " + request.args["host"], shell=True)   # injecao de comando


@app.route("/load", methods=["POST"])
def load():
    return str(pickle.loads(request.data))                      # desserializacao insegura


@app.route("/cfg", methods=["POST"])
def cfg():
    return str(yaml.load(request.data))                         # yaml.load sem SafeLoader


@app.route("/user")
def user(db=None):
    q = "SELECT * FROM users WHERE name = '%s'" % request.args["name"]   # SQL por concatenacao
    return str(db.execute(q))


def senha(p):
    return hashlib.md5(p.encode()).hexdigest()                  # hash fraco para senha


def baixa(url):
    return requests.get(url, verify=False).text                 # TLS sem verificacao


def temp():
    return tempfile.mktemp()                                    # nome previsivel (race)


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)                         # debug ligado e escuta em todas as interfaces
""",
    "src/js/server.js": r"""const express = require('express');
const { exec } = require('child_process');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const app = express();
app.use(cors({ origin: '*', credentials: true }));          // CORS aberto com credenciais

app.get('/run', (req, res) => exec('ls ' + req.query.dir, (e, out) => res.send(out)));   // injecao de comando
app.get('/calc', (req, res) => res.send(String(eval(req.query.expr))));                  // eval
app.get('/hi', (req, res) => res.send('<h1>Oi ' + req.query.nome + '</h1>'));            // XSS refletido
app.get('/token', (req, res) => res.send(Math.random().toString(36)));                   // token previsivel
app.get('/hash', (req, res) => res.send(crypto.createHash('md5').update(req.query.p).digest('hex')));
app.get('/sql', (req, res) => db.query("SELECT * FROM t WHERE id = " + req.query.id));   // SQL por concatenacao
const t = jwt.sign({ u: 1 }, 'secret', { algorithm: 'none' });                           // JWT sem assinatura
document.getElementById('x').innerHTML = location.hash;                                  // DOM XSS
app.listen(3000, '0.0.0.0');
""",
    "src/java/Vuln.java": r"""import java.io.*;
import java.security.MessageDigest;
import java.sql.*;
import java.util.Random;
import javax.xml.parsers.DocumentBuilderFactory;

public class Vuln {
    static final String PASSWORD = "FAKE-lab-Pa55w0rd";                      // segredo fixo (FALSO)

    public static void run(String arg) throws Exception {
        Runtime.getRuntime().exec("sh -c " + arg);                           // injecao de comando
        MessageDigest.getInstance("MD5").digest(arg.getBytes());             // hash fraco
        new ObjectInputStream(new FileInputStream(arg)).readObject();        // desserializacao insegura
        Statement s = DriverManager.getConnection("jdbc:mysql://db/app", "app", PASSWORD).createStatement();
        s.executeQuery("SELECT * FROM users WHERE name = '" + arg + "'");    // SQL por concatenacao
        DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(arg); // XXE (parser padrao)
        int token = new Random().nextInt();                                  // PRNG nao criptografico
    }
}
""",
    "src/php/index.php": r"""<?php
$page = $_GET['page'];
include($page . '.php');                                  // inclusao arbitraria de arquivo
eval($_POST['code']);                                     // eval
system($_GET['cmd']);                                     // execucao de comando
$r = mysql_query("SELECT * FROM users WHERE id = " . $_GET['id']);   // SQL por concatenacao
$h = md5($_POST['senha']);                                // hash fraco
$o = unserialize($_COOKIE['dados']);                      // desserializacao insegura
echo "Ola " . $_GET['nome'];                              // XSS refletido
$db = new mysqli('db', 'root', 'FAKE-lab-root-Pa55', 'app');
""",
    "src/go/main.go": r"""package main

import (
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"fmt"
	"math/rand"
	"net/http"
	"os/exec"
)

func main() {
	http.HandleFunc("/run", func(w http.ResponseWriter, r *http.Request) {
		out, _ := exec.Command("sh", "-c", r.URL.Query().Get("c")).Output() // injecao de comando
		w.Write(out)
	})
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // TLS sem verificacao
	_ = tr
	_ = md5.Sum([]byte("senha"))                                                 // hash fraco
	_ = rand.Int()                                                               // math/rand para segredo
	db, _ := sql.Open("mysql", "app:FAKE-lab-Pa55w0rd@tcp(db)/app")
	db.Query(fmt.Sprintf("SELECT * FROM t WHERE id = %s", "x"))                  // SQL por Sprintf
	http.ListenAndServe("0.0.0.0:8080", nil)
}
""",
    "src/csharp/Vuln.cs": r"""using System;
using System.Data.SqlClient;
using System.Net;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;

class Vuln {
    static void Run(string arg, System.IO.Stream s) {
        new BinaryFormatter().Deserialize(s);                                       // desserializacao insegura
        MD5.Create().ComputeHash(System.Text.Encoding.UTF8.GetBytes(arg));          // hash fraco
        ServicePointManager.ServerCertificateValidationCallback += (a, b, c, d) => true;   // TLS sem verificacao
        var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = '" + arg + "'"); // SQL por concatenacao
        var cs = "Server=db;User Id=sa;Password=FAKE-lab-Pa55w0rd;";
    }
}
""",
    "src/ruby/app.rb": r"""require 'yaml'
get '/run' do
  eval(params[:code])                                      # eval
  `ls #{params[:dir]}`                                     # injecao de comando
  YAML.load(params[:y])                                    # YAML.load inseguro
  Marshal.load(params[:m])                                 # desserializacao insegura
  User.where("name = '#{params[:name]}'")                  # SQL por interpolacao
end
""",
    "src/shell/deploy.sh": r"""#!/bin/bash
curl -s http://exemplo.lab.invalid/install.sh | bash        # executa script remoto sem verificar
wget --no-check-certificate https://exemplo.lab.invalid/x.tgz
chmod 777 /var/www -R
eval "$1"
rm -rf $DIR/
mysql -uroot -pFAKE-lab-root-Pa55 -e "select 1"
""",
    "src/c/vuln.c": r"""#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void f(char *in) {
    char buf[16];
    strcpy(buf, in);                  /* estouro de buffer */
    gets(buf);                        /* gets */
    sprintf(buf, in);                 /* format string */
    system(in);                       /* execucao de comando */
}
""",
}

CODIGO_LIMPO = {
    "src/python/app.py": r"""import hashlib
import hmac
import os
import secrets
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, abort, request

app = Flask(__name__)
SECRET_KEY = os.environ["APP_SECRET_KEY"]          # vem do ambiente


@app.route("/ping")
def ping():
    host = request.args["host"]
    if not host.replace(".", "").replace("-", "").isalnum():
        abort(400)
    return subprocess.check_output(["ping", "-c1", host], timeout=5)    # lista de argumentos, sem shell


@app.route("/cfg", methods=["POST"])
def cfg():
    return str(yaml.safe_load(request.data))


@app.route("/user")
def user():
    con = sqlite3.connect("app.db")
    return str(con.execute("SELECT * FROM users WHERE name = ?", (request.args["name"],)).fetchall())


def senha(p: str, salt: bytes) -> str:
    return hashlib.scrypt(p.encode(), salt=salt, n=2**14, r=8, p=1).hex()


def comparar(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


def baixa(url: str) -> str:
    return requests.get(url, timeout=10).text          # TLS verificado


def token() -> str:
    return secrets.token_urlsafe(32)


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=False)
""",
    "src/js/server.js": r"""const express = require('express');
const { execFile } = require('child_process');
const crypto = require('crypto');
const helmet = require('helmet');
const app = express();
app.use(helmet());

app.get('/run', (req, res) => execFile('ls', ['--', String(req.query.dir)], (e, out) => res.send(out)));
app.get('/token', (req, res) => res.send(crypto.randomBytes(32).toString('hex')));
app.get('/sql', (req, res) => db.query('SELECT * FROM t WHERE id = ?', [req.query.id]));
app.listen(3000, '127.0.0.1');
""",
    "src/go/main.go": r"""package main

import (
	"crypto/rand"
	"database/sql"
	"net/http"
	"os/exec"
)

func main() {
	http.HandleFunc("/run", func(w http.ResponseWriter, r *http.Request) {
		out, _ := exec.Command("ls", "--", r.URL.Query().Get("d")).Output()
		w.Write(out)
	})
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	db, _ := sql.Open("mysql", "")
	db.Query("SELECT * FROM t WHERE id = ?", "x")
	http.ListenAndServe("127.0.0.1:8080", nil)
}
""",
    "src/shell/deploy.sh": r"""#!/usr/bin/env bash
set -euo pipefail
curl -fsSLo /tmp/x.tgz https://exemplo.lab.invalid/x.tgz
echo "0000000000000000000000000000000000000000000000000000000000000000  /tmp/x.tgz" | sha256sum -c - || exit 1
install -d -m 0750 /var/www
""",
}

REQ_VULN = """Django==2.2.0
Flask==0.12.2
PyYAML==5.3
requests==2.19.0
Pillow==8.0.0
urllib3==1.24.1
Jinja2==2.10
Werkzeug==0.14.1
"""
REQ_LIMPO = """Django==5.1.4
Flask==3.1.0
PyYAML==6.0.2
requests==2.32.5
urllib3==2.5.0
Jinja2==3.1.6
Werkzeug==3.1.3
"""

POM_VULN = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>lab.eigan</groupId><artifactId>app-lab</artifactId><version>1.0.0</version>
  <dependencies>
    <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency>
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>2.9.8</version></dependency>
    <dependency><groupId>org.springframework</groupId><artifactId>spring-beans</artifactId><version>5.3.17</version></dependency>
    <dependency><groupId>commons-collections</groupId><artifactId>commons-collections</artifactId><version>3.2.1</version></dependency>
    <dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId><version>1.26</version></dependency>
  </dependencies>
</project>
"""
POM_LIMPO = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>lab.eigan</groupId><artifactId>app-lab</artifactId><version>1.0.0</version>
  <dependencies>
    <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.24.3</version></dependency>
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>2.18.2</version></dependency>
  </dependencies>
</project>
"""

GOMOD_VULN = """module lab.invalid/app

go 1.15

require (
	golang.org/x/text v0.3.0
	gopkg.in/yaml.v2 v2.2.2
)
"""
GOMOD_LIMPO = """module lab.invalid/app

go 1.23

require (
	golang.org/x/text v0.21.0
	gopkg.in/yaml.v3 v3.0.1
)
"""

GEMLOCK_VULN = """GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.10.0)
      mini_portile2 (~> 2.3.0)
    mini_portile2 (2.3.0)
    rails (5.2.0)

PLATFORMS
  ruby

DEPENDENCIES
  nokogiri (= 1.10.0)
  rails (= 5.2.0)

BUNDLED WITH
   2.1.4
"""
GEMLOCK_LIMPO = """GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.18.1)
    rails (8.0.1)

PLATFORMS
  ruby

DEPENDENCIES
  nokogiri
  rails

BUNDLED WITH
   2.6.2
"""

CARGO_VULN = """# This file is automatically @generated by Cargo.
version = 3

[[package]]
name = "app-lab"
version = "0.1.0"
dependencies = ["regex", "smallvec", "time"]

[[package]]
name = "regex"
version = "1.5.4"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "smallvec"
version = "0.6.9"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "time"
version = "0.1.43"
source = "registry+https://github.com/rust-lang/crates.io-index"
"""
CARGO_LIMPO = """# This file is automatically @generated by Cargo.
version = 3

[[package]]
name = "app-lab"
version = "0.1.0"
dependencies = ["regex"]

[[package]]
name = "regex"
version = "1.11.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
"""

COMPOSER_VULN = (
    json.dumps({"name": "lab/app", "require": {"guzzlehttp/guzzle": "6.3.0"}}, indent=2) + "\n"
)
COMPOSER_LOCK_VULN = (
    json.dumps({"packages": [{"name": "guzzlehttp/guzzle", "version": "6.3.0"}]}, indent=2) + "\n"
)
COMPOSER_LIMPO = (
    json.dumps({"name": "lab/app", "require": {"guzzlehttp/guzzle": "7.9.2"}}, indent=2) + "\n"
)
COMPOSER_LOCK_LIMPO = (
    json.dumps({"packages": [{"name": "guzzlehttp/guzzle", "version": "7.9.2"}]}, indent=2) + "\n"
)

CSPROJ_VULN = """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net6.0</TargetFramework></PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="9.0.1" />
    <PackageReference Include="log4net" Version="2.0.8" />
    <PackageReference Include="System.Text.RegularExpressions" Version="4.3.0" />
  </ItemGroup>
</Project>
"""
CSPROJ_LIMPO = """<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="log4net" Version="3.0.3" />
  </ItemGroup>
</Project>
"""

DOCKERFILE_RUIM = """FROM node:8
USER root
ENV DB_PASSWORD=FAKE-lab-Pa55w0rd
ENV API_TOKEN=FAKE-lab-token-0000
ADD http://exemplo.lab.invalid/app.tar.gz /app/
RUN apt-get update && apt-get install -y curl sudo openssh-server && curl -s http://exemplo.lab.invalid/i.sh | sh
RUN chmod -R 777 /app
COPY . /app
EXPOSE 22 3306 8080
CMD ["node", "/app/server.js"]
"""
DOCKERFILE_BOM = """FROM node:22.12-bookworm-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY . .

FROM gcr.io/distroless/nodejs22-debian12:nonroot
WORKDIR /app
COPY --from=build --chown=nonroot:nonroot /app /app
USER nonroot
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD ["/nodejs/bin/node", "-e", "fetch('http://127.0.0.1:8080/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
CMD ["server.js"]
"""

COMPOSE_RUIM = """services:
  app:
    image: app:latest
    privileged: true
    network_mode: host
    pid: host
    cap_add: [SYS_ADMIN, NET_ADMIN]
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /:/host
    environment:
      DB_PASSWORD: FAKE-lab-Pa55w0rd
  db:
    image: mysql:5.7
    ports:
      - "0.0.0.0:3306:3306"
    environment:
      MYSQL_ROOT_PASSWORD: FAKE-lab-root-Pa55
"""
COMPOSE_BOM = """services:
  app:
    image: registry.lab.invalid/app:1.4.2
    read_only: true
    user: "10001:10001"
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    ports:
      - "127.0.0.1:8080:8080"
    environment:
      DB_PASSWORD_FILE: /run/secrets/db_password
    secrets: [db_password]
    healthcheck:
      test: ["CMD", "/app/healthcheck"]
      interval: 30s
    deploy:
      resources:
        limits: {cpus: "1", memory: 512M}
secrets:
  db_password:
    file: ./secrets/db_password.txt
"""

K8S_RUIM = """apiVersion: apps/v1
kind: Deployment
metadata: {name: app-ruim}
spec:
  replicas: 1
  selector: {matchLabels: {app: app-ruim}}
  template:
    metadata: {labels: {app: app-ruim}}
    spec:
      hostNetwork: true
      hostPID: true
      containers:
        - name: app
          image: app:latest
          securityContext:
            privileged: true
            runAsUser: 0
            allowPrivilegeEscalation: true
          env:
            - {name: DB_PASSWORD, value: FAKE-lab-Pa55w0rd}
          volumeMounts: [{name: host, mountPath: /host}]
      volumes:
        - {name: host, hostPath: {path: /}}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: default-admin}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin}
subjects: [{kind: ServiceAccount, name: default, namespace: default}]
"""
K8S_BOM = """apiVersion: apps/v1
kind: Deployment
metadata: {name: app-bom}
spec:
  replicas: 2
  selector: {matchLabels: {app: app-bom}}
  template:
    metadata: {labels: {app: app-bom}}
    spec:
      automountServiceAccountToken: false
      securityContext: {runAsNonRoot: true, seccompProfile: {type: RuntimeDefault}}
      containers:
        - name: app
          image: registry.lab.invalid/app:1.4.2
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: [ALL]}
          resources:
            requests: {cpu: 100m, memory: 128Mi}
            limits: {cpu: 500m, memory: 256Mi}
          livenessProbe: {httpGet: {path: /health, port: 8080}}
          readinessProbe: {httpGet: {path: /ready, port: 8080}}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: negar-tudo}
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
"""

TF_RUIM = """provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"                       # valor de exemplo da documentacao da AWS
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"   # valor de exemplo da documentacao da AWS
}

resource "aws_s3_bucket" "dados" {
  bucket = "lab-dados-publicos"
  acl    = "public-read"
}

resource "aws_security_group" "aberto" {
  name = "aberto"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "banco" {
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  publicly_accessible = true
  storage_encrypted   = false
  username            = "admin"
  password            = "FAKE-lab-Pa55w0rd"
  skip_final_snapshot = true
}

resource "aws_iam_policy" "tudo" {
  name   = "tudo"
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }] })
}

resource "aws_ebs_volume" "disco" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = false
}
"""
TF_BOM = """variable "admin_cidr" {
  type = string
}

resource "aws_s3_bucket" "dados" {
  bucket = "lab-dados-privados"
}

resource "aws_s3_bucket_public_access_block" "dados" {
  bucket                  = aws_s3_bucket.dados.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "dados" {
  bucket = aws_s3_bucket.dados.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "aws:kms" }
  }
}

resource "aws_s3_bucket_versioning" "dados" {
  bucket = aws_s3_bucket.dados.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_security_group" "restrito" {
  name = "restrito"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }
}

resource "aws_db_instance" "banco" {
  engine                  = "postgres"
  instance_class          = "db.t3.micro"
  publicly_accessible     = false
  storage_encrypted       = true
  backup_retention_period = 7
  manage_master_user_password = true
  username                = "admin"
}
"""

CONFIGS_RUIM = {
    "configs/nginx.conf": """server {
    listen 80;
    server_tokens on;
    autoindex on;
    ssl_protocols SSLv3 TLSv1 TLSv1.1;
    ssl_ciphers ALL:!aNULL;
    location / { add_header Access-Control-Allow-Origin *; }
}
""",
    "configs/sshd_config": """PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
Protocol 1
X11Forwarding yes
Ciphers 3des-cbc,aes128-cbc
MACs hmac-md5
""",
    "configs/redis.conf": """bind 0.0.0.0
protected-mode no
# requirepass desligado
""",
    "configs/my.cnf": """[mysqld]
bind-address = 0.0.0.0
skip-grant-tables
local-infile = 1
""",
    "configs/php.ini": """display_errors = On
expose_php = On
allow_url_include = On
allow_url_fopen = On
session.cookie_httponly = 0
""",
    "configs/httpd.conf": """ServerTokens Full
ServerSignature On
TraceEnable On
Options Indexes FollowSymLinks
""",
    "configs/.env": """APP_ENV=production
APP_DEBUG=true
DB_PASSWORD=FAKE-lab-Pa55w0rd!x9
SECRET_KEY=FAKE-lab-secret-key-0123456789abcdef
""",
}
CONFIGS_BOM = {
    "configs/nginx.conf": """server {
    listen 443 ssl;
    server_tokens off;
    autoindex off;
    ssl_protocols TLSv1.2 TLSv1.3;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff always;
}
""",
    "configs/sshd_config": """PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
X11Forwarding no
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com
""",
    "configs/redis.conf": """bind 127.0.0.1
protected-mode yes
requirepass use-um-segredo-do-cofre
""",
    "configs/php.ini": """display_errors = Off
expose_php = Off
allow_url_include = Off
session.cookie_httponly = 1
session.cookie_secure = 1
""",
    "configs/.env.example": "APP_ENV=production\nAPP_DEBUG=false\nDB_PASSWORD=\nSECRET_KEY=\n",
}


def projeto(raiz: Path, vulneravel: bool) -> None:
    v = vulneravel
    arq: dict[str, str] = {
        "README.md": LEIAME_VULN if v else LEIAME_LIMPO,
        "package.json": json.dumps(
            {"name": "app-lab", "version": "1.0.0", "dependencies": NPM_VULN if v else NPM_LIMPO},
            indent=2,
        )
        + "\n",
        "package-lock.json": npm_lock(NPM_VULN if v else NPM_LIMPO),
        "requirements.txt": REQ_VULN if v else REQ_LIMPO,
        "pom.xml": POM_VULN if v else POM_LIMPO,
        "go.mod": GOMOD_VULN if v else GOMOD_LIMPO,
        "Gemfile.lock": GEMLOCK_VULN if v else GEMLOCK_LIMPO,
        "Cargo.lock": CARGO_VULN if v else CARGO_LIMPO,
        "composer.json": COMPOSER_VULN if v else COMPOSER_LIMPO,
        "composer.lock": COMPOSER_LOCK_VULN if v else COMPOSER_LOCK_LIMPO,
        "App.csproj": CSPROJ_VULN if v else CSPROJ_LIMPO,
        "Dockerfile": DOCKERFILE_RUIM if v else DOCKERFILE_BOM,
        "docker-compose.yml": COMPOSE_RUIM if v else COMPOSE_BOM,
        "k8s/deployment.yaml": K8S_RUIM if v else K8S_BOM,
        "terraform/main.tf": TF_RUIM if v else TF_BOM,
        ".gitignore": ".env\n" if not v else "",
    }
    arq.update(CODIGO_VULN if v else CODIGO_LIMPO)
    arq.update(CONFIGS_RUIM if v else CONFIGS_BOM)
    escreve(raiz, arq)


# =========================================================================== SEGREDOS (nao versionados)
def _alnum(rng: random.Random, n: int, alfabeto: str = string.ascii_letters + string.digits) -> str:
    return "".join(rng.choice(alfabeto) for _ in range(n))


def segredos(raiz: Path) -> None:
    """Tokens FALSOS com o FORMATO de tokens reais, montados em tempo de execucao."""
    rng = random.Random(20261102)
    aws = "AKIA" + _alnum(rng, 16, string.ascii_uppercase + "234567")
    aws_sec = _alnum(rng, 40, string.ascii_letters + string.digits + "/+")
    ghp = "gh" + "p_" + _alnum(rng, 36)
    gl = "glp" + "at-" + _alnum(rng, 20, string.ascii_letters + string.digits + "_-")
    slack = (
        "xox"
        + "b-"
        + "-".join(_alnum(rng, n, string.digits) for n in (12, 13))
        + "-"
        + _alnum(rng, 24)
    )
    stripe = "sk_" + "live_" + _alnum(rng, 24)
    google = "AI" + "za" + _alnum(rng, 35, string.ascii_letters + string.digits + "_-")
    npm = "npm" + "_" + _alnum(rng, 36)
    sendgrid = (
        "SG"
        + "."
        + _alnum(rng, 22)
        + "."
        + _alnum(rng, 43, string.ascii_letters + string.digits + "_-")
    )
    import base64

    def b64(d: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")

    jwt = (
        b64({"alg": "HS256", "typ": "JWT"})
        + "."
        + b64({"sub": "1234567890", "name": "Fulano Lab", "iat": 1700000000})
        + "."
        + _alnum(rng, 43)
    )
    try:
        pem = subprocess.run(
            ["openssl", "genrsa", "2048"], capture_output=True, check=True, timeout=30
        ).stdout.decode()
    except Exception:
        pem = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            + base64.b64encode(rng.randbytes(120)).decode()
            + "\n-----END RSA PRIVATE KEY-----\n"
        )
    arq = {
        "LEIA-ME-FALSO.md": "# SEGREDOS FALSOS DO LAB EIGAN\nGerados em tempo de execucao por ferramentas/gerar_alvos.py --segredos. Nenhum funciona.\n",
        ".env": f"AWS_ACCESS_KEY_ID={aws}\nAWS_SECRET_ACCESS_KEY={aws_sec}\nGITHUB_TOKEN={ghp}\nSTRIPE_SECRET_KEY={stripe}\n",
        "config/ci.yml": f"variables:\n  GITLAB_TOKEN: {gl}\n  SLACK_BOT_TOKEN: {slack}\n  SENDGRID_API_KEY: {sendgrid}\n",
        "src/maps.js": f"const GOOGLE_API_KEY = '{google}';\nconst JWT = '{jwt}';\n",
        ".npmrc": f"//registry.npmjs.org/:_authToken={npm}\n",
        "id_rsa": pem,
        "deploy.sh": f"export AWS_ACCESS_KEY_ID={aws}\nexport AWS_SECRET_ACCESS_KEY={aws_sec}\ncurl -u fulano:FAKE-lab-Pa55w0rd https://exemplo.lab.invalid/api\n",
        "db.properties": "jdbc.url=jdbc:postgresql://db.lab.invalid/app\njdbc.password=FAKE-lab-Pa55w0rd!x9\n",
        "limpo/config.yml": "token: ${CI_TOKEN}\npassword: changeme\nexample_key: AKIAXXXXXXXXXXXXXXXX\n",
    }
    escreve(raiz, arq)


def main() -> int:
    if "--segredos" in sys.argv:
        segredos(AQUI / "_gerado" / "segredos")
        print(f"segredos falsos em {AQUI / '_gerado' / 'segredos'}")
        return 0
    projeto(AQUI / "projeto-vulneravel", True)
    projeto(AQUI / "projeto-limpo", False)
    print(f"alvos de codigo escritos em {AQUI}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
