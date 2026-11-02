"""Assinaturas de conteúdo que CONFIRMAM uma exposição (nunca só o código HTTP).

Cada função recebe a resposta de uma sonda e devolve um :class:`Match` (com a
evidência já sem segredos) ou ``None``. Páginas HTML genéricas (soft 404, SPA que
devolve ``index.html`` para qualquer rota) nunca passam numa assinatura de arquivo
de texto ou binário: o formato do arquivo precisa aparecer no corpo.
"""

from __future__ import annotations

import json
import re
import zlib
from dataclasses import dataclass, field
from typing import Any

from ...core.http import Response
from ...core.models import Confidence, Severity
from ...core.redact import mask
from .common import looks_html


@dataclass(frozen=True)
class Match:
    evidence: str
    severity: Severity | None = None
    confidence: Confidence = Confidence.CONFIRMED
    details: dict[str, Any] = field(default_factory=dict)
    finding: str | None = None  # substitui o achado da sonda (ex.: .sql.gz que é despejo SQL)


def _lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


def total_size(resp: Response) -> int | None:
    """Tamanho real do arquivo (``Content-Range`` de leitura parcial ou ``Content-Length``)."""
    ranged = re.search(r"/(\d+)\s*$", resp.header("content-range") or "")
    if ranged:
        return int(ranged.group(1))
    length = (resp.header("content-length") or "").strip()
    return int(length) if re.fullmatch(r"[0-9]{1,15}", length) else None


def _size(resp: Response) -> str:
    size = total_size(resp)
    if not size:
        return ""
    if size >= 1_048_576:
        return f" (~{size / 1_048_576:.1f} MB)"
    return f" (~{max(1, size // 1024)} KB)"


def json_body(resp: Response) -> Any:
    try:
        return json.loads(resp.text)
    except (ValueError, RecursionError):
        return None


def htmlish(text: str) -> bool:
    """O corpo é uma página HTML (erro, soft 404, SPA) e não um arquivo de texto?"""
    head = text[:4096]
    return looks_html(head) or bool(re.search(r"<(?:html|body|head)[\s>]", head, re.I))


# -- controle de versão -------------------------------------------------------------

_GIT_REF = re.compile(r"^ref: refs/[\w./\-]+$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_URL_WITH_CREDENTIALS = re.compile(r"\b\w+://[^/\s:@]+:[^@\s/]+@")
_GIT_REMOTE = re.compile(r"^[ \t]*url\s*=\s*(\S+)", re.M)


def git_head(resp: Response) -> Match | None:
    lines = _lines(resp.text[:512])
    if len(lines) != 1:
        return None
    if _GIT_REF.match(lines[0]):
        return Match(f".git/HEAD legível ({lines[0]})")
    if _GIT_SHA.match(lines[0]):
        return Match(".git/HEAD legível (aponta para um commit)")
    return None


def _hide_userinfo(url: str) -> str:
    return re.sub(r"//[^/\s]*@", "//***@", url)[:120]


def git_config(resp: Response) -> Match | None:
    text = resp.text[:65_536]
    if "[core]" not in text or "repositoryformatversion" not in text or htmlish(text):
        return None
    remote = _GIT_REMOTE.search(text)
    shown = f"; remoto: {_hide_userinfo(remote.group(1))}" if remote else ""
    if _URL_WITH_CREDENTIALS.search(text):
        return Match(
            ".git/config legível e com usuário/senha na URL do repositório remoto" + shown,
            Severity.CRITICAL,
        )
    return Match(".git/config legível (configuração do repositório)" + shown)


_GIT_INDEX_VERSIONS = (b"\x00\x00\x00\x02", b"\x00\x00\x00\x03", b"\x00\x00\x00\x04")


def git_index(resp: Response) -> Match | None:
    """Cabeçalho do índice do git: ``DIRC`` + versão (2, 3 ou 4) + número de arquivos."""
    body = resp.body
    if len(body) < 12 or body[:4] != b"DIRC" or body[4:8] not in _GIT_INDEX_VERSIONS:
        return None
    entries = int.from_bytes(body[8:12], "big")
    return Match(
        f".git/index legível ({entries} arquivos rastreados): o repositório pode ser reconstruído"
    )


def svn_entries(resp: Response) -> Match | None:
    """Formato 8 a 12: "12" sozinho (SVN 1.7+) ou o número seguido da entrada "dir"."""
    lines = resp.text[:2048].split("\n")
    first = lines[0].strip() if lines else ""
    if not re.fullmatch(r"[0-9]{1,3}", first) or not 8 <= int(first) <= 12:
        return None
    if len(_lines(resp.text[:2048])) == 1 or "dir" in lines[1:4]:
        return Match(".svn/entries legível (cópia de trabalho do Subversion)")
    return None


def sqlite_db(resp: Response) -> Match | None:
    if resp.body.startswith(b"SQLite format 3\x00"):
        return Match(
            f"Banco SQLite do Subversion (.svn/wc.db) disponível para download{_size(resp)}"
        )
    return None


_HG_TOKENS = {
    "revlogv1",
    "store",
    "fncache",
    "dotencode",
    "generaldelta",
    "sparserevlog",
    "share-safe",
}


def hg_requires(resp: Response) -> Match | None:
    lines = _lines(resp.text[:1024])
    if lines and all(re.fullmatch(r"[a-z0-9\-]+", ln) for ln in lines) and _HG_TOKENS & set(lines):
        return Match(".hg/requires legível (repositório Mercurial)")
    return None


def bzr_format(resp: Response) -> Match | None:
    head = resp.text[:512]
    if "Bazaar-NG meta directory" in head or "Bazaar Branch Format" in head:
        return Match(".bzr legível (repositório Bazaar)")
    return None


# -- configuração e segredos ----------------------------------------------------------

_ENV_LINE = re.compile(r"^(?:export\s+)?([A-Z][A-Z0-9_]{1,63})\s*=(.*)$")
_SECRET_KEY = re.compile(r"PASS|SECRET|KEY|TOKEN|PWD|AUTH|CREDENTIAL|PRIVATE|DSN|DATABASE_URL")
_PLACEHOLDER = re.compile(
    r"^(?:|null|none|nil|empty|changeme|change_?me|secret|password|senha|example|exemplo|test|"
    r"x+|\*+|\.+|your[_\-].*|seu[_\-].*|<.*>|\$\{.*\}|%.*%|\{\{.*\}\})$",
    re.I,
)


def _real_secret(value: str) -> bool:
    """Valor com cara de segredo de verdade (não vazio, não marcador de exemplo)."""
    value = value.strip().strip("'\"")
    if len(value) < 8 or _PLACEHOLDER.match(value):
        return False
    classes = sum(
        bool(re.search(pattern, value)) for pattern in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]")
    )
    return classes >= 2


def _env_pairs(text: str) -> list[tuple[str, str]] | None:
    """Pares CHAVE=valor de um .env (``None`` se o texto não tiver esse formato)."""
    if htmlish(text):
        return None
    lines = [ln for ln in _lines(text) if not ln.startswith("#")]
    pairs = [(m.group(1), m.group(2)) for m in (_ENV_LINE.match(ln) for ln in lines) if m]
    if not pairs or len(pairs) < 0.6 * len(lines):
        return None
    if len(pairs) == 1 and not (_SECRET_KEY.search(pairs[0][0]) and _real_secret(pairs[0][1])):
        return None  # uma linha solta só vale se for um segredo preenchido de verdade
    return pairs


def dotenv(resp: Response) -> Match | None:
    """``.env`` legível; crítico quando há segredos preenchidos (não só nomes de variáveis)."""
    pairs = _env_pairs(resp.text[:65_536])
    if pairs is None:
        return None
    keys = [key for key, _ in pairs]
    secrets_like = [key for key in keys if _SECRET_KEY.search(key)]
    filled = [key for key, value in pairs if _SECRET_KEY.search(key) and _real_secret(value)]
    evidence = f"{len(keys)} variáveis de ambiente legíveis (ex.: {', '.join(keys[:5])})"
    if secrets_like:
        evidence += f"; {len(secrets_like)} parecem segredos ({', '.join(secrets_like[:5])})"
    if filled:
        evidence += f"; {len(filled)} com valor preenchido"
    return Match(
        evidence,
        Severity.CRITICAL if filled else None,
        details={"variaveis": keys[:40], "segredos_preenchidos": len(filled)},
    )


def dotenv_template(resp: Response) -> Match | None:
    """``.env.example``: só conta como exposição se trouxer segredos preenchidos de verdade."""
    match = dotenv(resp)
    if match is None or not match.details.get("segredos_preenchidos"):
        return None
    return match


_PHP_CONFIG = re.compile(
    r"DB_(?:PASSWORD|USER|NAME|HOST)|define\s*\(|\$(?:db|database|password|pass|dbpass|config)\b|"
    r"mysqli?_connect|new\s+PDO",
    re.I,
)


def _starts_as_php(text: str) -> bool:
    return text.lstrip("﻿ \t\r\n").startswith("<?php")


def php_source(resp: Response) -> Match | None:
    """Código PHP entregue como texto: um servidor que executa PHP nunca mostra ``<?php``."""
    text = resp.text[:65_536]
    if "<?php" not in text or not _PHP_CONFIG.search(text):
        return None
    if htmlish(text) and not _starts_as_php(text):
        return None  # página que só cita um trecho de PHP (artigo, documentação)
    names = re.findall(r"define\s*\(\s*['\"](\w+)['\"]", text)[:6]
    extra = f" (constantes: {', '.join(names)})" if names else ""
    return Match("Código-fonte PHP de configuração legível" + extra)


def php_backup(resp: Response) -> Match | None:
    """Cópia de um script (``index.php.bak``): o arquivo COMEÇA com ``<?php``."""
    if _starts_as_php(resp.text[:1_024]):
        return Match("Cópia de script PHP legível (o servidor entrega o código-fonte)")
    return None


def vim_swap(resp: Response) -> Match | None:
    if resp.body.startswith(b"b0VIM"):
        return Match("Arquivo de troca do Vim (.swp) com o conteúdo do arquivo editado")
    return None


def php_or_vim(resp: Response) -> Match | None:
    return php_source(resp) or vim_swap(resp)


_HTACCESS_STRONG = re.compile(
    r"^[ \t]*(RewriteEngine|RewriteRule|RewriteCond|AuthType|AuthUserFile|AuthGroupFile)\s+\S",
    re.I | re.M,
)
_HTACCESS_ANY = re.compile(
    r"^[ \t]*(?:Require|Order|Deny from|Allow from|Options|ErrorDocument|DirectoryIndex|Header|<IfModule)\s*\S",
    re.I | re.M,
)


def htaccess(resp: Response) -> Match | None:
    """``.htaccess`` entregue como texto (o Apache devolve 403 por padrão)."""
    text = resp.text[:65_536]
    if htmlish(text):
        return None
    strong = _HTACCESS_STRONG.findall(text)
    if not strong and len(_HTACCESS_ANY.findall(text)) < 2:
        return None
    return Match(".htaccess legível (regras de reescrita e de acesso do site)", Severity.LOW)


def idea_workspace(resp: Response) -> Match | None:
    """Configuração do projeto em IDEs JetBrains (``.idea/workspace.xml``)."""
    text = resp.text[:65_536]
    if "<project version=" in text and "<component name=" in text:
        return Match(".idea/workspace.xml legível (arquivos e tarefas do projeto)", Severity.LOW)
    return None


def webconfig_source(resp: Response) -> Match | None:
    text = resp.text[:65_536]
    if "<configuration" in text and re.search(r"connectionStrings|<appSettings|system\.web", text):
        return Match("web.config legível (strings de conexão e configurações do ASP.NET)")
    return None


def java_webxml(resp: Response) -> Match | None:
    text = resp.text[:65_536]
    if "<web-app" in text and re.search(r"</web-app>|<servlet|<filter|<context-param", text):
        return Match("WEB-INF/web.xml legível (descritor da aplicação Java: servlets e filtros)")
    return None


def rails_database(resp: Response) -> Match | None:
    text = resp.text[:65_536]
    if htmlish(text) or not re.search(r"^[ \t]+adapter\s*:", text, re.M):
        return None
    if not re.search(r"^[ \t]+database\s*:", text, re.M):
        return None
    if not re.search(r"^(?:production|development|test|default)\s*:", text, re.M):
        return None
    severity = Severity.CRITICAL if re.search(r"^[ \t]+password\s*:\s*\S+", text, re.M) else None
    extra = " com senha do banco" if severity else ""
    return Match(f"config/database.yml (Rails) legível{extra}", severity)


_HTPASSWD = re.compile(
    r"^[^:\s#]{1,64}:(?:\$apr1\$|\$2[abxy]?\$|\{SHA\}|\$[156]\$|\$y\$|[A-Za-z0-9./]{13}$)"
)


def htpasswd(resp: Response) -> Match | None:
    text = resp.text[:16_384]
    if htmlish(text):
        return None
    lines = _lines(text)
    hits = [ln for ln in lines if _HTPASSWD.match(ln)]
    if not hits or len(hits) < 0.6 * len(lines):
        return None
    users = [h.split(":", 1)[0] for h in hits]
    return Match(f"{len(users)} usuário(s) com hash de senha: {', '.join(users[:5])}")


def ds_store(resp: Response) -> Match | None:
    if resp.body[:8] == b"\x00\x00\x00\x01Bud1":
        return Match(".DS_Store legível (lista os nomes dos arquivos da pasta)")
    return None


_PRIVATE_KEY = re.compile(
    r"-----BEGIN ((?:RSA |DSA |EC |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?)-----"
)


def private_key(resp: Response) -> Match | None:
    text = resp.text[:8_192]
    if htmlish(text):
        return None
    if re.match(r"\s*PuTTY-User-Key-File-[23]: ", text):
        return Match("Chave privada do PuTTY (.ppk) disponível para download")
    match = _PRIVATE_KEY.search(text)
    if not match:
        return None
    if "ENCRYPTED" in match.group(1):
        return Match("Chave privada (protegida por senha) disponível para download", Severity.HIGH)
    return Match(f"Chave privada disponível para download ({match.group(1).strip()})")


_SSH_PUBLIC = re.compile(r"^(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp\d+|sk-\S+) AAAA", re.M)
_SSH_KNOWN_HOST = re.compile(r"^(?:\|1\||[^\s#]+ )(?:\S+ )?(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp\d+) AAAA", re.M)  # fmt: skip

#: chaves do ``authorized_keys`` com opções (``from="..."``, ``command=...``, ``no-pty``...)
_SSH_AUTH_OPTIONS = re.compile(
    r'^(?:(?:[a-z-]+=(?:"[^"\n]*"|[^\s,"]+)|no-[a-z-]+|restrict|cert-authority),?)+ +'
    r"(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp\d+|sk-\S+) AAAA",
    re.M,
)


def ssh_public_keys(resp: Response) -> Match | None:
    """``authorized_keys`` ou ``known_hosts``: não são segredos, mas mapeiam acessos e servidores."""
    text = resp.text[:16_384]
    if htmlish(text):
        return None
    if _SSH_AUTH_OPTIONS.search(text):
        return Match(
            ".ssh/authorized_keys legível (chaves que podem entrar por SSH)", Severity.MEDIUM
        )
    if _SSH_KNOWN_HOST.search(text) or text.startswith("|1|"):
        return Match(".ssh/known_hosts legível (servidores que este acessa)", Severity.MEDIUM)
    if _SSH_PUBLIC.search(text):
        return Match(
            ".ssh/authorized_keys legível (chaves que podem entrar por SSH)", Severity.MEDIUM
        )
    return None


def aws_credentials(resp: Response) -> Match | None:
    text = resp.text[:8_192]
    match = re.search(r"aws_access_key_id\s*=\s*(\S+)", text, re.I)
    if not match or htmlish(text):
        return None
    return Match(f"Credenciais da AWS legíveis (aws_access_key_id = {mask(match.group(1))})")


def npmrc(resp: Response) -> Match | None:
    text = resp.text[:8_192]
    if htmlish(text):
        return None
    tokens = re.findall(
        r"^[ \t]*(?://[^\s=]+/:)?(?:_authToken|_auth|_password)[ \t]*=[ \t]*(\S+)", text, re.M
    )
    real = [t for t in tokens if not t.startswith("${")]
    if not real:
        return None
    return Match(f".npmrc com token de registro de pacotes ({mask(real[0])})")


def git_credentials(resp: Response) -> Match | None:
    text = resp.text[:8_192]
    if htmlish(text) or not _URL_WITH_CREDENTIALS.search(text):
        return None
    return Match(".git-credentials com usuário e senha/token de repositório")


def docker_config(resp: Response) -> Match | None:
    text = resp.text[:16_384]
    if '"auths"' in text and re.search(r'"auth"\s*:\s*"[A-Za-z0-9+/=]{8,}"', text):
        return Match("Configuração do Docker com credenciais de registro (auths)")
    return None


def netrc_or_pypirc(resp: Response) -> Match | None:
    text = resp.text[:8_192]
    if htmlish(text):
        return None
    if re.search(r"^[ \t]*machine\s+\S+", text, re.M) and re.search(r"\bpassword\s+\S+", text):
        return Match(".netrc com senha de acesso a servidores")
    if re.search(r"^\[(?:pypi|distutils|testpypi)\]", text, re.M) and re.search(
        r"^[ \t]*password\s*[:=]", text, re.M
    ):
        return Match(".pypirc com senha do índice de pacotes Python")
    return None


def kubeconfig(resp: Response) -> Match | None:
    text = resp.text[:65_536]
    if htmlish(text):
        return None
    if not all(
        re.search(rf"^{key}:", text, re.M) for key in ("apiVersion", "clusters", "contexts")
    ):
        return None
    secret = re.search(r"^[ \t]+(client-key-data|token|password)\s*:\s*\S+", text, re.M)
    extra = f" com credencial ({secret.group(1)})" if secret else ""
    return Match(f"kubeconfig legível: endereço e acesso ao cluster Kubernetes{extra}")


def terraform_state(resp: Response) -> Match | None:
    text = resp.text[:65_536]
    version = re.search(r'"terraform_version"\s*:\s*"([\d.]+)"', text)
    if not version or not re.search(r'"(?:resources|lineage)"\s*:', text):
        return None
    return Match(
        f"Estado do Terraform legível (Terraform {version.group(1)}): guarda segredos em texto claro"
    )


def sftp_config(resp: Response) -> Match | None:
    """Configuração de upload por SFTP/FTP de editores (Sublime SFTP, FTPSync, VS Code)."""
    text = resp.text[:16_384]
    if htmlish(text) or not re.search(r'"host"\s*:\s*"[^"]+"', text):
        return None
    if not re.search(r'"(?:remote_path|remotePath|connections|extra_list_connections)"\s*:', text):
        return None
    if re.search(r'"password"\s*:\s*"[^"]+"', text):
        return Match("Configuração de SFTP do editor com servidor, usuário e SENHA")
    return Match("Configuração de SFTP do editor com servidor e usuário", Severity.HIGH)


# -- backups e despejos de banco ------------------------------------------------------

_GZIP = bytes((0x1F, 0x8B, 0x08))  # cabeçalho gzip + método deflate
_MAGIC = (
    (b"PK\x03\x04", "ZIP"),
    (b"\x1f\x8b\x08", "gzip"),
    (b"Rar!\x1a\x07", "RAR"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip"),
    (b"BZh", "bzip2"),
)
_SQL_MARKERS = re.compile(
    r"(CREATE TABLE|INSERT INTO|DROP TABLE|LOCK TABLES|CREATE DATABASE|-- MySQL dump|"
    r"-- MariaDB dump|-- PostgreSQL database dump|-- phpMyAdmin SQL Dump|PRAGMA foreign_keys)",
    re.I,
)


def archive(resp: Response) -> Match | None:
    """Arquivo compactado reconhecido pelos primeiros bytes (número mágico)."""
    body = resp.body
    for magic, kind in _MAGIC:
        if body.startswith(magic) and (kind != "bzip2" or body[3:4].isdigit()):
            return Match(f"Arquivo compactado {kind} disponível para download{_size(resp)}")
    if len(body) > 262 and body[257:262] == b"ustar":
        return Match(f"Arquivo TAR disponível para download{_size(resp)}")
    return None


def _sql_markers(text: str) -> list[str]:
    """Marcadores de despejo SQL no começo do texto (vazio se não parecer um despejo)."""
    if htmlish(text):
        return []
    found = {m.group(1).upper() for m in _SQL_MARKERS.finditer(text)}
    if len(found) >= 2 or any(f.startswith("-- ") for f in found):
        return sorted(found)[:4]
    return []


def sql_dump(resp: Response) -> Match | None:
    markers = _sql_markers(resp.text[:65_536])
    if not markers:
        return None
    return Match(
        f"Despejo de banco de dados (SQL) disponível para download{_size(resp)}: "
        + ", ".join(markers)
    )


def _gunzip_head(body: bytes, limit: int = 16_384) -> str:
    """Começo descompactado de um gzip lido pela metade (vazio se não for gzip válido)."""
    try:
        data = zlib.decompressobj(wbits=31).decompress(body, limit)
    except zlib.error:
        return ""
    return data.decode("utf-8", errors="replace")


def compressed_dump(resp: Response) -> Match | None:
    """``.sql.gz``: despejo SQL compactado vira ``web.exposicao.dump_sql``; senão, backup."""
    plain = sql_dump(resp)  # servidor que entregou com Content-Encoding: gzip (já descompactado)
    if plain is not None:
        return Match(plain.evidence, finding="web.exposicao.dump_sql")
    if resp.body.startswith(_GZIP):
        markers = _sql_markers(_gunzip_head(resp.body))
        if markers:
            return Match(
                f"Despejo de banco de dados (SQL) compactado disponível para download{_size(resp)}: "
                + ", ".join(markers),
                finding="web.exposicao.dump_sql",
            )
    return archive(resp)
