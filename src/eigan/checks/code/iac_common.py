"""Peças comuns das regras de infraestrutura como código (Docker, Compose, Kubernetes, Terraform).

Aqui ficam os ids dos achados, a classificação dos arquivos, o formato de um
problema encontrado (``IacIssue``) e os critérios compartilhados: nomes de
variáveis que guardam segredos, portas de bancos de dados, capabilities do
Linux perigosas, sockets do Docker e caminhos sensíveis do host.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from ...core.models import Confidence, Severity
from .files import SourceFile
from .secret_rules import is_placeholder

ROOT = "code.iac.container_root"
UNPINNED = "code.iac.imagem_sem_versao"
ADD_REMOTE = "code.iac.add_remoto"
CURL_SH = "code.iac.curl_pipe_sh"
SECRET = "code.iac.segredo_em_texto"
SUDO = "code.iac.sudo"
PRIVILEGED = "code.iac.privilegiado"
HOST_NS = "code.iac.namespace_host"
DOCKER_SOCK = "code.iac.docker_sock"
DB_PORT = "code.iac.porta_banco_exposta"
ESCALATION = "code.iac.escalacao_privilegio"
CAPABILITIES = "code.iac.capabilities_perigosas"
HOSTPATH = "code.iac.hostpath"
NO_LIMITS = "code.iac.sem_limites"
WRITABLE_FS = "code.iac.fs_gravavel"
BUCKET_PUBLIC = "code.iac.bucket_publico"
FIREWALL_OPEN = "code.iac.firewall_aberto"
NO_ENCRYPTION = "code.iac.sem_criptografia"
DB_PUBLIC = "code.iac.banco_publico"

IAC_FINDINGS = (
    ROOT,
    UNPINNED,
    ADD_REMOTE,
    CURL_SH,
    SECRET,
    SUDO,
    PRIVILEGED,
    HOST_NS,
    DOCKER_SOCK,
    DB_PORT,
    ESCALATION,
    CAPABILITIES,
    HOSTPATH,
    NO_LIMITS,
    WRITABLE_FS,
    BUCKET_PUBLIC,
    FIREWALL_OPEN,
    NO_ENCRYPTION,
    DB_PUBLIC,
)

#: tipos de arquivo analisados
DOCKERFILE = "dockerfile"
COMPOSE = "compose"
KUBERNETES = "kubernetes"
TERRAFORM = "terraform"
#: tipo -> chave dos exemplos de correção da base (``Fix.tech``) e nome exibido
TECH = {
    DOCKERFILE: "dockerfile",
    COMPOSE: "docker-compose",
    KUBERNETES: "kubernetes",
    TERRAFORM: "terraform",
}
LABEL = {
    DOCKERFILE: "Dockerfile",
    COMPOSE: "docker-compose",
    KUBERNETES: "Kubernetes",
    TERRAFORM: "Terraform",
}

#: portas de bancos de dados, caches e filas que não devem ficar abertas para qualquer origem
DB_PORTS: dict[int, str] = {
    1433: "SQL Server",
    1521: "Oracle",
    2379: "etcd",
    3306: "MySQL/MariaDB",
    5432: "PostgreSQL",
    5672: "RabbitMQ",
    5984: "CouchDB",
    6379: "Redis",
    7474: "Neo4j",
    8086: "InfluxDB",
    9042: "Cassandra",
    9200: "Elasticsearch",
    9300: "Elasticsearch (cluster)",
    11211: "Memcached",
    15672: "RabbitMQ (painel)",
    27017: "MongoDB",
}
#: portas de administração remota
ADMIN_PORTS: dict[int, str] = {
    22: "SSH",
    23: "Telnet",
    2375: "API do Docker (sem TLS)",
    2376: "API do Docker",
    3389: "RDP",
    5985: "WinRM",
    5986: "WinRM (HTTPS)",
}

#: capabilities que o perfil "baseline" do Kubernetes aceita (Pod Security Standards)
BASELINE_CAPS = frozenset(
    {
        "AUDIT_WRITE",
        "CHOWN",
        "DAC_OVERRIDE",
        "FOWNER",
        "FSETID",
        "KILL",
        "MKNOD",
        "NET_BIND_SERVICE",
        "SETFCAP",
        "SETGID",
        "SETPCAP",
        "SETUID",
        "SYS_CHROOT",
    }
)
#: capabilities que, sozinhas, costumam bastar para escapar do container ou dominar o nó
CRITICAL_CAPS = frozenset(
    {
        "ALL",
        "BPF",
        "DAC_READ_SEARCH",
        "MAC_ADMIN",
        "MAC_OVERRIDE",
        "NET_ADMIN",
        "PERFMON",
        "SYS_ADMIN",
        "SYS_BOOT",
        "SYS_MODULE",
        "SYS_PTRACE",
        "SYS_RAWIO",
    }
)
_SOCKET_NAMES = frozenset(
    {"docker.sock", "containerd.sock", "crio.sock", "cri-dockerd.sock", "podman.sock"}
)
#: caminhos do host que dão acesso a credenciais, processos ou configuração do nó
SENSITIVE_HOST_PATHS = (
    "/etc",
    "/root",
    "/proc",
    "/sys",
    "/boot",
    "/dev",
    "/run",
    "/var/run",
    "/var/lib/kubelet",
    "/var/lib/docker",
    "/var/lib/containerd",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
)
#: arquivos do host montados por rotina e sem risco relevante (fuso horário, certificados de CA)
_HARMLESS_HOST_PATHS = (
    "/etc/localtime",
    "/etc/timezone",
    "/usr/share/zoneinfo",
    "/etc/ssl/certs",
    "/etc/pki/ca-trust",
    "/etc/ca-certificates",
    "/usr/local/share/ca-certificates",
    "/etc/machine-id",
    "/dev/null",
    "/dev/zero",
    "/dev/random",
    "/dev/urandom",
)
#: árvores inteiras sensíveis (qualquer subcaminho conta)
_SENSITIVE_TREES = (
    "/root",
    "/proc",
    "/sys",
    "/boot",
    "/dev",
    "/run",
    "/var/run",
    "/var/lib/kubelet",
    "/var/lib/docker",
    "/var/lib/containerd",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
)
#: subcaminhos de /etc e /usr com credenciais ou binários do sistema
#: (``/etc/nginx/conf.d`` ou ``/usr/share/nginx/html`` são rotina e não contam)
_SENSITIVE_SUBPATHS = (
    "/etc/kubernetes",
    "/etc/ssh",
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/etc/docker",
    "/etc/ssl/private",
    "/etc/pki/tls/private",
    "/etc/containerd",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/lib64",
    "/usr/local/bin",
    "/usr/local/sbin",
)
ROOT_USERS = frozenset({"root", "0", "root:root", "0:0", "root:0", "0:root"})

#: extensões que nunca são Dockerfile, mesmo com o nome começando por ``dockerfile.``
_NOT_DOCKERFILE = (
    ".dockerignore",
    ".md",
    ".txt",
    ".rst",
    ".py",
    ".js",
    ".ts",
    ".go",
    ".rb",
    ".rs",
    ".java",
    ".sh",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".lock",
    ".bak",
    ".orig",
)
_FIRST_INSTRUCTION = re.compile(
    r"^(?:ARG\s+[A-Za-z_]\w*|FROM\s+(?:--\w+=\S+\s+)*\S+(?:\s+AS\s+\S+)?\s*$)",
    re.I,
)
_COMPOSE_NAME = re.compile(r"^(?:docker-)?compose(?:[.\-][\w.\-]+)?\.ya?ml$")
_K8S_MARKERS = (re.compile(r"(?m)^apiVersion\s*:"), re.compile(r"(?m)^kind\s*:"))
_COMPOSE_MARKER = re.compile(r"(?m)^services\s*:")
_NAME_TOKENS = re.compile(r"[A-Z]?[a-z0-9]+|[A-Z0-9]+(?![a-z])")
_SECRET_WORDS = ("password", "passwd", "passphrase", "secret", "token", "apikey", "senha")
_SECRET_EXACT = frozenset({"pass", "pwd", "credential", "credentials"})
_SECRET_PAIRS = frozenset(
    {
        "api_key",
        "access_key",
        "secret_key",
        "private_key",
        "client_secret",
        "auth_token",
        "encryption_key",
        "signing_key",
        "master_key",
        "account_key",
    }
)
_NOT_SECRET_SUFFIX = frozenset(
    {
        "file",
        "path",
        "dir",
        "url",
        "uri",
        "name",
        "user",
        "username",
        "id",
        "host",
        "port",
        "length",
        "len",
        "min",
        "max",
        "size",
        "type",
        "mode",
        "policy",
        "header",
        "prefix",
        "format",
        "expiry",
        "expires",
        "expiration",
        "ttl",
        "timeout",
        "enabled",
        "required",
        "hash",
        "algorithm",
        "endpoint",
        "location",
        "count",
        "rounds",
        "auth",
        "prompt",
        "source",
        "env",
        "store",
        "backend",
        "provider",
        "manager",
        "rate",
    }
)
#: palavras que, em qualquer posição do nome, mostram que a variável é configuração e não segredo
_NOT_SECRET_ANYWHERE = frozenset(
    {
        "ttl",
        "expires",
        "expiry",
        "expiration",
        "rotation",
        "lifetime",
        "seconds",
        "minutes",
        "hours",
        "days",
        "interval",
        "regex",
        "hasher",
        "hashers",
        "encoding",
        "validators",
        "scanning",
    }
)
_BOOLEANISH = frozenset(
    {"true", "false", "yes", "no", "on", "off", "1", "0", "y", "n", "none", "null", "empty"}
)
_URL_PASSWORD = re.compile(r"[a-z][a-z0-9+.\-]*://[^/\s:@]*:([^/\s@]+)@", re.I)
_REFERENCE = re.compile(r"\$\{|\$[A-Za-z_]|\$\([A-Za-z_][\w.]*\)|\{\{|<[^>]*>|%\(|#\{")
_DURATION_OR_NUMBER = re.compile(r"\d{1,8}(?:ms|min|[smhdw])?", re.I)
_PLAIN_WORD = re.compile(r"[a-z]{1,10}")
_TEMPLATE_HINT = re.compile(
    r"your[_\- ]?(?:pass|secret|token|key)|seu_|sua_|replace[_\- ]?me|insert[_\- ]|fixme|todo|"
    r"change[_\- ]?me[_\- ]|\bcolocar\b|\btrocar\b|"
    r"^(?:test|dummy|example|sample|fake|mock)[\w\-]*$"
)
_WEAK_VALUES = frozenset(
    {
        "admin",
        "admin123",
        "changeit",
        "changeme",
        "guest",
        "letmein",
        "pass",
        "pass123",
        "passw0rd",
        "password",
        "password1",
        "password123",
        "postgres",
        "qwerty",
        "root",
        "secret",
        "senha",
        "senha123",
        "toor",
        "123456",
        "12345678",
        "123456789",
    }
)


@dataclass
class IacIssue:
    """Um problema encontrado por uma regra de IaC (vira um achado).

    ``fix`` é um trecho curto e colável com a correção para este recurso; a
    explicação completa e os exemplos por tecnologia vêm da base de conhecimento.
    """

    finding: str
    line: int
    title: str
    evidence: str
    severity: Severity | None = None
    confidence: Confidence = Confidence.FIRM
    discriminator: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    fix: str = ""


@dataclass
class IacReport:
    """Resultado da análise de um arquivo: problemas e controles aprovados (pontos fortes)."""

    issues: list[IacIssue] = field(default_factory=list)
    strengths: list[tuple[str, str]] = field(default_factory=list)  # (controle, texto)

    def add(self, issue: IacIssue | None) -> None:
        if issue is not None:
            self.issues.append(issue)

    def strength(self, control: str, text: str) -> None:
        self.strengths.append((control, text))


# -- classificação dos arquivos -------------------------------------------------------------


def is_dockerfile_name(lname: str) -> bool:
    if lname.endswith(_NOT_DOCKERFILE):
        return False  # ``Dockerfile.dockerignore``, ``dockerfile.py``, ``Dockerfile.md``...
    return (
        lname in ("dockerfile", "containerfile")
        or lname.startswith(("dockerfile.", "containerfile."))
        or lname.endswith(".dockerfile")
    )


def looks_like_dockerfile(text: str) -> bool:
    """A primeira instrução é ``FROM`` ou ``ARG``, como o formato do Dockerfile exige."""
    for raw in text.splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            return bool(_FIRST_INSTRUCTION.match(line))
    return False


def candidate(item: SourceFile) -> bool:
    """Vale a pena ler o arquivo? (filtro barato, só pelo nome)."""
    return is_dockerfile_name(item.lname) or item.ext in (".tf", ".yaml", ".yml")


def classify(item: SourceFile, text: str | None = None) -> str:
    """``dockerfile``, ``compose``, ``kubernetes``, ``terraform`` ou ``""``."""
    name = item.lname
    if is_dockerfile_name(name):
        return DOCKERFILE
    if item.ext == ".tf":
        return TERRAFORM
    if item.ext not in (".yaml", ".yml"):
        return ""
    if _COMPOSE_NAME.match(name):
        return COMPOSE
    if text is None:
        return ""
    if all(marker.search(text) for marker in _K8S_MARKERS):
        return KUBERNETES
    if _COMPOSE_MARKER.search(text):
        return COMPOSE  # o compose confirma pelo conteúdo (serviços com image/build)
    return ""


# -- segredos ---------------------------------------------------------------------------------


def name_tokens(name: str) -> list[str]:
    """``DB_PASSWORD`` / ``dbPassword`` / ``db-password`` -> ``["db", "password"]``."""
    return [token.lower() for token in _NAME_TOKENS.findall(name)]


def is_secret_name(name: str) -> bool:
    """O nome da variável sugere que ela guarda um segredo (e não o caminho/URL/tamanho de um)."""
    tokens = name_tokens(name)
    if not tokens or tokens[-1] in _NOT_SECRET_SUFFIX:
        return False
    if _NOT_SECRET_ANYWHERE.intersection(tokens):
        return False
    pairs = {f"{a}_{b}" for a, b in zip(tokens, tokens[1:], strict=False)}
    if pairs & _SECRET_PAIRS:
        return True
    return any(t in _SECRET_EXACT or t.endswith(_SECRET_WORDS) for t in tokens)


def literal_secret(value: str) -> bool:
    """Valor escrito por extenso (não é referência ``${VAR}``, exemplo, caminho nem booleano)."""
    text = value.strip().strip("'\"").strip()
    if not text or _REFERENCE.search(text) or text.lower() in _BOOLEANISH:
        return False
    if text.startswith(("/", "./", "~/", "\\")) or ("://" in text and "@" not in text):
        return False
    if _TEMPLATE_HINT.search(text.lower()):
        return False
    if not weak_secret(text) and (
        _DURATION_OR_NUMBER.fullmatch(text) or _PLAIN_WORD.fullmatch(text)
    ):
        return False  # número, duração ou palavra curta: configuração (``3600``, ``vault``)
    return not is_placeholder(text, strict=False)


def weak_secret(value: str) -> bool:
    """Senha fraca/padrão conhecida (``root``, ``changeme``, ``123456``...)."""
    return value.strip().strip("'\"").strip().lower() in _WEAK_VALUES


def url_password(value: str) -> str | None:
    """Senha escrita por extenso em ``esquema://usuário:senha@servidor`` (ou ``None``)."""
    match = _URL_PASSWORD.search(value)
    if match is None:
        return None
    password = match.group(1)
    return password if literal_secret(password) else None


def mask_url_password(value: str) -> str:
    """A URL sem a senha: ``postgres://app:***@db/app``."""
    return _URL_PASSWORD.sub(
        lambda m: (
            m.group(0)[: m.start(1) - m.start(0)] + "***" + m.group(0)[m.end(1) - m.start(0) :]
        ),
        value,
    )


_URL_USERINFO = re.compile(r"(\b[a-z][a-z0-9+.\-]*://)[^/\s@]+@", re.I)
_AUTH_HEADER = re.compile(r"(?i)(authorization\s*:\s*)(?:\w+\s+)?[^\s'\"]+")
_BEARER = re.compile(r"(?i)\b(bearer|token)\s+[A-Za-z0-9._~+/=\-]{8,}")
_PASSWORD_FLAG = re.compile(
    r"(?i)(--(?:password|passwd|pass)(?:=|\s+))\S+|(?<=\s)(-p)(?=[^\s\d-])\S{3,}"
)
_USER_PASS_FLAG = re.compile(r"(\s(?:-u|--user)\s+[^\s:]+:)\S+")


def scrub(text: str) -> str:
    """Remove credenciais de URLs, cabeçalhos, ``-p<senha>`` e ``--password`` de um comando."""
    text = _URL_USERINFO.sub(r"\1***@", text)
    text = _AUTH_HEADER.sub(r"\1***", text)
    text = _BEARER.sub(r"\1 ***", text)
    text = _USER_PASS_FLAG.sub(r"\1***", text)
    return _PASSWORD_FLAG.sub(lambda m: (m.group(1) or m.group(2)) + "***", text)


def mask_secret(value: str) -> str:
    """Máscara proporcional: senhas curtas não mostram nenhum caractere."""
    text = value.strip().strip("'\"").strip()
    keep = 4 if len(text) >= 20 else 2 if len(text) >= 12 else 0
    if keep == 0:
        return f"…({len(text)} caracteres)"
    return f"{text[:keep]}…({len(text)} caracteres)"


# -- imagens, portas, capabilities e caminhos -------------------------------------------------


def image_tag_issue(image: str) -> str | None:
    """``latest`` (tag latest), ``sem-tag`` ou ``None`` (versão fixa, digest ou variável)."""
    text = image.strip().strip("'\"")
    if not text or "$" in text or "{{" in text or "@" in text:
        return None
    name = text.rsplit("/", 1)[-1]
    if ":" not in name:
        return "sem-tag"
    return "latest" if name.rsplit(":", 1)[1].lower() == "latest" else None


@dataclass(frozen=True)
class PortSpec:
    """Porta publicada do compose. ``host_ip`` vazio = todas as interfaces; ``?`` = variável."""

    host_ip: str
    published: str
    target: int | None


_VAR_DEFAULT = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*:?-([^}]*)\}")
_VAR_PLAIN = re.compile(r"\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*")


def expand_vars(text: str) -> str:
    """``${VAR:-padrão}`` vira o padrão; ``${VAR}``/``$VAR`` sem padrão viram ``?``."""
    return _VAR_PLAIN.sub("?", _VAR_DEFAULT.sub(lambda m: m.group(1), text))


def parse_port(value: str) -> PortSpec:
    """``"127.0.0.1:5432:5432/tcp"`` -> host ``127.0.0.1``, publicada ``5432``, alvo 5432.

    Variáveis com padrão (``${PORTA:-5432}``) usam o padrão; sem padrão viram ``?``.
    """
    text = expand_vars(value.strip().strip("'\"").split("/", 1)[0])
    host = ""
    if text.startswith("["):
        host, _, text = text[1:].partition("]")
        text = text.lstrip(":")
        parts = text.split(":")
        published, target = (parts[0], parts[-1]) if len(parts) >= 2 else ("", parts[0])
        return PortSpec(host, published, _first_port(target))
    parts = text.rsplit(":", 2)
    if len(parts) == 3:
        host, published, target = parts
    elif len(parts) == 2:
        published, target = parts
    else:
        published, target = "", parts[0]
    return PortSpec(host, published, _first_port(target))


def all_interfaces(host_ip: str) -> bool:
    return host_ip.strip().strip("[]") in ("", "0.0.0.0", "::")  # nosec B104


def _first_port(text: str) -> int | None:
    head = text.split("-", 1)[0].strip()
    return int(head) if head.isdigit() else None


def normalize_cap(name: str) -> str:
    text = name.strip().strip("'\"").upper()
    return text[4:] if text.startswith("CAP_") else text


def risky_caps(names: list[str]) -> list[str]:
    """Capabilities adicionadas fora do conjunto aceito pelo perfil baseline."""
    found: list[str] = []
    for raw in names:
        cap = normalize_cap(raw)
        if cap and "$" not in cap and "{" not in cap and cap not in BASELINE_CAPS:
            if cap not in found:
                found.append(cap)
    return found


def caps_severity(caps: list[str]) -> Severity:
    return Severity.HIGH if any(cap in CRITICAL_CAPS for cap in caps) else Severity.MEDIUM


def is_runtime_socket(path: str) -> bool:
    """Socket do Docker/containerd/CRI-O/Podman (ou o pipe do Docker no Windows)."""
    text = path.strip().strip("'\"").replace("\\", "/").rstrip("/").lower()
    return text.rsplit("/", 1)[-1] in _SOCKET_NAMES or text.endswith("pipe/docker_engine")


def _under(text: str, bases: tuple[str, ...]) -> bool:
    return any(text == base or text.startswith(base + "/") for base in bases)


def harmless_host_path(path: str) -> bool:
    """Fuso horário, certificados de CA, ``/dev/null``...: montados por rotina, sem risco relevante."""
    raw = path.strip().strip("'\"")
    return raw.startswith("/") and _under("/" + raw.strip("/"), _HARMLESS_HOST_PATHS)


def sensitive_host_path(path: str) -> bool:
    """Raiz do host ou diretórios com credenciais, processos e configuração do nó."""
    raw = path.strip().strip("'\"")
    if not raw.startswith("/"):
        return False  # relativo, variável ou caminho do Windows
    text = "/" + raw.strip("/")
    if text == "/":
        return True
    if harmless_host_path(raw):
        return False
    if text in SENSITIVE_HOST_PATHS or _under(text, _SENSITIVE_TREES):
        return True
    return _under(text, _SENSITIVE_SUBPATHS)
