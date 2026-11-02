"""SSH: banner, KEXINIT e as regras puras usadas pela checagem ``net.ssh``.

O servidor SSH se identifica com um banner (RFC 4253 §4.2) e anuncia, antes de
qualquer login, os algoritmos que aceita (``SSH_MSG_KEXINIT``, RFC 4253 §7.1).
Este módulo lê essas duas mensagens — sem negociar chaves e sem enviar
credenciais — e reúne as regras (sem E/S) aplicadas sobre elas:

* **Política de algoritmos.** Ideias das listas FAIL/WARN da ferramenta
  ssh-audit (MIT), da RFC 9142 (troca de chaves), da RFC 8758 (RC4) e das notas
  de versão do OpenSSH. Diferenças deliberadas: curvas NIST P-256/384/521, grupo
  14 com SHA-256 e MACs SHA-2 sem EtM não viram achado (a RFC 9142 recomenda ou
  exige esses métodos; ambientes FIPS dependem deles), nem algoritmos nacionais
  (GOST, SM2), que não têm fraqueza demonstrada; HMAC-SHA1, ``ssh-rsa`` e CBC
  ficam como "obsoletos" (severidade baixa), porque ainda estão no padrão de
  muitos servidores e não têm ataque prático conhecido.
* **Terrapin (CVE-2023-48795).** ChaCha20-Poly1305, ou cifra CBC junto com MAC
  EtM, sem o marcador de "strict KEX" do servidor (draft-miller-sshm-strict-kex).
* **regreSSHion (CVE-2024-6387).** Faixas do aviso da Qualys e das notas do
  OpenSSH 9.8. Quando o banner traz a revisão do pacote Debian/Ubuntu, ela é
  comparada com a revisão corrigida pelas regras de versão do dpkg (Debian
  Policy §5.6.12).
"""

from __future__ import annotations

import re
import struct
import time
from collections.abc import Mapping
from dataclasses import dataclass, field

from .common import Connection

SSH_MSG_KEXINIT = 20
CLIENT_BANNER = b"SSH-2.0-EIGAN_Auditoria\r\n"
MAX_PACKET = 35_000  # RFC 4253 §6.1
MAX_LINE = 512  # a RFC limita a linha a 255 bytes; folga para servidores fora do padrão
MAX_PRE_LINES = 20  # linhas que o servidor pode mandar antes do banner (RFC 4253 §4.2)
MAX_NAMES = 64  # algoritmos aceitos por lista (o resto é descartado)
MAX_PACKETS = 3  # pacotes lidos à procura do KEXINIT (pode haver IGNORE/DEBUG antes)

#: listas do KEXINIT, na ordem do pacote
KEXINIT_FIELDS = (
    "kex",
    "hostkey",
    "cipher_c2s",
    "cipher_s2c",
    "mac_c2s",
    "mac_s2c",
    "compression_c2s",
    "compression_s2c",
    "lang_c2s",
    "lang_s2c",
)
CATEGORIES = ("kex", "hostkey", "cipher", "mac")

FRACO = "fraco"
OBSOLETO = "obsoleto"

#: marcadores de "strict KEX" do servidor (pré-padrão e padrão)
STRICT_KEX = ("kex-strict-s-v00@openssh.com", "kex-strict-s")
CHACHA = "chacha20-poly1305@openssh.com"
#: trocas de chaves híbridas pós-quânticas (sntrup761x25519, mlkem768x25519...)
PQ_MARKS = ("sntrup", "mlkem", "kyber")


# -- política de algoritmos ----------------------------------------------------


@dataclass(frozen=True)
class Rule:
    """Classificação de um algoritmo: nível, motivo e se ele torna o achado grave."""

    level: str
    reason: str
    critical: bool = False


def _rules(rule: Rule, *patterns: str) -> tuple[tuple[str, Rule], ...]:
    """Padrões (nome exato ou ``prefixo*``) que recebem a mesma regra."""
    return tuple((pattern, rule) for pattern in patterns)


_BLOCK64 = "bloco de 64 bits (ataques do tipo SWEET32)"
_SHA1_KEX = Rule(FRACO, "SHA-1 na troca de chaves (RFC 9142: SHOULD NOT)")
_SMALL_CURVE = Rule(FRACO, "curva elíptica pequena ou binária, fora das curvas da RFC 9142")
_UNREVIEWED = Rule(FRACO, "algoritmo experimental ou proprietário, sem revisão pública ampla")
_DSA = Rule(
    FRACO, "DSA de 1024 bits (desativado por padrão no OpenSSH 7.0 e removido no 10.0)", True
)
_RSA_SHA1 = Rule(OBSOLETO, "assinatura RSA com SHA-1 (desativada por padrão desde o OpenSSH 8.8)")

#: política por categoria; a primeira regra que casar vale
POLICY: Mapping[str, tuple[tuple[str, Rule], ...]] = {
    "kex": (
        *_rules(
            Rule(FRACO, "grupo Diffie-Hellman de 1024 bits com SHA-1 (RFC 9142: SHOULD NOT)", True),
            "diffie-hellman-group1-sha1",
            "kexAlgoDH1SHA1",
        ),
        *_rules(
            Rule(FRACO, "grupo Diffie-Hellman de 1024 bits", True), "diffie-hellman-group1-sha256"
        ),
        *_rules(
            Rule(FRACO, "RSA de 1024 bits com SHA-1 (RFC 9142: MUST NOT)", True), "rsa1024-sha1"
        ),
        *_rules(
            Rule(FRACO, "GSSAPI com grupo de 1024 bits e SHA-1 (RFC 9142: SHOULD NOT)", True),
            "gss-group1-sha1-*",
        ),
        *_rules(
            _SHA1_KEX, "diffie-hellman-group-exchange-sha1", "gss-gex-sha1-*", "gss-group14-sha1-*"
        ),
        *_rules(
            _SMALL_CURVE,
            "ecdh-sha2-nistp192",
            "ecdh-sha2-nistp224",
            "ecdh-sha2-nistb*",
            "ecdh-sha2-nistk*",
            "ecdh-sha2-nistt*",
        ),
        *_rules(_UNREVIEWED, "ecmqv-sha2", "m383-sha384@libassh.org", "m511-sha512@libassh.org"),
        *_rules(
            Rule(OBSOLETO, "SHA-1 na troca de chaves (a RFC 9142 só o admite como opcional: MAY)"),
            "diffie-hellman-group14-sha1",
            "kexAlgoDH14SHA1",
        ),
    ),
    "hostkey": (
        *_rules(
            _DSA,
            "ssh-dss",
            "ssh-dss-*",
            "ssh-dsa",
            "x509v3-ssh-dss",
            "x509v3-sign-dss*",
            "pgp-sign-dss",
            "spki-sign-dss",
        ),
        *_rules(Rule(FRACO, "chave do protocolo SSH-1", True), "ssh-rsa1"),
        *_rules(Rule(FRACO, "servidor sem chave de identificação", True), "null"),
        *_rules(Rule(FRACO, "assinatura DSA, abandonada pelo OpenSSH"), "dsa2048-*", "dsa3072-*"),
        *_rules(
            _SMALL_CURVE,
            "ecdsa-sha2-nistp192*",
            "ecdsa-sha2-nistp224*",
            "ecdsa-sha2-nistb*",
            "ecdsa-sha2-nistk*",
            "ecdsa-sha2-nistt*",
        ),
        *_rules(
            _RSA_SHA1,
            "ssh-rsa",
            "ssh-rsa-cert-*",
            "x509v3-ssh-rsa",
            "x509v3-sign-rsa",
            "pgp-sign-rsa",
            "spki-sign-rsa",
        ),
    ),
    "cipher": (
        *_rules(Rule(FRACO, "sem criptografia: a sessão trafega em texto puro", True), "none"),
        *_rules(Rule(FRACO, "DES de 56 bits (quebrado por força bruta)", True), "des-*"),
        *_rules(Rule(FRACO, "RC4 (RFC 8758: MUST NOT)", True), "arcfour*"),
        *_rules(Rule(FRACO, f"3DES, {_BLOCK64}"), "3des-*"),
        *_rules(Rule(FRACO, f"Blowfish, {_BLOCK64}"), "blowfish-*"),
        *_rules(Rule(FRACO, f"CAST-128, {_BLOCK64}"), "cast128-*"),
        *_rules(Rule(FRACO, f"IDEA, {_BLOCK64}"), "idea-*"),
        *_rules(_UNREVIEWED, "crypticore128@ssh.com"),
        *_rules(
            Rule(OBSOLETO, "modo CBC (desaconselhado; prefira CTR ou GCM)"),
            "aes128-cbc",
            "aes192-cbc",
            "aes256-cbc",
            "rijndael128-cbc",
            "rijndael192-cbc",
            "rijndael256-cbc",
            "rijndael-cbc@*",
        ),
        *_rules(Rule(OBSOLETO, "cifra em desuso, pouco revisada para SSH"), "seed-*"),
    ),
    "mac": (
        *_rules(Rule(FRACO, "sem verificação de integridade", True), "none"),
        *_rules(Rule(FRACO, "MD5", True), "hmac-md5*", "md5", "md5-8"),
        *_rules(Rule(FRACO, "RIPEMD-160 (em desuso)"), "hmac-ripemd*", "ripemd160", "ripemd160-8"),
        *_rules(Rule(FRACO, "SHA-1 truncado em 96 bits"), "hmac-sha1-96*"),
        *_rules(Rule(FRACO, "SHA-1 sem HMAC"), "sha1", "sha1-8"),
        *_rules(_UNREVIEWED, "cbcmac-*", "crypticore-mac@ssh.com"),
        *_rules(Rule(OBSOLETO, "HMAC com SHA-1"), "hmac-sha1", "hmac-sha1-etm@openssh.com"),
        *_rules(
            Rule(OBSOLETO, "etiqueta de integridade de 64 bits"),
            "umac-64@openssh.com",
            "umac-64-etm@openssh.com",
        ),
    ),
}


def _matches(pattern: str, name: str) -> bool:
    if pattern.endswith("*"):
        return name.startswith(pattern[:-1])
    return name == pattern


def classify(category: str, algorithm: str) -> Rule | None:
    """Regra que se aplica a um algoritmo (None = aceitável)."""
    for pattern, rule in POLICY.get(category, ()):
        if _matches(pattern, algorithm):
            return rule
    return None


# -- KEXINIT -------------------------------------------------------------------


_NAME = re.compile(r"[A-Za-z0-9@._+-]{1,128}")


def _merge(first: list[str], second: list[str]) -> list[str]:
    return first + [item for item in second if item not in first]


@dataclass
class KexInit:
    """Listas de algoritmos anunciadas pelo servidor."""

    lists: dict[str, list[str]] = field(default_factory=dict)

    def get(self, name: str) -> list[str]:
        return self.lists.get(name, [])

    @property
    def ciphers(self) -> list[str]:
        return _merge(self.get("cipher_c2s"), self.get("cipher_s2c"))

    @property
    def macs(self) -> list[str]:
        return _merge(self.get("mac_c2s"), self.get("mac_s2c"))

    def category(self, name: str) -> list[str]:
        """Algoritmos de ``kex``, ``hostkey``, ``cipher`` ou ``mac`` (as duas direções)."""
        if name == "cipher":
            return self.ciphers
        if name == "mac":
            return self.macs
        return self.get(name)

    @property
    def strict_kex(self) -> bool:
        return any(name in self.get("kex") for name in STRICT_KEX)

    @property
    def post_quantum(self) -> list[str]:
        return [name for name in self.get("kex") if any(mark in name for mark in PQ_MARKS)]


def parse_kexinit(payload: bytes) -> KexInit:
    """Interpreta o payload do ``SSH_MSG_KEXINIT`` (byte 20 + cookie + 10 listas)."""
    if not payload or payload[0] != SSH_MSG_KEXINIT:
        raise ValueError("não é um KEXINIT")
    pos = 17  # tipo + cookie de 16 bytes
    lists: dict[str, list[str]] = {}
    for name in KEXINIT_FIELDS:
        if pos + 4 > len(payload):
            raise ValueError("KEXINIT truncado")
        size = struct.unpack_from(">I", payload, pos)[0]
        pos += 4
        raw = payload[pos : pos + size]
        if len(raw) < size:
            raise ValueError("KEXINIT truncado")
        pos += size
        text = raw.decode("ascii", errors="replace")
        items = [item for item in text.split(",") if _NAME.fullmatch(item)]
        lists[name] = items[:MAX_NAMES]
    return KexInit(lists)


@dataclass
class Assessment:
    """Algoritmos classificados: ``{nível: {categoria: {algoritmo: motivo}}}``."""

    found: dict[str, dict[str, dict[str, str]]] = field(default_factory=dict)
    critical: list[tuple[str, str]] = field(default_factory=list)  # (categoria, algoritmo)

    def level(self, level: str) -> dict[str, dict[str, str]]:
        return self.found.get(level, {})


def assess(kex: KexInit) -> Assessment:
    """Classifica cada algoritmo oferecido como fraco, obsoleto ou aceitável."""
    result = Assessment()
    for category in CATEGORIES:
        for algorithm in kex.category(category):
            rule = classify(category, algorithm)
            if rule is None:
                continue
            result.found.setdefault(rule.level, {}).setdefault(category, {})[algorithm] = (
                rule.reason
            )
            if rule.critical:
                result.critical.append((category, algorithm))
    return result


def terrapin(kex: KexInit) -> tuple[bool, str]:
    """Condição do Terrapin (CVE-2023-48795): ChaCha20-Poly1305 ou CBC+EtM sem "strict KEX"."""
    if kex.strict_kex:
        return False, "o servidor anuncia strict KEX"
    ciphers, macs = kex.ciphers, kex.macs
    if CHACHA in ciphers:
        return True, f"oferece {CHACHA} sem strict KEX"
    cbc = [c for c in ciphers if c.endswith("-cbc") or "-cbc@" in c]
    etm = [m for m in macs if m.endswith("-etm@openssh.com")]
    if cbc and etm:
        return True, f"oferece CBC ({cbc[0]}) com MAC EtM ({etm[0]}) sem strict KEX"
    return False, "não oferece ChaCha20-Poly1305 nem CBC com MAC EtM"


# -- leitura do servidor ---------------------------------------------------------


def _printable(text: str) -> str:
    return "".join(ch for ch in text if ch.isprintable()).strip()


def read_banner(conn: Connection) -> str | None:
    """Linha de identificação ``SSH-...`` (linhas anteriores são permitidas pela RFC 4253 §4.2)."""
    deadline = time.monotonic() + conn.timeout * 2
    for _ in range(MAX_PRE_LINES):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        line = conn.read_until(b"\n", limit=MAX_LINE, timeout=remaining)
        if not line:
            return None
        text = _printable(line.decode("utf-8", errors="replace"))
        if text.startswith("SSH-"):
            return text
    return None


def read_packet(conn: Connection) -> bytes | None:
    """Um pacote binário SSH ainda sem criptografia (RFC 4253 §6): devolve o payload."""
    header = conn.read_exact(5)
    if len(header) < 5:
        return None
    length = struct.unpack(">I", header[:4])[0]
    padding = header[4]
    if not 5 <= length <= MAX_PACKET or padding >= length - 1:
        return None
    rest = conn.read_exact(length - 1)
    if len(rest) < length - 1:
        return None
    return rest[: length - 1 - padding]


def only_ssh1(banner: str) -> bool:
    """``SSH-1.5-...``: só o protocolo 1 (o ``SSH-1.99`` aceita também o 2)."""
    return banner.startswith(("SSH-1.", "SSH-1-")) and not banner.startswith("SSH-1.99")


def fetch(conn: Connection) -> tuple[str, KexInit | None]:
    """Lê o banner, envia o nosso e lê o KEXINIT do servidor (sem iniciar a troca de chaves)."""
    banner = read_banner(conn)
    if banner is None:
        return "", None
    if only_ssh1(banner) or not conn.send(CLIENT_BANNER):
        return banner, None
    deadline = time.monotonic() + conn.timeout * 2
    for _ in range(MAX_PACKETS):
        if time.monotonic() >= deadline:
            return banner, None
        payload = read_packet(conn)
        if payload is None:
            return banner, None
        if payload[:1] == bytes([SSH_MSG_KEXINIT]):
            try:
                return banner, parse_kexinit(payload)
            except ValueError:
                return banner, None
    return banner, None


# -- banner e versão -------------------------------------------------------------

_BANNER = re.compile(r"^SSH-(?P<proto>[^-\s]+)-(?P<software>\S+)(?:[ \t]+(?P<comment>.*))?$")
_OPENSSH = re.compile(r"^OpenSSH_(?P<numbers>\d+(?:\.\d+)*)(?:p(?P<portable>\d+))?", re.I)
_OPENSSH_WINDOWS = re.compile(r"^OpenSSH_for_Windows_(?P<numbers>\d+(?:\.\d+)*)", re.I)
_DISTRO = re.compile(r"^(?P<name>Ubuntu|Debian)-(?P<revision>[0-9A-Za-z.+~]+)$")


@dataclass(frozen=True)
class Banner:
    """Identificação ``SSH-protocolo-software comentário`` (RFC 4253 §4.2)."""

    raw: str
    protocol: str
    software: str
    comment: str = ""


def parse_banner(line: str) -> Banner | None:
    text = _printable(line)
    match = _BANNER.match(text)
    if match is None:
        return None
    return Banner(text, match["proto"], match["software"], (match["comment"] or "").strip())


@dataclass(frozen=True)
class OpenSshVersion:
    """Versão do OpenSSH: ``8.9p1`` (portátil), ``8.7`` (Red Hat, OpenBSD) ou Windows."""

    text: str
    numbers: tuple[int, ...]
    portable: int | None
    windows: bool = False

    @property
    def branch(self) -> tuple[int, int]:
        minor = self.numbers[1] if len(self.numbers) > 1 else 0
        return self.numbers[0], minor


def parse_openssh(software: str) -> OpenSshVersion | None:
    """``OpenSSH_9.6p1`` → 9.6p1; ``OpenSSH_for_Windows_9.5`` → 9.5 (Windows); outro → None."""
    match = _OPENSSH_WINDOWS.match(software)
    if match:
        numbers = tuple(int(n) for n in match["numbers"].split("."))
        return OpenSshVersion(match["numbers"], numbers, None, windows=True)
    match = _OPENSSH.match(software)
    if match is None:
        return None
    numbers = tuple(int(n) for n in match["numbers"].split("."))
    portable = int(match["portable"]) if match["portable"] else None
    return OpenSshVersion(match.group(0)[len("OpenSSH_") :], numbers, portable)


def parse_distro(comment: str) -> tuple[str, str] | None:
    """``Ubuntu-3ubuntu0.10`` → (ubuntu, 3ubuntu0.10): a revisão do pacote no banner."""
    match = _DISTRO.match(comment.strip())
    if match is None:
        return None
    return match["name"].lower(), match["revision"]


# -- comparação de versões do dpkg (Debian Policy §5.6.12) ------------------------


def _lex_order(char: str) -> int:
    """Ordem do dpkg: '~' antes de tudo (até do fim), letras antes dos demais símbolos."""
    if char == "~":
        return -1
    if char.isascii() and char.isalpha():
        return ord(char)
    return ord(char) + 256


def _lex_compare(left: str, right: str) -> int:
    for index in range(max(len(left), len(right))):
        a = _lex_order(left[index]) if index < len(left) else 0
        b = _lex_order(right[index]) if index < len(right) else 0
        if a != b:
            return -1 if a < b else 1
    return 0


def _run(text: str, start: int, digits: bool) -> int:
    """Fim do trecho só de dígitos (``digits``) ou só de não dígitos a partir de ``start``."""
    end = start
    while end < len(text) and (text[end] in "0123456789") == digits:
        end += 1
    return end


def dpkg_compare(left: str, right: str) -> int:
    """Compara versões/revisões de pacote Debian: -1, 0 ou 1."""
    i = j = 0
    while i < len(left) or j < len(right):
        end_i, end_j = _run(left, i, False), _run(right, j, False)
        diff = _lex_compare(left[i:end_i], right[j:end_j])
        if diff:
            return diff
        i, j = end_i, end_j
        end_i, end_j = _run(left, i, True), _run(right, j, True)
        a, b = int(left[i:end_i] or 0), int(right[j:end_j] or 0)
        if a != b:
            return -1 if a < b else 1
        i, j = end_i, end_j
    return 0


# -- regreSSHion (CVE-2024-6387) ---------------------------------------------------

VULNERAVEL = "vulneravel"
INDICIO = "indicio"
CORRIGIDO = "corrigido"
NAO_AFETADO = "nao_afetado"

#: revisão do pacote openssh que corrige o CVE-2024-6387 (USN-6859-1, DSA-5724-1 e
#: rastreador de segurança do Debian), por distribuição e versão do OpenSSH
REGRESSHION_FIXED: Mapping[tuple[str, str], str] = {
    ("ubuntu", "9.6p1"): "3ubuntu13.3",  # Ubuntu 24.04 LTS
    ("ubuntu", "9.3p1"): "1ubuntu3.6",  # Ubuntu 23.10
    ("ubuntu", "8.9p1"): "3ubuntu0.10",  # Ubuntu 22.04 LTS
    ("debian", "9.2p1"): "2+deb12u3",  # Debian 12 (bookworm)
    ("debian", "9.7p1"): "7",  # Debian unstable (sid) em julho de 2024
}


@dataclass(frozen=True)
class Verdict:
    """Resultado da avaliação de uma versão: situação, motivo e versão analisada."""

    status: str
    reason: str
    version: str = ""


def regresshion(banner: Banner) -> Verdict | None:
    """Avalia o banner contra o regreSSHion. None se o servidor não for OpenSSH."""
    version = parse_openssh(banner.software)
    if version is None:
        return None
    if version.windows:
        return Verdict(
            NAO_AFETADO,
            "OpenSSH para Windows: a Microsoft informa que o Windows não é afetado",
            version.text,
        )
    ancient = version.branch < (4, 4)
    affected = (8, 5) <= version.branch <= (9, 7)
    if not ancient and not affected:
        return Verdict(
            NAO_AFETADO,
            f"OpenSSH {version.text} está fora das faixas afetadas (anteriores à 4.4p1 e 8.5p1 a 9.7p1)",
            version.text,
        )
    if version.portable is None:
        return Verdict(
            INDICIO,
            "a versão não tem o sufixo 'p' do OpenSSH portátil: é o caso do OpenBSD (não afetado) "
            "e de pacotes da família Red Hat, que corrigiram a falha sem mudar o número da versão "
            "(confira com 'rpm -q openssh-server')",
            version.text,
        )
    distro = parse_distro(banner.comment)
    if affected and distro is not None:
        return _distro_verdict(version, *distro)
    if banner.comment:
        return Verdict(
            INDICIO,
            f"o banner traz uma marca de distribuição ('{banner.comment}'): o fornecedor pode ter "
            "aplicado a correção sem mudar a versão",
            version.text,
        )
    if ancient:
        return Verdict(
            INDICIO,
            f"OpenSSH {version.text} é anterior à 4.4p1: vulnerável, salvo se o pacote tiver as "
            "correções antigas dos CVE-2006-5051 e CVE-2008-4109",
            version.text,
        )
    return Verdict(
        VULNERAVEL, f"OpenSSH {version.text} está na faixa afetada (8.5p1 a 9.7p1)", version.text
    )


def _distro_verdict(version: OpenSshVersion, distro: str, revision: str) -> Verdict:
    fixed = REGRESSHION_FIXED.get((distro, version.text))
    package = f"{version.text}-{revision}"
    if fixed is None:
        return Verdict(
            INDICIO,
            f"pacote {distro} {package}: o EIGAN não conhece a revisão corrigida para esta versão; "
            "confira o aviso de segurança da distribuição",
            version.text,
        )
    if dpkg_compare(revision, fixed) >= 0:
        return Verdict(
            CORRIGIDO,
            f"pacote {distro} {package} já tem a correção (corrigida na revisão {fixed})",
            version.text,
        )
    return Verdict(
        VULNERAVEL,
        f"pacote {distro} {package} é anterior à revisão corrigida {fixed}",
        version.text,
    )
