"""Regras de detecção de segredos (chaves, tokens, senhas) em arquivos de texto.

Os padrões de provedores seguem os formatos documentados pelos próprios serviços
e as regras de dois projetos abertos — gitleaks (https://github.com/gitleaks/gitleaks,
licença MIT, ``config/gitleaks.toml``) e detect-secrets
(https://github.com/Yelp/detect-secrets, licença Apache-2.0). As expressões foram
reescritas para o ``re`` do Python; nenhum arquivo desses projetos foi copiado.

Para reduzir falsos positivos:

- cada regra tem palavras-chave: o regex só roda se alguma aparece no arquivo;
- regras genéricas (``senha = "..."``) exigem que o nome da variável **termine** em
  um substantivo de segredo (``password``, ``api_key``, ``token``...), entropia
  mínima e descartam valores de exemplo (``changeme``, ``<sua-chave>``, ``${VAR}``);
- chaves privadas só contam se houver conteúdo base64 depois do cabeçalho.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
from collections import Counter
from dataclasses import dataclass

from ...core.models import Severity

PRIVATE_KEY = "code.segredos.chave_privada"
CLOUD = "code.segredos.nuvem"
TOKEN = "code.segredos.token"
JWT = "code.segredos.jwt"
GENERIC = "code.segredos.generico"
CONNECTION = "code.segredos.conexao"
ENV_FILE = "code.segredos.env_versionado"
SENSITIVE_FILE = "code.segredos.arquivo_sensivel"

SECRET_FINDINGS = (PRIVATE_KEY, CLOUD, TOKEN, JWT, GENERIC, CONNECTION, ENV_FILE, SENSITIVE_FILE)


@dataclass(frozen=True)
class SecretRule:
    """Uma regra: o regex, onde está o segredo (``group``) e como filtrar."""

    id: str
    label: str
    finding: str
    pattern: re.Pattern[str]
    severity: Severity
    keywords: tuple[str, ...]
    group: int = 0
    min_entropy: float = 0.0
    generic: bool = False  # heurística por nome de variável (mais sujeita a falso positivo)
    requires: re.Pattern[str] | None = None  # contexto exigido no mesmo arquivo
    files: tuple[str, ...] = ()  # só nestes nomes de arquivo (minúsculas)
    revoke: str = ""


def _rule(
    rule_id: str,
    label: str,
    finding: str,
    pattern: str,
    severity: Severity,
    keywords: str,
    revoke: str,
    *,
    group: int = 1,
    min_entropy: float = 0.0,
    generic: bool = False,
    requires: str = "",
    files: str = "",
) -> SecretRule:
    """Monta uma regra (palavras-chave e arquivos separados por espaço; regex em ASCII)."""
    return SecretRule(
        rule_id,
        label,
        finding,
        re.compile(pattern, re.ASCII),
        severity,
        tuple(keywords.split()),
        group=group,
        min_entropy=min_entropy,
        generic=generic,
        requires=re.compile(requires) if requires else None,
        files=tuple(files.split()),
        revoke=revoke,
    )


_C, _H, _M, _L = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW
#: identificador que termina com nome de segredo (o filtro ``generic_key_ok`` decide)
_KEY = (
    r"(?i:(?<![A-Za-z0-9_.\-])(?P<key>[A-Za-z0-9_.\-]{0,40}"
    r"(?:pass(?:word|wd|phrase)?|pwd|secret|token|senha|segredo|chave|credentials?|creds|apikey|"
    r"(?:api|access|private|secret|auth|signing|encryption|master|client|hmac|jwt)[_.\-]?key)"
    r"[A-Za-z0-9_.\-]{0,40}))"
)
_GENERIC_WORDS = "pass pwd secret token senha segredo chave credential creds key"
_GENERIC_REVOKE = "Troque a senha/chave no serviço em que ela é usada."

RULES: tuple[SecretRule, ...] = (
    _rule("chave-privada", "Chave privada (PEM/OpenSSH/PGP)", PRIVATE_KEY,
          r"-----BEGIN[ A-Z0-9_\-]{0,40}PRIVATE KEY(?: BLOCK)?-----", _C, "-----begin",
          "Gere um novo par de chaves e troque a chave pública/certificado em todos os lugares "
          "que confiam nela (servidores, authorized_keys, autoridade certificadora).", group=0),
    _rule("chave-putty", "Chave privada do PuTTY (.ppk)", PRIVATE_KEY,
          r"PuTTY-User-Key-File-\d+: [\w\-]+", _C, "putty-user-key-file",
          "Gere um novo par de chaves e remova a chave pública antiga dos servidores.", group=0),
    _rule("aws-access-key", "ID de chave de acesso da AWS", CLOUD,
          r"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b", _H, "akia asia abia acca a3t",
          "Console AWS > IAM > usuário > Credenciais de segurança: desative e exclua a chave.",
          min_entropy=3.0),
    _rule("aws-secret-key", "Chave secreta da AWS", CLOUD,
          r"(?i)aws.{0,20}?(?:secret|key|token|pass).{0,20}?[\"']?\s*[=:]\s*[\"']?"
          r"([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])", _C, "aws",
          "Console AWS > IAM: desative e exclua a chave de acesso; revise o CloudTrail.",
          min_entropy=4.0),
    _rule("gcp-api-key", "Chave de API do Google Cloud", CLOUD,
          r"\b(AIza[\w\-]{35})(?![\w\-])", _M, "aiza",
          "Google Cloud Console > APIs e serviços > Credenciais: gere outra chave, restrinja por "
          "API/domínio e exclua a antiga.", min_entropy=4.0),
    _rule("azure-storage-key", "Chave de conta de armazenamento do Azure", CLOUD,
          r"(?i)AccountKey\s*=\s*([A-Za-z0-9+/]{86}==)", _C, "accountkey",
          "Portal do Azure > conta de armazenamento > Chaves de acesso: gire (rotate) a chave."),
    _rule("azure-sas", "Token SAS do Azure", CLOUD,
          r"\bsv=\d{4}-\d{2}-\d{2}&[^\s'\"<>]{0,300}?\bsig=([A-Za-z0-9%+/=]{30,})", _H, "sig=",
          "Revogue a política de acesso armazenada ou gire a chave da conta que assinou o SAS."),
    _rule("azure-ad-secret", "Segredo de aplicativo do Microsoft Entra ID (Azure AD)", CLOUD,
          r"(?:^|[\\'\"`\s>=:(,)])([a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.\-]{31,34})(?:$|[\\'\"`\s<),])",
          _H, "q~", "Portal do Azure > Registros de aplicativo > Certificados e segredos: exclua o "
          "segredo.", min_entropy=3.0),
    _rule("digitalocean-token", "Token da DigitalOcean", CLOUD,
          r"\b(do[por]_v1_[a-f0-9]{64})\b", _H, "_v1_",
          "Painel da DigitalOcean > API > Tokens: revogue o token."),
    _rule("github-token", "Token do GitHub", TOKEN,
          r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36})\b", _H, "ghp_ gho_ ghu_ ghs_ ghr_",
          "GitHub > Settings > Developer settings > Personal access tokens: revogue o token.",
          min_entropy=3.0),
    _rule("github-fine-grained", "Token de acesso refinado do GitHub", TOKEN,
          r"\b(github_pat_\w{82})\b", _H, "github_pat_",
          "GitHub > Settings > Developer settings > Fine-grained tokens: revogue o token.",
          min_entropy=3.0),
    _rule("gitlab-token", "Token do GitLab", TOKEN,
          r"\b((?:glpat|gldt|glrt|glptt)-[\w\-]{20,}|GR1348941[\w\-]{20})(?![\w\-])", _H,
          "glpat- gldt- glrt- glptt- gr1348941",
          "GitLab > Preferências > Tokens de acesso (ou o projeto/runner): revogue o token.",
          min_entropy=3.0),
    _rule("slack-token", "Token do Slack", TOKEN,
          r"\b(xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9\-]*|xox[pe](?:-[0-9]{10,13}){3}-"
          r"[a-zA-Z0-9\-]{28,34}|(?i:xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+))", _H,
          "xoxb- xoxp- xoxe- xapp-",
          "api.slack.com > Your Apps > OAuth & Permissions: revogue e reinstale o app."),
    _rule("slack-webhook", "Webhook do Slack", TOKEN,
          r"(https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56})", _M,
          "hooks.slack.com",
          "Slack > configurações do app > Incoming Webhooks: remova o webhook e crie outro."),
    _rule("stripe-live", "Chave secreta de produção da Stripe", TOKEN,
          r"\b((?:sk|rk)_(?:live|prod)_[0-9a-zA-Z]{24,99})\b", _C,
          "sk_live_ rk_live_ sk_prod_ rk_prod_",
          "Painel da Stripe > Desenvolvedores > Chaves de API: gire (roll) a chave.",
          min_entropy=2.0),
    _rule("stripe-test", "Chave secreta de teste da Stripe", TOKEN,
          r"\b((?:sk|rk)_test_[0-9a-zA-Z]{24,99})\b", _L, "sk_test_ rk_test_",
          "Painel da Stripe (modo de teste) > Chaves de API: gire a chave.", min_entropy=2.0),
    _rule("twilio-api-key", "Chave de API da Twilio", TOKEN,
          r"\b(SK[0-9a-fA-F]{32})\b", _H, "twilio",
          "Console da Twilio > Account > API keys & tokens: exclua a chave.",
          min_entropy=3.0, requires=r"(?i)twilio"),
    _rule("sendgrid", "Chave de API da SendGrid", TOKEN,
          r"\b(SG\.[\w\-]{22}\.[\w\-]{43})(?![\w\-])", _H, "sg.",
          "SendGrid > Settings > API Keys: exclua a chave.", min_entropy=2.0),
    _rule("npm-token", "Token do npm", TOKEN,
          r"\b(npm_[A-Za-z0-9]{36})\b", _H, "npm_", "npmjs.com > Access Tokens: exclua o token.",
          min_entropy=2.0),
    _rule("npmrc-auth", "Credencial de registro no .npmrc/.yarnrc", TOKEN,
          r"(?i)(?:_auth(?:Token)?|npmAuthToken|npmAuthIdent)\s*[=:]\s*[\"']?([^\s$'\"{]{16,})", _H,
          "_auth npmauth",
          "Revogue o token no registro (npmjs.com, GitHub Packages, Artifactory...).",
          files=".npmrc .yarnrc .yarnrc.yml"),
    _rule("pypi-token", "Token do PyPI", TOKEN,
          r"\b(pypi-AgEIcHlwaS5vcmc[\w\-]{50,})", _H, "pypi-ageichlwas5vcmc",
          "pypi.org > Account settings > API tokens: remova o token.", min_entropy=3.0),
    _rule("openai-key", "Chave de API da OpenAI", TOKEN,
          r"\b(sk-(?:(?:proj|svcacct|admin)-)?[\w\-]{20,}T3BlbkFJ[\w\-]{20,})", _H, "t3blbkfj",
          "platform.openai.com > API keys: revogue a chave."),
    _rule("anthropic-key", "Chave de API da Anthropic", TOKEN,
          r"\b(sk-ant-(?:api03|admin01)-[\w\-]{93}AA)(?![\w\-])", _H, "sk-ant-",
          "console.anthropic.com > API keys: desative a chave."),
    _rule("huggingface-token", "Token do Hugging Face", TOKEN,
          r"\b(hf_[A-Za-z]{34})\b", _M, "hf_",
          "huggingface.co > Settings > Access Tokens: invalide o token.", min_entropy=2.0),
    _rule("telegram-bot", "Token de bot do Telegram", TOKEN,
          r"\b([0-9]{5,16}:A[A-Za-z0-9_\-]{34})(?![A-Za-z0-9_\-])", _M, "telegr",
          "No @BotFather, use /revoke para gerar outro token.", requires=r"(?i)telegr"),
    _rule("shopify-token", "Token da Shopify", TOKEN,
          r"\b(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b", _H, "shpat_ shpca_ shppa_ shpss_",
          "Admin da Shopify > Apps > app personalizado: revogue o token de acesso.",
          min_entropy=2.0),
    _rule("heroku-key", "Chave de API da Heroku", TOKEN,
          r"\b(HRKU-AA[0-9a-zA-Z_\-]{58})(?![\w\-])", _H, "hrku-aa",
          "Heroku > Account settings > Applications/API Key: revogue a autorização.",
          min_entropy=4.0),
    _rule("terraform-cloud-token", "Token da API do Terraform Cloud/HCP", TOKEN,
          r"\b([a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9\-_=]{60,70})", _H, "atlasv1",
          "HCP Terraform > User settings > Tokens: exclua o token.", min_entropy=3.5),
    _rule("doppler-token", "Token de API da Doppler", TOKEN,
          r"\b(dp\.pt\.[a-zA-Z0-9]{43})\b", _H, "dp.pt.",
          "Painel da Doppler > Access > Tokens: revogue o token.", min_entropy=2.0),
    _rule("linear-key", "Chave de API da Linear", TOKEN,
          r"\b(lin_api_[a-zA-Z0-9]{40})\b", _M, "lin_api_",
          "Linear > Settings > Security & access > API keys: revogue a chave.", min_entropy=2.0),
    _rule("postman-key", "Chave de API do Postman", TOKEN,
          r"\b(PMAK-[a-fA-F0-9]{24}-[a-fA-F0-9]{34})\b", _H, "pmak-",
          "Postman > Settings > API keys: exclua a chave.", min_entropy=3.0),
    _rule("databricks-token", "Token de acesso da Databricks", TOKEN,
          r"\b(dapi[a-f0-9]{32}(?:-\d)?)\b", _H, "dapi",
          "Databricks > Settings > Developer > Access tokens: revogue o token.", min_entropy=3.0),
    _rule("jwt", "Token JWT", JWT,
          r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})", _M, "eyj",
          "Se o token ainda é válido, invalide a sessão/emissor ou troque a chave de assinatura "
          "(o que invalida todos os tokens emitidos com ela)."),
    _rule("url-credenciais", "Usuário e senha em URL de conexão", CONNECTION,
          r"\b[a-z][a-z0-9+.\-]{1,20}://(?P<user>[^\s:@/'\"<>{}$]{0,64}):"
          r"(?P<value>[^\s:@/'\"<>{}$]{3,128})@(?P<host>\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.\-_]+)", _H, "://",
          "Troque a senha desse usuário no serviço (banco, fila, FTP...) e revise os acessos.",
          group=2),
    _rule("connection-string", "Senha em string de conexão", CONNECTION,
          r"(?i)(?:^|[;\"'\s])(?:password|pwd)\s*=\s*(?P<value>[^;\"'\s]{4,128})\s*(?:;|[\"']|$)",
          _H, "password= pwd=", "Troque a senha do usuário do banco de dados e revise os acessos.",
          requires=r"(?i)(?:server|data source|host|database|initial catalog|uid|user id)\s*="),
    _rule("atribuicao-generica", "Senha ou chave atribuída no código", GENERIC,
          _KEY + r"[\"']?\s*(?::=|=>|(?<![=!<>])=(?!=)|:)\s*(?P<q>[\"'`])"
          r"(?P<value>[^\"'`\s]{8,200})(?P=q)", _M, _GENERIC_WORDS, _GENERIC_REVOKE,
          group=3, min_entropy=3.0, generic=True),
    _rule("atribuicao-config", "Senha ou chave em arquivo de configuração", GENERIC,
          r"(?m)^[ \t]*(?:export[ \t]+)?" + _KEY
          + r"[ \t]*[=:][ \t]*(?P<value>[^\s#'\"]{8,200})[ \t]*(?:[ \t]#[^\r\n]*)?\r?$", _M, _GENERIC_WORDS,
          _GENERIC_REVOKE, group=2, min_entropy=3.0, generic=True),
    _rule("atribuicao-xml", "Senha ou chave em elemento XML", GENERIC,
          r"<" + _KEY + r">\s*(?P<value>[^<\s]{8,200})\s*</(?P=key)>", _M, _GENERIC_WORDS,
          _GENERIC_REVOKE, group=2, min_entropy=3.0, generic=True),
    _rule("php-define", "Senha ou chave em define() do PHP", GENERIC,
          r"define\(\s*['\"](?P<key>[A-Z0-9_]*(?:PASSWORD|SECRET|KEY|SALT|TOKEN)[A-Z0-9_]*)['\"]"
          r"\s*,\s*(?P<q>['\"])(?P<value>[^'\"\n]{8,200})(?P=q)", _M, "define(",
          "Troque a senha/chave (no WordPress, gere novos salts em api.wordpress.org/secret-key).",
          group=3, min_entropy=3.0, generic=True),
)  # fmt: skip

# -- filtros ---------------------------------------------------------------------

_PLACEHOLDER_EXACT = frozenset(
    "password passwd changeme changeit secret senha token example exemplo placeholder dummy "
    "default none null undefined test testing redacted masked notasecret mysecret supersecret "
    "secretkey password123 123456 12345678 123456789 1234567890 qwerty pass pass123 admin123 "
    "letmein abc123 abcdef abcdefgh".split()
)
#: trechos que denunciam exemplo em qualquer regra (inclusive de provedores)
_PLACEHOLDER_ANY = (
    "example", "exemplo", "sample", "placeholder", "dummy", "fake", "redacted", "xxxx", "****",
    "....", "____", "0000000000",
)  # fmt: skip
#: trechos que denunciam exemplo/variável nas regras genéricas (senha = "...")
_PLACEHOLDER_GENERIC = (
    "changeme", "change_me", "change-me", "your_", "your-", "your ", "yourkey", "yoursecret",
    "seu_", "sua_", "replace", "insert", "fixme", "todo", "123456789", "abcdefghij", "test",
    "<", ">", "${", "{{", "%(", "#{", "%s", "%d", "process.env", "os.environ", "getenv",
)  # fmt: skip
#: valores cifrados (sops, Jasypt, Spring Cloud Config, Ansible Vault): não são vazamento
_ENCRYPTED_PREFIXES = ("enc[", "enc(", "{cipher}", "$ansible_vault", "vault:v", "encrypted:")
#: chave do emulador de armazenamento do Azure (pública, documentada pela Microsoft)
_PUBLIC_VALUES = (
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr",
    # chaves de exemplo da documentação da Stripe (copiadas em milhares de tutoriais), montadas
    # por partes para os varredores de segredos não as confundirem com chaves reais
    "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc",
    "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc",
    "pk_test_TYooMQauvdEDq54NiTphI7jx",
)
#: ``iat`` do token de exemplo do jwt.io (aparece em tutoriais e testes do mundo todo)
_JWT_SAMPLE_IAT = 1516239022

#: último termo do nome da variável que indica um segredo
_SECRET_NOUNS = frozenset(
    "password passwd pwd pass passphrase secret token senha segredo credential credentials "
    "creds apikey secretkey privatekey accesskey authkey clientsecret".split()
)
#: ``<dono>_key`` que guarda segredo (``api_key``, ``signing_key``...); ``key`` sozinho não
_KEY_OWNERS = frozenset(
    "api access private secret auth signing encryption master client hmac jwt".split()
)
#: qualificadores no fim do nome que não mudam o sentido (``DB_PASSWORD_PROD``)
_KEY_QUALIFIERS = frozenset(
    "base value val prod production dev development staging stage live local old new raw "
    "plain plaintext nova antiga atual padrao".split()
)
#: nomes em português começam pelo substantivo: ``senha_banco``, ``chave_api``
_PT_SECRET_FIRST = frozenset({"senha", "segredo"})
_PT_KEY_OWNERS = frozenset("api secreta privada acesso app jwt mestra".split())
_PT_NOT_SECRET = frozenset(
    "nome url tamanho hash minima maxima campo label rotulo dica mensagem regra politica "
    "confirmacao expiracao validade tentativas forca".split()
)
#: variáveis cujo nome já diz que o valor não é segredo real
_PLACEHOLDER_KEY = ("example", "dummy", "fake", "mock", "sample", "anonymous", "placeholder")
_KEY_SPLIT = re.compile(r"[_.\-]+|(?<=[a-z0-9])(?=[A-Z])")
_IDENTIFIER = re.compile(r"[A-Za-z]+(?:[_\-. ][A-Za-z]+)*")
_WORD_PART = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])")
_TRAILING_NUMBER = re.compile(r"[_\-.]\d{1,3}$")
_UUID = re.compile(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}")
_MIME = re.compile(
    r"(?:application|text|image|audio|video|multipart|font|message)/[A-Za-z0-9.+\-]+(?:;.*)?"
)
_REPEATED = re.compile(r"^(.)\1+$")
_BASE64_BODY = re.compile(r"[A-Za-z0-9+/=]{40,}")
_EMAIL = re.compile(r"[^@\s]+@[^@\s]+\.[A-Za-z]{2,}")
_OPENSSH_MAGIC = b"openssh-key-v1\x00"


def shannon_entropy(value: str) -> float:
    """Entropia de Shannon em bits por caractere (segredos aleatórios ficam acima de ~3,5)."""
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum(c / total * math.log2(c / total) for c in counts.values())


def is_placeholder(value: str, *, strict: bool) -> bool:
    """Valor de exemplo/variável em vez de segredo real. ``strict`` = regras genéricas."""
    lowered = value.lower().strip()
    if any(value.startswith(public) for public in _PUBLIC_VALUES):
        return True
    if _REPEATED.match(lowered) or any(part in lowered for part in _PLACEHOLDER_ANY):
        return True
    if not strict:
        return False
    if lowered in _PLACEHOLDER_EXACT or any(part in lowered for part in _PLACEHOLDER_GENERIC):
        return True
    if lowered.startswith(_ENCRYPTED_PREFIXES) or (value.startswith("{") and value.endswith("}")):
        return True
    return lowered.startswith(("$", "%", "@", "/", "./", "~/", "\\")) or "://" in lowered


def key_parts(key: str) -> list[str]:
    """``dbPassword_PROD`` -> ``["db", "password", "prod"]``."""
    return [part.lower() for part in _KEY_SPLIT.split(key) if part]


def generic_key_ok(key: str) -> bool:
    """O nome termina com um substantivo de segredo (não é nome, URL, hash ou tamanho de um)."""
    lowered = key.lower()
    if any(word in lowered for word in _PLACEHOLDER_KEY):
        return False
    parts = key_parts(key)
    while parts and (parts[-1] in _KEY_QUALIFIERS or re.fullmatch(r"v?\d+", parts[-1])):
        parts.pop()
    if not parts:
        return False
    last = parts[-1]
    if last in _SECRET_NOUNS:
        return True
    if parts[0] in _PT_SECRET_FIRST and last not in _PT_NOT_SECRET:
        return True
    if parts[0] == "chave" and len(parts) >= 2 and parts[1] in _PT_KEY_OWNERS:
        return True
    return last == "key" and len(parts) >= 2 and parts[-2] in _KEY_OWNERS


def _word_like(value: str) -> bool:
    """Texto feito de palavras (``accessToken``, ``Bearer``, ``client-secret``), não aleatório."""
    value = _TRAILING_NUMBER.sub("", value)
    if not _IDENTIFIER.fullmatch(value):
        return False
    parts = [p for chunk in re.split(r"[_\-. ]", value) for p in _WORD_PART.findall(chunk)]
    return bool(parts) and all(len(p) <= 15 and re.search("[aeiouyAEIOUY]", p) for p in parts)


def generic_value_ok(value: str, min_entropy: float) -> bool:
    """Valor com cara de senha/chave: não é palavra comum e tem entropia suficiente."""
    if _word_like(value) or _UUID.fullmatch(value) or _MIME.fullmatch(value):
        return False
    if "(" in value and ")" in value:
        return False  # chamada de função, não um valor literal
    if value.replace(".", "").replace("-", "").isdigit():
        return False  # números/versões
    if _EMAIL.fullmatch(value):
        return False  # e-mail (ex.: senha convencional do FTP anônimo)
    return shannon_entropy(value) >= min_entropy


def private_key_has_body(text: str, end: int) -> bool:
    """Depois do cabeçalho ``BEGIN ... PRIVATE KEY`` há conteúdo base64 de verdade?"""
    window = text[end : end + 400]
    window = window.replace("\\n", "\n").replace("\\r", "")
    compact = re.sub(r"[\s\"',+]", "", window)
    return bool(_BASE64_BODY.match(compact)) or compact.startswith("Proc-Type:")


def private_key_encrypted(header: str, text: str, end: int) -> bool:
    """A chave está protegida por senha (PKCS#8 cifrada, PEM ``Proc-Type``, OpenSSH ou PuTTY)?"""
    window = text[end : end + 800].replace("\\n", "\n").replace("\\r", "")
    if "ENCRYPTED" in header or "Proc-Type: 4,ENCRYPTED" in window[:200]:
        return True
    if header.startswith("PuTTY"):
        match = re.search(r"Encryption:\s*(\S+)", window[:300])
        return match is not None and match.group(1).lower() != "none"
    if "OPENSSH" in header:
        body = re.sub(r"[^A-Za-z0-9+/]", "", window.split("-----", 1)[0])[:200]
        try:
            raw = base64.b64decode(body[: len(body) // 4 * 4])
        except (binascii.Error, ValueError):
            return False
        cipher = _openssh_cipher(raw)
        return cipher is not None and cipher != b"none"
    return False


def _openssh_cipher(raw: bytes) -> bytes | None:
    """Nome do algoritmo de cifra gravado no início de uma chave ``openssh-key-v1``."""
    if not raw.startswith(_OPENSSH_MAGIC) or len(raw) < len(_OPENSSH_MAGIC) + 4:
        return None
    start = len(_OPENSSH_MAGIC)
    size = int.from_bytes(raw[start : start + 4], "big")
    return raw[start + 4 : start + 4 + size] if size <= 64 else None


def jwt_is_valid(token: str) -> bool:
    """Cabeçalho com ``alg`` (descarta sequências aleatórias) e não é o exemplo do jwt.io."""
    parts = token.split(".")
    if len(parts) < 2:
        return False
    header, payload = _jwt_part(parts[0]), _jwt_part(parts[1])
    if not isinstance(header, dict) or "alg" not in header:
        return False
    return not (isinstance(payload, dict) and payload.get("iat") == _JWT_SAMPLE_IAT)


def _jwt_part(part: str) -> object:
    try:
        raw = base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
        return json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return None


_CONFIG_EXTS = (".env", ".ini", ".cfg", ".conf", ".properties", ".toml", ".yaml", ".yml")
_CONFIG_NAMES = frozenset({".pypirc", ".npmrc", ".yarnrc", ".netrc", "_netrc", ".pgpass"})


def is_config_file(lname: str) -> bool:
    """Arquivos de configuração em que ``CHAVE=valor`` sem aspas é comum."""
    if lname in _CONFIG_NAMES or lname.startswith(".env"):
        return True
    return lname.endswith(_CONFIG_EXTS)
