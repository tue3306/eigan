"""Segredos no código: regras de provedores, filtros de falso positivo e relato mascarado."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from fakes_code import (
    ALNUM,
    BASE32_UP,
    BASE64ISH,
    HEX_LOWER,
    URLSAFE,
    init_fake_git,
    joined,
    project_fact,
    random_text,
    write_tree,
)
from helpers import CheckOutcome, run_check

from eigan.checks.code import gitmeta, secret_scan
from eigan.checks.code.secret_rules import (
    CLOUD,
    CONNECTION,
    ENV_FILE,
    GENERIC,
    JWT,
    PRIVATE_KEY,
    RULES,
    SECRET_FINDINGS,
    SENSITIVE_FILE,
    TOKEN,
    generic_key_ok,
    is_placeholder,
    shannon_entropy,
)
from eigan.core import kb
from eigan.core.models import Confidence, Severity
from eigan.core.registry import get_check, load_builtin_checks
from eigan.core.settings import Settings


@pytest.fixture(autouse=True)
def so_git_do_proprio_projeto(monkeypatch: pytest.MonkeyPatch) -> None:
    """Isola dos repositórios que possam existir acima da pasta temporária."""
    monkeypatch.setattr(
        gitmeta, "_find_git_root", lambda root: root if (root / ".git").exists() else None
    )


def rnd(size: int, alphabet: str = ALNUM, seed: str = "s") -> str:
    return random_text(size, alphabet, seed=seed)


def b64json(data: dict[str, object]) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")


def make_jwt(iat: int = 1700000000) -> str:
    return ".".join(
        [
            b64json({"alg": "HS256", "typ": "JWT"}),
            b64json({"sub": "user-42", "name": "Maria", "iat": iat}),
            rnd(43, URLSAFE),
        ]
    )


def pem(kind: str = "RSA PRIVATE KEY") -> str:
    body = "\n".join(rnd(64, BASE64ISH, seed=f"pem{i}") for i in range(6))
    return f"-----BEGIN {kind}-----\n{body}\n-----END {kind}-----\n"


AZ_KEY = rnd(86, BASE64ISH.replace("/", "a"))
SLACK = joined("xoxb", "-", "1234567890123", "-", "2345678901234", "-", rnd(24))
HOOK = joined("https://hooks.slack", ".com/services/", "T", rnd(8), "/B", rnd(8), "/", rnd(24))
HF = joined("hf", "_", rnd(34, "abcdefghijklmnopqrstuvwxyzABCDEFGH"))

#: (id da regra, nome do arquivo, texto com o segredo montado em tempo de execução)
CASES: list[tuple[str, str, str]] = [
    ("chave-privada", "deploy.pem", pem()),
    ("chave-privada", "id.pem", pem("PRIVATE KEY")),
    ("chave-putty", "k.ppk", joined("PuTTY-User-", "Key-File-3: ssh-ed25519\nEncryption: none\n")),
    ("aws-access-key", "app.py", f'KEY = "{joined("AKIA", rnd(16, BASE32_UP))}"'),
    ("aws-secret-key", "app.py", f'aws_secret_access_key = "{rnd(40, BASE64ISH, seed="aws")}"'),
    ("gcp-api-key", "app.js", f'const k = "{joined("AIza", rnd(35, URLSAFE))}";'),
    ("azure-storage-key", "app.cs", f"AccountKey={AZ_KEY}==;"),
    ("azure-sas", "u.txt", f"https://x.blob.core.windows.net/c?sv=2020-08-04&ss=b&sig={rnd(44)}"),
    ("azure-ad-secret", "app.py", f'secret = "{rnd(3)}8Q~{rnd(34, seed="ad")}"'),
    ("digitalocean-token", "a.sh", f"TOKEN={joined('dop', '_v1_', rnd(64, HEX_LOWER))}"),
    ("github-token", "a.sh", f"x={joined('ghp', '_', rnd(36))}"),
    ("github-fine-grained", "a.sh", f"x={joined('github', '_pat_', rnd(82))}"),
    ("gitlab-token", "a.sh", f"x={joined('glpat', '-', rnd(20, URLSAFE))}"),
    ("slack-token", "a.sh", f"x={SLACK}"),
    ("slack-webhook", "a.sh", f"u={HOOK}"),
    ("stripe-live", "a.py", f'k = "{joined("sk", "_live_", rnd(24))}"'),
    ("stripe-test", "a.py", f'k = "{joined("sk", "_test_", rnd(24))}"'),
    ("twilio-api-key", "a.py", f'# twilio\nk = "{joined("SK", rnd(32, HEX_LOWER))}"'),
    ("sendgrid", "a.py", f'k = "{joined("SG", ".", rnd(22, URLSAFE), ".", rnd(43, URLSAFE))}"'),
    ("npm-token", "a.sh", f"x={joined('npm', '_', rnd(36))}"),
    ("npmrc-auth", ".npmrc", f"//registry.npmjs.org/:_authToken={rnd(36, seed='npmrc')}\n"),
    ("pypi-token", "a.sh", f"x={joined('pypi-', 'AgEIcHlwaS5vcmc', rnd(60, URLSAFE))}"),
    ("openai-key", "a.py", f'k = "{joined("sk-", rnd(24), "T3BlbkFJ", rnd(24))}"'),
    ("anthropic-key", "a.py", f'k = "{joined("sk-ant-", "api03-", rnd(93, URLSAFE), "AA")}"'),
    ("huggingface-token", "a.py", f'k = "{HF}"'),
    ("telegram-bot", "a.py", f'# telegram\nk = "123456789:{joined("A", rnd(34, URLSAFE))}"'),
    ("shopify-token", "a.py", f'k = "{joined("shp", "at_", rnd(32, HEX_LOWER))}"'),
    ("heroku-key", "a.sh", f"x={joined('HRKU-', 'AA', rnd(58, URLSAFE))}"),
    ("terraform-cloud-token", "a.sh", f"x={rnd(14)}.atlasv1.{rnd(64, URLSAFE)}"),
    ("doppler-token", "a.sh", f"x={joined('dp', '.pt.', rnd(43))}"),
    ("linear-key", "a.sh", f"x={joined('lin_api', '_', rnd(40))}"),
    (
        "postman-key",
        "a.sh",
        f"x={joined('PMAK', '-', rnd(24, HEX_LOWER), '-', rnd(34, HEX_LOWER))}",
    ),
    ("databricks-token", "a.sh", f"x={joined('dapi', rnd(32, HEX_LOWER))}"),
    ("jwt", "a.txt", f"Authorization: Bearer {make_jwt()}"),
    ("url-credenciais", "a.py", f'u = "postgres://app:{rnd(18)}@db.prod.corp.net/app"'),
    ("connection-string", "a.cs", f'"Server=db;Database=x;User Id=sa;Password={rnd(14)};"'),
    ("atribuicao-generica", "a.py", f'api_key = "{rnd(32, seed="gen")}"'),
    ("atribuicao-config", "settings.ini", f"db_password = {rnd(20, seed='cfg')}\n"),
    ("atribuicao-xml", "web.config", f"<password>{rnd(18, seed='xml')}</password>"),
    ("php-define", "wp.php", f"define('AUTH_{'KEY'}', '{rnd(40, seed='php')}');"),
]


def rule_ids(text: str, lname: str) -> set[str]:
    return {hit.rule.id for hit in secret_scan.scan_text(text, lname)}


def test_casos_cobrem_todas_as_regras() -> None:
    assert {case[0] for case in CASES} == {rule.id for rule in RULES}


@pytest.mark.parametrize(
    ("rule_id", "name", "text"), CASES, ids=[f"{c[0]}-{i}" for i, c in enumerate(CASES)]
)
def test_regra_detecta_segredo(rule_id: str, name: str, text: str) -> None:
    assert rule_id in rule_ids(text, name)


# -- falsos positivos --------------------------------------------------------------


NEGATIVES: list[tuple[str, str]] = [
    ("a.py", 'password = "changeme"'),
    ("a.py", 'api_key = "your_api_key_here"'),
    ("a.py", 'api_key = os.environ["API_KEY_VALUE"]'),
    ("a.py", 'secret = "${SECRET_FROM_VAULT}"'),
    ("a.py", 'token = "Bearer"'),
    ("a.py", 'password_field = "passwordConfirmation"'),
    ("a.py", 'key = "' + rnd(32, seed="k") + '"'),  # "key" sozinho não é segredo
    ("a.py", 'hash_password = "' + "a" * 32 + '"'),
    ("a.py", 'k = "AKIAIOSFODNN7EXAMPLE"'),
    ("a.sh", "x=" + joined("ghp", "_", "a" * 36)),
    ("a.py", 'k = "' + joined("sk", "_live_", "x" * 24) + '"'),
    ("a.py", 'u = "postgres://user:password@localhost/db"'),
    ("a.py", 'u = "postgres://app:secret@db.example.com/app"'),
    ("a.py", 'u = "redis://:pass@localhost:6379"'),
    ("a.txt", "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----"),
    ("a.md", "As chaves começam com -----BEGIN RSA PRIVATE KEY----- no formato PEM."),
    ("a.txt", f"eyJ{rnd(20)}.eyJ{rnd(20, seed='b')}.{rnd(30, seed='c')}"),  # não é JWT de verdade
    ("settings.ini", "password = ${DB_PASSWORD}\n"),
    ("settings.ini", "secret = ENC[AES256_GCM,data:abcdefghijklmnop]\n"),
    ("a.py", 'secret_name = "my-secret-name-in-vault"'),
]


@pytest.mark.parametrize(("name", "text"), NEGATIVES, ids=[str(i) for i in range(len(NEGATIVES))])
def test_nao_detecta_exemplos(name: str, text: str) -> None:
    assert rule_ids(text, name) == set()


def test_jwt_de_exemplo_do_jwt_io_e_ignorado() -> None:
    assert "jwt" not in rule_ids(make_jwt(iat=1516239022), "a.txt")


def test_chave_privada_cifrada_tem_severidade_menor() -> None:
    [hit] = secret_scan.scan_text(pem("ENCRYPTED PRIVATE KEY"), "k.pem")
    assert hit.severity is Severity.HIGH
    assert "senha" in hit.note


def test_linha_com_marcador_de_excecao_e_ignorada() -> None:
    value = rnd(32, seed="allow")
    assert rule_ids(f'api_key = "{value}"  # pragma: allowlist secret', "a.py") == set()
    assert rule_ids(f'api_key = "{value}"  # gitleaks:allow', "a.py") == set()
    assert rule_ids(f'# pragma: allowlist nextline secret\napi_key = "{value}"', "a.py") == set()
    assert rule_ids(f'api_key = "{value}"', "a.py") == {"atribuicao-generica"}


def test_arquivo_minificado_ignora_regras_genericas() -> None:
    text = 'var a={api_key:"' + rnd(32, seed="min") + '"};' + "x=1;" * 100
    assert rule_ids(text, "app.min.js") == set()


def test_django_secret_key_fica_para_a_checagem_de_configuracao() -> None:
    text = f'from django.conf import settings\nSECRET_KEY = "{rnd(50, seed="dj")}"\n'
    assert rule_ids(text, "settings.py") == set()


def test_servidor_local_com_senha_forte_vira_baixo() -> None:
    text = f'u = "postgres://app:{rnd(18)}@localhost/app"'
    [hit] = secret_scan.scan_text(text, "a.py")
    assert hit.severity is Severity.LOW


def test_funcoes_de_apoio() -> None:
    assert shannon_entropy("aaaa") == 0.0
    assert shannon_entropy(rnd(40)) > 4.0
    assert is_placeholder("exampleexampleexample", strict=False)
    assert is_placeholder("changeme", strict=True)
    assert not is_placeholder(rnd(32), strict=True)
    assert generic_key_ok("DB_PASSWORD_PROD")
    assert generic_key_ok("senha_banco")
    assert generic_key_ok("api_key")
    assert not generic_key_ok("key")
    assert not generic_key_ok("example_password")


# -- a checagem completa -----------------------------------------------------------


def scan(
    root: Path, files: dict[str, str | bytes] | None = None, **settings: object
) -> CheckOutcome:
    if files:
        write_tree(root, files)
    return run_check(
        "code.secrets", project_fact(root), settings=Settings(**settings) if settings else None
    )


def test_checagem_registrada_com_base_completa() -> None:
    load_builtin_checks()
    registered = get_check("code.secrets")
    assert set(SECRET_FINDINGS) <= set(registered.findings)
    for finding_id in SECRET_FINDINGS:
        entry = kb.get(finding_id)
        assert entry is not None
        assert entry.steps
        assert entry.references
        assert entry.verify


def test_achado_nunca_exibe_o_segredo_inteiro(tmp_path: Path) -> None:
    secret = joined("ghp", "_", rnd(36, seed="mask"))
    out = scan(tmp_path, {"src/deploy.sh": f"export GH={secret}\n"})
    [finding] = out.findings
    assert finding.check_id == TOKEN
    assert finding.severity is Severity.HIGH
    assert finding.asset == "src/deploy.sh:1"
    blob = json.dumps(
        [finding.evidence, finding.title, finding.details, finding.discriminator], default=str
    )
    assert secret not in blob
    assert secret[8:] not in blob
    assert finding.discriminator.startswith("github-token@")


def test_chave_privada_e_critica_e_sem_conteudo(tmp_path: Path) -> None:
    out = scan(tmp_path, {"infra/server.pem": pem()})
    [finding] = out.findings
    assert finding.check_id == PRIVATE_KEY
    assert finding.severity is Severity.CRITICAL
    assert finding.confidence is Confidence.CONFIRMED
    assert rnd(64, BASE64ISH, seed="pem0") not in json.dumps(finding.evidence)


def test_segredo_em_teste_tem_severidade_menor(tmp_path: Path) -> None:
    secret = joined("ghp", "_", rnd(36, seed="t"))
    out = scan(tmp_path, {"tests/test_x.py": f'T = "{secret}"\n'})
    [finding] = out.findings
    assert finding.severity is Severity.LOW
    assert "teste" in json.dumps(finding.details, ensure_ascii=False).lower()


def test_projeto_limpo_gera_ponto_forte(tmp_path: Path) -> None:
    out = scan(tmp_path, {"src/app.py": "print('ola')\n", "README.md": "# app\n"})
    assert out.findings == []
    assert [p.asset for p in out.passed] == [str(tmp_path)]


def test_binarios_e_lockfiles_sao_ignorados(tmp_path: Path) -> None:
    secret = joined("ghp", "_", rnd(36, seed="lock"))
    out = scan(
        tmp_path,
        {"package-lock.json": f'{{"x": "{secret}"}}', "logo.png": f"x {secret}".encode()},
    )
    assert out.findings == []


def test_env_versionado_gera_achado(tmp_path: Path) -> None:
    write_tree(tmp_path, {".env": f"DB_PASSWORD={rnd(20, seed='env')}\nPORT=8080\n"})
    init_fake_git(tmp_path, tracked=[".env"], gitignore="node_modules/\n")
    out = scan(tmp_path)
    env = next(f for f in out.findings if f.check_id == ENV_FILE)
    assert env.severity is Severity.HIGH
    assert "DB_PASSWORD" in env.evidence
    assert rnd(20, seed="env") not in json.dumps([f.evidence for f in out.findings])


def test_env_ignorado_pelo_git_nao_gera_achado(tmp_path: Path) -> None:
    write_tree(tmp_path, {".env": f"DB_PASSWORD={rnd(20, seed='env')}\n", "src/a.py": "x = 1\n"})
    init_fake_git(tmp_path, tracked=["src/a.py"], gitignore=".env\n")
    assert scan(tmp_path).findings == []


def test_env_fora_do_gitignore_e_medio(tmp_path: Path) -> None:
    write_tree(tmp_path, {".env": f"API_TOKEN={rnd(24, seed='env2')}\n"})
    init_fake_git(tmp_path, tracked=[], gitignore="build/\n")
    env = [f for f in scan(tmp_path).findings if f.check_id == ENV_FILE]
    assert len(env) == 1
    assert env[0].severity is Severity.MEDIUM


def test_env_modelo_e_env_so_com_config_publica_nao_geram_achado(tmp_path: Path) -> None:
    write_tree(
        tmp_path,
        {".env.example": "DB_PASSWORD=changeme\n", ".env": "PORT=8080\nDEBUG=false\n"},
    )
    init_fake_git(tmp_path, tracked=[".env", ".env.example"])
    assert [f for f in scan(tmp_path).findings if f.check_id == ENV_FILE] == []


def test_keystore_versionado(tmp_path: Path) -> None:
    write_tree(tmp_path, {"app/release.jks": b"\xfe\xed\xfe\xed" + b"\x00" * 32})
    init_fake_git(tmp_path, tracked=["app/release.jks"])
    [finding] = scan(tmp_path).findings
    assert finding.check_id == SENSITIVE_FILE
    assert finding.severity is Severity.HIGH


def test_keystore_sem_git_nao_e_relatado(tmp_path: Path) -> None:
    out = scan(tmp_path, {"app/release.jks": b"\xfe\xed\xfe\xed" + b"\x00" * 32})
    assert out.findings == []


def test_segredo_em_arquivo_ignorado_perde_um_nivel(tmp_path: Path) -> None:
    secret = joined("ghp", "_", rnd(36, seed="ign"))
    write_tree(tmp_path, {"local.sh": f"x={secret}\n", "src/b.sh": f"x={secret}\n"})
    init_fake_git(tmp_path, tracked=["src/b.sh"], gitignore="local.sh\n")
    by_asset = {f.asset.split(":")[0]: f for f in scan(tmp_path).findings}
    assert by_asset["src/b.sh"].severity is Severity.HIGH
    assert by_asset["local.sh"].severity is Severity.MEDIUM


def test_varios_segredos_na_mesma_linha_sao_mascarados(tmp_path: Path) -> None:
    a = joined("ghp", "_", rnd(36, seed="a"))
    b = joined("npm", "_", rnd(36, seed="b"))
    out = scan(tmp_path, {"x.sh": f"A={a} B={b}\n"})
    assert len(out.findings) == 2
    for finding in out.findings:
        assert a not in finding.evidence
        assert b not in finding.evidence


def test_limite_de_tamanho_do_arquivo(tmp_path: Path) -> None:
    secret = joined("ghp", "_", rnd(36, seed="big"))
    out = scan(tmp_path, {"big.sh": f"x={secret}\n" + "#" * 5000}, max_file_bytes=1000)
    assert out.findings == []


def test_constantes_dos_achados_sao_distintas() -> None:
    assert len(set(SECRET_FINDINGS)) == len(SECRET_FINDINGS) == 8
    assert {CLOUD, JWT, GENERIC, CONNECTION} < set(SECRET_FINDINGS)


# -- regressões da revisão ----------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        'DB_PASSWORD = "{v}"',
        "API_KEY={v}",
        'dbPassword = "{v}"',
        '"clientSecret": "{v}"',
        "POSTGRES_PASSWORD: {v}",
        'const apiKey = "{v}"',
        "export GITHUB_TOKEN={v}",
    ],
)
def test_nomes_em_maiusculas_e_camel_case_sao_detectados(line: str) -> None:
    text = line.format(v=rnd(24, seed="case")) + "\n"
    assert "atribuicao" in "".join(rule_ids(text, "settings.env"))


@pytest.mark.parametrize("name", ["MAX_TOKENS", "PASSWORD_MIN_LENGTH", "TOKEN_URL"])
def test_nomes_que_nao_sao_segredo_continuam_ignorados(name: str) -> None:
    assert rule_ids(f'{name} = "{rnd(24, seed="neg")}"\n', "settings.py") == set()


def test_django_secret_key_so_e_ignorada_com_django_no_texto() -> None:
    value = rnd(50, seed="dj2")
    assert rule_ids(f'SECRET_KEY = "{value}"\n', "settings.py") != set()
    assert rule_ids(f'import django\nSECRET_KEY = "{value}"\n', "settings.py") == set()


def test_arquivo_de_configuracao_com_crlf_e_comentario_no_fim() -> None:
    value = rnd(24, seed="crlf")
    crlf = f"db.host=x\r\ndb.password={value}\r\napi_key={value}\r\n"
    assert len(secret_scan.scan_text(crlf, "app.properties")) == 2
    assert rule_ids(f"db.password={value} # prod\n", "app.properties")


def test_valores_que_sao_mime_uuid_ou_chamada_nao_sao_segredo() -> None:
    for value in (
        "application/x-www-form-urlencoded",
        "550e8400-e29b-41d4-a716-446655440000",
        "Password-Is-Required-1",
        "tokenizer.encode(abcdefgh)",
    ):
        assert rule_ids(f'secret = "{value}"\n', "a.py") == set(), value


def test_chave_de_exemplo_da_documentacao_da_stripe_e_ignorada() -> None:
    assert rule_ids("key = sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc\n", "a.py") == set()


@pytest.mark.parametrize(
    "url",
    [
        "redis://:{v}@[::1]:6379",
        "ftp://anonymous:anonymous@ftp.x.org/",
        "amqp://guest:guest@rabbitmq/",
        "postgres://postgres:postgres@db:5432/app",
    ],
)
def test_url_com_ipv6_local_ou_credencial_padrao(url: str) -> None:
    text = f'u = "{url.format(v=rnd(16, seed="v6"))}"'
    hits = secret_scan.scan_text(text, "a.py")
    assert all(h.severity is Severity.LOW for h in hits)  # IPv6 local: baixo; padrão: nenhum


def test_muitos_achados_no_mesmo_arquivo_nao_explodem() -> None:
    import time

    text = "\n".join(f"AKIA{rnd(16, BASE32_UP, seed=str(i))}" for i in range(6000))
    start = time.monotonic()
    hits = secret_scan.scan_text(text, "dump.txt")
    assert time.monotonic() - start < 10
    assert 0 < len(hits) <= secret_scan.MAX_HITS_PER_RULE


def test_chave_privada_nao_e_cortada_pelo_limite_de_ocorrencias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(secret_scan, "MAX_TOTAL", 5)
    keys = "\n".join(f"AKIA{rnd(16, BASE32_UP, seed=str(i))}" for i in range(60))
    pem = "-----BEGIN RSA PRIVATE KEY-----\n" + rnd(120, BASE64ISH, seed="pem") + "\n"
    out = scan(
        tmp_path, {"aaa/keys.txt": keys, "zzz/prod.pem": pem + "-----END RSA PRIVATE KEY-----\n"}
    )
    assert any(f.check_id == PRIVATE_KEY for f in out.findings)


def test_env_com_flags_e_numeros_nao_e_segredo() -> None:
    text = (
        "AUTH_ENABLED=true\nBYPASS_CACHE=1\nTOKEN_EXPIRY=3600\nPASSWORD_MIN_LENGTH=8\nAUTHOR=John\n"
    )
    assert secret_scan.env_secret_names(text)[1] == []
    real = f"DB_PASSWORD={rnd(20, seed='envp')}\n"
    assert secret_scan.env_secret_names(real)[1] == ["DB_PASSWORD"]


def test_gitignore_com_bom_ainda_ignora_o_env(tmp_path: Path) -> None:
    init_fake_git(tmp_path, tracked=["src/a.py"], gitignore=".env\n")
    (tmp_path / ".gitignore").write_bytes(b"\xef\xbb\xbf.env\n")
    out = scan(tmp_path, {".env": f"DB_PASSWORD={rnd(20, seed='bom')}\n", "src/a.py": "x = 1\n"})
    assert not [f for f in out.findings if f.check_id == ENV_FILE]
