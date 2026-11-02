"""IaC: Dockerfile (usuário root, imagem sem versão, ADD remoto, curl|sh, segredos, sudo)."""

from __future__ import annotations

from pathlib import Path

import pytest
from fakes_code_iac import ids, lines_of, of, scan

from eigan.checks.code.iac_common import (
    ADD_REMOTE,
    CURL_SH,
    ROOT,
    SECRET,
    SUDO,
    UNPINNED,
)

GOOD = (
    "FROM python:3.12-slim\n"
    "RUN useradd -r app\n"
    "COPY . /app\n"
    "USER app\n"
    'CMD ["python", "/app/main.py"]\n'
)


def docker(tmp_path: Path, text: str, name: str = "Dockerfile"):
    return scan(tmp_path, {name: text})


def test_dockerfile_bom_nao_gera_achados(tmp_path: Path) -> None:
    out = docker(tmp_path, GOOD)
    assert ids(out) == set()


def test_sem_user_e_container_root(tmp_path: Path) -> None:
    out = docker(tmp_path, "FROM python:3.12-slim\nCOPY . /app\n")
    assert of(out, ROOT)
    assert of(out, ROOT)[0].asset == "Dockerfile"


def test_user_root_explicito(tmp_path: Path) -> None:
    out = docker(tmp_path, "FROM python:3.12-slim\nUSER root\n")
    found = of(out, ROOT)
    assert found
    assert lines_of(out, ROOT) == [2]


def test_user_final_nao_root_encerra_o_problema(tmp_path: Path) -> None:
    out = docker(tmp_path, "FROM python:3.12-slim\nUSER root\nRUN id\nUSER 1000\n")
    assert not of(out, ROOT)


@pytest.mark.parametrize("image", ["ubuntu:latest", "ubuntu", "node:latest"])
def test_imagem_sem_versao_fixa(tmp_path: Path, image: str) -> None:
    out = docker(tmp_path, f"FROM {image}\nUSER app\n")
    assert of(out, UNPINNED)


@pytest.mark.parametrize(
    "image",
    ["ubuntu:22.04", "python:3.12-slim", "alpine@sha256:" + "a" * 64, "scratch"],
)
def test_imagem_com_versao_ou_digest_e_aceita(tmp_path: Path, image: str) -> None:
    out = docker(tmp_path, f"FROM {image}\nUSER app\n")
    assert not of(out, UNPINNED)


def test_from_de_estagio_anterior_nao_e_imagem_solta(tmp_path: Path) -> None:
    text = "FROM golang:1.22 AS build\nRUN go build\nFROM build AS final\nUSER app\n"
    out = docker(tmp_path, text)
    assert not of(out, UNPINNED)


def test_add_com_url_remota(tmp_path: Path) -> None:
    out = docker(tmp_path, "FROM alpine:3.20\nADD https://exemplo.test/app.tar.gz /opt/\nUSER a\n")
    assert of(out, ADD_REMOTE)


def test_add_local_e_copy_nao_alertam(tmp_path: Path) -> None:
    out = docker(tmp_path, "FROM alpine:3.20\nADD app.tar.gz /opt/\nCOPY a /b\nUSER a\n")
    assert not of(out, ADD_REMOTE)


@pytest.mark.parametrize(
    "run",
    [
        "curl -fsSL https://exemplo.test/install.sh | sh",
        "wget -qO- https://exemplo.test/install.sh | bash",
        "curl -sSL https://exemplo.test/i.sh | sudo bash",
    ],
)
def test_curl_pipe_shell(tmp_path: Path, run: str) -> None:
    out = docker(tmp_path, f"FROM alpine:3.20\nRUN {run}\nUSER a\n")
    assert of(out, CURL_SH)


def test_curl_para_arquivo_nao_e_pipe_para_shell(tmp_path: Path) -> None:
    out = docker(
        tmp_path,
        "FROM alpine:3.20\nRUN curl -fsSLo /tmp/x.tgz https://exemplo.test/x.tgz\nUSER a\n",
    )
    assert not of(out, CURL_SH)


def test_segredo_em_env_e_mascarado(tmp_path: Path) -> None:
    valor = "Zq9" + "Xk2mP7vLw4"
    out = docker(tmp_path, f"FROM alpine:3.20\nENV DB_PASSWORD={valor}\nUSER a\n")
    found = of(out, SECRET)
    assert found
    texto = repr([f.evidence for f in found]) + repr([f.details for f in found])
    assert valor not in texto


def test_segredo_em_arg(tmp_path: Path) -> None:
    out = docker(tmp_path, "FROM alpine:3.20\nARG API_TOKEN=abcDEF123456xyz\nUSER a\n")
    assert of(out, SECRET)


@pytest.mark.parametrize(
    "linha",
    [
        "ENV APP_ENV=production",
        "ENV PASSWORD_MIN_LENGTH=12",
    ],
)
def test_env_sem_segredo_literal_nao_alerta(tmp_path: Path, linha: str) -> None:
    out = docker(tmp_path, f"FROM alpine:3.20\n{linha}\nUSER a\n")
    assert not of(out, SECRET)


def test_sudo_no_run(tmp_path: Path) -> None:
    out = docker(tmp_path, "FROM alpine:3.20\nRUN sudo apk add curl\nUSER a\n")
    assert of(out, SUDO)


def test_palavra_sudoers_nao_e_sudo(tmp_path: Path) -> None:
    out = docker(tmp_path, "FROM alpine:3.20\nRUN echo pseudo > /tmp/sudoku\nUSER a\n")
    assert not of(out, SUDO)


def test_continuacao_de_linha_aponta_linha_inicial(tmp_path: Path) -> None:
    text = (
        "FROM alpine:3.20\nRUN apk add curl && \\n    curl -sSL https://e.test/i.sh | sh\nUSER a\n"
    )
    out = docker(tmp_path, text)
    assert lines_of(out, CURL_SH) == [2]


def test_arquivo_chamado_dockerfile_mas_sem_from_e_ignorado(tmp_path: Path) -> None:
    out = docker(tmp_path, "isto nao e um dockerfile\nUSER root\n")
    assert not out.findings


def test_nome_alternativo_dockerfile_dev(tmp_path: Path) -> None:
    out = docker(tmp_path, "FROM ubuntu:latest\n", name="api/Dockerfile.dev")
    assert of(out, UNPINNED)
    assert of(out, UNPINNED)[0].asset == "api/Dockerfile.dev"


def test_achados_trazem_correcao_colavel(tmp_path: Path) -> None:
    out = docker(tmp_path, "FROM ubuntu:latest\nRUN sudo ls\n")
    for f in out.findings:
        assert f.details["correcao"].strip()
        assert f.details["tipo"] == "Dockerfile"


def test_pasta_de_teste_reduz_severidade(tmp_path: Path) -> None:
    out = docker(tmp_path, "FROM alpine:3.20\nENV DB_PASSWORD=abcDEF123456xyz\nUSER a\n")
    normal = of(out, SECRET)[0].severity
    out2 = scan(
        tmp_path / "p2",
        {"tests/Dockerfile": "FROM alpine:3.20\nENV DB_PASSWORD=abcDEF123456xyz\nUSER a\n"},
    )
    assert of(out2, SECRET)[0].severity.rank < normal.rank


def test_ponto_forte_quando_tudo_esta_correto(tmp_path: Path) -> None:
    out = docker(tmp_path, GOOD)
    assert out.passed


@pytest.mark.parametrize("linha", ["ARG TOKEN", "ENV DB_PASSWORD=${DB_PASSWORD}"])
def test_segredo_por_referencia_tem_severidade_menor_que_literal(
    tmp_path: Path, linha: str
) -> None:
    """Sem valor literal o segredo ainda vai para o histórico da imagem, mas com menos gravidade."""
    out = docker(tmp_path, f"FROM alpine:3.20\n{linha}\nUSER a\n")
    literal = scan(
        tmp_path / "lit",
        {"Dockerfile": "FROM alpine:3.20\nENV DB_PASSWORD=abcDEF123456xyz\nUSER a\n"},
    )
    top = of(literal, SECRET)[0].severity.rank
    assert all(f.severity.rank < top for f in of(out, SECRET))


# -- regressões da revisão ----------------------------------------------------------------------


def _dump(findings) -> str:
    return " | ".join(repr(f) for f in findings)


@pytest.mark.parametrize(
    "linha",
    [
        "ENV TOKEN_EXPIRY_SECONDS=3600",
        "ENV PASSWORD_RESET_DAYS=7",
        "ENV SECRET_ROTATION_INTERVAL=30d",
        "ENV TOKEN_BUCKET_RATE=10",
        "ENV SECRET_STORE=vault",
        "ENV SECRET_BACKEND=aws",
        "ENV PASSWORD_HASHERS=argon2",
        "ENV PASSWORD_AUTH=disabled",
        "ENV PASSWORD_SOURCE=env",
        "ENV TOKEN_EXPIRES_IN=3600",
    ],
)
def test_configuracao_com_nome_de_segredo_nao_alerta(tmp_path: Path, linha: str) -> None:
    out = docker(tmp_path, f"FROM x:1\n{linha}\nUSER 1000\n")
    assert SECRET not in ids(out)


def test_segredo_real_continua_alertando(tmp_path: Path) -> None:
    out = docker(tmp_path, "FROM x:1\nENV DB_PASSWORD=Xk9fLq2mVz81\nUSER 1000\n")
    assert SECRET in ids(out)


@pytest.mark.parametrize(
    "comando",
    [
        "curl -s http://localhost:8080/health | python3 -m json.tool",
        'curl -s https://api.example.com/v | node -e "console.log(1)"',
        "curl -s https://api.example.com/v | python3 -c 'import sys'",
        "curl -fsSL https://example.com/a.tar.gz | tar xz",
    ],
)
def test_pipe_para_interpretador_que_nao_executa_o_download(tmp_path: Path, comando: str) -> None:
    out = docker(tmp_path, f"FROM python:3.12\nRUN {comando}\nUSER app\n")
    assert CURL_SH not in ids(out)


def test_curl_pipe_sh_loopback_nao_vira_alta(tmp_path: Path) -> None:
    out = docker(tmp_path, "FROM x:1\nRUN curl -s http://localhost/i.sh | sh\nUSER app\n")
    assert of(out, CURL_SH)[0].severity.value != "high"


def test_curl_pipe_python_sem_argumento_alerta(tmp_path: Path) -> None:
    out = docker(tmp_path, "FROM x:1\nRUN curl -s https://example.com/i.py | python3 -\nUSER app\n")
    assert CURL_SH in ids(out)


def test_regex_do_curl_nao_e_quadratica(tmp_path: Path) -> None:
    import time

    inicio = time.monotonic()
    docker(tmp_path, "FROM x:1\nRUN " + "curl " * 20000 + "\nUSER app\n")
    assert time.monotonic() - inicio < 5


def test_credenciais_de_url_e_flags_nao_vazam(tmp_path: Path) -> None:
    texto = (
        "FROM x:1\n"
        "ADD https://user:Tok3nSecret99@example.com/a.tgz /opt/\n"
        "RUN curl -H 'Authorization: Bearer abcdef0123456789abcdef' "
        "https://user:pw12345678@x.test/i.sh | sh\n"
        "RUN sudo mysql -u root -pSuperSecretPassw0rd -e 'select 1'\n"
        "USER app\n"
    )
    out = docker(tmp_path, texto)
    despejo = _dump(out.findings)
    for segredo in ("Tok3nSecret99", "pw12345678", "SuperSecretPassw0rd", "abcdef0123456789abcdef"):
        assert segredo not in despejo
    assert ADD_REMOTE in ids(out)
    assert CURL_SH in ids(out)
    assert SUDO in ids(out)


def test_senha_na_url_de_variavel_comum_alerta_mascarada(tmp_path: Path) -> None:
    out = docker(
        tmp_path, "FROM x:1\nENV DATABASE_URL=postgres://postgres:postgres@db/x\nUSER app\n"
    )
    assert SECRET in ids(out)
    assert "postgres://postgres:***@db/x" in _dump(of(out, SECRET))


@pytest.mark.parametrize(
    "primeira",
    ["ARG A=1 B=2", 'ARG V="1.0 beta"', "ARG A=1 \\n    B=2"],
)
def test_dockerfile_com_arg_complexo_no_inicio_e_analisado(tmp_path: Path, primeira: str) -> None:
    out = docker(tmp_path, f"{primeira}\nFROM x:latest\n")
    assert UNPINNED in ids(out)
