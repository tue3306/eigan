"""IaC: docker-compose (privileged, host, docker.sock, portas de banco, senhas em texto)."""

from __future__ import annotations

from pathlib import Path

import pytest
from fakes_code_iac import ids, lines_of, of, scan

from eigan.checks.code.iac_common import (
    DB_PORT,
    DOCKER_SOCK,
    HOST_NS,
    PRIVILEGED,
    SECRET,
)

GOOD = """services:
  web:
    image: nginx:1.27
    ports:
      - "8080:80"
  db:
    image: postgres:16
    ports:
      - "127.0.0.1:5432:5432"
    environment:
      POSTGRES_PASSWORD: ${DB_PASSWORD}
"""


def compose(tmp_path: Path, text: str, name: str = "docker-compose.yml"):
    return scan(tmp_path, {name: text})


def svc(body: str, image: str = "nginx:1.27") -> str:
    return f"services:\n  app:\n    image: {image}\n{body}"


def test_compose_correto_nao_gera_achados(tmp_path: Path) -> None:
    out = compose(tmp_path, GOOD)
    assert ids(out) == set()
    assert out.passed


def test_privileged_true(tmp_path: Path) -> None:
    out = compose(tmp_path, svc("    privileged: true\n"))
    assert lines_of(out, PRIVILEGED) == [4]
    assert of(out, PRIVILEGED)[0].asset == "docker-compose.yml"


def test_privileged_false_e_aceito(tmp_path: Path) -> None:
    out = compose(tmp_path, svc("    privileged: false\n"))
    assert not of(out, PRIVILEGED)


@pytest.mark.parametrize("campo", ["network_mode: host", "pid: host", "ipc: host"])
def test_namespace_do_host(tmp_path: Path, campo: str) -> None:
    out = compose(tmp_path, svc(f"    {campo}\n"))
    assert of(out, HOST_NS)


@pytest.mark.parametrize("campo", ["network_mode: bridge", "pid: service:web"])
def test_namespace_nao_host_nao_alerta(tmp_path: Path, campo: str) -> None:
    out = compose(tmp_path, svc(f"    {campo}\n"))
    assert not of(out, HOST_NS)


@pytest.mark.parametrize(
    "volume",
    ["/var/run/docker.sock:/var/run/docker.sock", "/run/docker.sock:/var/run/docker.sock:ro"],
)
def test_docker_sock_montado(tmp_path: Path, volume: str) -> None:
    out = compose(tmp_path, svc(f"    volumes:\n      - {volume}\n"))
    assert of(out, DOCKER_SOCK)


def test_volume_comum_nao_e_docker_sock(tmp_path: Path) -> None:
    out = compose(tmp_path, svc("    volumes:\n      - ./dados:/data\n      - cache:/cache\n"))
    assert not of(out, DOCKER_SOCK)


@pytest.mark.parametrize(
    "porta",
    ['"5432:5432"', "5432:5432", '"0.0.0.0:3306:3306"', '"6379:6379"', '"27017:27017"'],
)
def test_porta_de_banco_em_todas_as_interfaces(tmp_path: Path, porta: str) -> None:
    out = compose(tmp_path, svc(f"    ports:\n      - {porta}\n", image="postgres:16"))
    assert of(out, DB_PORT)


@pytest.mark.parametrize(
    "porta", ['"127.0.0.1:5432:5432"', '"[::1]:3306:3306"', '"8080:80"', '"443:443"']
)
def test_porta_de_banco_local_ou_web_nao_alerta(tmp_path: Path, porta: str) -> None:
    out = compose(tmp_path, svc(f"    ports:\n      - {porta}\n"))
    assert not of(out, DB_PORT)


def test_senha_em_texto_no_environment_e_mascarada(tmp_path: Path) -> None:
    valor = "Qx7" + "mN4pLz9Wk"
    body = f"    environment:\n      POSTGRES_PASSWORD: {valor}\n"
    out = compose(tmp_path, svc(body, image="postgres:16"))
    found = of(out, SECRET)
    assert found
    assert valor not in repr([(f.evidence, f.details, f.title) for f in found])


def test_senha_em_lista_de_environment(tmp_path: Path) -> None:
    body = "    environment:\n      - MYSQL_ROOT_PASSWORD=abcDEF123456xyz\n"
    out = compose(tmp_path, svc(body, image="mysql:8"))
    assert of(out, SECRET)


@pytest.mark.parametrize(
    "linha",
    [
        "POSTGRES_PASSWORD: ${DB_PASSWORD}",
        "POSTGRES_PASSWORD_FILE: /run/secrets/db",
        "PASSWORD_MIN_LENGTH: 12",
        "APP_ENV: production",
    ],
)
def test_senha_por_referencia_ou_arquivo_nao_alerta(tmp_path: Path, linha: str) -> None:
    out = compose(tmp_path, svc(f"    environment:\n      {linha}\n"))
    assert not of(out, SECRET)


def test_nomes_alternativos_de_compose(tmp_path: Path) -> None:
    out = compose(tmp_path, svc("    privileged: true\n"), name="deploy/compose.prod.yaml")
    assert of(out, PRIVILEGED)
    assert of(out, PRIVILEGED)[0].asset == "deploy/compose.prod.yaml"


def test_yaml_qualquer_sem_services_nao_e_compose(tmp_path: Path) -> None:
    out = compose(tmp_path, "privileged: true\nnetwork_mode: host\n", name="config.yml")
    assert not out.findings


def test_varios_servicos_geram_achados_separados(tmp_path: Path) -> None:
    text = (
        "services:\n  a:\n    image: x:1\n    privileged: true\n"
        "  b:\n    image: y:1\n    privileged: true\n"
    )
    out = compose(tmp_path, text)
    assert len(of(out, PRIVILEGED)) == 2
    assert lines_of(out, PRIVILEGED) == [4, 7]


def test_correcao_presente(tmp_path: Path) -> None:
    out = compose(tmp_path, svc("    privileged: true\n    network_mode: host\n"))
    assert out.findings
    for f in out.findings:
        assert f.details["correcao"].strip()
        assert f.details["tipo"] == "docker-compose"


# -- regressões da revisão ----------------------------------------------------------------------


def _compose(env: str = "", volumes: str = "") -> str:
    text = "services:\n  app:\n    image: app:1.0\n"
    if env:
        text += "    environment:\n" + "".join(f"      {line}\n" for line in env.splitlines())
    if volumes:
        text += "    volumes:\n" + "".join(f"      - {line}\n" for line in volumes.splitlines())
    return text


@pytest.mark.parametrize(
    "env",
    ["TOKEN_EXPIRY_SECONDS: 3600", "PASSWORD_RESET_DAYS: 7", "SECRET_BACKEND: vault"],
)
def test_configuracao_com_nome_de_segredo_nao_alerta(tmp_path: Path, env: str) -> None:
    out = scan(tmp_path, {"docker-compose.yml": _compose(env=env)})
    assert SECRET not in ids(out)


def test_valor_de_teste_nao_e_segredo(tmp_path: Path) -> None:
    out = scan(tmp_path, {"docker-compose.yml": _compose(env="J_SECRET: test")})
    assert SECRET not in ids(out)


@pytest.mark.parametrize(
    "volume",
    [
        "/etc/nginx/conf.d:/etc/nginx/conf.d:ro",
        "/etc/letsencrypt:/etc/letsencrypt:ro",
        "/usr/share/nginx/html:/usr/share/nginx/html:ro",
    ],
)
def test_montagem_de_configuracao_comum_nao_gera_hostpath(tmp_path: Path, volume: str) -> None:
    out = scan(tmp_path, {"docker-compose.yml": _compose(volumes=volume)})
    assert "code.iac.hostpath" not in ids(out)


def test_montagem_de_etc_inteiro_continua_alertando(tmp_path: Path) -> None:
    out = scan(tmp_path, {"docker-compose.yml": _compose(volumes="/etc:/host-etc")})
    assert "code.iac.hostpath" in ids(out)
