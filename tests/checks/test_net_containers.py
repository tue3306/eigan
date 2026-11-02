"""Docker, Kubernetes (API e kubelet) e etcd (``net.containers``)."""

from __future__ import annotations

import json
from typing import Any

import pytest
from fakes_net import fake_tcp, fast_settings, http_response, http_routes, service_fact
from helpers import CheckOutcome, run_check

from eigan.checks.net import common, containers
from eigan.core.models import Confidence, Exposure, Fact, Severity
from eigan.core.registry import get_check


def run_it(fact: Fact) -> CheckOutcome:
    return run_check("net.containers", fact, settings=fast_settings())


def at(monkeypatch: pytest.MonkeyPatch, exposure: Exposure) -> None:
    monkeypatch.setattr(common, "exposure_of", lambda _host: exposure)


def _json(body: Any, status: int = 200) -> bytes:
    return http_response(status, json.dumps(body), (("Content-Type", "application/json"),))


def test_checagem_so_roda_nos_servicos_de_infraestrutura() -> None:
    item = get_check("net.containers")
    assert item is not None
    assert item.when is not None
    for name in ("docker", "kubernetes", "kubelet", "etcd"):
        assert item.when(service_fact(1, name))
    assert not item.when(service_fact(1, "http"))


# -- Docker --------------------------------------------------------------------------------------


DOCKER_VERSION = {"Version": "24.0.7", "ApiVersion": "1.43", "Os": "linux", "Arch": "amd64"}


@pytest.mark.parametrize(
    ("exposure", "severity"),
    [
        (Exposure.INTERNET, Severity.CRITICAL),
        (Exposure.INTERNAL, Severity.CRITICAL),
        (Exposure.LOCAL, Severity.HIGH),
    ],
)
def test_docker_sem_autenticacao(
    monkeypatch: pytest.MonkeyPatch, exposure: Exposure, severity: Severity
) -> None:
    at(monkeypatch, exposure)
    with fake_tcp(http_routes({"/version": _json(DOCKER_VERSION)})) as server:
        out = run_it(service_fact(server.port, "docker", product="docker"))
    [finding] = out.by_id("net.docker.api_exposta")
    assert finding.severity is severity
    assert finding.confidence is Confidence.CONFIRMED
    assert "sem TLS" in finding.evidence
    assert "Docker 24.0.7" in finding.evidence
    assert finding.details == {"versao": "24.0.7", "api": "1.43"}
    assert finding.title == "API do Docker exposta sem TLS"


def test_docker_com_tls_sem_certificado_de_cliente(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNAL)
    with fake_tcp(http_routes({"/version": _json(DOCKER_VERSION)}), tls=True) as server:
        out = run_it(service_fact(server.port, "docker", tls=True))
    [finding] = out.by_id("net.docker.api_exposta")
    assert "certificado de cliente" in finding.title
    assert "com TLS, mas sem exigir certificado de cliente" in finding.evidence


@pytest.mark.parametrize(
    "reply",
    [
        _json({"message": "Unauthorized"}, 401),
        _json({"message": "page not found"}, 404),
        http_response(200, "<html>Docker é legal</html>"),
        _json({"Version": "1.0"}),  # JSON de outra coisa, sem ApiVersion
        _json(["lista"]),
    ],
)
def test_docker_sem_prova_nao_vira_achado(monkeypatch: pytest.MonkeyPatch, reply: bytes) -> None:
    at(monkeypatch, Exposure.INTERNET)
    with fake_tcp(http_routes({"/version": reply})) as server:
        out = run_it(service_fact(server.port, "docker", confirmed=False))
    assert not out.findings
    assert any("não respondeu /version" in line for line in out.logs)


# -- Kubernetes ----------------------------------------------------------------------------------


NAMESPACES = {
    "kind": "NamespaceList",
    "apiVersion": "v1",
    "items": [{"metadata": {"name": "default"}}],
}
FORBIDDEN = {"kind": "Status", "apiVersion": "v1", "status": "Failure", "code": 403}


@pytest.mark.parametrize(
    ("exposure", "severity"),
    [
        (Exposure.INTERNET, Severity.CRITICAL),
        (Exposure.INTERNAL, Severity.CRITICAL),
        (Exposure.LOCAL, Severity.HIGH),
    ],
)
def test_kubernetes_anonimo(
    monkeypatch: pytest.MonkeyPatch, exposure: Exposure, severity: Severity
) -> None:
    at(monkeypatch, exposure)
    with fake_tcp(http_routes({"/api/v1/namespaces": _json(NAMESPACES)})) as server:
        out = run_it(
            service_fact(server.port, "kubernetes", product="kubernetes", version="1.28.3")
        )
    [finding] = out.by_id("net.kubernetes.anonimo")
    assert finding.severity is severity
    assert "Kubernetes 1.28.3" in finding.evidence
    assert "net.kubernetes.api_exposta" not in out.ids()
    assert any(b"limit=1" in data for data in server.received)


def test_kubernetes_protegido_na_internet(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNET)
    with fake_tcp(http_routes({"/api/v1/namespaces": _json(FORBIDDEN, 403)})) as server:
        out = run_it(service_fact(server.port, "kubernetes", version="1.28.3"))
    assert "net.kubernetes.anonimo" not in out.ids()
    assert any(p.control == "net.kubernetes.anonimo" for p in out.passed)
    [finding] = out.by_id("net.kubernetes.api_exposta")
    assert "1.28.3" in finding.evidence


@pytest.mark.parametrize("exposure", [Exposure.INTERNAL, Exposure.LOCAL])
def test_kubernetes_protegido_fora_da_internet(
    monkeypatch: pytest.MonkeyPatch, exposure: Exposure
) -> None:
    at(monkeypatch, exposure)
    with fake_tcp(http_routes({"/api/v1/namespaces": _json(FORBIDDEN, 403)})) as server:
        out = run_it(service_fact(server.port, "kubernetes"))
    assert not out.findings
    assert any(p.control == "net.kubernetes.anonimo" for p in out.passed)


def test_kubernetes_soft_404_nao_e_anonimo(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNAL)
    with fake_tcp(http_routes({}, default=http_response(200, "<html>items</html>"))) as server:
        out = run_it(service_fact(server.port, "kubernetes"))
    assert not out.findings
    assert not out.passed


# -- kubelet -------------------------------------------------------------------------------------


PODS = {
    "kind": "PodList",
    "items": [
        {"metadata": {"namespace": "kube-system", "name": "coredns-1"}},
        {"metadata": {"namespace": "prod", "name": "api-2"}},
        {"sem": "metadata"},
    ],
}


def test_kubelet_anonimo_porta_de_escrita(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNAL)
    with fake_tcp(http_routes({"/pods": _json(PODS)}), tls=True) as server:
        out = run_it(service_fact(server.port, "kubelet", tls=True))
    [finding] = out.by_id("net.kubelet.anonimo")
    assert finding.severity is Severity.CRITICAL
    assert "3 pod(s)" in finding.evidence
    assert "kube-system/coredns-1" in finding.evidence
    assert finding.details["pods"][:2] == ["kube-system/coredns-1", "prod/api-2"]


def test_kubelet_somente_leitura_e_alta(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNET)
    with fake_tcp(http_routes({"/pods": _json(PODS)})) as server:
        out = run_it(service_fact(server.port, "kubelet"))
    [finding] = out.by_id("net.kubelet.anonimo")
    assert finding.severity is Severity.HIGH
    assert "somente leitura" in finding.evidence


@pytest.mark.parametrize("status", [401, 403])
def test_kubelet_protegido(monkeypatch: pytest.MonkeyPatch, status: int) -> None:
    at(monkeypatch, Exposure.INTERNAL)
    with fake_tcp(http_routes({"/pods": http_response(status, "Unauthorized")})) as server:
        out = run_it(service_fact(server.port, "kubelet"))
    assert not out.findings
    assert any(p.control == "net.kubelet.anonimo" for p in out.passed)


def test_kubelet_resposta_estranha_nao_vira_achado(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNAL)
    with fake_tcp(http_routes({"/pods": _json({"ok": True})})) as server:
        out = run_it(service_fact(server.port, "kubelet"))
    assert not out.findings
    assert not out.passed


# -- etcd ----------------------------------------------------------------------------------------


COUNT = {"header": {"cluster_id": "1", "revision": "9"}, "count": "128"}


@pytest.mark.parametrize(
    ("exposure", "severity"),
    [
        (Exposure.INTERNET, Severity.CRITICAL),
        (Exposure.INTERNAL, Severity.CRITICAL),
        (Exposure.LOCAL, Severity.HIGH),
    ],
)
def test_etcd_sem_autenticacao(
    monkeypatch: pytest.MonkeyPatch, exposure: Exposure, severity: Severity
) -> None:
    at(monkeypatch, exposure)
    with fake_tcp(http_routes({"/v3/kv/range": _json(COUNT)})) as server:
        out = run_it(service_fact(server.port, "etcd", product="etcd", version="3.5.9"))
    [finding] = out.by_id("net.etcd.sem_senha")
    assert finding.severity is severity
    assert "128 chave(s) no etcd 3.5.9" in finding.evidence
    assert finding.details == {"chaves": "128"}
    request = b"".join(server.received)
    assert b"POST /v3/kv/range" in request
    assert b'"count_only": true' in request  # nunca lê os valores


def test_etcd_sem_chaves_omite_a_contagem(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNAL)
    with fake_tcp(http_routes({"/v3/kv/range": _json({"header": {"revision": "1"}})})) as server:
        out = run_it(service_fact(server.port, "etcd"))
    [finding] = out.by_id("net.etcd.sem_senha")
    assert finding.details == {"chaves": "0"}


def test_etcd_versoes_antigas_da_rota(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNAL)
    with fake_tcp(http_routes({"/v3alpha/kv/range": _json(COUNT)})) as server:
        out = run_it(service_fact(server.port, "etcd"))
    assert "v3alpha/kv/range" in out.by_id("net.etcd.sem_senha")[0].evidence


@pytest.mark.parametrize(
    "reply",
    [
        _json({"error": "etcdserver: user name is empty", "code": 3}, 400),
        _json({"error": "etcdserver: invalid auth token", "code": 16}, 401),
        _json({"message": "etcdserver: permission denied"}, 403),
    ],
)
def test_etcd_com_autenticacao(monkeypatch: pytest.MonkeyPatch, reply: bytes) -> None:
    at(monkeypatch, Exposure.INTERNET)
    with fake_tcp(http_routes({"/v3/kv/range": reply})) as server:
        out = run_it(service_fact(server.port, "etcd"))
    assert not out.findings
    assert any(p.control == "net.etcd.sem_senha" for p in out.passed)


def test_etcd_sem_rota_v3_nao_avalia(monkeypatch: pytest.MonkeyPatch) -> None:
    at(monkeypatch, Exposure.INTERNET)
    with fake_tcp(http_routes({})) as server:
        out = run_it(service_fact(server.port, "etcd"))
    assert not out.findings
    assert not out.passed
    assert any("não foi avaliada" in line for line in out.logs)


@pytest.mark.parametrize(
    "reply",
    [
        http_response(200, "<html>qualquer coisa</html>"),
        _json({"header": {"revision": "1"}, "error": "outro erro"}),
        _json({"sem": "header"}),
        http_response(500, "erro interno"),
    ],
)
def test_etcd_inconclusivo_nao_vira_achado(monkeypatch: pytest.MonkeyPatch, reply: bytes) -> None:
    at(monkeypatch, Exposure.INTERNET)
    with fake_tcp(http_routes({"/v3/kv/range": reply})) as server:
        out = run_it(service_fact(server.port, "etcd"))
    assert not out.findings
    assert not out.passed
    assert any("inconclusiva" in line for line in out.logs)


def test_consulta_do_etcd_pede_todas_as_chaves_so_na_contagem() -> None:
    assert containers.ETCD_COUNT == {"key": "AA==", "range_end": "AA==", "count_only": True}
