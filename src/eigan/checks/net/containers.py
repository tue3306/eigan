"""Docker, Kubernetes (API e kubelet) e etcd: APIs de infraestrutura sem autenticação.

Somente leituras que qualquer cliente faria para saber com quem está falando:
``GET /version`` (Docker), ``GET /api/v1/namespaces?limit=1`` (Kubernetes),
``GET /pods`` (kubelet) e uma contagem de chaves no etcd (``count_only``, sem ler
nenhum valor).
"""

from __future__ import annotations

import json
from typing import Any

from ...core import facts
from ...core.context import CheckContext
from ...core.facts import base_url
from ...core.http import Response
from ...core.models import Category, Confidence, Exposure, Fact, Severity
from ...core.registry import check
from . import (
    common,
    kb_containers,  # noqa: F401 — registra as entradas da base
)
from .banners import clean_text
from .common import host_port, io_timeout, service_asset, where

CONTAINER_SERVICES = frozenset({"docker", "kubernetes", "kubelet", "etcd"})
KUBELET_READONLY_PORT = 10255
#: intervalo "todas as chaves" (de \0 até o fim) pedindo só a contagem
ETCD_COUNT = {"key": "AA==", "range_end": "AA==", "count_only": True}
ETCD_PATHS = ("v3/kv/range", "v3beta/kv/range", "v3alpha/kv/range")
#: mensagens do etcd quando a autenticação está ligada (gateway gRPC/JSON)
ETCD_AUTH_ERRORS = (
    "user name is empty",
    "permission denied",
    "invalid auth token",
    "authentication",
)


def _json(resp: Response | None) -> Any:
    if resp is None:
        return None
    try:
        return json.loads(resp.text)
    except ValueError:
        return None


def _base(fact: Fact, host: str, port: int) -> str:
    return base_url("https" if fact.data.get("tls") else "http", host, port)


@check(
    id="net.containers",
    name="Docker, Kubernetes e etcd",
    category=Category.NETWORK,
    consumes=facts.SERVICE,
    when=lambda fact: fact.data.get("service") in CONTAINER_SERVICES,
    description=(
        "Verifica se as APIs do Docker, do Kubernetes (API server e kubelet) e do etcd "
        "respondem sem autenticação."
    ),
    findings=(
        "net.docker.api_exposta",
        "net.kubernetes.anonimo",
        "net.kubernetes.api_exposta",
        "net.kubelet.anonimo",
        "net.etcd.sem_senha",
    ),
    order=30,
)
def check_containers(ctx: CheckContext, fact: Fact) -> None:
    host, port = host_port(fact)
    service = str(fact.data.get("service"))
    asset = service_asset(host, port)
    handler = {"docker": _docker, "kubernetes": _kubernetes, "kubelet": _kubelet, "etcd": _etcd}
    handler[service](ctx, fact, host, port, asset)


def _docker(ctx: CheckContext, fact: Fact, host: str, port: int, asset: str) -> None:
    resp = ctx.http.get(
        _base(fact, host, port) + "version", timeout=io_timeout(ctx), max_bytes=65536
    )
    data = _json(resp)
    if resp is None or resp.status != 200 or not isinstance(data, dict) or "ApiVersion" not in data:
        ctx.log(f"{asset}: a API do Docker não respondeu /version sem credenciais.")
        return
    with_tls = bool(fact.data.get("tls"))
    tls = "com TLS, mas sem exigir certificado de cliente" if with_tls else "sem TLS"
    ctx.report(
        "net.docker.api_exposta",
        asset=asset,
        title=(
            "API do Docker exposta sem autenticação (TLS sem certificado de cliente)"
            if with_tls
            else None
        ),
        severity=common.by_exposure(
            host, internet=Severity.CRITICAL, internal=Severity.CRITICAL, local=Severity.HIGH
        ),  # fmt: skip
        evidence=(
            f"GET /version respondido sem autenticação ({tls}, {where(host)}): Docker "
            f"{data.get('Version', '?')}, API {data.get('ApiVersion')}, "
            f"{data.get('Os', '?')}/{data.get('Arch', '?')}."
        ),
        details={"versao": data.get("Version"), "api": data.get("ApiVersion")},
        confidence=Confidence.CONFIRMED,
        tech=["docker", "linux"],
    )


def _kubernetes(ctx: CheckContext, fact: Fact, host: str, port: int, asset: str) -> None:
    base = _base(fact, host, port)
    resp = ctx.http.get(
        base + "api/v1/namespaces?limit=1", timeout=io_timeout(ctx), max_bytes=65536
    )
    data = _json(resp)
    version = str(fact.data.get("version") or "")
    if resp is not None and resp.status == 200 and isinstance(data, dict) and "items" in data:
        ctx.report(
            "net.kubernetes.anonimo",
            asset=asset,
            severity=common.by_exposure(
                host, internet=Severity.CRITICAL, internal=Severity.CRITICAL, local=Severity.HIGH
            ),  # fmt: skip
            evidence=(
                f"GET /api/v1/namespaces respondido para usuário anônimo ({where(host)}); "
                f"Kubernetes {version or 'versão não informada'}."
            ),
            confidence=Confidence.CONFIRMED,
            tech=["kubernetes"],
        )
        return
    if resp is not None and resp.status in (401, 403):
        ctx.passed("net.kubernetes.anonimo", "API do Kubernetes recusa leitura anônima", asset)
    if common.exposure_of(host) is Exposure.INTERNET:
        ctx.report(
            "net.kubernetes.api_exposta",
            asset=asset,
            evidence=(
                f"A API do Kubernetes responde na Internet ({base}); "
                f"versão revelada sem login: {version or 'não informada'}."
            ),
            confidence=Confidence.CONFIRMED,
            tech=["linux"],
        )


def _kubelet(ctx: CheckContext, fact: Fact, host: str, port: int, asset: str) -> None:
    resp = ctx.http.get(
        _base(fact, host, port) + "pods", timeout=io_timeout(ctx), max_bytes=2_000_000
    )
    data = _json(resp)
    if resp is None or resp.status != 200 or not isinstance(data, dict) or "items" not in data:
        if resp is not None and resp.status in (401, 403):
            ctx.passed("net.kubelet.anonimo", "Kubelet recusa requisições anônimas", asset)
        return
    pods = [_pod_name(item) for item in data.get("items") or [] if isinstance(item, dict)]
    readonly = port == KUBELET_READONLY_PORT or not fact.data.get("tls")
    high = Severity.HIGH if readonly else Severity.CRITICAL
    ctx.report(
        "net.kubelet.anonimo",
        asset=asset,
        severity=common.by_exposure(host, internet=high, internal=high, local=Severity.MEDIUM),
        evidence=(
            f"GET /pods respondido sem autenticação ({where(host)}"
            + ("; porta somente leitura" if readonly else "")
            + f"): {len(pods)} pod(s), ex.: {', '.join(pods[:5]) or 'nenhum'}."
        ),
        details={"pods": pods[:30]},
        confidence=Confidence.CONFIRMED,
        tech=["kubernetes"],
    )


def _etcd(ctx: CheckContext, fact: Fact, host: str, port: int, asset: str) -> None:
    base = _base(fact, host, port)
    body = json.dumps(ETCD_COUNT)
    for path in ETCD_PATHS:
        ctx.check_cancel()
        resp = ctx.http.post(base + path, body=body, headers={"Content-Type": "application/json"},
                             timeout=io_timeout(ctx), max_bytes=65536)  # fmt: skip
        if resp is None:
            ctx.log(f"{asset}: o etcd não respondeu à consulta de contagem de chaves.")
            return
        data = _json(resp)
        if resp.status == 404:
            continue
        if (
            resp.status == 200
            and isinstance(data, dict)
            and "header" in data
            and "error" not in data
        ):
            count = data.get("count", "0")
            ctx.report(
                "net.etcd.sem_senha",
                asset=asset,
                severity=common.by_exposure(
                    host,
                    internet=Severity.CRITICAL,
                    internal=Severity.CRITICAL,
                    local=Severity.HIGH,
                ),  # fmt: skip
                evidence=(
                    f"POST /{path} (somente contagem) respondido sem credenciais ({where(host)}): "
                    f"{count} chave(s) no etcd {fact.data.get('version') or ''}".rstrip()
                    + "."
                ),
                details={"chaves": count},
                confidence=Confidence.CONFIRMED,
                tech=["etcd"],
            )
            return
        if _etcd_denied(resp.status, data):
            ctx.passed("net.etcd.sem_senha", "etcd exige autenticação para ler chaves", asset)
        else:
            ctx.log(f"{asset}: resposta inconclusiva do etcd (HTTP {resp.status}).")
        return
    ctx.log(f"{asset}: o etcd não oferece a API v3 por HTTP; a autenticação não foi avaliada.")


def _pod_name(item: dict[str, Any]) -> str:
    meta = item.get("metadata")
    if not isinstance(meta, dict):
        return "?"
    return clean_text(f"{meta.get('namespace', '?')}/{meta.get('name', '?')}", 120)


def _etcd_denied(status: int, data: Any) -> bool:
    """401/403 ou erro de autenticação do etcd (o gateway JSON responde com ``error``)."""
    if status in (401, 403):
        return True
    message = str(data.get("error") or data.get("message") or "") if isinstance(data, dict) else ""
    return any(text in message.lower() for text in ETCD_AUTH_ERRORS)
