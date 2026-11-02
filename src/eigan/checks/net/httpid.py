"""Identificação de serviços HTTP: servidor web genérico ou API conhecida.

Muitos serviços de infraestrutura falam HTTP (Docker, Elasticsearch, etcd,
Kubernetes, CouchDB, InfluxDB, ClickHouse). Reconhecê-los pelo conteúdo — e
não só pela porta — evita falso positivo e permite as checagens específicas.
Também extrai tecnologias e versões dos cabeçalhos (``Server``,
``X-Powered-By``, ``X-Jenkins``...) para a checagem de versões vulneráveis.
"""

from __future__ import annotations

import json
import re
from typing import Any

from ...core.context import CheckContext
from ...core.facts import base_url
from ...core.http import Response
from .banners import Identified
from .common import io_timeout

GO_NOT_FOUND = "404 page not found"
ETCD_PORTS = frozenset({2379, 2380, 4001})
KUBELET_PORTS = frozenset({10250, 10255})

_TOKEN = re.compile(r"([A-Za-z][\w.\-]*)/(\d[\w.\-]*)")
_OPENSSL = re.compile(r"(\d+\.\d+\.\d+[a-z]{0,2})")
_NAMES = {
    "apache": "apache",
    "tomcat": "tomcat",
    "microsoft-iis": "iis",
    "nginx": "nginx",
    "openssl": "openssl",
    "php": "php",
    "lighttpd": "lighttpd",
    "openresty": "openresty",
    "litespeed": "litespeed",
    "jetty": "jetty",
    "gunicorn": "gunicorn",
    "werkzeug": "werkzeug",
    "python": "python",
    "caddy": "caddy",
    "couchdb": "couchdb",
    "docker": "docker",
    "tornadoserver": "tornado",
    "cherrypy": "cherrypy",
    "envoy": "envoy",
    "squid": "squid",
    "varnish": "varnish",
    "kestrel": "kestrel",
    "node.js": "nodejs",
    "express": "express",
    "asp.net": "aspnet",
}
_KINDS = {"php": "language", "python": "language", "nodejs": "language", "aspnet": "framework",
          "express": "framework", "openssl": "service"}  # fmt: skip


def _json(resp: Response) -> Any:
    try:
        return json.loads(resp.text)
    except ValueError:
        return None


def header_techs(resp: Response) -> list[dict[str, str]]:
    """Tecnologias (nome, versão, tipo, evidência) dos cabeçalhos da resposta."""
    found: dict[str, dict[str, str]] = {}

    def add(name: str, version: str, evidence: str) -> None:
        key = _NAMES.get(name.lower(), "")
        if not key or (key in found and found[key]["version"]):
            return
        if key == "openssl":
            match = _OPENSSL.match(version)
            version = match.group(1) if match else ""
        elif key == "docker":
            version = version.split(" ")[0]
        kind = _KINDS.get(key, "server")
        found[key] = {"name": key, "version": version, "kind": kind, "evidence": evidence}

    server = resp.header("server") or ""
    for name, version in _TOKEN.findall(server):
        add(name, version, f"Server: {server}")
    for word in ("Microsoft-IIS", "LiteSpeed", "Kestrel", "Caddy", "nginx", "Apache"):
        # "Apache-Coyote" e "Apache Tomcat" são o Tomcat, não o Apache httpd
        tomcat = word == "Apache" and "tomcat" in found
        if not tomcat and re.search(rf"(?<![\w-]){word}(?![\w-])", server, re.I):
            add(word, "", f"Server: {server}")
    if server.lower().startswith("apache-coyote"):
        found.setdefault("tomcat", {"name": "tomcat", "version": "", "kind": "server",
                                    "evidence": f"Server: {server}"})  # fmt: skip
    powered = resp.header("x-powered-by") or ""
    for name, version in _TOKEN.findall(powered):
        add(name, version, f"X-Powered-By: {powered}")
    for word in ("Express", "ASP.NET"):
        if word.lower() in powered.lower():
            add(word, "", f"X-Powered-By: {powered}")
    aspnet = resp.header("x-aspnet-version")
    if aspnet:
        add("ASP.NET", aspnet, f"X-AspNet-Version: {aspnet}")
    jenkins = resp.header("x-jenkins")
    if jenkins:
        found["jenkins"] = {"name": "jenkins", "version": jenkins.strip(), "kind": "service",
                            "evidence": f"X-Jenkins: {jenkins}"}  # fmt: skip
    return list(found.values())


def identify_http(ctx: CheckContext, host: str, port: int, scheme: str) -> Identified | None:
    """GET / e classificação. None se a porta não respondeu HTTP."""
    url = base_url(scheme, host, port)
    resp = ctx.http.get(url, timeout=io_timeout(ctx), max_bytes=65536)
    if resp is None:
        return None
    tls = scheme == "https"
    status = f"HTTP {resp.status}" + (
        f" — Server: {resp.header('server')}" if resp.header("server") else ""
    )
    ident = _api(ctx, url, resp, port) or Identified("https" if tls else "http")
    ident.tls = tls
    ident.banner = ident.banner or status
    ident.extra["techs"] = header_techs(resp)
    ident.extra["status"] = resp.status
    return ident


def _api(ctx: CheckContext, url: str, resp: Response, port: int) -> Identified | None:
    """Reconhece APIs de infraestrutura pela resposta (e por um GET extra quando preciso)."""
    data = _json(resp)
    server = (resp.header("server") or "").lower()
    if _looks_docker(resp, server):
        return _docker(ctx, url, resp)
    if _looks_elastic(resp, data):
        return _elastic(data, resp.status)
    if isinstance(data, dict) and data.get("couchdb") or server.startswith("couchdb/"):
        version = str(data.get("version", "")) if isinstance(data, dict) else ""
        return Identified("couchdb", "couchdb", version)
    if resp.header("x-influxdb-version"):
        return Identified("influxdb", "influxdb", (resp.header("x-influxdb-version") or "").strip())
    if resp.text == "Ok.\n" and (
        port == 8123 or any(k.lower().startswith("x-clickhouse") for k, _ in resp.headers)
    ):
        return Identified("clickhouse", "clickhouse")
    if isinstance(data, dict) and _looks_kubernetes(data):
        return _kubernetes(ctx, url)
    if resp.text.strip() == GO_NOT_FOUND:
        if port in KUBELET_PORTS:
            return Identified("kubelet", "kubernetes")
        etcd = _etcd(ctx, url)
        if etcd is not None:
            return etcd
    elif port in ETCD_PORTS:
        return _etcd(ctx, url)
    return None


def _looks_docker(resp: Response, server: str) -> bool:
    """Daemon do Docker (ou a API compatível do Podman): ``Server: Docker/...`` ou os
    cabeçalhos que só ele manda junto (``Api-Version`` + ``Docker-Experimental``/``Ostype``)."""
    if server.startswith(("docker/", "libpod/")):
        return True
    extra = (
        resp.header("docker-experimental")
        or resp.header("ostype")
        or resp.header("libpod-api-version")
    )
    return bool(resp.header("api-version") and extra)


def _looks_elastic(resp: Response, data: Any) -> bool:
    """Elasticsearch/OpenSearch: documento raiz (``cluster_name`` + ``version.lucene_version``),
    o cabeçalho ``X-Elastic-Product`` ou o erro 401 típico da camada de segurança."""
    if (resp.header("x-elastic-product") or "").lower() == "elasticsearch":
        return True
    if isinstance(data, dict):
        version = data.get("version")
        if "cluster_name" in data and isinstance(version, dict) and "lucene_version" in version:
            return True
        if "for search" in str(data.get("tagline", "")).lower():
            return True
    text = resp.text[:2000]
    return resp.status == 401 and "security_exception" in text and "REST request" in text


def _looks_kubernetes(data: dict[str, Any]) -> bool:
    if data.get("kind") == "Status" and data.get("apiVersion") == "v1":
        return True
    paths = data.get("paths")
    return isinstance(paths, list) and "/api" in paths and "/apis" in paths


def _docker(ctx: CheckContext, url: str, first: Response) -> Identified:
    version = ""
    server = first.header("server") or ""
    product = "podman" if server.lower().startswith("libpod/") else "docker"
    if server.lower().startswith(("docker/", "libpod/")):
        version = server.split("/", 1)[1].split(" ")[0]
    extra: dict[str, Any] = {"api": first.header("api-version") or ""}
    resp = ctx.http.get(url + "version", timeout=io_timeout(ctx), max_bytes=65536)
    data = _json(resp) if resp is not None and resp.status == 200 else None
    if isinstance(data, dict):
        version = str(data.get("Version") or version)
        extra.update({"api": data.get("ApiVersion", extra["api"]), "os": data.get("Os", "")})
        extra["versao_lida_sem_login"] = True
    return Identified("docker", product, version, extra=extra)


def _elastic(data: Any, status: int) -> Identified:
    version = ""
    product = "elasticsearch"
    if isinstance(data, dict) and isinstance(data.get("version"), dict):
        version = str(data["version"].get("number", ""))
        if str(data["version"].get("distribution", "")).lower() == "opensearch":
            product = "opensearch"
    return Identified("elasticsearch", product, version, extra={"protegido": status == 401})


def _kubernetes(ctx: CheckContext, url: str) -> Identified:
    resp = ctx.http.get(url + "version", timeout=io_timeout(ctx), max_bytes=65536)
    data = _json(resp) if resp is not None and resp.status == 200 else None
    version = ""
    if isinstance(data, dict):
        version = str(data.get("gitVersion", "")).lstrip("v").split("+")[0]
    return Identified("kubernetes", "kubernetes", version)


def _etcd(ctx: CheckContext, url: str) -> Identified | None:
    resp = ctx.http.get(url + "version", timeout=io_timeout(ctx), max_bytes=65536)
    data = _json(resp) if resp is not None and resp.status == 200 else None
    if isinstance(data, dict) and "etcdserver" in data:
        return Identified("etcd", "etcd", str(data.get("etcdserver", "")))
    return None
