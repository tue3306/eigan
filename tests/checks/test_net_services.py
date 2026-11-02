"""Identificação de serviços (``net.services``): banners, sondas, HTTP/TLS e fatos ensinados."""

from __future__ import annotations

import json
from typing import Any

import pytest
from fakes_net import (
    amqp_start,
    closing,
    cql_supported,
    fake_tcp,
    fast_settings,
    http_response,
    http_routes,
    line_replies,
    mongo_command,
    mongo_msg,
    mongo_reply,
    mysql_greeting,
    rdp_confirm,
    smb1_response,
    smb2_response,
    tds_prelogin_response,
    tns_refuse,
)
from helpers import CheckOutcome, Route, run_check

from eigan.checks.net import common, httpid, identify, probes, services, winproto
from eigan.checks.net.banners import Identified
from eigan.core.context import CheckContext, ScanContext
from eigan.core.http import Response
from eigan.core.models import Exposure, Fact
from eigan.core.registry import get_check
from eigan.core.target import parse_target


def port_fact(port: int, host: str = "127.0.0.1", **data: Any) -> Fact:
    payload = {
        "host": host,
        "port": port,
        "hint": "",
        "aceita_tudo": False,
        "label": f"{host}:{port}",
    }
    payload.update(data)
    return Fact("port.open", f"{host}:{port}/tcp", payload)


def identified(port: int, **data: Any) -> tuple[Fact, CheckOutcome]:
    """Roda a identificação na porta e devolve o fato ``service`` e o resultado."""
    out = run_check("net.services", port_fact(port, **data), settings=fast_settings())
    [service] = [f for f in out.facts if f.kind == "service"]
    return service, out


def techs(out: CheckOutcome) -> dict[str, Any]:
    return {f.data["name"]: f.data["version"] for f in out.facts if f.kind == "tech"}


def hint(monkeypatch: pytest.MonkeyPatch, port: int, *names: str) -> None:
    """Faz a porta do servidor falso se comportar como a porta padrão do protocolo."""
    monkeypatch.setitem(identify.PORT_HINTS, port, names)


# -- HTTP e TLS --------------------------------------------------------------------------------


def test_http_vira_servico_web_com_tecnologias(monkeypatch: pytest.MonkeyPatch) -> None:
    page = http_response(
        200, "<html>ok</html>", (("Server", "nginx/1.24.0"), ("X-Powered-By", "PHP/8.2.1"))
    )
    with fake_tcp(http_routes({"/": page})) as server:
        hint(monkeypatch, server.port, "http", "tls")
        service, out = identified(server.port)
    assert service.data["service"] == "http"
    assert service.data["tls"] is False
    assert service.data["confirmed"] is True
    assert out.fact_keys("http.service") == {f"http://127.0.0.1:{server.port}/"}
    assert not out.fact_keys("tls.service")
    assert techs(out) == {"nginx": "1.24.0", "php": "8.2.1"}
    php = next(f for f in out.facts if f.kind == "tech" and f.data["name"] == "php")
    assert php.data["kind"] == "language"
    assert php.data["port"] == server.port


def test_https_gera_servico_web_e_tls(serve) -> None:
    srv = serve({"/": Route(200, "<html>ok</html>")}, tls=True)
    with pytest.MonkeyPatch.context() as patch:
        hint(patch, srv.port, "tls", "http")
        service, out = identified(srv.port)
    assert service.data["service"] == "https"
    assert service.data["tls"] is True
    assert service.data["extra"]["versao_tls"].startswith("TLS")
    assert out.fact_keys("http.service") == {f"https://127.0.0.1:{srv.port}/"}
    assert out.fact_keys("tls.service") == {f"127.0.0.1:{srv.port}"}


def test_porta_desconhecida_silenciosa_que_fala_http(serve) -> None:
    srv = serve({"/": Route(200, "<html>ok</html>")})
    service, out = identified(srv.port)
    assert service.data["service"] == "http"
    assert service.data["confirmed"] is True
    assert out.fact_keys("http.service") == {f"http://127.0.0.1:{srv.port}/"}


def test_tls_com_banner_de_correio(monkeypatch: pytest.MonkeyPatch) -> None:
    with fake_tcp(greeting=b"* OK Dovecot ready.\r\n", tls=True, hangup=True) as server:
        hint(monkeypatch, server.port, "tls")
        monkeypatch.setattr(identify, "TLS_BANNER_PORTS", frozenset({server.port}))
        service, out = identified(server.port)
    assert (service.data["service"], service.data["product"]) == ("imap", "dovecot")
    assert service.data["tls"] is True
    assert out.fact_keys("tls.service") == {f"127.0.0.1:{server.port}"}
    assert not out.fact_keys("http.service")


def test_tls_sem_protocolo_reconhecido(monkeypatch: pytest.MonkeyPatch) -> None:
    with fake_tcp(lambda _data: None, tls=True) as server:
        hint(monkeypatch, server.port, "tls")
        service, out = identified(server.port)
    assert service.data["service"] == "tls"
    assert service.data["tls"] is True
    assert out.fact_keys("tls.service") == {f"127.0.0.1:{server.port}"}
    assert not out.fact_keys("http.service")


# -- protocolos em que o servidor fala primeiro -----------------------------------------------


@pytest.mark.parametrize(
    ("greeting", "service", "product", "version", "tech"),
    [
        (b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3\r\n", "ssh", "openssh", "9.6p1", True),
        (b"220 (vsFTPd 3.0.5)\r\n", "ftp", "vsftpd", "3.0.5", True),
        (b"220 mx.exemplo.com ESMTP Postfix\r\n", "smtp", "postfix", "", True),
        (b"+OK Dovecot ready.\r\n", "pop3", "dovecot", "", True),
        (b"* OK IMAP4rev1 pronto\r\n", "imap", "", "", False),
        (mysql_greeting("8.0.35"), "mysql", "mysql", "8.0.35", True),
        (mysql_greeting("5.5.5-10.11.2-MariaDB"), "mysql", "mariadb", "10.11.2", True),
        (b"RFB 003.008\n", "vnc", "vnc", "", True),
        (b"\xff\xfd\x18\xff\xfd\x20", "telnet", "", "", False),
    ],
)
def test_banner_identifica(
    greeting: bytes, service: str, product: str, version: str, tech: bool
) -> None:
    with fake_tcp(greeting=greeting, hangup=True) as server:
        fact, out = identified(server.port)
    assert fact.data["service"] == service
    assert fact.data["product"] == product
    assert fact.data["version"] == version
    assert fact.data["confirmed"] is True
    assert not out.fact_keys("http.service")
    if tech:
        assert techs(out) == {product: version or None}
    else:
        assert not techs(out)


@pytest.mark.parametrize(
    ("reply", "expected"),
    [(b"250-mx\r\n250 STARTTLS\r\n", "smtp"), (b"500 comando desconhecido\r\n", "ftp")],
)
def test_banner_220_generico_desempata_com_ehlo(reply: bytes, expected: str) -> None:
    respond = line_replies({"EHLO": reply, "QUIT": b"221 tchau\r\n"})
    with fake_tcp(respond, greeting=b"220 Bem-vindo\r\n") as server:
        fact, _out = identified(server.port)
    assert fact.data["service"] == expected
    assert fact.data["confirmed"] is True
    assert any(b"EHLO eigan.invalid" in data for data in server.received)


# -- protocolos em que o cliente fala primeiro -------------------------------------------------


def test_redis(monkeypatch: pytest.MonkeyPatch) -> None:
    with fake_tcp(closing(b"+PONG\r\n")) as server:
        hint(monkeypatch, server.port, "redis")
        fact, out = identified(server.port)
    assert server.received == [probes.REDIS_PING]
    assert (fact.data["service"], fact.data["product"]) == ("redis", "redis")
    assert fact.data["extra"]["autenticacao"] == "nenhuma"
    assert "redis" in techs(out)


def test_memcached(monkeypatch: pytest.MonkeyPatch) -> None:
    with fake_tcp(closing(b"VERSION 1.6.21\r\n")) as server:
        hint(monkeypatch, server.port, "memcached")
        fact, out = identified(server.port)
    assert fact.data["version"] == "1.6.21"
    assert techs(out) == {"memcached": "1.6.21"}


def test_postgresql(monkeypatch: pytest.MonkeyPatch) -> None:
    with fake_tcp(closing(b"N")) as server:
        hint(monkeypatch, server.port, "postgres")
        fact, _out = identified(server.port)
    assert server.received == [probes.POSTGRES_SSLREQUEST]
    assert fact.data["service"] == "postgresql"
    assert fact.data["extra"]["tls"] is False


def test_sql_server(monkeypatch: pytest.MonkeyPatch) -> None:
    with fake_tcp(closing(tds_prelogin_response(16, 0, 4085))) as server:
        hint(monkeypatch, server.port, "mssql")
        fact, out = identified(server.port)
    assert (fact.data["service"], fact.data["version"]) == ("mssql", "16.0.4085")
    assert fact.data["extra"]["edicao"] == "SQL Server 2022"
    assert techs(out) == {"mssql": "16.0.4085"}


def test_ajp(monkeypatch: pytest.MonkeyPatch) -> None:
    with fake_tcp(closing(b"AB\x00\x01\x09")) as server:
        hint(monkeypatch, server.port, "ajp")
        fact, _out = identified(server.port)
    assert server.received == [probes.AJP_CPING]
    assert fact.data["service"] == "ajp"
    assert fact.data["confirmed"] is True


def test_amqp(monkeypatch: pytest.MonkeyPatch) -> None:
    with fake_tcp(closing(amqp_start("RabbitMQ", "3.12.13"))) as server:
        hint(monkeypatch, server.port, "amqp")
        fact, out = identified(server.port)
    assert server.received == [probes.AMQP_HEADER]
    assert (fact.data["service"], fact.data["product"]) == ("amqp", "rabbitmq")
    assert techs(out) == {"rabbitmq": "3.12.13"}


def test_cassandra(monkeypatch: pytest.MonkeyPatch) -> None:
    with fake_tcp(closing(cql_supported())) as server:
        hint(monkeypatch, server.port, "cql")
        fact, _out = identified(server.port)
    assert fact.data["service"] == "cassandra"


def test_oracle(monkeypatch: pytest.MonkeyPatch) -> None:
    refuse = tns_refuse("TNSLSNR for Linux: Version 19.3.0.0.0 - Production")
    with fake_tcp(closing(refuse)) as server:
        hint(monkeypatch, server.port, "oracle")
        fact, out = identified(server.port)
    assert (fact.data["service"], fact.data["version"]) == ("oracle-tns", "19.3.0.0.0")
    assert techs(out) == {"oracle": "19.3.0.0.0"}


def test_dns_por_tcp(monkeypatch: pytest.MonkeyPatch) -> None:
    answer = probes.DNS_QUERY_TCP[:2] + int(probes.DNS_PROBE_ID).to_bytes(2, "big") + b"\x80\x00"
    with fake_tcp(closing(answer + b"\x00" * 8)) as server:
        hint(monkeypatch, server.port, "dns")
        fact, _out = identified(server.port)
    assert fact.data["service"] == "dns"
    assert fact.data["extra"]["rcode"] == "NOERROR"


def test_rdp(monkeypatch: pytest.MonkeyPatch) -> None:
    with fake_tcp(closing(rdp_confirm(0x02, winproto.PROTOCOL_HYBRID))) as server:
        hint(monkeypatch, server.port, "rdp")
        fact, _out = identified(server.port)
    assert fact.data["service"] == "rdp"
    assert "CredSSP" in fact.data["banner"]


def test_smb_prefere_smb2(monkeypatch: pytest.MonkeyPatch) -> None:
    with fake_tcp(closing(smb2_response(dialect=0x0302, security_mode=0x03))) as server:
        hint(monkeypatch, server.port, "smb")
        fact, _out = identified(server.port)
    assert fact.data["service"] == "smb"
    assert fact.data["extra"] == {"dialeto": "3.0.2", "assinatura_obrigatoria": True}


def test_smb_servidor_so_com_smb1(monkeypatch: pytest.MonkeyPatch) -> None:
    def respond(data: bytes) -> bytes | None:
        return smb1_response() if data[4:8] == b"\xffSMB" else None

    with fake_tcp(respond) as server:
        hint(monkeypatch, server.port, "smb")
        fact, _out = identified(server.port)
    assert fact.data["service"] == "smb"
    assert fact.data["extra"]["dialeto"] == "NT LM 0.12"


def _mongo_modern(data: bytes) -> bytes | None:
    command = mongo_command(data)
    if "hello" in command:
        return mongo_msg({"ok": 1.0, "isWritablePrimary": True, "maxWireVersion": 17})
    if "buildInfo" in command:
        return mongo_msg({"ok": 1.0, "version": "6.0.5"})
    return mongo_msg({"ok": 0.0, "errmsg": "no such command"})


def test_mongodb_hello_e_build_info(monkeypatch: pytest.MonkeyPatch) -> None:
    with fake_tcp(_mongo_modern) as server:
        hint(monkeypatch, server.port, "mongodb")
        fact, out = identified(server.port)
    assert (fact.data["service"], fact.data["version"]) == ("mongodb", "6.0.5")
    assert fact.data["extra"]["wire"] == 17
    assert fact.data["extra"]["legado"] is False
    assert techs(out) == {"mongodb": "6.0.5"}


def test_mongodb_antigo_sem_hello_usa_ismaster(monkeypatch: pytest.MonkeyPatch) -> None:
    def respond(data: bytes) -> bytes | None:
        command = mongo_command(data)
        if "isMaster" in command:
            return mongo_msg({"ok": 1.0, "ismaster": True, "maxWireVersion": 8})
        if "buildInfo" in command:
            return mongo_msg({"ok": 1.0, "version": "4.2.0"})
        return mongo_msg({"ok": 0.0, "errmsg": "no such command: 'hello'"})

    with fake_tcp(respond) as server:
        hint(monkeypatch, server.port, "mongodb")
        fact, _out = identified(server.port)
    assert fact.data["version"] == "4.2.0"
    assert fact.data["extra"]["wire"] == 8


def test_mongodb_legado_op_query(monkeypatch: pytest.MonkeyPatch) -> None:
    def respond(data: bytes) -> bytes | None:
        command = mongo_command(data)
        if int.from_bytes(data[12:16], "little") == 2013:
            return None  # servidor anterior ao 3.6 não entende OP_MSG
        if "buildInfo" in command:
            return mongo_reply({"ok": 1.0, "version": "3.2.1"})
        return mongo_reply({"ok": 1.0, "ismaster": True, "maxWireVersion": 4})

    with fake_tcp(respond) as server:
        hint(monkeypatch, server.port, "mongodb")
        fact, _out = identified(server.port)
    assert (fact.data["service"], fact.data["version"]) == ("mongodb", "3.2.1")
    assert fact.data["extra"]["legado"] is True


def test_sonda_errada_nao_confirma_e_cai_no_banner(monkeypatch: pytest.MonkeyPatch) -> None:
    # a porta "é do Redis", mas quem responde é um FTP: vale o que o protocolo mostrou
    with fake_tcp(greeting=b"220 (vsFTPd 3.0.5)\r\n", hangup=True) as server:
        hint(monkeypatch, server.port, "redis")
        fact, _out = identified(server.port)
    assert fact.data["service"] == "ftp"


# -- APIs de infraestrutura sobre HTTP --------------------------------------------------------


def _json(body: Any, status: int = 200, headers: tuple[tuple[str, str], ...] = ()) -> bytes:
    return http_response(status, json.dumps(body), (("Content-Type", "application/json"), *headers))


def test_docker_pelo_server_e_version(monkeypatch: pytest.MonkeyPatch) -> None:
    routes = {
        "/": _json(
            {"message": "page not found"},
            404,
            (("Server", "Docker/24.0.7 (linux)"), ("Api-Version", "1.43"), ("Ostype", "linux")),
        ),
        "/version": _json({"Version": "24.0.7", "ApiVersion": "1.43", "Os": "linux"}),
    }
    with fake_tcp(http_routes(routes)) as server:
        hint(monkeypatch, server.port, "http")
        fact, out = identified(server.port)
    assert (fact.data["service"], fact.data["product"]) == ("docker", "docker")
    assert fact.data["version"] == "24.0.7"
    assert fact.data["extra"]["api"] == "1.43"
    assert fact.data["extra"]["versao_lida_sem_login"] is True
    assert not out.fact_keys("http.service")  # não é "um site": não recebe as checagens web
    assert techs(out)["docker"] == "24.0.7"


def test_docker_protegido_ainda_e_identificado(monkeypatch: pytest.MonkeyPatch) -> None:
    routes = {
        "/": http_response(401, "", (("Api-Version", "1.43"), ("Docker-Experimental", "false"))),
    }
    with fake_tcp(http_routes(routes, default=http_response(401, ""))) as server:
        hint(monkeypatch, server.port, "http")
        fact, _out = identified(server.port)
    assert fact.data["service"] == "docker"
    assert "versao_lida_sem_login" not in fact.data["extra"]


def test_podman_compativel_com_docker(monkeypatch: pytest.MonkeyPatch) -> None:
    routes = {"/": _json({"message": "not found"}, 404, (("Server", "Libpod/4.9.0 (linux)"),))}
    with fake_tcp(http_routes(routes)) as server:
        hint(monkeypatch, server.port, "http")
        fact, _out = identified(server.port)
    assert (fact.data["service"], fact.data["product"]) == ("docker", "podman")
    assert fact.data["version"] == "4.9.0"


def test_elasticsearch_documento_raiz(monkeypatch: pytest.MonkeyPatch) -> None:
    root = {
        "cluster_name": "producao",
        "tagline": "You Know, for Search",
        "version": {"number": "8.11.1", "lucene_version": "9.8.0"},
    }
    with fake_tcp(http_routes({"/": _json(root)})) as server:
        hint(monkeypatch, server.port, "http")
        fact, out = identified(server.port)
    assert (fact.data["service"], fact.data["product"]) == ("elasticsearch", "elasticsearch")
    assert fact.data["version"] == "8.11.1"
    assert fact.data["extra"]["protegido"] is False
    assert techs(out)["elasticsearch"] == "8.11.1"


def test_opensearch_e_reconhecido(monkeypatch: pytest.MonkeyPatch) -> None:
    root = {
        "cluster_name": "c",
        "tagline": "The OpenSearch Project: https://opensearch.org/",
        "version": {"distribution": "opensearch", "number": "2.11.0", "lucene_version": "9.7.0"},
    }
    with fake_tcp(http_routes({"/": _json(root)})) as server:
        hint(monkeypatch, server.port, "http")
        fact, _out = identified(server.port)
    assert (fact.data["service"], fact.data["product"]) == ("elasticsearch", "opensearch")


def test_elasticsearch_protegido_401(monkeypatch: pytest.MonkeyPatch) -> None:
    body = {
        "error": {"type": "security_exception", "reason": "missing authentication for REST request"}
    }
    with fake_tcp(http_routes({"/": _json(body, 401)})) as server:
        hint(monkeypatch, server.port, "http")
        fact, _out = identified(server.port)
    assert fact.data["service"] == "elasticsearch"
    assert fact.data["extra"]["protegido"] is True


def test_kubernetes_api(monkeypatch: pytest.MonkeyPatch) -> None:
    routes = {
        "/": _json({"kind": "Status", "apiVersion": "v1", "status": "Failure", "code": 403}, 403),
        "/version": _json({"gitVersion": "v1.28.3+k3s1", "major": "1", "minor": "28"}),
    }
    with fake_tcp(http_routes(routes)) as server:
        hint(monkeypatch, server.port, "http")
        fact, out = identified(server.port)
    assert (fact.data["service"], fact.data["version"]) == ("kubernetes", "1.28.3")
    assert techs(out)["kubernetes"] == "1.28.3"


def test_kubernetes_lista_de_caminhos(monkeypatch: pytest.MonkeyPatch) -> None:
    routes = {"/": _json({"paths": ["/api", "/apis", "/healthz"]})}
    with fake_tcp(http_routes(routes)) as server:
        hint(monkeypatch, server.port, "http")
        fact, _out = identified(server.port)
    assert fact.data["service"] == "kubernetes"
    assert fact.data["version"] == ""


def test_etcd(monkeypatch: pytest.MonkeyPatch) -> None:
    routes = {"/version": _json({"etcdserver": "3.5.9", "etcdcluster": "3.5.0"})}
    with fake_tcp(http_routes(routes)) as server:
        hint(monkeypatch, server.port, "http")
        fact, out = identified(server.port)
    assert (fact.data["service"], fact.data["version"]) == ("etcd", "3.5.9")
    assert techs(out)["etcd"] == "3.5.9"


def test_kubelet_pela_porta_e_404_do_go(monkeypatch: pytest.MonkeyPatch) -> None:
    with fake_tcp(http_routes({})) as server:
        hint(monkeypatch, server.port, "http")
        monkeypatch.setattr(httpid, "KUBELET_PORTS", frozenset({server.port}))
        fact, _out = identified(server.port)
    assert (fact.data["service"], fact.data["product"]) == ("kubelet", "kubernetes")


def test_servico_go_generico_nao_vira_etcd(monkeypatch: pytest.MonkeyPatch) -> None:
    with fake_tcp(http_routes({})) as server:
        hint(monkeypatch, server.port, "http")
        fact, out = identified(server.port)
    assert fact.data["service"] == "http"
    assert out.fact_keys("http.service") == {f"http://127.0.0.1:{server.port}/"}


def test_couchdb(monkeypatch: pytest.MonkeyPatch) -> None:
    routes = {"/": _json({"couchdb": "Welcome", "version": "3.3.2"})}
    with fake_tcp(http_routes(routes)) as server:
        hint(monkeypatch, server.port, "http")
        fact, _out = identified(server.port)
    assert (fact.data["service"], fact.data["version"]) == ("couchdb", "3.3.2")


def test_influxdb(monkeypatch: pytest.MonkeyPatch) -> None:
    page = http_response(404, "", (("X-Influxdb-Version", "1.8.10"),))
    with fake_tcp(http_routes({"/": page})) as server:
        hint(monkeypatch, server.port, "http")
        fact, _out = identified(server.port)
    assert (fact.data["service"], fact.data["version"]) == ("influxdb", "1.8.10")


def test_clickhouse(monkeypatch: pytest.MonkeyPatch) -> None:
    page = http_response(200, "Ok.\n", (("X-ClickHouse-Summary", "{}"),))
    with fake_tcp(http_routes({"/": page})) as server:
        hint(monkeypatch, server.port, "http")
        fact, _out = identified(server.port)
    assert fact.data["service"] == "clickhouse"


def test_site_que_cita_tudo_continua_sendo_site(serve) -> None:
    body = "<html>cluster_name lucene_version etcdserver couchdb Docker kubernetes Ok.</html>"
    srv = serve({}, default=Route(200, body))  # responde 200 para qualquer caminho (soft 404)
    with pytest.MonkeyPatch.context() as patch:
        hint(patch, srv.port, "http")
        fact, out = identified(srv.port)
    assert fact.data["service"] == "http"
    assert out.fact_keys("http.service") == {f"http://127.0.0.1:{srv.port}/"}


def test_json_de_outro_servico_nao_vira_elasticsearch(monkeypatch: pytest.MonkeyPatch) -> None:
    body = {"cluster_name": "x", "version": "1.2.3", "tagline": "nada a ver"}
    with fake_tcp(http_routes({"/": _json(body)})) as server:
        hint(monkeypatch, server.port, "http")
        fact, _out = identified(server.port)
    assert fact.data["service"] == "http"


# -- cabeçalhos -> tecnologias ------------------------------------------------------------------


def _response(*headers: tuple[str, str]) -> Response:
    return Response("http://h/", 200, "OK", list(headers), b"", 0.0)


def _tech_table(resp: Response) -> dict[str, str]:
    return {item["name"]: item["version"] for item in httpid.header_techs(resp)}


def test_tecnologias_do_cabecalho_server() -> None:
    resp = _response(("Server", "Apache/2.4.49 (Unix) OpenSSL/1.0.1f PHP/7.4.3"))
    assert _tech_table(resp) == {"apache": "2.4.49", "openssl": "1.0.1f", "php": "7.4.3"}


def test_tecnologias_sem_versao_e_outros_cabecalhos() -> None:
    assert _tech_table(_response(("Server", "nginx"))) == {"nginx": ""}
    assert _tech_table(_response(("Server", "Microsoft-IIS/10.0"))) == {"iis": "10.0"}
    assert _tech_table(_response(("Server", "Apache-Coyote/1.1"))) == {"tomcat": ""}
    assert _tech_table(_response(("Server", "Apache Tomcat/9.0.30"))) == {"tomcat": "9.0.30"}
    assert _tech_table(_response(("Server", "Apache"))) == {"apache": ""}
    assert _tech_table(_response(("X-Powered-By", "Express"))) == {"express": ""}
    assert _tech_table(_response(("X-AspNet-Version", "4.0.30319"))) == {"aspnet": "4.0.30319"}
    jenkins = httpid.header_techs(_response(("X-Jenkins", "2.426.1")))
    assert jenkins[0]["name"] == "jenkins"
    assert jenkins[0]["version"] == "2.426.1"
    assert _tech_table(_response()) == {}
    assert _tech_table(_response(("Server", "ProdutoCaseiro/1.0"))) == {}


# -- sem confirmação ---------------------------------------------------------------------------


def test_porta_silenciosa_fica_sem_confirmacao(monkeypatch: pytest.MonkeyPatch) -> None:
    with fake_tcp(lambda _data: None) as server:
        monkeypatch.setattr(identify, "service_name", lambda _port: "redis")
        fact, out = identified(server.port)
    assert fact.data["service"] == "redis"
    assert fact.data["confirmed"] is False
    assert not techs(out)
    assert "suposto pela porta" in fact.reason


def test_porta_desconhecida_sem_resposta(monkeypatch: pytest.MonkeyPatch) -> None:
    with fake_tcp(lambda _data: None) as server:
        monkeypatch.setattr(identify, "service_name", lambda _port: "")
        fact, _out = identified(server.port)
    assert fact.data["service"] == "desconhecido"
    assert fact.data["confirmed"] is False


def test_banner_desconhecido_fica_registrado() -> None:
    with fake_tcp(greeting=b"Bem-vindo ao servico XYZ\r\n", hangup=True) as server:
        fact, _out = identified(server.port)
    assert fact.data["confirmed"] is False
    assert "XYZ" in fact.data["banner"]


def test_host_que_aceita_tudo_sem_protocolo_nao_vira_servico(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with fake_tcp(lambda _data: None) as server:
        monkeypatch.setattr(identify, "service_name", lambda _port: "mysql")
        out = run_check(
            "net.services", port_fact(server.port, aceita_tudo=True), settings=fast_settings()
        )
    assert not out.facts
    assert any("aceita qualquer conexão" in line for line in out.logs)


def test_host_que_aceita_tudo_com_protocolo_confirmado_vale() -> None:
    with fake_tcp(greeting=b"SSH-2.0-OpenSSH_9.6\r\n", hangup=True) as server:
        fact, _out = identified(server.port, aceita_tudo=True)
    assert fact.data["service"] == "ssh"


def test_fato_sem_porta_e_ignorado() -> None:
    out = run_check("net.services", port_fact(0), settings=fast_settings())
    assert not out.facts


# -- apoios --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("found", "text"),
    [
        (Identified("ssh", "openssh", "9.6p1"), "ssh (openssh 9.6p1)"),
        (Identified("https", tls=True), "https"),
        (Identified("redis", "redis"), "redis"),
        (Identified("imap", "dovecot", tls=True), "imap (dovecot) sobre TLS"),
    ],
)
def test_descricao_curta(found: Identified, text: str) -> None:
    assert services.describe(found) == text


def test_url_do_servico() -> None:
    assert identify.service_url("h", 80, False) == "http://h/"
    assert identify.service_url("h", 443, True) == "https://h/"
    assert identify.service_url("h", 8443, True) == "https://h:8443/"
    assert identify.service_url("::1", 8080, False) == "http://[::1]:8080/"


def test_tecnologia_sem_versao_recebe_a_versao_depois() -> None:
    scan = ScanContext(parse_target("https://127.0.0.1/"), fast_settings())
    with fake_tcp(greeting=b"220 (vsFTPd 3.0.5)\r\n", hangup=True) as first:
        run_check("net.services", port_fact(first.port), scan=scan)
    [tech] = scan.facts_of("tech")
    assert tech.data["version"] == "3.0.5"
    assert tech.data["port"] == first.port


def test_cadeia_host_porta_servico_achado(monkeypatch: pytest.MonkeyPatch) -> None:
    """Do host ao achado: varredura -> identificação -> checagem do serviço."""
    scan = ScanContext(parse_target("https://127.0.0.1/"), fast_settings())
    monkeypatch.setattr(common, "exposure_of", lambda _host: Exposure.INTERNET)

    def respond(data: bytes) -> bytes | None:
        if data == probes.REDIS_PING:
            return b"+PONG\r\n"
        return b"$38\r\n# Server\r\nredis_version:7.2.4\r\nos:Linux\r\n\r\n"

    with fake_tcp(respond) as server:
        hint(monkeypatch, server.port, "redis")
        scan.settings.ports = str(server.port)
        host = Fact("host", "127.0.0.1", {"host": "127.0.0.1", "label": "127.0.0.1"})
        opened = run_check("net.portscan", host, scan=scan)
        [port_open] = [f for f in opened.facts if f.kind == "port.open"]
        found = run_check("net.services", port_open, scan=scan)
        [service] = [f for f in found.facts if f.kind == "service"]
        final = run_check("net.bancos", service, scan=scan)
    assert {"net.banco.exposto", "net.redis.sem_senha"} <= final.ids()


def test_mesmo_produto_em_duas_portas_mantem_as_duas_versoes() -> None:
    scan = ScanContext(parse_target("10.0.0.5"), fast_settings())
    ctx = CheckContext(scan, get_check("net.services"), port_fact(1, host="10.0.0.5"))
    first = services.add_tech(ctx, "10.0.0.5", 80, "openssh", "9.6", "service", "SSH-2.0-a")
    second = services.add_tech(ctx, "10.0.0.5", 2222, "openssh", "7.2", "service", "SSH-2.0-b")
    again = services.add_tech(ctx, "10.0.0.5", 80, "openssh", "9.6", "service", "SSH-2.0-a")
    assert first is not None and second is not None and again is first
    versions = {f.data["port"]: f.data["version"] for f in scan.facts_of("tech")}
    assert versions == {80: "9.6", 2222: "7.2"}


def test_saudacao_atrasada_do_smtp_ainda_e_identificada(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import socket
    import threading
    import time

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(4)
    port = server.getsockname()[1]
    monkeypatch.setattr(common, "GREETING_PORTS", frozenset({port}))

    def serve() -> None:
        try:
            while True:
                conn, _ = server.accept()
                time.sleep(3.0)
                try:
                    conn.sendall(b"220 mx.example.com ESMTP Postfix\r\n")
                    conn.recv(100)
                except OSError:
                    pass
                conn.close()
        except OSError:
            return

    threading.Thread(target=serve, daemon=True).start()
    try:
        ctx = CheckContext(
            ScanContext(parse_target("127.0.0.1"), fast_settings()),
            get_check("net.services"),
            port_fact(port),
        )
        found = identify.identify(ctx, "127.0.0.1", port)
    finally:
        server.close()
    assert found.confirmed
    assert found.service == "smtp"
