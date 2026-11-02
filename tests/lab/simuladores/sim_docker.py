"""SIMULADO: Docker Engine API (HTTP).

  inseguro   : API em HTTP puro, sem TLS e sem autenticacao (/version, /info, /containers/json)
  endurecido : TLS 1.2+ exigindo certificado de cliente (CA do laboratorio); sem certificado
               o handshake falha, como no dockerd com --tlsverify
Respostas JSON fixas no formato da API v1.41. Nao ha containers nem execucao.
"""

from __future__ import annotations

import _comum as c

VERSAO = {
    "Platform": {"Name": "Docker Engine - Community (simulado)"},
    "Version": "20.10.7",
    "ApiVersion": "1.41",
    "MinAPIVersion": "1.12",
    "Os": "linux",
    "Arch": "amd64",
    "KernelVersion": "5.4.0-lab",
    "GoVersion": "go1.13.15",
}
INFO = {
    "ID": "LAB0:SIMU:LADO",
    "Containers": 1,
    "Name": "eigan-lab-docker",
    "ServerVersion": "20.10.7",
    "SecurityOptions": ["name=seccomp,profile=default"],
    "OperatingSystem": "Ubuntu 20.04 (simulado)",
}
CONTAINERS = [
    {
        "Id": "0123456789ab",
        "Names": ["/web-lab"],
        "Image": "nginx:1.18",
        "State": "running",
        "Ports": [{"PrivatePort": 80, "PublicPort": 8080, "Type": "tcp"}],
    }
]


def rotas(metodo, caminho, cab):
    p = caminho.split("?")[0].removeprefix("/v1.41")
    if p == "/_ping":
        return (
            200,
            {"Content-Type": "text/plain", "Api-Version": "1.41", "Docker-Experimental": "false"},
            "OK",
        )
    if p == "/version":
        return 200, {"Api-Version": "1.41"}, VERSAO
    if p == "/info":
        return 200, {"Api-Version": "1.41"}, INFO
    if p == "/containers/json":
        return 200, {"Api-Version": "1.41"}, CONTAINERS
    return 404, {}, {"message": "page not found"}


if __name__ == "__main__":
    k = c.certs()
    c.rodar(
        [
            c.servidor_http(c.porta("PORT_SIM_DOCKER_INS"), rotas, "Docker/20.10.7 (linux)"),
            c.servidor_http(
                c.porta("PORT_SIM_DOCKER_END"),
                rotas,
                "Docker/27.0 (linux)",
                tls=c.contexto_tls(k["cert"], k["chave"], k["ca"], exigir_cliente=True),
            ),
        ]
    )
