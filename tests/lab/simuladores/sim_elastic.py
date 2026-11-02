"""SIMULADO: Elasticsearch (REST em HTTP).

  inseguro   : sem autenticacao: GET / (versao), /_cluster/health, /_cat/indices e /_search respondem 200
  endurecido : seguranca ligada: 401 com WWW-Authenticate: Basic em todos os caminhos (inclusive /)
Dados fixos e ficticios; nao existe indice de verdade.
"""

from __future__ import annotations

import _comum as c

RAIZ = {
    "name": "eigan-lab-node",
    "cluster_name": "lab-cluster",
    "cluster_uuid": "LABLABLABLABLABLABLAB",
    "version": {
        "number": "7.10.0",
        "build_flavor": "default",
        "build_type": "docker",
        "lucene_version": "8.7.0",
    },
    "tagline": "You Know, for Search",
}


def rotas_inseguro(metodo, caminho, cab):
    p = caminho.split("?")[0]
    if p == "/":
        return 200, {}, RAIZ
    if p == "/_cluster/health":
        return 200, {}, {"cluster_name": "lab-cluster", "status": "green", "number_of_nodes": 1}
    if p.startswith("/_cat/indices"):
        return 200, {"Content-Type": "text/plain"}, "green open clientes-lab aaaa 1 0 2 0 4kb 4kb\n"
    if p.endswith("/_search"):
        return (
            200,
            {},
            {"hits": {"total": {"value": 2}, "hits": [{"_source": {"nome": "Fulano (ficticio)"}}]}},
        )
    return 404, {}, {"error": "no handler found for uri", "status": 404}


def rotas_endurecido(metodo, caminho, cab):
    corpo = {
        "error": {"type": "security_exception", "reason": "missing authentication credentials"},
        "status": 401,
    }
    return 401, {"WWW-Authenticate": 'Basic realm="security" charset="UTF-8"'}, corpo


if __name__ == "__main__":
    c.rodar(
        [
            c.servidor_http(c.porta("PORT_SIM_ELASTIC_INS"), rotas_inseguro, ""),
            c.servidor_http(c.porta("PORT_SIM_ELASTIC_END"), rotas_endurecido, ""),
        ]
    )
