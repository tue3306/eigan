"""SIMULADO: API server do Kubernetes (HTTPS).

  inseguro   : acesso anonimo permitido (--anonymous-auth=true com RBAC frouxo): /version, /api,
               /api/v1/namespaces e /healthz respondem 200 sem credenciais
  endurecido : anonimo desligado: tudo responde 401 Unauthorized (formato metav1.Status),
               exceto /healthz que devolve "ok" (comportamento padrao do kube-apiserver)
Certificado: autoassinado no inseguro, emitido pela CA do laboratorio no endurecido.
"""

from __future__ import annotations

import _comum as c

VERSION = {
    "major": "1",
    "minor": "19",
    "gitVersion": "v1.19.0",
    "gitCommit": "0000000000000000000000000000000000000000",
    "gitTreeState": "clean",
    "buildDate": "2020-08-26T14:23:04Z",
    "goVersion": "go1.15",
    "compiler": "gc",
    "platform": "linux/amd64",
}
NAMESPACES = {
    "kind": "NamespaceList",
    "apiVersion": "v1",
    "metadata": {},
    "items": [{"metadata": {"name": n}} for n in ("default", "kube-system", "kube-public")],
}
NAO_AUTORIZADO = {
    "kind": "Status",
    "apiVersion": "v1",
    "metadata": {},
    "status": "Failure",
    "message": "Unauthorized",
    "reason": "Unauthorized",
    "code": 401,
}


def rotas_inseguro(metodo, caminho, cab):
    p = caminho.split("?")[0]
    if p == "/version":
        return 200, {}, VERSION
    if p in ("/healthz", "/livez", "/readyz"):
        return 200, {"Content-Type": "text/plain"}, "ok"
    if p == "/api":
        return 200, {}, {"kind": "APIVersions", "versions": ["v1"]}
    if p == "/api/v1/namespaces":
        return 200, {}, NAMESPACES
    return (
        403,
        {},
        {
            "kind": "Status",
            "status": "Failure",
            "reason": "Forbidden",
            "code": 403,
            "message": f'forbidden: User "system:anonymous" cannot get path "{p}"',
        },
    )


def rotas_endurecido(metodo, caminho, cab):
    if caminho.split("?")[0] == "/healthz":
        return 200, {"Content-Type": "text/plain"}, "ok"
    return 401, {"WWW-Authenticate": 'Bearer realm="kubernetes"'}, NAO_AUTORIZADO


if __name__ == "__main__":
    k = c.certs()
    c.rodar(
        [
            c.servidor_http(
                c.porta("PORT_SIM_K8S_INS"),
                rotas_inseguro,
                "kube-apiserver (simulado)",
                tls=c.contexto_tls(k["auto_cert"], k["auto_chave"]),
            ),
            c.servidor_http(
                c.porta("PORT_SIM_K8S_END"),
                rotas_endurecido,
                "kube-apiserver (simulado)",
                tls=c.contexto_tls(k["cert"], k["chave"]),
            ),
        ]
    )
