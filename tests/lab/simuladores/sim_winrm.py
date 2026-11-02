"""SIMULADO: WinRM (WS-Management sobre HTTP, porta estilo 5985) - apenas inseguro.

Imita o que um cliente enxerga: o endpoint /wsman em HTTP puro (sem TLS) que anuncia autenticacao
Basic (AllowUnencrypted + Basic habilitados) alem de Negotiate. Nao autentica ninguem.
"""

from __future__ import annotations

import _comum as c


def rotas(metodo, caminho, cab):
    if caminho.split("?")[0].lower().startswith("/wsman"):
        if metodo == "POST":
            return 401, {"WWW-Authenticate": 'Negotiate, Basic realm="WSMAN"'}, b""
        return 405, {"Allow": "POST"}, b""
    return 404, {}, b""


if __name__ == "__main__":
    c.rodar([c.servidor_http(c.porta("PORT_SIM_WINRM_INS"), rotas, "Microsoft-HTTPAPI/2.0")])
