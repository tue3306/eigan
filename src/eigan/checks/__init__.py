"""Checagens nativas do EIGAN, organizadas por família.

Cada subpacote importa explicitamente os seus módulos — assim o executável
empacotado leva todas as checagens (um teste garante que nenhuma ficou de fora).
"""

from . import code, dns, host, logs, net, tls, web  # noqa: F401
