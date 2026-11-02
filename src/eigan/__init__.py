"""EIGAN — auditor de segurança blue team.

Encontra vulnerabilidades e configurações fracas em sites, aplicações web,
servidores, na própria máquina, em projetos de código e em logs — e explica, em
português, o risco de cada problema e o passo a passo para corrigir.

Funciona sem IA e sem chaves de API: a análise é feita por um motor de regras
(encadeamento de fatos), uma base de conhecimento embarcada e dados offline.
Uso autorizado apenas: audite somente o que você administra ou tem permissão
escrita para testar.
"""

__version__ = "0.0.0"
APP_NAME = "EIGAN"
APP_TAGLINE = "Auditoria defensiva de segurança, sem IA e sem chaves de API"

__all__ = ["APP_NAME", "APP_TAGLINE", "__version__"]
