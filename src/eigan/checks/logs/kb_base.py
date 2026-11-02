"""Montagem das entradas da base de conhecimento da análise de logs.

Todo achado de logs é um indício de incidente: o mesmo roteiro de resposta (conter, preservar
evidências, trocar credenciais, bloquear a origem, revisar) vale para todos, e cada entrada
acrescenta os passos específicos do seu caso.
"""

from __future__ import annotations

from ...core import kb
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Severity

#: passos de resposta a incidente comuns a todos os achados de logs
PASSOS_COMUNS = (
    "Preserve as evidências antes de mexer: copie os logs originais (somente leitura) para "
    "outro local e anote data, hora e quem coletou.",
    "Se houver sinal de acesso bem-sucedido, isole a máquina da rede (sem desligá-la, para não "
    "perder a memória) e avise o responsável de segurança.",
    "Troque as senhas, chaves e tokens das contas e serviços envolvidos, a partir de um "
    "computador que você sabe estar limpo.",
    "Revise o que mais a mesma origem ou conta fez em outros logs (firewall, aplicação, "
    "banco de dados) e envie os logs para um local central, onde o atacante não consiga apagá-los.",
)

#: passo de bloqueio, só para achados que têm um IP de origem
PASSO_BLOQUEIO = (
    "Bloqueie o IP de origem no firewall ou no WAF (IPv4 e IPv6). Se o IP for do seu proxy ou "
    "balanceador, o log não mostra o cliente real: bloqueie pelo cabeçalho X-Forwarded-For, "
    "senão o site inteiro sai do ar. Não bloqueie IP interno sem investigar a máquina."
)
_PREFIXOS_COM_IP = (
    "logs.ssh.",
    "logs.web.",
    "logs.windows.forca_bruta",
    "logs.windows.rdp_apos_falhas",
)

REF_ATTACK = "https://attack.mitre.org/techniques/{}/"


def ref_attack(*tecnicas: str) -> tuple[str, ...]:
    """Endereços das técnicas do ATT&CK (subtécnicas usam barra: T1110/001)."""
    return tuple(REF_ATTACK.format(t.replace(".", "/")) for t in tecnicas)


def registrar(
    id: str,
    titulo: str,
    severidade: Severity,
    resumo: str,
    explicacao: str,
    risco: str,
    passos: tuple[str, ...],
    verificar: str,
    referencias: tuple[str, ...],
    *,
    exemplos: tuple[Fix, ...] = (),
    esforco: str = "medio",
    cwe: str = "CWE-778",
    owasp: str = "A09:2021",
    cis: tuple[str, ...] = ("8.11", "13.1"),
    lgpd: bool = True,
    tags: tuple[str, ...] = (),
) -> KBEntry:
    """Cria e registra uma entrada de logs (grupo de correção ``incidente``)."""
    bloqueio = (PASSO_BLOQUEIO,) if id.startswith(_PREFIXOS_COM_IP) else ()
    entrada = KBEntry(
        id=id,
        title=titulo,
        category=Category.LOGS,
        severity=severidade,
        summary=resumo,
        explanation=explicacao,
        risk=risco,
        steps=(*passos, *PASSOS_COMUNS, *bloqueio),
        examples=exemplos,
        verify=verificar,
        effort=esforco,
        fix_group="incidente",
        references=referencias,
        cwe=cwe,
        owasp=owasp,
        cis=cis,
        lgpd=lgpd,
        tags=("logs", "incidente", *tags),
    )
    kb.register(entrada)
    return entrada
