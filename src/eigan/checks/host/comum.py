"""Apoio comum às checagens de host: ativo, plataformas e execução tolerante a privilégio."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ...core.context import CheckContext
from ...core.models import Confidence, Severity
from . import sistema

WINDOWS = frozenset({"windows"})
LINUX = frozenset({"linux"})


def ativo(ctx: CheckContext) -> str:
    """Ativo dos achados de host: a máquina auditada (ex.: ``Esta máquina (SRV01)``)."""
    return ctx.target.display


def admin(ctx: CheckContext) -> bool:
    """Se a auditoria roda como administrador/root (calculado uma vez)."""
    return ctx.memo("host:admin", sistema.is_admin)


def nao_verificado(ctx: CheckContext, item: str, motivo: str = sistema.NAO_VERIFICADO) -> None:
    ctx.log(f"{item}: {motivo}")


def executar(ctx: CheckContext, item: str, funcao: Callable[[CheckContext], None]) -> None:
    """Roda uma verificação; leitura negada vira "não verificado" (nunca um achado)."""
    ctx.check_cancel()
    try:
        funcao(ctx)
    except sistema.AcessoNegado:
        nao_verificado(ctx, item)


def relatar_windows(
    ctx: CheckContext,
    achado: str,
    evidencia: str,
    *,
    confianca: Confidence = Confidence.FIRM,
    severidade: Severity | None = None,
    discriminator: str = "",
    **detalhes: Any,
) -> None:
    """Reporta um achado de Windows na máquina auditada, com a configuração exata na evidência."""
    ctx.report(
        achado,
        asset=ativo(ctx),
        severity=severidade,
        discriminator=discriminator,
        evidence=evidencia,
        details=detalhes,
        confidence=confianca,
        tech=["windows"],
    )


def aprovar(ctx: CheckContext, controle: str, texto: str) -> None:
    """Registra um controle verificado e aprovado na máquina auditada."""
    ctx.passed(controle, texto, ativo(ctx))


def inteiro(valor: object) -> int | None:
    """Converte valores do registro/JSON (int, '1', True) em inteiro; None se não der."""
    if isinstance(valor, bool):
        return int(valor)
    if isinstance(valor, int):
        return valor
    texto = str(valor).strip()
    for base in (10, 0):  # "10", depois "0x91"
        try:
            return int(texto, base)
        except ValueError:
            continue
    return None


def como_lista(valor: object) -> list[dict[str, object]]:
    """``ConvertTo-Json`` devolve objeto único ou lista: normaliza para lista de dicionários."""
    if isinstance(valor, dict):
        return [valor]
    if isinstance(valor, list):
        return [item for item in valor if isinstance(item, dict)]
    return []


def verdadeiro(valor: object) -> bool | None:
    """``True``/``'True'``/``1`` -> True; ``False``/``'False'``/``0`` -> False; outro -> None."""
    if isinstance(valor, bool):
        return valor
    texto = str(valor).strip().lower()
    if texto in ("true", "1", "yes", "sim", "on"):
        return True
    if texto in ("false", "0", "no", "nao", "não", "off"):
        return False
    return None
