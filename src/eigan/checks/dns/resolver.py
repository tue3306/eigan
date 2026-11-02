"""Consultas DNS (dnspython) com tempo limite curto e resposta sempre tolerante.

Toda checagem de DNS passa por :func:`consultar` (com cache por auditoria), que
chama :func:`query` — o único ponto que fala com o resolvedor. A transferência
de zona fica em :func:`axfr`. Os testes substituem os dois com ``monkeypatch``
e nunca tocam a rede.

Sem resolvedor configurado, sem rede ou com o servidor DNS falhando, a resposta
é ``ERRO``: as checagens registram "não verificado" e não reportam achados.
"""

from __future__ import annotations

import contextlib
import threading
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from ...core.context import CheckContext
from ...core.models import Fact
from .nomes import normalizar, plataforma

#: tempo total de uma consulta (todas as tentativas) e por servidor
TEMPO_CONSULTA = 3.0
TEMPO_SERVIDOR = 2.0
#: tempo de espera por mensagem numa transferência de zona (o total é o dobro)
TEMPO_AXFR = 4.0
#: basta uma amostra da zona para provar a transferência (não baixamos tudo)
LIMITE_NOMES_AXFR = 200

OK = "ok"
NXDOMAIN = "nxdomain"  # o nome não existe
VAZIO = "vazio"  # o nome existe, mas não tem registros desse tipo
ERRO = "erro"  # sem resposta conclusiva (tempo esgotado, SERVFAIL, sem rede)


@dataclass(frozen=True)
class Resposta:
    """Resultado de uma consulta: ``status`` e os registros em texto."""

    status: str
    registros: tuple[str, ...] = ()
    erro: str = ""

    @property
    def ok(self) -> bool:
        return self.status == OK and bool(self.registros)

    @property
    def ausente(self) -> bool:
        """Ausência comprovada pelo DNS (NXDOMAIN ou nome sem esse tipo de registro)."""
        return self.status in (NXDOMAIN, VAZIO) or (self.status == OK and not self.registros)

    @property
    def existe(self) -> bool:
        """O nome existe no DNS (com ou sem registros desse tipo)."""
        return self.status in (OK, VAZIO)


@dataclass(frozen=True)
class Transferencia:
    """Resultado de uma tentativa de AXFR.

    ``respondeu`` diz se o servidor deu uma resposta conclusiva (recusa ou zona);
    False quando nada se pode concluir (tempo esgotado, sem rota).
    """

    permitida: bool
    nomes: tuple[str, ...] = ()
    registros: int = 0
    erro: str = ""
    respondeu: bool = True


# -- acesso à rede (substituído nos testes) ----------------------------------------
@lru_cache(maxsize=2)
def _resolvedor(sem_validacao: bool = False) -> Any:
    import dns.flags
    import dns.resolver

    resolvedor = dns.resolver.Resolver()
    resolvedor.timeout = TEMPO_SERVIDOR
    resolvedor.lifetime = TEMPO_CONSULTA
    if sem_validacao:
        # CD (checking disabled): um resolvedor que valida DNSSEC devolve os dados
        # mesmo quando a validação falha — é assim que se enxerga uma cadeia quebrada.
        resolvedor.flags = dns.flags.RD | dns.flags.CD
    return resolvedor


def query(
    nome: str, tipo: str, tempo: float = TEMPO_CONSULTA, sem_validacao: bool = False
) -> Resposta:
    """Consulta ``tipo`` de ``nome`` no resolvedor do sistema. Nunca levanta exceção."""
    try:
        import dns.exception
        import dns.resolver
    except ImportError:  # pragma: no cover - dependência declarada
        return Resposta(ERRO, erro="dnspython indisponível")
    try:
        resolvedor = _resolvedor(sem_validacao)
    except Exception as exc:  # noqa: BLE001 — sem configuração de DNS na máquina
        return Resposta(ERRO, erro=f"resolvedor indisponível: {exc}")
    try:
        resposta = resolvedor.resolve(
            nome, tipo, raise_on_no_answer=False, search=False, lifetime=tempo
        )
    except dns.resolver.NXDOMAIN:
        return Resposta(NXDOMAIN)
    except dns.resolver.NoAnswer:
        return Resposta(VAZIO)
    except dns.exception.Timeout:
        return Resposta(ERRO, erro="tempo esgotado")
    except dns.resolver.NoNameservers:
        return Resposta(ERRO, erro="os servidores DNS não responderam (SERVFAIL/REFUSED)")
    except (dns.exception.DNSException, OSError, ValueError, UnicodeError) as exc:
        return Resposta(ERRO, erro=str(exc) or exc.__class__.__name__)
    if resposta.rrset is None:
        return Resposta(VAZIO)
    return Resposta(OK, tuple(_texto(rdata, tipo) for rdata in resposta.rrset))


def axfr(servidor: str, zona: str, tempo: float = TEMPO_AXFR) -> Transferencia:
    """Pede a transferência da zona (AXFR, só leitura) ao servidor ``servidor`` (IP).

    Lê só o começo da transferência (até ``LIMITE_NOMES_AXFR`` nomes): para provar
    que o servidor entrega a zona, não é preciso baixá-la inteira.
    """
    try:
        import dns.exception
        import dns.query
        import dns.rdatatype
    except ImportError:  # pragma: no cover - dependência declarada
        return Transferencia(False, erro="dnspython indisponível", respondeu=False)
    nomes: set[str] = set()
    registros = 0
    try:
        mensagens = dns.query.xfr(servidor, zona, timeout=tempo, lifetime=tempo * 2)
        with contextlib.closing(mensagens):
            for mensagem in mensagens:
                for rrset in mensagem.answer:
                    if rrset.rdtype != dns.rdatatype.SOA:
                        registros += len(rrset)
                    nomes.add(rrset.name.to_text())
                if len(nomes) >= LIMITE_NOMES_AXFR:
                    break
    except dns.exception.Timeout:
        if not registros:
            return Transferencia(False, erro="tempo esgotado", respondeu=False)
    except ConnectionRefusedError:
        return Transferencia(False, erro="conexão TCP recusada")
    except OSError as exc:  # sem rota/sem rede: nada se conclui
        if not registros:
            return Transferencia(False, erro=str(exc) or "sem conexão", respondeu=False)
    except Exception as exc:  # noqa: BLE001 — REFUSED/NOTAUTH, conexão fechada, resposta inválida
        if not registros:
            return Transferencia(False, erro=str(exc) or exc.__class__.__name__)
    if not registros:
        return Transferencia(False, erro="a resposta não trouxe registros da zona")
    return Transferencia(True, tuple(sorted(nomes)), registros)


def _texto(rdata: Any, tipo: str) -> str:
    """Representação estável de um registro (sem o ponto final dos nomes)."""
    kind = tipo.upper()
    if kind in ("A", "AAAA"):
        return str(getattr(rdata, "address", rdata))
    if kind == "MX":
        destino = getattr(rdata, "exchange", None)
        nome = destino.to_text(omit_final_dot=True) if destino is not None else ""
        return f"{getattr(rdata, 'preference', 0)} {nome or '.'}"
    if kind in ("NS", "CNAME", "PTR"):
        destino = getattr(rdata, "target", None)
        return destino.to_text(omit_final_dot=True) if destino is not None else str(rdata)
    if kind == "TXT":
        # RFC 7208, 3.3: as partes de um TXT se juntam sem espaço
        partes = getattr(rdata, "strings", ())
        return b"".join(partes).decode("utf-8", errors="replace")
    if kind == "CAA":
        valor = getattr(rdata, "value", b"")
        if isinstance(valor, bytes):
            valor = valor.decode("utf-8", errors="replace")
        tag = getattr(rdata, "tag", b"")
        if isinstance(tag, bytes):
            tag = tag.decode("ascii", errors="replace")
        return f'{getattr(rdata, "flags", 0)} {tag} "{valor}"'
    return str(rdata)


# -- consultas com cache por auditoria ---------------------------------------------
def consultar(ctx: CheckContext, nome: str, tipo: str, *, sem_validacao: bool = False) -> Resposta:
    """``query`` com cache: a mesma pergunta não é repetida na mesma auditoria.

    ``sem_validacao`` liga o bit CD (só usado para ler as chaves DNSSEC).
    """
    alvo, kind = normalizar(nome), tipo.upper()
    ctx.check_cancel()
    chave = f"dns:{kind}:{alvo}" + (":cd" if sem_validacao else "")
    return ctx.memo(chave, lambda: query(alvo, kind, sem_validacao=sem_validacao))


def txt(ctx: CheckContext, nome: str) -> Resposta:
    return consultar(ctx, nome, "TXT")


def primeira_vez(ctx: CheckContext, chave: str) -> bool:
    """True só para a primeira checagem que pedir ``chave`` (evita trabalho repetido)."""
    trava = ctx.memo("dns:trava", threading.Lock)
    vistos: set[str] = ctx.memo("dns:vistos", set)
    with trava:
        if chave in vistos:
            return False
        vistos.add(chave)
        return True


def descrever(resposta: Resposta) -> str:
    """Texto curto para o registro de atividade quando o DNS não responde."""
    return resposta.erro or resposta.status


def dominio_do_fato(fact: Fact) -> str:
    return normalizar(str(fact.data.get("domain") or fact.key))


def sob_plataforma(ctx: CheckContext, dominio: str, assunto: str) -> bool:
    """True (e registra o motivo) quando ``dominio`` está sob uma plataforma compartilhada.

    Em ``meusite.github.io`` ou ``loja.myshopify.com`` quem publica SPF, DMARC,
    CAA e DNSSEC é o provedor: cobrar isso do cliente seria falso positivo.
    """
    sufixo = plataforma(dominio)
    if sufixo is None:
        return False
    ctx.log(
        f"{assunto} de {dominio} não avaliado: o nome fica sob {sufixo}, uma plataforma "
        "compartilhada cujo DNS é administrado pelo provedor."
    )
    return True


def hosts_mx(resposta: Resposta) -> list[str]:
    """Servidores MX reais, em ordem de preferência (sem o MX nulo ``0 .`` da RFC 7505)."""
    itens: list[tuple[int, str]] = []
    for registro in resposta.registros:
        partes = registro.split()
        destino = partes[-1].rstrip(".").lower() if partes else ""
        if not destino:
            continue
        preferencia = (
            int(partes[0]) if len(partes) > 1 and partes[0].isascii() and partes[0].isdigit() else 0
        )
        itens.append((preferencia, destino))
    return [destino for _, destino in sorted(itens)]
