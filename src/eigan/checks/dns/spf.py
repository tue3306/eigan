"""Leitura de registros SPF (RFC 7208): sintaxe, política final e limites de consultas DNS.

Só interpreta texto e segue ``include``/``redirect`` pelo cache de DNS da
auditoria; não avalia o IP de nenhum remetente. Termos com macros (``%{i}``...)
contam como consulta, mas não são seguidos. A contagem é a do pior caso (um
remetente que não casa com nenhum termo, como um e-mail falsificado): é nele que
os limites da norma (10 consultas, 2 consultas vazias) derrubam o SPF.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from ...core.context import CheckContext
from . import resolver
from .resolver import hosts_mx

MECANISMOS = frozenset({"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"})
#: termos que custam uma consulta DNS (o modificador redirect também custa) — RFC 7208, 4.6.4
CONSULTAM = frozenset({"include", "a", "mx", "ptr", "exists"})
LIMITE_CONSULTAS = 10
LIMITE_VAZIAS = 2
LIMITE_MX = 10
PROFUNDIDADE_MAXIMA = 10
#: a contagem para aqui: já prova o estouro e um SPF abusivo não prende a auditoria
TETO_CONTAGEM = 40
#: redes maiores que isto autorizam uma fatia enorme da Internet (mais de 16 milhões de IPv4)
PREFIXO_MINIMO = {"ip4": 8, "ip6": 16}

_MODIFICADOR = re.compile(r"^([a-z][a-z0-9._-]*)=(.*)$", re.I)
_CIDR = re.compile(r"^(?:/(\d{1,2}))?(?://(\d{1,3}))?$")
_ROTULO = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$", re.I)


@dataclass(frozen=True)
class Termo:
    qualificador: str  # + - ~ ?
    nome: str  # all, include, a, mx...
    valor: str = ""  # domínio ou rede, sem qualificador e sem o sufixo /CIDR
    cidr: str = ""  # sufixo /CIDR de a e mx, como escrito (ex.: "/0")


@dataclass
class Spf:
    registro: str
    termos: list[Termo] = field(default_factory=list)
    redirect: str | None = None
    invalidos: list[str] = field(default_factory=list)

    @property
    def all(self) -> Termo | None:
        return next((t for t in self.termos if t.nome == "all"), None)

    @property
    def efetivos(self) -> list[Termo]:
        """Termos avaliados: os que vêm depois de "all" são ignorados (RFC 7208, 5.1)."""
        saida: list[Termo] = []
        for termo in self.termos:
            saida.append(termo)
            if termo.nome == "all":
                break
        return saida

    @property
    def redirect_vale(self) -> bool:
        """O redirect só é usado quando não há "all" no registro (RFC 7208, 6.1)."""
        return bool(self.redirect) and self.all is None

    @property
    def redes_amplas(self) -> list[str]:
        """Faixas aprovadas (``+``) tão grandes que anulam a lista de remetentes."""
        amplas: list[str] = []
        for termo in self.efetivos:
            if termo.qualificador == "+" and termo.nome in PREFIXO_MINIMO:
                rede = ipaddress.ip_network(termo.valor, strict=False)
                if rede.prefixlen < PREFIXO_MINIMO[termo.nome]:
                    amplas.append(f"{termo.nome}:{termo.valor}")
            elif (
                termo.qualificador == "+" and termo.nome in ("a", "mx") and _cidr4_zero(termo.cidr)
            ):
                amplas.append(f"{termo.nome}{termo.cidr}")
        return amplas

    @property
    def autoriza_alguem(self) -> bool:
        """True se algum termo pode aprovar um remetente (``pass``)."""
        if self.redirect_vale:
            return True
        return any(t.qualificador == "+" for t in self.efetivos)


def _cidr4_zero(cidr: str) -> bool:
    """``/0`` no IPv4 de a/mx: aprova todos os endereços IPv4 (o IPv6 vem após ``//``)."""
    casou = _CIDR.match(cidr)
    return bool(casou and casou.group(1) is not None and int(casou.group(1)) == 0)


def eh_spf(texto: str) -> bool:
    """Registro SPF: começa com ``v=spf1`` seguido de espaço ou fim (RFC 7208, 4.5)."""
    limpo = texto.strip().lower()
    return limpo == "v=spf1" or limpo.startswith("v=spf1 ")


def registros_spf(resposta: resolver.Resposta) -> list[str]:
    return [texto.strip() for texto in resposta.registros if eh_spf(texto)]


# -- sintaxe -----------------------------------------------------------------------
def analisar(registro: str) -> Spf:
    """Separa os termos de um registro ``v=spf1 ...`` e anota os erros de sintaxe."""
    spf = Spf(registro=registro)
    vistos: dict[str, int] = {}
    for parte in registro.split()[1:]:
        modificador = _MODIFICADOR.match(parte)
        if modificador:
            _modificador(spf, parte, modificador.group(1).lower(), modificador.group(2), vistos)
            continue
        termo, problema = _mecanismo(parte)
        if problema:
            spf.invalidos.append(f"{parte}: {problema}")
        elif termo is not None:
            spf.termos.append(termo)
    return spf


def _modificador(spf: Spf, parte: str, nome: str, valor: str, vistos: dict[str, int]) -> None:
    if nome not in ("redirect", "exp"):
        return  # modificadores desconhecidos são ignorados (RFC 7208, 6)
    vistos[nome] = vistos.get(nome, 0) + 1
    if vistos[nome] == 2:
        spf.invalidos.append(f"{nome}= aparece mais de uma vez (só pode aparecer uma)")
    problema = _problema_dominio(valor)
    if problema:
        spf.invalidos.append(f"{parte}: {problema}")
    elif nome == "redirect" and vistos[nome] == 1:
        spf.redirect = normalizar_dominio(valor)


def _mecanismo(parte: str) -> tuple[Termo | None, str]:
    qualificador = parte[0] if parte[0] in "+-~?" else "+"
    corpo = parte[1:] if parte[0] in "+-~?" else parte
    nome = re.split(r"[:/]", corpo, maxsplit=1)[0].lower()
    resto = corpo[len(nome) :]
    if nome not in MECANISMOS:
        return None, "mecanismo desconhecido"
    if nome == "all":
        return (Termo(qualificador, nome), "") if not resto else (None, "'all' não aceita valor")
    if nome in ("ip4", "ip6"):
        return _rede(qualificador, nome, resto)
    dominio, cidr = (resto[1:], "") if resto.startswith(":") else ("", resto)
    if dominio and nome in ("a", "mx") and "/" in dominio and "%" not in dominio:
        dominio, cidr = dominio.split("/", 1)[0], "/" + dominio.split("/", 1)[1]
    if nome in ("include", "exists") and (not dominio or cidr):
        return None, f"'{nome}' exige um domínio e não aceita /CIDR"
    if nome == "ptr" and cidr:
        return None, "'ptr' não aceita /CIDR"
    if cidr and not _cidr_valido(cidr):
        return None, "prefixo /CIDR inválido"
    if resto.startswith(":") and _problema_dominio(dominio):
        return None, _problema_dominio(dominio)
    return Termo(qualificador, nome, normalizar_dominio(dominio), cidr), ""


def _rede(qualificador: str, nome: str, resto: str) -> tuple[Termo | None, str]:
    if not resto.startswith(":") or len(resto) < 2:
        return None, f"'{nome}' exige um endereço"
    valor = resto[1:]
    try:
        if nome == "ip4":
            ipaddress.IPv4Network(valor, strict=False)
        else:
            ipaddress.IPv6Network(valor, strict=False)
    except ValueError:
        return None, f"endereço {nome} inválido"
    return Termo(qualificador, nome, valor), ""


def _cidr_valido(cidr: str) -> bool:
    casou = _CIDR.match(cidr)
    if not casou or cidr in ("", "/"):
        return False
    ip4, ip6 = casou.group(1), casou.group(2)
    return (ip4 is None or int(ip4) <= 32) and (ip6 is None or int(ip6) <= 128)


def _problema_dominio(valor: str) -> str:
    """Erro de sintaxe de um domain-spec (macros não são validadas)."""
    if not valor:
        return "domínio vazio"
    if "%" in valor:
        return ""
    rotulos = valor.rstrip(".").split(".")
    if len(rotulos) < 2 or not all(_ROTULO.match(r) for r in rotulos):
        return "domínio mal formado"
    if not re.search(r"[a-z]", rotulos[-1], re.I):
        return "domínio mal formado (endereço IP? use ip4:/ip6:)"
    return ""


def normalizar_dominio(valor: str) -> str:
    return valor.strip().lower().rstrip(".")


# -- política final ----------------------------------------------------------------
@dataclass(frozen=True)
class Politica:
    """O que vale para quem não está na lista: ``qualificador`` (None = neutro)."""

    qualificador: str | None
    conclusiva: bool = True
    motivo: str = ""


def buscar(ctx: CheckContext, dominio: str) -> tuple[resolver.Resposta, list[str]]:
    """``(resposta TXT, registros SPF)`` de um domínio, pelo cache da auditoria."""
    resposta = resolver.txt(ctx, dominio)
    return resposta, registros_spf(resposta)


def politica_final(ctx: CheckContext, spf: Spf, profundidade: int = 0) -> Politica:
    """Segue ``redirect`` até achar o "all" que vale; sem "all" nem redirect = neutro."""
    termo = spf.all
    if termo is not None:
        return Politica(termo.qualificador)
    if not spf.redirect:
        return Politica(None)
    if "%" in spf.redirect or profundidade >= PROFUNDIDADE_MAXIMA:
        return Politica(None, False, f"redirect={spf.redirect} não pode ser seguido")
    resposta, registros = buscar(ctx, spf.redirect)
    if resposta.status == resolver.ERRO:
        return Politica(None, False, f"DNS sem resposta para {spf.redirect}")
    if len(registros) != 1:
        return Politica(None, False, f"redirect={spf.redirect} sem um SPF válido")
    return politica_final(ctx, analisar(registros[0]), profundidade + 1)


# -- limites de consultas (RFC 7208, 4.6.4) ------------------------------------------
@dataclass
class Contagem:
    consultas: int = 0
    vazias: list[str] = field(default_factory=list)
    problemas: list[str] = field(default_factory=list)  # viram permerror
    mx_grandes: list[str] = field(default_factory=list)
    abertos: list[str] = field(default_factory=list)  # includes que aprovam qualquer servidor
    incompleta: bool = False  # alguma consulta sem resposta: contagem pode estar abaixo do real

    @property
    def estourou(self) -> bool:
        return self.consultas > LIMITE_CONSULTAS

    @property
    def no_teto(self) -> bool:
        return self.consultas >= TETO_CONTAGEM


def contar_consultas(
    ctx: CheckContext,
    spf: Spf,
    dominio: str,
    contagem: Contagem | None = None,
    visitados: frozenset[str] = frozenset(),
    aprova: bool = True,
) -> Contagem:
    """Soma as consultas DNS do SPF de ``dominio``, seguindo ``include`` e ``redirect``.

    ``aprova`` diz se um "pass" deste registro aprovaria o remetente lá em cima (um
    ``-include:`` transforma o "pass" do registro incluído em "fail").
    """
    total = contagem if contagem is not None else Contagem()
    cadeia = visitados | {dominio}
    for termo in spf.efetivos:
        if termo.nome not in CONSULTAM:
            continue
        if total.no_teto:
            return total
        total.consultas += 1
        if termo.nome == "include":
            passa = aprova and termo.qualificador == "+"
            _seguir(ctx, termo.valor, "include", total, cadeia, passa)
        else:
            _conferir_vazia(ctx, termo, dominio, total)
    if spf.redirect_vale and spf.redirect and not total.no_teto:
        total.consultas += 1
        _seguir(ctx, spf.redirect, "redirect", total, cadeia, aprova)
    return total


def _seguir(
    ctx: CheckContext,
    alvo: str,
    origem: str,
    total: Contagem,
    cadeia: frozenset[str],
    aprova: bool,
) -> None:
    if "%" in alvo:
        return  # macro: depende do remetente
    if alvo in cadeia:
        total.problemas.append(f"{origem}:{alvo} forma um laço (a avaliação estoura o limite)")
        return
    if len(cadeia) > PROFUNDIDADE_MAXIMA:
        return
    resposta, registros = buscar(ctx, alvo)
    if resposta.status == resolver.ERRO:
        total.incompleta = True
        return
    if resposta.ausente:
        total.vazias.append(f"{origem}:{alvo}")
    if not registros:
        total.problemas.append(f"{origem}:{alvo} não publica SPF (o resultado vira permerror)")
        return
    if len(registros) > 1:
        total.problemas.append(
            f"{origem}:{alvo} publica {len(registros)} registros SPF (permerror)"
        )
        return
    interno = analisar(registros[0])
    total.problemas.extend(f"{origem}:{alvo} -> {problema}" for problema in interno.invalidos)
    if aprova and interno.all is not None and interno.all.qualificador == "+":
        total.abertos.append(f"{origem}:{alvo}")
    contar_consultas(ctx, interno, alvo, total, cadeia, aprova)


def _conferir_vazia(ctx: CheckContext, termo: Termo, dominio: str, total: Contagem) -> None:
    """Consultas "vazias" (NXDOMAIN ou sem resposta) e o limite de 10 MX por mecanismo."""
    alvo = termo.valor or dominio
    if "%" in alvo or termo.nome == "ptr":
        return  # depende do remetente
    if termo.nome == "mx":
        resposta = resolver.consultar(ctx, alvo, "MX")
        if resposta.status == resolver.ERRO:
            total.incompleta = True
        elif resposta.ausente:
            total.vazias.append(f"mx:{alvo}")
        elif len(hosts_mx(resposta)) > LIMITE_MX:
            total.mx_grandes.append(f"mx:{alvo} ({len(hosts_mx(resposta))} servidores)")
        return
    tipos = ("A",) if termo.nome == "exists" else ("A", "AAAA")
    respostas = [resolver.consultar(ctx, alvo, tipo) for tipo in tipos]
    if any(r.status == resolver.ERRO for r in respostas):
        total.incompleta = True
    elif all(r.ausente for r in respostas):
        total.vazias.append(f"{termo.nome}:{alvo}")
