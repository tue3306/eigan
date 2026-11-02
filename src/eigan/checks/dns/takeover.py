"""Sequestro de subdomínio: CNAMEs que apontam para recursos de terceiros que não existem mais.

Segue a cadeia de CNAMEs do domínio do alvo (e de ``www.<domínio>``) e compara os
destinos com o catálogo embarcado ``data/dns_takeover.json``: serviços marcados
como vulneráveis pelo projeto can-i-take-over-xyz (CC BY 4.0), mais os formatos de
nome do Azure documentados pela Microsoft. A prova é sempre concreta: NXDOMAIN no
destino (nos serviços em que isso basta) ou a assinatura do provedor na página do
subdomínio. Destino inexistente em que outra conta não consegue recriar o nome é
só um "CNAME órfão" (baixa). Nada é registrado nem reivindicado no provedor.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from ...core import facts
from ...core.context import CheckContext
from ...core.http import Response
from ...core.models import Category, Confidence, Fact
from ...core.registry import check
from ...data import load_json
from . import resolver
from .nomes import dentro_de, dominio_organizacional, dominio_registravel, normalizar, tld_existe
from .resolver import dominio_do_fato

MAX_SALTOS = 5
TAMANHO_PAGINA = 262_144
#: parte da página examinada pelas assinaturas por regex
LIMITE_REGEX = 65_536
#: página de sucesso (2xx) só vale como prova se for curta e sem scripts
LIMITE_PAGINA_VIVA = 16_384
_SCRIPTS = re.compile(r"<(script|style)\b.*?</\1\s*>", re.I | re.S)


@lru_cache(maxsize=1)
def servicos() -> tuple[dict[str, Any], ...]:
    return tuple(load_json("dns_takeover.json").get("servicos", []))


@dataclass(frozen=True)
class Destino:
    """Destino da cadeia de CNAMEs que pertence a um serviço do catálogo."""

    servico: dict[str, Any]
    nome: str
    reivindicavel: bool  # o formato do nome permite que outra conta o recrie


def _sufixo_do_servico(servico: dict[str, Any], alvo: str) -> str | None:
    sufixo = next((padrao for padrao in servico["cname"] if dentro_de(alvo, padrao)), None)
    if sufixo is None:
        return None
    filtro = servico.get("cname_regex")
    return None if filtro and not re.search(filtro, alvo) else sufixo


def _formato_reivindicavel(servico: dict[str, Any], alvo: str, sufixo: str) -> bool:
    """Compara os rótulos antes do sufixo com os formatos que uma nova conta consegue criar."""
    formatos = servico.get("rotulos")
    if not formatos:
        return True
    resto = alvo[: -len(sufixo)].rstrip(".")
    return bool(resto) and resto.count(".") + 1 in formatos


def servico_de(alvos: list[str]) -> Destino | None:
    """Primeiro destino da cadeia que pertence a um serviço vulnerável conhecido."""
    for alvo in alvos:
        for servico in servicos():
            sufixo = _sufixo_do_servico(servico, alvo)
            if sufixo is not None:
                return Destino(servico, alvo, _formato_reivindicavel(servico, alvo, sufixo))
    return None


def trecho_assinatura(servico: dict[str, Any], texto: str) -> str | None:
    """Trecho da página que casa com a assinatura do serviço (também sem entidades HTML)."""
    assinatura = servico.get("assinatura")
    if not assinatura:
        return None
    texto = texto[:LIMITE_REGEX]  # regex sobre texto do alvo: limita o custo
    for pagina in (texto, html.unescape(texto)):
        if servico.get("regex"):
            casou = re.search(assinatura, pagina)
            if casou:
                return casou.group(0)[:160]
            continue
        for forma in (assinatura, html.unescape(assinatura)):
            if forma in pagina:
                return forma
    return None


def motivo_sem_reivindicacao(alvos: list[str]) -> str:
    """Por que o provedor do destino não deixa recriar o nome ('' se não for o caso)."""
    for item in load_json("dns_takeover.json").get("sem_reivindicacao", []):
        if any(dentro_de(alvo, padrao) for alvo in alvos for padrao in item["cname"]):
            return str(item["motivo"])
    return ""


def urls_para(nome: str) -> list[str]:
    """Endereços consultados para ler a página do subdomínio. Substituído nos testes."""
    return [f"http://{nome}/", f"https://{nome}/"]


def candidatos(dominio: str, org: str) -> list[str]:
    """O domínio do alvo, ``www.<domínio>`` e o ``www`` do domínio organizacional."""
    nomes = [dominio]
    if not dominio.startswith("www."):
        nomes.append(f"www.{dominio}")
    nomes.append(f"www.{org}")
    return list(dict.fromkeys(nomes))


@check(
    id="dns.takeover",
    name="Sequestro de subdomínio (CNAME órfão)",
    category=Category.DNS,
    consumes=facts.DNS_DOMAIN,
    description=(
        "Segue os CNAMEs do domínio e de www.<domínio> e procura destinos em serviços de "
        "terceiros que não existem mais (NXDOMAIN ou página-assinatura do provedor)."
    ),
    findings=("dns.takeover.possivel", "dns.takeover.dominio_livre", "dns.cname.orfao"),
    timeout=120.0,
    order=50,
)
def check_takeover(ctx: CheckContext, fact: Fact) -> None:
    dominio = dominio_do_fato(fact)
    org = dominio_organizacional(dominio)
    for nome in candidatos(dominio, org):
        ctx.check_cancel()
        if resolver.primeira_vez(ctx, f"takeover:{nome}"):
            _avaliar(ctx, nome, org)


def cadeia_cname(ctx: CheckContext, nome: str) -> tuple[list[str], bool]:
    """``(destinos, resolvida)``: a cadeia a partir de ``nome``, até ``MAX_SALTOS``.

    ``resolvida`` é False quando o DNS não respondeu e a cadeia pode estar incompleta.
    """
    alvos: list[str] = []
    atual = nome
    for _ in range(MAX_SALTOS):
        resposta = resolver.consultar(ctx, atual, "CNAME")
        if resposta.status == resolver.ERRO:
            return alvos, False
        if not resposta.ok:
            break
        proximo = normalizar(resposta.registros[0])
        if proximo == nome or proximo in alvos:
            break  # laço de CNAMEs
        alvos.append(proximo)
        atual = proximo
    return alvos, True


def _avaliar(ctx: CheckContext, nome: str, org: str) -> None:
    alvos, resolvida = cadeia_cname(ctx, nome)
    if not resolvida:
        ctx.log(f"Sequestro de subdomínio em {nome} não verificado: o DNS não respondeu.")
        return
    if not alvos:
        return
    final = alvos[-1]
    existe = resolver.consultar(ctx, final, "A")
    if existe.status == resolver.ERRO:
        ctx.log(f"Sequestro de subdomínio em {nome} não verificado: DNS sem resposta para {final}.")
        return
    inexistente = existe.status == resolver.NXDOMAIN
    cadeia = f"{nome} CNAME " + " -> ".join(alvos)
    destino = servico_de(alvos)
    if destino is not None:
        _avaliar_servico(ctx, nome, cadeia, destino, inexistente)
    elif inexistente:
        _avaliar_desconhecido(ctx, nome, org, alvos, cadeia)
    else:
        _ativo(ctx, nome, final)


def _ativo(ctx: CheckContext, nome: str, final: str) -> None:
    ctx.passed("dns.takeover", f"O CNAME de {nome} aponta para um destino ativo ({final})", nome)


def _avaliar_servico(
    ctx: CheckContext, nome: str, cadeia: str, destino: Destino, inexistente: bool
) -> None:
    rotulo = destino.servico["servico"]
    if destino.servico.get("nxdomain"):
        if inexistente:
            _avaliar_nxdomain(ctx, nome, cadeia, destino)
        else:
            _ativo(ctx, nome, destino.nome)
    elif inexistente:
        _orfao(ctx, nome, f"{cadeia} (destino em {rotulo} responde NXDOMAIN)")
    else:
        _avaliar_pagina(ctx, nome, cadeia, destino)


def _avaliar_nxdomain(ctx: CheckContext, nome: str, cadeia: str, destino: Destino) -> None:
    rotulo = destino.servico["servico"]
    if not destino.reivindicavel:
        _orfao(
            ctx,
            nome,
            f"{cadeia} (NXDOMAIN; o formato de {destino.nome} traz um identificador único, "
            f"que outra conta de {rotulo} não consegue recriar)",
        )
        return
    verificacao = destino.servico.get("verificacao_txt")
    if verificacao:
        registro = resolver.txt(ctx, f"{verificacao}.{nome}")
        if registro.status == resolver.ERRO:
            ctx.log(
                f"Sequestro de {nome} não verificado: DNS sem resposta para {verificacao}.{nome}."
            )
            return
        if registro.ok:
            _orfao(ctx, nome, f"{cadeia} (NXDOMAIN; protegido pelo TXT {verificacao}.{nome})")
            return
    ctx.report(
        "dns.takeover.possivel",
        asset=nome,
        evidence=f"{cadeia}: o destino não existe (NXDOMAIN) e o nome pode ser criado por outra conta em {rotulo}.",
        details={"servico": rotulo, "prova": "nxdomain", "destino": destino.nome},
        confidence=Confidence.FIRM,
    )


def _avaliar_pagina(ctx: CheckContext, nome: str, cadeia: str, destino: Destino) -> None:
    rotulo = destino.servico["servico"]
    paginas = _ler_paginas(ctx, nome)
    if not paginas:
        ctx.log(f"Sequestro de {nome} não verificado: sem resposta HTTP do subdomínio ({rotulo}).")
        return
    for pagina in paginas:
        trecho, confianca = _prova_da_pagina(destino.servico, pagina)
        if trecho is not None:
            ctx.report(
                "dns.takeover.possivel",
                asset=nome,
                evidence=f"{cadeia}: {pagina.url} mostra a página de recurso inexistente de {rotulo} ('{trecho}').",
                details={
                    "servico": rotulo,
                    "prova": "assinatura",
                    "url": pagina.url,
                    "http": pagina.status,
                },
                confidence=confianca,
            )
            return
    _ativo(ctx, nome, destino.nome)


def _prova_da_pagina(servico: dict[str, Any], pagina: Response) -> tuple[str | None, Confidence]:
    """Assinatura na página: confirmada com erro HTTP; só tentativa em 2xx curto e sem scripts.

    Um site ativo pode citar a frase do provedor (blog, bundle JS); por isso uma
    resposta 2xx grande ou com a frase só dentro de ``<script>`` não prova nada.
    """
    if pagina.status >= 400:
        return trecho_assinatura(servico, pagina.text), Confidence.CONFIRMED
    if pagina.status >= 300 or len(pagina.text) > LIMITE_PAGINA_VIVA:
        return None, Confidence.TENTATIVE
    return trecho_assinatura(servico, _SCRIPTS.sub(" ", pagina.text)), Confidence.TENTATIVE


def _ler_paginas(ctx: CheckContext, nome: str) -> list[Response]:
    paginas: list[Response] = []
    for url in urls_para(nome):
        ctx.check_cancel()
        resposta = ctx.http.get(url, max_bytes=TAMANHO_PAGINA, follow_redirects=False)
        if resposta is not None:
            paginas.append(resposta)
    return paginas


def _avaliar_desconhecido(
    ctx: CheckContext, nome: str, org: str, alvos: list[str], cadeia: str
) -> None:
    final = alvos[-1]
    dono = dominio_registravel(final)
    externo = dono is not None and tld_existe(final) and dono != dominio_registravel(org)
    if dono is not None and externo:
        if resolver.consultar(ctx, dono, "SOA").status == resolver.NXDOMAIN:
            ctx.report(
                "dns.takeover.dominio_livre",
                asset=nome,
                evidence=f"{cadeia}: o domínio {dono} não existe no DNS (NXDOMAIN) e pode estar livre para registro.",
                details={"dominio_destino": dono},
                confidence=Confidence.FIRM,
            )
            return
    motivo = motivo_sem_reivindicacao(alvos)
    extra = f"; {motivo}" if motivo else ""
    _orfao(ctx, nome, f"{cadeia} (destino responde NXDOMAIN{extra})")


def _orfao(ctx: CheckContext, nome: str, evidencia: str) -> None:
    ctx.report("dns.cname.orfao", asset=nome, evidence=evidencia, confidence=Confidence.CONFIRMED)
