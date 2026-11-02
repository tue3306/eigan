"""E-mail do domínio: SPF, DMARC, DKIM e domínios que não usam e-mail.

Tudo é avaliado no domínio organizacional (``www.exemplo.com.br`` -> ``exemplo.com.br``),
uma única vez por auditoria. Só reportamos ausência quando o DNS responde de
forma conclusiva (NXDOMAIN ou nome sem o registro); tempo esgotado ou falha do
resolvedor viram "não verificado" no registro de atividade.
"""

from __future__ import annotations

import re

from ...core import facts
from ...core.context import CheckContext
from ...core.models import Category, Confidence, Fact
from ...core.registry import check
from . import dmarc, resolver, spf
from .nomes import dominio_organizacional
from .resolver import dominio_do_fato, hosts_mx

#: seletores DKIM testados: os dos grandes provedores (Microsoft 365, Google, Proton,
#: SendGrid, Mailchimp/Mandrill, Fastmail) e nomes genéricos comuns.
#: Não encontrar NÃO prova ausência de DKIM: o seletor é escolhido por quem assina.
SELETORES_DKIM = (
    "selector1",
    "selector2",
    "google",
    "default",
    "dkim",
    "mail",
    "k1",
    "s1",
    "s2",
    "fm1",
    "fm2",
    "fm3",
    "protonmail",
    "protonmail2",
    "protonmail3",
)
#: falhas de DNS seguidas que encerram a busca de DKIM como "não verificado"
MAX_FALHAS_DKIM = 3
_CHAVE_DKIM = re.compile(r"(?:^|;)\s*p\s*=\s*[A-Za-z0-9+/]", re.I)


@check(
    id="dns.email",
    name="Proteção do e-mail do domínio (SPF, DKIM, DMARC)",
    category=Category.DNS,
    consumes=facts.DNS_DOMAIN,
    description=(
        "Confere SPF (existência, 'all', duplicidade, sintaxe, limites de 10 consultas e de "
        "2 consultas vazias), DMARC (política, subdomínios, pct, relatórios), DKIM nos "
        "seletores comuns e a proteção de domínios que não usam e-mail."
    ),
    findings=(
        "dns.email.spf_ausente",
        "dns.email.spf_multiplo",
        "dns.email.spf_permissivo",
        "dns.email.spf_neutro",
        "dns.email.spf_softfail",
        "dns.email.spf_consultas",
        "dns.email.spf_invalido",
        "dns.email.dmarc_ausente",
        "dns.email.dmarc_invalido",
        "dns.email.dmarc_monitoramento",
        "dns.email.dmarc_parcial",
        "dns.email.dmarc_sem_relatorio",
        "dns.email.dkim_nao_encontrado",
        "dns.email.estacionado",
    ),
    order=30,
)
def check_email(ctx: CheckContext, fact: Fact) -> None:
    dominio = dominio_do_fato(fact)
    if resolver.sob_plataforma(ctx, dominio, "E-mail"):
        return
    org = dominio_organizacional(dominio)
    if not resolver.primeira_vez(ctx, f"email:{org}"):
        return
    mx = resolver.consultar(ctx, org, "MX")
    raiz = resolver.txt(ctx, org)
    if resolver.NXDOMAIN in (raiz.status, mx.status):
        ctx.log(f"E-mail: o domínio {org} não existe no DNS (NXDOMAIN); nada a verificar.")
        return
    if raiz.status == resolver.ERRO and mx.status == resolver.ERRO:
        ctx.log(
            f"E-mail de {org} não verificado: o DNS não respondeu ({resolver.descrever(raiz)})."
        )
        return
    registro_dmarc = resolver.txt(ctx, f"_dmarc.{org}")
    registros = spf.registros_spf(raiz) if raiz.status != resolver.ERRO else None
    if (
        mx.status != resolver.ERRO
        and not hosts_mx(mx)
        and _nao_envia(registros)
        and not _tem_dkim(ctx, org)
    ):
        _avaliar_estacionado(ctx, org, registros or [], registro_dmarc)
        return
    if registros is None:
        ctx.log(f"SPF de {org} não verificado: o DNS não respondeu ({resolver.descrever(raiz)}).")
    else:
        _avaliar_spf(ctx, org, registros)
    if registro_dmarc.status == resolver.ERRO:
        ctx.log(
            f"DMARC de {org} não verificado: o DNS não respondeu "
            f"({resolver.descrever(registro_dmarc)})."
        )
    else:
        _avaliar_dmarc(ctx, org, registro_dmarc)
    _avaliar_dkim(ctx, org)


def _tem_dkim(ctx: CheckContext, org: str) -> bool:
    """Há chave DKIM em algum seletor comum? Então o domínio envia e-mail (não é estacionado)."""
    falhas = 0
    for seletor in SELETORES_DKIM:
        resposta = resolver.txt(ctx, f"{seletor}._domainkey.{org}")
        if resposta.status == resolver.ERRO:
            falhas += 1
            if falhas >= MAX_FALHAS_DKIM:
                return False
        elif any(_CHAVE_DKIM.search(texto) for texto in resposta.registros):
            return True
    return False


def _nao_envia(registros: list[str] | None) -> bool:
    """O domínio não declara remetentes: sem SPF ou com SPF que não autoriza ninguém."""
    if registros is None:
        return False
    return all(not spf.analisar(r).autoriza_alguem for r in registros)


# -- domínio que não usa e-mail -------------------------------------------------------
def _spf_bloqueia_tudo(registros: list[str]) -> bool:
    """Um único SPF, sem erros de sintaxe, terminando em ``-all``."""
    if len(registros) != 1:
        return False
    lido = spf.analisar(registros[0])
    return not lido.invalidos and lido.all is not None and lido.all.qualificador == "-"


def _dmarc_rejeita_tudo(resposta: resolver.Resposta) -> tuple[bool, str]:
    """``(protegido, descrição)``: DMARC p=reject, inclusive subdomínios, em 100%."""
    candidatos = dmarc.candidatos(resposta)
    if len(candidatos) != 1:
        return False, "ausente" if not candidatos else f"{len(candidatos)} registros"
    lido = dmarc.analisar(candidatos[0])
    if not lido.versao_exata or lido.politica is None:
        return False, f"inválido: {lido.registro}"
    protegido = lido.politica == "reject" and lido.subdominios == "reject" and lido.pct == 100
    return protegido, f"p={lido.politica}, sp={lido.subdominios}, pct={lido.pct}"


def _avaliar_estacionado(
    ctx: CheckContext, org: str, registros: list[str], resposta: resolver.Resposta
) -> None:
    faltas: list[str] = []
    if not _spf_bloqueia_tudo(registros):
        atual = registros[0] if len(registros) == 1 else ("nenhum" if not registros else "vários")
        faltas.append(f"SPF 'v=spf1 -all' (atual: {atual})")
    politica = "não verificado"
    if resposta.status == resolver.ERRO:
        ctx.log(
            f"DMARC de {org} não verificado: o DNS não respondeu ({resolver.descrever(resposta)})."
        )
    else:
        protegido, politica = _dmarc_rejeita_tudo(resposta)
        if not protegido:
            faltas.append(f"DMARC p=reject valendo também para os subdomínios (atual: {politica})")
    if not faltas:
        if resposta.status != resolver.ERRO:
            ctx.passed(
                "dns.email.estacionado",
                "Domínio sem e-mail protegido contra falsificação (SPF -all e DMARC p=reject)",
                org,
            )
        return
    ctx.report(
        "dns.email.estacionado",
        asset=org,
        evidence=(
            f"{org} não publica MX (sem MX, só o registro A/AAAA recebe e-mail) e falta: "
            + "; ".join(faltas)
        ),
        details={"faltando": faltas, "dmarc": politica},
        confidence=Confidence.CONFIRMED,
    )


# -- SPF ---------------------------------------------------------------------------
def _avaliar_spf(ctx: CheckContext, org: str, registros: list[str]) -> None:
    if not registros:
        ctx.report(
            "dns.email.spf_ausente",
            asset=org,
            evidence=f"Nenhum registro TXT 'v=spf1' em {org}.",
            confidence=Confidence.CONFIRMED,
        )
        return
    if len(registros) > 1:
        ctx.report(
            "dns.email.spf_multiplo",
            asset=org,
            evidence=f"{len(registros)} registros SPF em {org}:\n" + "\n".join(registros),
            details={"registros": registros},
            confidence=Confidence.CONFIRMED,
        )
        return
    registro = spf.analisar(registros[0])
    contagem = spf.contar_consultas(ctx, registro, org)
    problemas = registro.invalidos + contagem.problemas
    if problemas:
        ctx.report(
            "dns.email.spf_invalido",
            asset=org,
            evidence="\n".join(problemas + [registro.registro]),
            details={"problemas": problemas},
            confidence=Confidence.CONFIRMED,
        )
    estourou = _avaliar_limites(ctx, org, registro, contagem)
    if contagem.incompleta:
        ctx.log(
            f"SPF de {org}: parte dos includes não respondeu; a contagem de consultas pode estar incompleta."
        )
    amplo = _avaliar_amplitude(ctx, org, registro, contagem)
    _avaliar_all(
        ctx, org, registro, quebrado=bool(problemas) or estourou or amplo or contagem.incompleta
    )


def _avaliar_limites(
    ctx: CheckContext, org: str, registro: spf.Spf, contagem: spf.Contagem
) -> bool:
    """Reporta os limites de consultas da RFC 7208 (4.6.4). True se algum estourou."""
    estourou = False
    if contagem.estourou:
        estourou = True
        ctx.report(
            "dns.email.spf_consultas",
            asset=org,
            evidence=(
                f"O SPF de {org} exige mais de {spf.LIMITE_CONSULTAS} consultas DNS (contadas: "
                f"{contagem.consultas}{' ou mais' if contagem.no_teto else ''}, seguindo os "
                f"includes).\n{registro.registro}"
            ),
            details={"consultas": contagem.consultas},
            confidence=Confidence.CONFIRMED,
        )
    if len(contagem.vazias) > spf.LIMITE_VAZIAS:
        estourou = True
        ctx.report(
            "dns.email.spf_consultas",
            asset=org,
            title="SPF com mais de 2 consultas DNS vazias",
            evidence=(
                f"{len(contagem.vazias)} termos do SPF consultam nomes que não existem ou não têm "
                f"registros (o limite recomendado é {spf.LIMITE_VAZIAS}): "
                + ", ".join(contagem.vazias)
            ),
            details={"vazias": contagem.vazias},
            confidence=Confidence.FIRM,
            discriminator="vazias",
        )
    if contagem.mx_grandes:
        estourou = True
        ctx.report(
            "dns.email.spf_consultas",
            asset=org,
            title="Mecanismo mx do SPF com mais de 10 servidores",
            evidence="Cada mx do SPF aceita no máximo 10 servidores: "
            + ", ".join(contagem.mx_grandes),
            details={"mx": contagem.mx_grandes},
            confidence=Confidence.CONFIRMED,
            discriminator="mx",
        )
    return estourou


def _avaliar_amplitude(
    ctx: CheckContext, org: str, registro: spf.Spf, contagem: spf.Contagem
) -> bool:
    """Termos que, mesmo com ``-all`` no fim, aprovam quase qualquer servidor. True se houver."""
    amplas = registro.redes_amplas
    if amplas:
        ctx.report(
            "dns.email.spf_permissivo",
            asset=org,
            title="SPF autoriza uma faixa enorme de endereços",
            evidence=f"Faixas aprovadas: {', '.join(amplas)}\n{registro.registro}",
            details={"faixas": amplas},
            confidence=Confidence.CONFIRMED,
            discriminator="faixa",
        )
    if contagem.abertos:
        ctx.report(
            "dns.email.spf_permissivo",
            asset=org,
            title="SPF inclui um registro que autoriza qualquer servidor (+all)",
            evidence=f"Termina em +all: {', '.join(contagem.abertos)}\n{registro.registro}",
            details={"includes": contagem.abertos},
            confidence=Confidence.CONFIRMED,
            discriminator="include",
        )
    return bool(amplas or contagem.abertos)


def _avaliar_all(ctx: CheckContext, org: str, registro: spf.Spf, *, quebrado: bool) -> None:
    politica = spf.politica_final(ctx, registro)
    evidencia = registro.registro
    if not politica.conclusiva:
        ctx.log(f"Política final do SPF de {org} não verificada: {politica.motivo}.")
        return
    if politica.qualificador == "+":
        ctx.report(
            "dns.email.spf_permissivo",
            asset=org,
            evidence=evidencia,
            confidence=Confidence.CONFIRMED,
        )
    elif politica.qualificador in (None, "?"):
        motivo = "?all" if politica.qualificador == "?" else "sem 'all' nem 'redirect'"
        ctx.report(
            "dns.email.spf_neutro",
            asset=org,
            evidence=f"{evidencia}\n(resultado neutro para quem não está na lista: {motivo})",
            confidence=Confidence.CONFIRMED,
        )
    elif politica.qualificador == "~":
        ctx.report(
            "dns.email.spf_softfail", asset=org, evidence=evidencia, confidence=Confidence.CONFIRMED
        )
    elif not quebrado:
        ctx.passed("dns.email.spf", f"SPF restritivo (-all): {evidencia}", org)


# -- DMARC -------------------------------------------------------------------------
def _avaliar_dmarc(ctx: CheckContext, org: str, resposta: resolver.Resposta) -> None:
    nome = f"_dmarc.{org}"
    candidatos = dmarc.candidatos(resposta)
    if not candidatos:
        outros = (
            f" (TXT encontrados: {'; '.join(resposta.registros)})" if resposta.registros else ""
        )
        ctx.report(
            "dns.email.dmarc_ausente",
            asset=org,
            evidence=f"Nenhum registro 'v=DMARC1' em {nome}{outros}.",
            confidence=Confidence.CONFIRMED,
        )
        return
    if len(candidatos) > 1:
        _dmarc_invalido(
            ctx, org, f"{len(candidatos)} registros DMARC em {nome}:\n" + "\n".join(candidatos)
        )
        return
    lido = dmarc.analisar(candidatos[0])
    if not lido.versao_exata:
        _dmarc_invalido(
            ctx,
            org,
            f"{lido.registro}\n(a versão precisa ser exatamente 'v=DMARC1', em maiúsculas)",
            Confidence.FIRM,
        )
        return
    efetiva = _politica_efetiva(ctx, org, lido)
    if efetiva is None:
        return
    problemas = _avaliar_politica(ctx, org, lido, efetiva)
    _avaliar_relatorios(ctx, org, lido)  # sem relatórios a política vale do mesmo jeito
    if not problemas:
        ctx.passed("dns.email.dmarc", f"DMARC aplicado (p={efetiva}): {lido.registro}", org)


def _dmarc_invalido(
    ctx: CheckContext, org: str, evidencia: str, confianca: Confidence = Confidence.CONFIRMED
) -> None:
    ctx.report("dns.email.dmarc_invalido", asset=org, evidence=evidencia, confidence=confianca)


def _politica_efetiva(ctx: CheckContext, org: str, lido: dmarc.Dmarc) -> str | None:
    """Política que vale; None (e achado) quando ``p``/``sp`` são inválidos.

    RFC 7489, 6.6.3, passo 6: sem ``p`` válido (ou com ``sp`` inválido) o registro
    vale como ``p=none`` se houver ``rua``; sem ``rua``, é ignorado.
    """
    if lido.politica is not None and not lido.sp_invalido:
        return lido.politica
    falha = (
        "sp= inválido"
        if lido.politica is not None
        else "falta a tag p= com none, quarantine ou reject"
    )
    efeito = "vale como p=none (só monitora)" if lido.rua else "o registro é ignorado"
    _dmarc_invalido(ctx, org, f"{lido.registro}\n({falha}; {efeito})")
    return None


def _avaliar_politica(ctx: CheckContext, org: str, lido: dmarc.Dmarc, efetiva: str) -> int:
    if efetiva == "none":
        ctx.report(
            "dns.email.dmarc_monitoramento",
            asset=org,
            evidence=lido.registro,
            confidence=Confidence.CONFIRMED,
        )
        return 1
    problemas = 0
    if lido.subdominios == "none":
        problemas += 1
        ctx.report(
            "dns.email.dmarc_monitoramento",
            asset=org,
            title="DMARC sem política para os subdomínios (sp=none)",
            evidence=lido.registro,
            confidence=Confidence.CONFIRMED,
            discriminator="sp",
        )
    if lido.pct < 100:
        problemas += 1
        ctx.report(
            "dns.email.dmarc_parcial",
            asset=org,
            evidence=lido.registro,
            details={"pct": lido.pct},
            confidence=Confidence.CONFIRMED,
        )
    return problemas


def _avaliar_relatorios(ctx: CheckContext, org: str, lido: dmarc.Dmarc) -> None:
    if not lido.rua:
        ctx.report(
            "dns.email.dmarc_sem_relatorio",
            asset=org,
            evidence=lido.registro,
            confidence=Confidence.CONFIRMED,
        )
        return
    bloqueados = dmarc.relatorios_bloqueados(ctx, lido, org)
    if not bloqueados:
        return
    esperados = [f"{org}._report._dmarc.{host}" for host in bloqueados]
    ctx.report(
        "dns.email.dmarc_sem_relatorio",
        asset=org,
        title="Destino dos relatórios DMARC não autorizou o recebimento",
        evidence=(
            f"{lido.registro}\nO rua aponta para outro domínio, que não publica a autorização "
            f"(TXT 'v=DMARC1' em {', '.join(esperados)}); os provedores não enviam os relatórios."
        ),
        details={"destinos": bloqueados, "registros_esperados": esperados},
        confidence=Confidence.FIRM,
        discriminator="externo",
    )


# -- DKIM --------------------------------------------------------------------------
def _avaliar_dkim(ctx: CheckContext, org: str) -> None:
    encontrados: list[str] = []
    falhas = 0
    for seletor in SELETORES_DKIM:
        resposta = resolver.txt(ctx, f"{seletor}._domainkey.{org}")
        if resposta.status == resolver.ERRO:
            falhas += 1
            if falhas >= MAX_FALHAS_DKIM:
                ctx.log(f"DKIM de {org} não verificado: o DNS não respondeu.")
                return
            continue
        if any(_CHAVE_DKIM.search(texto) for texto in resposta.registros):
            encontrados.append(seletor)
    if encontrados:
        ctx.passed(
            "dns.email.dkim", f"Chave DKIM publicada (seletor {', '.join(encontrados)})", org
        )
        return
    ctx.report(
        "dns.email.dkim_nao_encontrado",
        asset=org,
        evidence="Seletores testados: " + ", ".join(SELETORES_DKIM),
        confidence=Confidence.TENTATIVE,
    )
