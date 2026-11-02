"""Zona DNS do domínio: inventário de registros, CAA, DNSSEC e transferência de zona (AXFR)."""

from __future__ import annotations

import base64
import ipaddress
import time

from ...core import facts
from ...core.context import CheckContext
from ...core.models import Category, Confidence, Fact
from ...core.netutil import is_metadata_address
from ...core.redact import redact
from ...core.registry import check
from . import resolver
from .nomes import dominio_organizacional
from .resolver import dominio_do_fato

TIPOS_INVENTARIO = ("A", "AAAA", "MX", "NS", "TXT", "CAA", "CNAME", "SOA")
MAX_SERVIDORES_AXFR = 6
MAX_IPS_POR_SERVIDOR = 2
ORCAMENTO_AXFR = 90.0  # segundos por zona; o check inteiro tem 120 s
#: algoritmo RSA/MD5 do DNSSEC: o key tag dele é calculado de outro jeito (e ele está aposentado)
_ALGORITMO_RSAMD5 = 1


def cadeia_ate_raiz(nome: str) -> list[str]:
    """``a.exemplo.com.br`` -> ``[a.exemplo.com.br, exemplo.com.br, com.br, br]``."""
    rotulos = nome.split(".")
    return [".".join(rotulos[i:]) for i in range(len(rotulos))]


# -- inventário ----------------------------------------------------------------------
@check(
    id="dns.records",
    name="Registros DNS do domínio",
    category=Category.DNS,
    consumes=facts.DNS_DOMAIN,
    description=(
        "Consulta A, AAAA, MX, NS, TXT, CAA, CNAME e SOA do domínio e registra o inventário "
        "(com o domínio organizacional) para as demais checagens."
    ),
    findings=(),
    facts=(facts.DNS_RECORDS,),
    order=10,
)
def check_registros(ctx: CheckContext, fact: Fact) -> None:
    dominio = dominio_do_fato(fact)
    dados: dict[str, list[str]] = {}
    status: dict[str, str] = {}
    for tipo in TIPOS_INVENTARIO:
        ctx.check_cancel()
        resposta = resolver.consultar(ctx, dominio, tipo)
        dados[tipo.lower()] = list(resposta.registros)
        status[tipo] = resposta.status
    if all(valor == resolver.ERRO for valor in status.values()):
        ctx.log(f"DNS de {dominio} não respondeu; inventário de registros não coletado.")
        return
    if all(valor in (resolver.NXDOMAIN, resolver.ERRO) for valor in status.values()):
        ctx.log(f"O domínio {dominio} não existe no DNS (NXDOMAIN).")
        return
    org = dominio_organizacional(dominio)
    resumo = ", ".join(f"{tipo}: {len(dados[tipo.lower()])}" for tipo in TIPOS_INVENTARIO)
    dados["txt"] = [redact(texto) for texto in dados["txt"]]  # TXT às vezes guarda tokens
    ctx.add_fact(
        facts.DNS_RECORDS,
        dominio,
        f"Registros DNS de {dominio} ({resumo})",
        domain=dominio,
        org=org,
        **dados,
    )


# -- CAA -----------------------------------------------------------------------------
def restringe_emissao(registros: tuple[str, ...]) -> bool:
    """O conjunto CAA limita certificados comuns: só a propriedade ``issue`` faz isso.

    RFC 8659: com apenas ``iodef`` ou propriedades desconhecidas o CAA não restringe nada
    (seção 3), e ``issuewild`` só vale para nomes curinga (seção 4.3).
    """
    for registro in registros:
        partes = registro.split(None, 2)
        if len(partes) >= 2 and partes[1].lower() == "issue":
            return True
    return False


@check(
    id="dns.caa",
    name="Autoridades certificadoras autorizadas (CAA)",
    category=Category.DNS,
    consumes=facts.DNS_DOMAIN,
    description=(
        "Procura o conjunto CAA que vale para o nome, subindo a árvore do DNS até o nível "
        "abaixo da raiz (RFC 8659), e confere se ele limita a emissão de certificados."
    ),
    findings=("dns.caa.ausente",),
    order=40,
)
def check_caa(ctx: CheckContext, fact: Fact) -> None:
    dominio = dominio_do_fato(fact)
    if resolver.sob_plataforma(ctx, dominio, "CAA"):
        return
    org = dominio_organizacional(dominio)
    nomes = cadeia_ate_raiz(dominio)
    for nome in nomes:
        ctx.check_cancel()
        resposta = resolver.consultar(ctx, nome, "CAA")
        if resposta.status == resolver.ERRO:
            ctx.log(f"CAA de {nome} não verificado: o DNS não respondeu ({resposta.erro}).")
            return
        if resposta.status == resolver.NXDOMAIN and nome == org:
            ctx.log(f"CAA: o domínio {org} não existe no DNS.")
            return
        if resposta.ok:
            _avaliar_caa(ctx, nome, resposta.registros, org)
            return
    if not resolver.primeira_vez(ctx, f"caa:{org}"):
        return  # a mesma organização já foi avaliada por outro subdomínio
    ctx.report(
        "dns.caa.ausente",
        asset=org,
        evidence="Nenhum registro CAA em: " + ", ".join(nomes),
        confidence=Confidence.CONFIRMED,
    )


def _avaliar_caa(ctx: CheckContext, nome: str, registros: tuple[str, ...], org: str) -> None:
    texto = "; ".join(registros)
    if restringe_emissao(registros):
        ctx.passed("dns.caa", f"CAA publicado em {nome}: {texto}", org)
        return
    ctx.report(
        "dns.caa.ausente",
        asset=org,
        title="Registro CAA sem a propriedade issue (não limita os certificados comuns)",
        evidence=(
            f"CAA em {nome}: {texto}\nSem 'issue', qualquer autoridade certificadora ainda pode "
            "emitir certificados para nomes comuns (RFC 8659, seções 3 e 4.3)."
        ),
        details={"caa": list(registros), "nome": nome},
        confidence=Confidence.CONFIRMED,
    )


# -- DNSSEC --------------------------------------------------------------------------
def tag_da_chave(registro: str) -> int | None:
    """Key tag de um DNSKEY em texto (RFC 4034, apêndice B); None se não der para calcular."""
    partes = registro.split()
    try:
        flags, protocolo, algoritmo = int(partes[0]), int(partes[1]), int(partes[2])
        chave = base64.b64decode("".join(partes[3:]), validate=True)
        if algoritmo == _ALGORITMO_RSAMD5:
            return None
        rdata = flags.to_bytes(2, "big") + bytes((protocolo, algoritmo)) + chave
    except (IndexError, ValueError, OverflowError):
        return None
    soma = sum(byte << 8 if i % 2 == 0 else byte for i, byte in enumerate(rdata))
    return (soma + (soma >> 16)) & 0xFFFF


def tag_do_ds(registro: str) -> int | None:
    """Primeiro campo de um registro DS: o key tag da chave a que ele aponta."""
    partes = registro.split()
    return int(partes[0]) if partes and partes[0].isascii() and partes[0].isdigit() else None


def ds_sem_chave(ds: tuple[str, ...], chaves: tuple[str, ...]) -> bool:
    """True quando nenhum DS corresponde a uma chave publicada (só com tags calculadas)."""
    tags_ds = [tag_do_ds(registro) for registro in ds]
    tags_chaves = [tag_da_chave(registro) for registro in chaves]
    if None in tags_ds or None in tags_chaves:
        return False  # registro que não sabemos ler: nada a afirmar
    return not set(tags_ds) & set(tags_chaves)


@check(
    id="dns.dnssec",
    name="Assinatura DNSSEC",
    category=Category.DNS,
    consumes=facts.DNS_DOMAIN,
    description=(
        "Verifica se o domínio organizacional publica DNSKEY, se o DS está no domínio pai e "
        "se o DS corresponde a uma chave publicada."
    ),
    findings=("dns.dnssec.ausente", "dns.dnssec.incompleto", "dns.dnssec.quebrado"),
    order=45,
)
def check_dnssec(ctx: CheckContext, fact: Fact) -> None:
    dominio = dominio_do_fato(fact)
    if resolver.sob_plataforma(ctx, dominio, "DNSSEC"):
        return
    org = dominio_organizacional(dominio)
    if not resolver.primeira_vez(ctx, f"dnssec:{org}"):
        return
    # CD: um resolvedor que valida esconderia (SERVFAIL) justamente a cadeia quebrada
    ds = resolver.consultar(ctx, org, "DS", sem_validacao=True)
    chaves = resolver.consultar(ctx, org, "DNSKEY", sem_validacao=True)
    if resolver.ERRO in (ds.status, chaves.status):
        ctx.log(f"DNSSEC de {org} não verificado: o DNS não respondeu ({ds.erro or chaves.erro}).")
        return
    if resolver.NXDOMAIN in (ds.status, chaves.status):
        ctx.log(f"DNSSEC: o domínio {org} não existe no DNS.")
        return
    if ds.ok:
        _avaliar_ds(ctx, org, ds.registros, chaves.registros)
    elif chaves.ok:
        ctx.report(
            "dns.dnssec.incompleto",
            asset=org,
            evidence=f"{org} publica {len(chaves.registros)} DNSKEY, mas não há DS no domínio pai.",
            confidence=Confidence.CONFIRMED,
        )
    else:
        ctx.report(
            "dns.dnssec.ausente",
            asset=org,
            evidence=f"{org}: sem registro DS e sem DNSKEY.",
            confidence=Confidence.CONFIRMED,
        )


def _avaliar_ds(ctx: CheckContext, org: str, ds: tuple[str, ...], chaves: tuple[str, ...]) -> None:
    if not chaves:
        motivo = "o domínio pai publica DS, mas a zona não publica nenhuma chave DNSKEY"
    elif ds_sem_chave(ds, chaves):
        tags = ", ".join(sorted({registro.split()[0] for registro in ds}))
        motivo = f"nenhuma chave DNSKEY publicada corresponde ao DS do domínio pai (key tag {tags})"
    else:
        ctx.passed("dns.dnssec", f"DNSSEC ativo: DS publicado para {org}", org)
        return
    ctx.report(
        "dns.dnssec.quebrado",
        asset=org,
        evidence=f"{org}: {motivo}.\nDS: " + "; ".join(ds),
        details={"ds": list(ds), "dnskey": len(chaves)},
        confidence=Confidence.CONFIRMED,
    )


# -- AXFR ----------------------------------------------------------------------------
@check(
    id="dns.axfr",
    name="Transferência de zona (AXFR)",
    category=Category.DNS,
    consumes=facts.DNS_DOMAIN,
    description=(
        "Pede a transferência da zona (AXFR, só leitura) a cada servidor NS do domínio; "
        "servidor que entrega a zona a qualquer um é achado."
    ),
    findings=("dns.axfr.permitido",),
    active=True,
    timeout=120.0,
    order=60,
)
def check_axfr(ctx: CheckContext, fact: Fact) -> None:
    dominio = dominio_do_fato(fact)
    if resolver.sob_plataforma(ctx, dominio, "AXFR"):
        return
    org = dominio_organizacional(dominio)
    zonas = [org]
    if dominio != org and resolver.consultar(ctx, dominio, "NS").ok:
        zonas.append(dominio)  # subdomínio delegado: zona própria
    for zona in zonas:
        if resolver.primeira_vez(ctx, f"axfr:{zona}"):
            _testar_zona(ctx, zona)


_REDES_INTERNAS = tuple(
    ipaddress.ip_network(rede)
    for rede in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")
)


def ip_fora_do_escopo(ip: str) -> bool:
    """True para loopback, link-local, privado, multicast e metadados de nuvem.

    Um NS publicado pelo alvo não pode fazer o auditor sondar a própria máquina
    ou a rede interna de quem audita.
    """
    try:
        endereco = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if (
        endereco.is_loopback
        or endereco.is_link_local
        or endereco.is_unspecified
        or endereco.is_multicast
        or is_metadata_address(ip)
    ):
        return True
    return any(endereco.version == rede.version and endereco in rede for rede in _REDES_INTERNAS)


def _ips(ctx: CheckContext, servidor: str) -> list[str]:
    enderecos: list[str] = []
    for tipo in ("A", "AAAA"):
        enderecos.extend(resolver.consultar(ctx, servidor, tipo).registros)
    permitidos = [ip for ip in enderecos if not ip_fora_do_escopo(ip)]
    if len(permitidos) < len(enderecos):
        ctx.log(f"AXFR em {servidor}: endereços locais ou privados ignorados (fora do escopo).")
    return permitidos[:MAX_IPS_POR_SERVIDOR]


def _testar_zona(ctx: CheckContext, zona: str) -> None:
    ns = resolver.consultar(ctx, zona, "NS")
    if not ns.ok:
        ctx.log(f"AXFR de {zona} não verificado: sem servidores NS ({ns.status} {ns.erro}).")
        return
    servidores = sorted(ns.registros)[:MAX_SERVIDORES_AXFR]
    recusaram: list[str] = []
    incompleto = False
    prazo = time.monotonic() + ORCAMENTO_AXFR
    for servidor in servidores:
        ctx.check_cancel()
        if time.monotonic() > prazo:
            ctx.log(f"AXFR em {servidor} não verificado: o tempo da checagem acabou.")
            incompleto = True
            continue
        resultado = _tentar_servidor(ctx, zona, servidor)
        if resultado is None:
            ctx.log(f"AXFR em {servidor} não verificado: sem resposta.")
        elif resultado:
            recusaram.append(servidor)
    if not incompleto and len(recusaram) == len(servidores):
        ctx.passed("dns.axfr", f"Transferência de zona recusada por {', '.join(recusaram)}", zona)


def _tentar_servidor(ctx: CheckContext, zona: str, servidor: str) -> bool | None:
    """True = recusou; False = entregou a zona (achado); None = sem resposta."""
    respondeu = False
    for ip in _ips(ctx, servidor):
        ctx.check_cancel()
        resultado = resolver.axfr(ip, zona)
        if resultado.permitida:
            _reportar_axfr(ctx, zona, servidor, ip, resultado.nomes)
            return False
        respondeu = respondeu or resultado.respondeu
    return True if respondeu else None


def _reportar_axfr(
    ctx: CheckContext, zona: str, servidor: str, ip: str, nomes: tuple[str, ...]
) -> None:
    completos = [zona if nome == "@" else f"{nome}.{zona}" for nome in nomes]
    amostra = ", ".join(completos[:10]) + (" ..." if len(completos) > 10 else "")
    ctx.report(
        "dns.axfr.permitido",
        asset=zona,
        evidence=f"{servidor} ({ip}) entregou a zona {zona}: {len(completos)} nomes. Ex.: {amostra}",
        details={"servidor": servidor, "ip": ip, "nomes": len(completos)},
        confidence=Confidence.CONFIRMED,
        discriminator=servidor,
    )
