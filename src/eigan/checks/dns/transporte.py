"""Criptografia na entrega de e-mails ao domínio: MTA-STS (RFC 8461) e TLS-RPT (RFC 8460).

Só faz sentido para domínios que recebem e-mail (têm MX). A política MTA-STS é
lida em ``https://mta-sts.<domínio>/.well-known/mta-sts.txt`` pelo cliente HTTP
da auditoria, sem seguir redirecionamentos (a norma proíbe), e o certificado
desse endereço é validado à parte, porque o cliente HTTP não valida certificados
de propósito. Falha de rede do lado de quem audita não vira achado: só
"não verificado" no registro de atividade.
"""

from __future__ import annotations

import re
import socket
import ssl
from dataclasses import dataclass, field
from pathlib import Path

from ...core import facts
from ...core.context import CheckContext
from ...core.http import Response
from ...core.models import Category, Confidence, Fact
from ...core.registry import check
from . import resolver
from .nomes import dominio_organizacional
from .resolver import dominio_do_fato, hosts_mx

MODOS = ("enforce", "testing", "none")
#: RFC 8461, 3.2: max_age não pode passar de 31557600 segundos (cerca de um ano)
MAX_AGE_MAXIMO = 31_557_600
#: RFC 8461, 3.3: tamanho máximo recomendado da política
TAMANHO_MAXIMO = 65_536

_CANDIDATO_STS = re.compile(r"^\s*v\s*=\s*stsv1\s*(?:;|$)", re.I)
_VERSAO_STS = re.compile(r"^v=STSv1\s*(?:;|$)")
_ID_STS = re.compile(r"^[A-Za-z0-9]{1,32}$")
_CANDIDATO_RPT = re.compile(r"^\s*v\s*=\s*tlsrptv1\s*(?:;|$)", re.I)
_VERSAO_RPT = re.compile(r"^v=TLSRPTv1\s*(?:;|$)")


def politica_url(org: str) -> str:
    """Endereço fixo da política (RFC 8461, 3.3). Substituído nos testes."""
    return f"https://mta-sts.{org}/.well-known/mta-sts.txt"


def buscar_politica(ctx: CheckContext, url: str) -> Response | None:
    """GET da política, sem redirecionar, no tempo limite da auditoria."""
    return ctx.http.get(
        url,
        timeout=ctx.settings.http_timeout,
        max_bytes=TAMANHO_MAXIMO,
        follow_redirects=False,
    )


@dataclass(frozen=True)
class Certificado:
    """``valido``: True/False; None quando não deu para concluir (rede, sem raízes)."""

    valido: bool | None
    erro: str = ""


def _sem_raizes(contexto: ssl.SSLContext) -> bool:
    """True quando a máquina não tem certificados raiz para validar a cadeia."""
    if contexto.cert_store_stats().get("x509_ca", 0):
        return False
    caminhos = ssl.get_default_verify_paths()
    return not any(c and Path(c).exists() for c in (caminhos.cafile, caminhos.capath))


def verificar_certificado(host: str, tempo: float, porta: int = 443) -> Certificado:
    """Valida o certificado de ``host`` (cadeia e nome), como fazem os servidores de e-mail."""
    contexto = ssl.create_default_context()
    try:
        with socket.create_connection((host, porta), timeout=tempo) as bruto:
            with contexto.wrap_socket(bruto, server_hostname=host):
                return Certificado(True)
    except ssl.SSLCertVerificationError as exc:
        if exc.verify_code == 20 and _sem_raizes(contexto):
            return Certificado(None, "sem certificados raiz nesta máquina")
        return Certificado(False, exc.verify_message or str(exc))
    except (OSError, ssl.SSLError) as exc:
        return Certificado(None, str(exc) or exc.__class__.__name__)


def ler_politica(texto: str) -> dict[str, list[str]]:
    """``chave: valor`` por linha (CRLF ou LF); ``mx`` pode repetir."""
    campos: dict[str, list[str]] = {}
    for linha in texto.splitlines():
        chave, sep, valor = linha.partition(":")
        if sep:
            campos.setdefault(chave.strip(), []).append(valor.strip())
    return campos


def mx_coberto(host: str, padrao: str) -> bool:
    """Casamento de MX com a política: ``*.`` cobre exatamente um rótulo à esquerda."""
    host = host.lower().rstrip(".")
    padrao = padrao.lower().rstrip(".")
    if padrao.startswith("*."):
        return "." in host and host.split(".", 1)[1] == padrao[2:]
    return host == padrao


@dataclass
class Avaliacao:
    """Problemas da política MTA-STS de um domínio."""

    problemas: list[str] = field(default_factory=list)  # a política não vale (MUST da norma)
    duvidosos: list[str] = field(
        default_factory=list
    )  # SHOULD da norma: parte dos remetentes falha
    descobertos: list[str] = field(default_factory=list)  # MX fora das linhas mx
    modo: str = ""

    @property
    def vazia(self) -> bool:
        return not (self.problemas or self.duvidosos or self.descobertos)


@check(
    id="dns.mta_sts",
    name="Criptografia na entrega de e-mails (MTA-STS, TLS-RPT)",
    category=Category.DNS,
    consumes=facts.DNS_DOMAIN,
    description=(
        "Para domínios que recebem e-mail: confere o anúncio _mta-sts, a política MTA-STS "
        "(HTTP 200 sem redirecionar, certificado, version/mode/max_age, cobertura dos MX) e "
        "o registro de relatórios TLS-RPT."
    ),
    findings=(
        "dns.email.mta_sts_ausente",
        "dns.email.mta_sts_invalido",
        "dns.email.mta_sts_nao_aplicado",
        "dns.email.tls_rpt_ausente",
    ),
    order=35,
)
def check_mta_sts(ctx: CheckContext, fact: Fact) -> None:
    dominio = dominio_do_fato(fact)
    if resolver.sob_plataforma(ctx, dominio, "MTA-STS"):
        return
    org = dominio_organizacional(dominio)
    if not resolver.primeira_vez(ctx, f"mta-sts:{org}"):
        return
    mx = resolver.consultar(ctx, org, "MX")
    if mx.status == resolver.ERRO:
        ctx.log(f"MTA-STS de {org} não verificado: o DNS não respondeu ({resolver.descrever(mx)}).")
        return
    servidores = hosts_mx(mx)
    if not servidores:
        return  # o domínio não recebe e-mail
    _avaliar_mta_sts(ctx, org, servidores)
    _avaliar_tls_rpt(ctx, org)


# -- MTA-STS -----------------------------------------------------------------------
def _avaliar_mta_sts(ctx: CheckContext, org: str, servidores: list[str]) -> None:
    resposta = resolver.txt(ctx, f"_mta-sts.{org}")
    if resposta.status == resolver.ERRO:
        ctx.log(
            f"MTA-STS de {org} não verificado: o DNS não respondeu ({resolver.descrever(resposta)})."
        )
        return
    candidatos = [t.strip() for t in resposta.registros if _CANDIDATO_STS.match(t)]
    if not candidatos:
        ctx.report(
            "dns.email.mta_sts_ausente",
            asset=org,
            evidence=f"Sem TXT 'v=STSv1' em _mta-sts.{org}; MX: {', '.join(servidores)}.",
            confidence=Confidence.CONFIRMED,
        )
        return
    avaliacao = Avaliacao(problemas=_problemas_anuncio(org, candidatos))
    if not _avaliar_politica(ctx, org, servidores, avaliacao) and not avaliacao.problemas:
        return  # política não verificada e anúncio correto: nada a afirmar
    _relatar(ctx, org, avaliacao)


def _problemas_anuncio(org: str, candidatos: list[str]) -> list[str]:
    """Erros do TXT _mta-sts (RFC 8461, 3.1): um único registro, versão exata e id válido."""
    nome = f"_mta-sts.{org}"
    if len(candidatos) > 1:
        return [
            f"{len(candidatos)} registros 'v=STSv1' em {nome}: os remetentes ignoram todos (deve haver um)"
        ]
    registro = candidatos[0]
    if not _VERSAO_STS.match(registro):
        return [f"'{registro}' em {nome}: a versão deve ser exatamente 'v=STSv1;' no início"]
    tags = dict(
        (chave.strip(), valor.strip())
        for chave, sep, valor in (parte.partition("=") for parte in registro.split(";"))
        if sep
    )
    identificador = tags.get("id")
    if identificador is None:
        return [f"'{registro}' em {nome}: falta o campo id="]
    if not _ID_STS.match(identificador):
        return [
            f"id='{identificador}' em {nome}: deve ter de 1 a 32 letras ou números, sem outros símbolos"
        ]
    return []


def _avaliar_politica(
    ctx: CheckContext, org: str, servidores: list[str], avaliacao: Avaliacao
) -> bool:
    """Busca e valida a política. False quando nada se pôde concluir sobre ela."""
    url = politica_url(org)
    host = f"mta-sts.{org}"
    resposta = buscar_politica(ctx, url)
    if resposta is None:
        if _nome_inexistente(ctx, host):
            avaliacao.problemas.append(
                f"o nome {host} não existe no DNS: a política em {url} não pode ser lida"
            )
            return True
        ctx.log(f"Política MTA-STS de {org} não verificada: sem resposta de {url}.")
        return False
    if resposta.status != 200:
        avaliacao.problemas.append(
            f"{url} respondeu HTTP {resposta.status} (a norma exige 200, sem redirecionamento)"
        )
        return True
    if resposta.truncated:
        avaliacao.problemas.append(f"a política em {url} passa de 64 KB")
    if resposta.content_type != "text/plain":
        avaliacao.duvidosos.append(
            f"{url} é servido como '{resposta.content_type or 'sem Content-Type'}' (deve ser text/plain)"
        )
    certificado = verificar_certificado(host, ctx.settings.http_timeout)
    if certificado.valido is False:
        avaliacao.problemas.append(f"certificado de {host} não é válido: {certificado.erro}")
    elif certificado.valido is None:
        ctx.log(f"Certificado de {host} não verificado: {certificado.erro}.")
    _validar_campos(ler_politica(resposta.text), servidores, avaliacao)
    return True


def _nome_inexistente(ctx: CheckContext, host: str) -> bool:
    respostas = [resolver.consultar(ctx, host, tipo) for tipo in ("A", "AAAA")]
    return all(r.ausente for r in respostas)


def _campo(campos: dict[str, list[str]], nome: str, avaliacao: Avaliacao) -> str:
    """Primeiro valor de ``nome``; anota o erro quando falta (os nomes diferenciam maiúsculas)."""
    valores = campos.get(nome)
    if valores:
        return valores[0]
    parecido = next((chave for chave in campos if chave.lower() == nome), None)
    if parecido:
        avaliacao.problemas.append(f"o campo '{parecido}' deve ser escrito exatamente '{nome}'")
    else:
        avaliacao.problemas.append(f"falta o campo '{nome}' na política")
    return ""


def _validar_campos(
    campos: dict[str, list[str]], servidores: list[str], avaliacao: Avaliacao
) -> None:
    """Campos obrigatórios da política (RFC 8461, 3.2) e cobertura dos MX (4.1)."""
    versao = _campo(campos, "version", avaliacao)
    if versao and versao != "STSv1":
        avaliacao.problemas.append(f"version: {versao} (deve ser STSv1)")
    modo = _campo(campos, "mode", avaliacao)
    if modo and modo not in MODOS:
        avaliacao.problemas.append(f"mode: {modo} (use enforce, testing ou none, em minúsculas)")
    avaliacao.modo = modo if modo in MODOS else ""
    idade = _campo(campos, "max_age", avaliacao)
    if idade and (not (idade.isascii() and idade.isdigit()) or len(idade) > 10):
        avaliacao.problemas.append(f"max_age: {idade} (deve ser um número de segundos)")
    elif idade and int(idade) > MAX_AGE_MAXIMO:
        avaliacao.problemas.append(f"max_age: {idade} passa do máximo de {MAX_AGE_MAXIMO} segundos")
    if avaliacao.modo not in ("enforce", "testing"):
        return
    padroes = campos.get("mx", [])
    if not padroes:
        avaliacao.problemas.append("falta pelo menos uma linha mx (obrigatória fora do mode: none)")
        return
    avaliacao.descobertos = [h for h in servidores if not any(mx_coberto(h, p) for p in padroes)]


def _relatar(ctx: CheckContext, org: str, avaliacao: Avaliacao) -> None:
    url = politica_url(org)
    if avaliacao.vazia:
        if avaliacao.modo == "enforce":
            ctx.passed("dns.email.mta_sts", "MTA-STS em modo enforce cobrindo todos os MX", org)
        elif avaliacao.modo:
            ctx.report(
                "dns.email.mta_sts_nao_aplicado",
                asset=org,
                evidence=f"Política em {url} com mode: {avaliacao.modo}.",
                confidence=Confidence.CONFIRMED,
            )
        return
    linhas = avaliacao.problemas + avaliacao.duvidosos
    if avaliacao.descobertos:
        linhas.append("MX fora das linhas mx da política: " + ", ".join(avaliacao.descobertos))
    ctx.report(
        "dns.email.mta_sts_invalido",
        asset=org,
        evidence="\n".join(linhas),
        details={"problemas": linhas, "politica": url, "mode": avaliacao.modo},
        confidence=Confidence.CONFIRMED
        if avaliacao.problemas or avaliacao.descobertos
        else Confidence.FIRM,
    )


# -- TLS-RPT -----------------------------------------------------------------------
def _problemas_tls_rpt(candidatos: list[str]) -> list[str]:
    """Erros do TXT _smtp._tls (RFC 8460, 3): um registro, versão exata e rua mailto:/https:."""
    if len(candidatos) > 1:
        return [
            f"{len(candidatos)} registros 'v=TLSRPTv1': os remetentes ignoram todos (deve haver um)"
        ]
    registro = candidatos[0]
    if not _VERSAO_RPT.match(registro):
        return [f"'{registro}': a versão deve ser exatamente 'v=TLSRPTv1' no início"]
    rua = ""
    for parte in registro.split(";")[1:]:
        chave, sep, valor = parte.partition("=")
        if sep and chave.strip() == "rua":
            rua = valor.strip()
            break
    if not rua:
        return [f"'{registro}': falta o campo rua= com o destino dos relatórios"]
    uris = [uri.strip() for uri in rua.split(",")]
    validos = [
        u
        for u in uris
        if (u.lower().startswith("mailto:") and "@" in u) or u.lower().startswith("https://")
    ]
    if not validos:
        return [f"'{registro}': rua sem endereço mailto: ou https:// válido"]
    return []


def _avaliar_tls_rpt(ctx: CheckContext, org: str) -> None:
    nome = f"_smtp._tls.{org}"
    resposta = resolver.txt(ctx, nome)
    if resposta.status == resolver.ERRO:
        ctx.log(
            f"TLS-RPT de {org} não verificado: o DNS não respondeu ({resolver.descrever(resposta)})."
        )
        return
    candidatos = [t.strip() for t in resposta.registros if _CANDIDATO_RPT.match(t)]
    if not candidatos:
        ctx.report(
            "dns.email.tls_rpt_ausente",
            asset=org,
            evidence=f"Sem TXT 'v=TLSRPTv1' em {nome}.",
            confidence=Confidence.CONFIRMED,
        )
        return
    problemas = _problemas_tls_rpt(candidatos)
    if not problemas:
        ctx.passed("dns.email.tls_rpt", f"Relatórios TLS-RPT publicados em {nome}", org)
        return
    ctx.report(
        "dns.email.tls_rpt_ausente",
        asset=org,
        title="Registro TLS-RPT inválido",
        evidence="\n".join(problemas),
        details={"problemas": problemas},
        confidence=Confidence.CONFIRMED,
        discriminator="invalido",
    )
