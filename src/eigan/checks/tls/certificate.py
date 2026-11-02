"""Certificado do serviço TLS: validade, confiança, nome, chave e assinatura.

O certificado é lido sem validar nada (para conseguir auditar justamente os inválidos) e
interpretado por um leitor DER próprio. A confiança é conferida em uma segunda conexão, com
o repositório de autoridades do sistema (``ssl.create_default_context``), que devolve o
motivo exato da recusa. A conferência de nome segue a RFC 9525: só o campo SAN conta.
"""

from __future__ import annotations

import ssl
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ...core import facts, netutil
from ...core.context import CheckContext
from ...core.http import insecure_context
from ...core.models import Category, Confidence, Fact, Severity
from ...core.registry import check
from . import kb_certificado, suites, wire, x509
from .asn1 import Asn1Error
from .common import Endpoint, endpoint_of, io_timeout, severity_by_exposure, tech_hint
from .kb_certificado import (
    EXPIRED,
    EXPIRING,
    INCOMPLETE_CHAIN,
    NAME_MISMATCH,
    NOT_YET_VALID,
    SELF_SIGNED,
    UNTRUSTED,
    WEAK_KEY,
    WEAK_SIGNATURE,
)
from .x509 import Certificate

RSA_MIN_BITS = 2048
EC_MIN_BITS = 256
DSA_MIN_BITS = 2048
WARN_WINDOW = timedelta(days=30)
URGENT_WINDOW = timedelta(days=7)
#: pequena diferença de relógio entre esta máquina e o servidor não é problema do certificado
CLOCK_TOLERANCE = timedelta(minutes=10)
#: quantos nomes do SAN vão para detalhes e inventário (o certificado é controlado pelo alvo)
_MAX_NAMES = 50

# Estados da verificação da cadeia
TRUSTED = "confiavel"
REJECTED = "rejeitado"
NOT_EVALUATED = "nao_avaliado"

# Códigos X509_V_ERR_* do OpenSSL (include/openssl/x509_vfy.h)
ERR_NOT_YET_VALID = 9
ERR_EXPIRED = 10
ERR_DEPTH_ZERO_SELF_SIGNED = 18
ERR_ISSUER_LOCALLY = 20
ERR_VERIFY_LEAF = 21
_ISSUER_UNKNOWN = frozenset({ERR_ISSUER_LOCALLY, ERR_VERIFY_LEAF})

#: onde as distribuições Linux guardam as autoridades, para quando o OpenSSL embutido no
#: executável não encontra o repositório do sistema (lista conferida em crypto/x509 do Go)
_LINUX_CA_FILES = (
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/pki/tls/cacert.pem",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/cert.pem",
)
_LINUX_CA_DIRS = ("/etc/ssl/certs", "/etc/pki/tls/certs")


@dataclass(frozen=True)
class Peer:
    """O que o servidor apresentou: o certificado final e o tamanho da cadeia entregue."""

    der: bytes
    chain_size: int | None = None  # None = não deu para saber


@dataclass(frozen=True)
class Verdict:
    """Resultado da verificação da cadeia com as autoridades do sistema."""

    state: str
    code: int = 0
    message: str = ""


# -- leitura do certificado --------------------------------------------------------------
def _now() -> datetime:
    return datetime.now(UTC)


def _lazy_root_store() -> bool:
    """No Windows as raízes são baixadas sob demanda: faltar uma não prova que ela não é confiável."""
    return sys.platform == "win32"


def _reader_context() -> ssl.SSLContext:
    """Contexto só para ler o certificado de qualquer servidor, inclusive os antigos."""
    context = insecure_context()
    context.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0)
    return context


def _delivered_chain(tls: ssl.SSLSocket) -> int | None:
    """Quantos certificados o servidor entregou (só a partir do Python 3.13)."""
    method = getattr(tls, "get_unverified_chain", None)
    if method is None:  # Python < 3.13: o objeto interno já oferece o método (desde 3.10)
        method = getattr(getattr(tls, "_sslobj", None), "get_unverified_chain", None)
    if method is None:
        return None
    try:
        return len(method()) or None
    except (ssl.SSLError, ValueError, AttributeError, TypeError):
        return None


def _ssl_peer(endpoint: Endpoint, sni: str | None, timeout: float) -> Peer | None:
    sock = netutil.tcp_connect(endpoint.host, endpoint.port, timeout)
    if sock is None:
        return None
    try:
        sock.settimeout(timeout)
        with _reader_context().wrap_socket(sock, server_hostname=sni) as tls:
            der = tls.getpeercert(binary_form=True)
            return Peer(der, _delivered_chain(tls)) if der else None
    except (ssl.SSLError, OSError, ValueError):
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _raw_peer(endpoint: Endpoint, timeout: float) -> Peer | None:
    """Servidor antigo demais para o OpenSSL local: lê o certificado do handshake em texto claro."""
    attempts = (
        (suites.TLS12, suites.TLS12_PROBE),
        (suites.TLS10, suites.LEGACY_PROBE),
        (suites.SSL3, suites.SSL3_PROBE),
    )
    for version, offered in attempts:
        payload = wire.client_hello(version, offered, endpoint.sni)
        chain = wire.read_certificates(endpoint.host, endpoint.port, payload, timeout)
        if chain:
            return Peer(chain[0], len(chain))
    return None


def fetch_peer(endpoint: Endpoint, timeout: float) -> Peer | None:
    """Certificado que o servidor apresenta (None se não houver TLS ou conexão)."""
    if not netutil.port_open(endpoint.host, endpoint.port, timeout):
        return None
    peer = _ssl_peer(endpoint, endpoint.sni, timeout)
    if peer is None and endpoint.sni:
        peer = _ssl_peer(endpoint, None, timeout)  # o servidor pode recusar o nome pedido
    return peer or _raw_peer(endpoint, timeout)


# -- verificação da cadeia ---------------------------------------------------------------
def _load_linux_store(context: ssl.SSLContext) -> None:
    """Carrega as autoridades do Linux quando o caminho padrão do OpenSSL não existe."""
    if sys.platform == "win32":
        return
    for name in _LINUX_CA_FILES:
        if Path(name).is_file():
            context.load_verify_locations(cafile=name)
            return
    for name in _LINUX_CA_DIRS:
        if Path(name).is_dir():
            context.load_verify_locations(capath=name)
            return


def _has_authorities(context: ssl.SSLContext) -> bool:
    """Há autoridades carregadas? Um diretório (capath) só é lido sob demanda pelo OpenSSL."""
    if context.cert_store_stats().get("x509_ca"):
        return True
    default_dir = ssl.get_default_verify_paths().capath
    names = ([default_dir] if default_dir else []) + list(_LINUX_CA_DIRS)
    for name in names:
        try:
            if Path(name).is_dir() and any(Path(name).iterdir()):
                return True
        except OSError:  # sem permissão para listar: trata como repositório vazio
            continue
    return False


def trust_context() -> ssl.SSLContext | None:
    """Contexto que valida a cadeia com o repositório do sistema (None se ele estiver vazio)."""
    try:
        context = ssl.create_default_context()
        if not context.cert_store_stats().get("x509_ca"):
            _load_linux_store(context)
    except (ssl.SSLError, OSError, ValueError):
        return None
    if not _has_authorities(context):
        return None
    # O nome é conferido à parte (RFC 9525). Interessa só a cadeia: o modo estrito do Python 3.13+
    # recusaria certificados que os navegadores aceitam, e chave curta tem achado próprio.
    context.check_hostname = False
    context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    try:
        context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        context.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        pass
    context.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0)
    return context


def verify_chain(endpoint: Endpoint, timeout: float) -> Verdict:
    """Tenta o handshake exigindo cadeia válida. Falha de rede nunca vira achado."""
    context = trust_context()
    if context is None:
        return Verdict(NOT_EVALUATED, message="repositório de autoridades vazio nesta máquina")
    sock = netutil.tcp_connect(endpoint.host, endpoint.port, timeout)
    if sock is None:
        return Verdict(NOT_EVALUATED, message="não foi possível conectar")
    try:
        sock.settimeout(timeout)
        with context.wrap_socket(sock, server_hostname=endpoint.sni):
            return Verdict(TRUSTED)
    except ssl.SSLCertVerificationError as exc:
        return Verdict(REJECTED, exc.verify_code, exc.verify_message)
    except (ssl.SSLError, OSError, ValueError) as exc:
        return Verdict(NOT_EVALUATED, message=str(exc))
    finally:
        try:
            sock.close()
        except OSError:
            pass


# -- regras ------------------------------------------------------------------------------
def renewal_window(lifetime: timedelta) -> timedelta:
    """Quanto antes do fim a renovação normalmente acontece (recomendação do Let's Encrypt).

    Um terço da validade; metade, nos certificados com menos de 10 dias.
    """
    return lifetime / 2 if lifetime < timedelta(days=10) else lifetime / 3


def expiry_severity(left: timedelta, lifetime: timedelta) -> Severity | None:
    """Severidade de um vencimento próximo; None quando ainda está dentro do normal.

    Vale < 30 dias (média) e < 7 dias (alta), mas nunca antes da janela normal de renovação:
    um certificado de 47 dias com 20 dias restantes, ou um de 6 dias com 4, está em dia.
    """
    window = renewal_window(lifetime)
    if left < min(URGENT_WINDOW, window / 2):
        return Severity.HIGH
    if left < min(WARN_WINDOW, window):
        return Severity.MEDIUM
    return None


def _date(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%d %H:%M UTC")


def _issuer_label(cert: Certificate) -> str:
    return cert.issuer.get("O") or cert.issuer.get("CN") or cert.issuer.text


def _names_label(cert: Certificate) -> str:
    if cert.names:
        shown = ", ".join(cert.names[:8])
        return shown + (f" e mais {len(cert.names) - 8}" if len(cert.names) > 8 else "")
    return f"nenhum nome no SAN (CN: {cert.common_name or 'vazio'})"


def _dates_ok(cert: Certificate, moment: datetime) -> bool:
    return cert.not_before <= moment + CLOCK_TOLERANCE and moment <= cert.not_after


def _audit_dates(
    ctx: CheckContext, endpoint: Endpoint, cert: Certificate, moment: datetime
) -> None:
    asset = endpoint.asset
    tech = tech_hint(ctx, endpoint.host)
    if cert.not_after < cert.not_before:
        ctx.log(f"{asset}: datas do certificado incoerentes (fim antes do início); não avaliadas.")
        return
    if moment > cert.not_after:
        ago = (moment - cert.not_after).days
        ctx.report(
            EXPIRED,
            asset=asset,
            evidence=f"Venceu em {_date(cert.not_after)} (há {ago} dia(s)).",
            details={"not_after": cert.not_after.isoformat(), "dias_vencido": ago},
            confidence=Confidence.CONFIRMED,
            tech=tech,
        )
        return
    if moment + CLOCK_TOLERANCE < cert.not_before:
        ctx.report(
            NOT_YET_VALID,
            asset=asset,
            evidence=(
                f"Só vale a partir de {_date(cert.not_before)}; o relógio desta máquina marca "
                f"{_date(moment)}."
            ),
            details={"not_before": cert.not_before.isoformat()},
            confidence=Confidence.CONFIRMED,
            tech=tech,
        )
        return
    left = cert.not_after - moment
    severity = expiry_severity(left, cert.lifetime)
    if severity is None:
        ctx.passed(
            "tls.certificado.validade",
            f"Certificado válido até {cert.not_after:%Y-%m-%d} (faltam {left.days} dias)",
            asset,
        )
        return
    ctx.report(
        EXPIRING,
        asset=asset,
        severity=severity,
        evidence=(
            f"Vence em {_date(cert.not_after)} (faltam {left.days} dia(s), "
            f"de uma validade total de {cert.lifetime.days} dias)."
        ),
        details={"not_after": cert.not_after.isoformat(), "dias_restantes": left.days},
        confidence=Confidence.CONFIRMED,
        tech=tech,
    )


def _audit_trust(
    ctx: CheckContext,
    endpoint: Endpoint,
    cert: Certificate,
    peer: Peer,
    verdict: Verdict,
    moment: datetime,
) -> None:
    asset = endpoint.asset
    if verdict.state == NOT_EVALUATED:
        ctx.log(f"{asset}: a cadeia do certificado não foi avaliada ({verdict.message}).")
        return
    if verdict.state == TRUSTED:
        ctx.passed(
            "tls.certificado.confianca",
            f"Cadeia confiável: emitido por {_issuer_label(cert)}",
            asset,
        )
        return
    if verdict.code in (ERR_EXPIRED, ERR_NOT_YET_VALID) and not _dates_ok(cert, moment):
        return  # a cadeia é confiável; o problema é a data, que já tem achado próprio
    if endpoint.private_pki:
        ctx.log(
            f"{asset}: cadeia própria do serviço {endpoint.service or ''} "
            f"({verdict.message}); a confiança é configurada no cliente."
        )
        return
    _report_untrusted(ctx, endpoint, cert, peer, verdict)


def _report_untrusted(
    ctx: CheckContext, endpoint: Endpoint, cert: Certificate, peer: Peer, verdict: Verdict
) -> None:
    severity = severity_by_exposure(endpoint.host, Severity.HIGH, Severity.MEDIUM)
    details: dict[str, Any] = {
        "codigo": verdict.code,
        "motivo": verdict.message,
        "emissor": cert.issuer.text,
    }
    asset = endpoint.asset
    tech = tech_hint(ctx, endpoint.host)
    reason = f"A verificação recusou o certificado: {verdict.message}."
    if verdict.code == ERR_DEPTH_ZERO_SELF_SIGNED or cert.self_signed:
        evidence = f"{reason} Titular e emissor são o mesmo: {cert.subject.text}."
        ctx.report(
            SELF_SIGNED,
            severity=severity,
            evidence=evidence,
            confidence=Confidence.CONFIRMED,
            asset=asset,
            details=details,
            tech=tech,
        )
        return
    if verdict.code in _ISSUER_UNKNOWN and peer.chain_size == 1 and cert.ca_issuers:
        evidence = (
            f"{reason} O servidor entregou só o certificado final, emitido por "
            f"{cert.issuer.text}; ou falta o intermediário (disponível em "
            f"{cert.ca_issuers[0]}) ou a autoridade não é conhecida por esta máquina."
        )
        ctx.report(
            INCOMPLETE_CHAIN,
            evidence=evidence,
            confidence=Confidence.TENTATIVE,
            asset=asset,
            details=details,
            tech=tech,
        )
        return
    lazy = verdict.code in _ISSUER_UNKNOWN and _lazy_root_store()
    if lazy:
        severity = Severity.LOW  # sem corroboração, uma raiz ausente no Windows não é prova
    evidence = f"{reason} Emissor: {cert.issuer.text}."
    if lazy:
        evidence += (
            " O Windows baixa autoridades sob demanda: confira no navegador se esta raiz "
            "é mesmo desconhecida antes de agir."
        )
    ctx.report(
        UNTRUSTED,
        severity=severity,
        evidence=evidence,
        confidence=Confidence.TENTATIVE if lazy else Confidence.FIRM,
        asset=asset,
        details=details,
        tech=tech,
    )


def _audit_name(ctx: CheckContext, endpoint: Endpoint, cert: Certificate) -> None:
    asset = endpoint.asset
    reference = endpoint.reference
    if x509.matches_host(cert, reference):
        ctx.passed("tls.certificado.nome", f"O certificado vale para {reference}", asset)
        return
    if endpoint.by_ip:
        # Quem usa o serviço chega pelo nome; acessar pelo IP não diz nada sobre esse nome.
        ctx.log(f"{asset}: acessado pelo IP; o nome do certificado não foi conferido.")
        return
    if endpoint.private_pki:
        ctx.log(f"{asset}: PKI própria do serviço; o nome esperado é configurado no cliente.")
        return
    only_cn = not cert.san_dns and x509.dns_matches(cert.common_name or "", reference)
    note = " O nome só aparece no CN, que os clientes modernos ignoram." if only_cn else ""
    ctx.report(
        NAME_MISMATCH,
        asset=asset,
        evidence=f"Acessado como {reference}; o certificado vale para: {_names_label(cert)}.{note}",
        details={
            "esperado": reference,
            "san": list(cert.names[:_MAX_NAMES]),
            "total_san": len(cert.names),
            "cn": cert.common_name,
        },
        confidence=Confidence.CONFIRMED,
        tech=tech_hint(ctx, endpoint.host),
    )


def _weak_key_limit(cert: Certificate) -> int | None:
    """Tamanho mínimo aceito para o tipo da chave (None = sem critério para julgar)."""
    if not cert.key.bits:
        return None
    limits = {"RSA": RSA_MIN_BITS, "RSA-PSS": RSA_MIN_BITS, "EC": EC_MIN_BITS, "DSA": DSA_MIN_BITS}
    return limits.get(cert.key.kind)


def _audit_key(ctx: CheckContext, endpoint: Endpoint, cert: Certificate) -> None:
    limit = _weak_key_limit(cert)
    if limit is not None and cert.key.bits < limit:
        ctx.report(
            WEAK_KEY,
            asset=endpoint.asset,
            evidence=f"Chave {cert.key.label}; o mínimo para este tipo é {limit} bits.",
            details={"tipo": cert.key.kind, "bits": cert.key.bits, "curva": cert.key.curve},
            confidence=Confidence.CONFIRMED,
            tech=tech_hint(ctx, endpoint.host),
        )
    elif limit is not None or cert.key.kind in ("Ed25519", "Ed448"):
        ctx.passed("tls.certificado.chave", f"Chave {cert.key.label}", endpoint.asset)


def _audit_signature(ctx: CheckContext, endpoint: Endpoint, cert: Certificate) -> None:
    if cert.self_signed:
        return  # em autoassinado a confiança não vem da assinatura; o achado próprio já cobre
    if cert.weak_signature:
        ctx.report(
            WEAK_SIGNATURE,
            asset=endpoint.asset,
            evidence=f"Assinatura {cert.signature} (hash {cert.signature_hash}).",
            details={"algoritmo": cert.signature, "hash": cert.signature_hash},
            confidence=Confidence.CONFIRMED,
            tech=tech_hint(ctx, endpoint.host),
        )
    elif cert.signature_hash != "desconhecido":
        ctx.passed("tls.certificado.assinatura", f"Assinatura {cert.signature}", endpoint.asset)


def _teach_inventory(
    ctx: CheckContext, endpoint: Endpoint, cert: Certificate, peer: Peer, verdict: Verdict
) -> None:
    trusted = None if verdict.state == NOT_EVALUATED else verdict.state == TRUSTED
    ctx.add_fact(
        facts.TLS_CERT,
        endpoint.key,
        f"Certificado apresentado por {endpoint.asset}",
        host=endpoint.host,
        port=endpoint.port,
        subject=cert.subject.text,
        common_name=cert.common_name,
        organization=cert.subject.get("O"),
        issuer=cert.issuer.text,
        not_before=cert.not_before.isoformat(),
        not_after=cert.not_after.isoformat(),
        san=list(cert.names[:_MAX_NAMES]),
        san_total=len(cert.names),
        key=cert.key.label,
        signature=cert.signature,
        serial=format(cert.serial, "x"),
        sha256=cert.sha256,
        self_signed=cert.self_signed,
        chain_size=peer.chain_size,
        trusted=trusted,
        verify_message=verdict.message,
        label=f"{endpoint.asset} — {cert.common_name or cert.subject.text}",
    )


@check(
    id="tls.certificate",
    name="Certificado TLS",
    category=Category.TLS,
    consumes=facts.TLS_SERVICE,
    description=(
        "Lê o certificado do serviço e confere validade, cadeia de confiança, nome, "
        "tamanho da chave e algoritmo de assinatura."
    ),
    findings=kb_certificado.FINDINGS,
    facts=(facts.TLS_CERT,),
    order=20,
)
def check_certificate(ctx: CheckContext, fact: Fact) -> None:
    endpoint = endpoint_of(fact)
    if endpoint is None:
        ctx.log(f"Serviço TLS com dados incompletos: {fact.key}.")
        return
    timeout = io_timeout(ctx)
    peer = fetch_peer(endpoint, timeout)
    if peer is None:
        ctx.log(f"{endpoint.asset}: não foi possível ler o certificado.")
        return
    try:
        cert = x509.parse_certificate(peer.der)
    except Asn1Error as exc:
        ctx.log(f"{endpoint.asset}: certificado ilegível ({exc}); não avaliado.")
        return
    ctx.check_cancel()
    verdict = verify_chain(endpoint, timeout)
    moment = _now()
    _teach_inventory(ctx, endpoint, cert, peer, verdict)
    _audit_dates(ctx, endpoint, cert, moment)
    _audit_trust(ctx, endpoint, cert, peer, verdict, moment)
    _audit_name(ctx, endpoint, cert)
    _audit_key(ctx, endpoint, cert)
    _audit_signature(ctx, endpoint, cert)
