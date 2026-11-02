"""Acesso remoto e compartilhamento: RDP, SMB e VNC — e o conector AJP do Tomcat.

Cada verificação usa só a primeira troca do protocolo, a mesma de um cliente
comum antes de qualquer usuário ou senha:

* RDP: duas negociações X.224 curtas, uma pedindo só a "segurança RDP padrão" e
  outra só TLS. Se o servidor aceita alguma, a tela de logon abre sem NLA; se recusa
  com ``HYBRID_REQUIRED_BY_SERVER`` (código 5), a NLA é obrigatória;
* SMB: NEGOTIATE do SMB1 oferecendo só "NT LM 0.12" (o SMBv1 está ativo?) e
  NEGOTIATE do SMB2 (a assinatura é obrigatória?);
* VNC: lê a versão do RFB e os tipos de segurança oferecidos e fecha a conexão sem
  escolher nenhum;
* AJP: vale o CPong já recebido na identificação; nada além do CPing é enviado
  (nunca uma requisição AJP, que é o caminho da exploração Ghostcat).

Exposição à Internet de RDP, SMB e VNC é achado por si; na rede interna esses
serviços são uso administrativo comum e só as fraquezas do protocolo são apontadas.
"""

from __future__ import annotations

from collections.abc import Callable

from ...core import facts, vulndb
from ...core.context import CheckContext
from ...core.models import Category, Confidence, Exposure, Fact, Severity
from ...core.registry import check
from ...core.versions import in_range
from . import (
    common,
    kb_remoto,  # noqa: F401 — registra as entradas da base
    probes,
    winproto,
)
from .banners import rfb_version
from .common import Connection, connect_timeout, host_port, io_timeout, service_asset, talk, where
from .probes import RfbSecurity
from .winproto import RdpNegotiation, SmbNegotiation

GHOSTCAT = "CVE-2020-1938"
#: versões afetadas pela Ghostcat (início incluído, correção excluída) — avisos de segurança
#: do Tomcat 7, 8.5 e 9 e a NVD; o ramo 9 inclui as versões de marco (9.0.0.M1 em diante)
GHOSTCAT_RANGES = (("7.0.0", "7.0.100"), ("8.5.0", "8.5.51"), ("9.0.0.M1", "9.0.31"))


def _service_is(name: str) -> Callable[[Fact], bool]:
    return lambda fact: fact.data.get("service") == name


# -- RDP -------------------------------------------------------------------------------
@check(
    id="net.rdp",
    name="Área de Trabalho Remota (RDP)",
    category=Category.NETWORK,
    consumes=facts.SERVICE,
    when=_service_is("rdp"),
    description=(
        "Aponta RDP exposto à Internet e verifica, pela negociação X.224, se a autenticação "
        "em nível de rede (NLA) é obrigatória."
    ),
    findings=("net.rdp.exposto", "net.rdp.sem_nla"),
    order=30,
)
def check_rdp(ctx: CheckContext, fact: Fact) -> None:
    host, port = host_port(fact)
    asset = service_asset(host, port)
    classic = rdp_negotiate(ctx, host, port, winproto.PROTOCOL_RDP)
    ctx.check_cancel()
    tls_only = rdp_negotiate(ctx, host, port, winproto.PROTOCOL_SSL)
    if classic is None and tls_only is None and not fact.data.get("confirmed"):
        ctx.log(f"{asset}: a porta não respondeu à negociação RDP; nada foi avaliado.")
        return
    if common.on_internet(host):
        ctx.report(
            "net.rdp.exposto",
            asset=asset,
            evidence=f"O RDP respondeu à negociação X.224 na porta {port}/tcp ({where(host)}).",
            confidence=Confidence.CONFIRMED,
            tech=["windows"],
        )
    required, evidence = nla_verdict(classic, tls_only)
    if required is None:
        ctx.log(f"{asset}: não foi possível concluir se a NLA é obrigatória ({evidence}).")
        return
    if required:
        ctx.passed("net.rdp.sem_nla", f"RDP exige autenticação antes da sessão ({evidence})", asset)
        return
    no_tls = classic is not None and classic.accepted
    ctx.report(
        "net.rdp.sem_nla",
        asset=asset,
        title="RDP aceita a 'segurança RDP padrão' (sem TLS e sem NLA)" if no_tls else None,
        severity=common.by_exposure(
            host, internet=Severity.HIGH, internal=Severity.MEDIUM, local=Severity.LOW
        ),
        evidence=f"{evidence} ({where(host)}).",
        details={"sem_tls": no_tls},
        confidence=Confidence.CONFIRMED,
        tech=["windows"],
    )


def rdp_negotiate(ctx: CheckContext, host: str, port: int, protocols: int) -> RdpNegotiation | None:
    """Uma negociação X.224 pedindo ``protocols``. None se não houver resposta RDP."""
    data = talk(ctx, host, port, winproto.rdp_request(protocols), limit=512)
    return winproto.parse_rdp(data) if data else None


def nla_verdict(
    classic: RdpNegotiation | None, tls_only: RdpNegotiation | None
) -> tuple[bool | None, str]:
    """(autenticação antes da sessão é obrigatória?, evidência). None = inconclusivo.

    ``classic``: resposta ao pedido só com "RDP padrão"; ``tls_only``: só com TLS.
    """
    if classic is not None and classic.accepted and classic.selected == winproto.PROTOCOL_RDP:
        return (
            False,
            f"Pedido só com 'RDP padrão': o servidor {classic.describe()} (sem TLS e sem NLA)",
        )
    if tls_only is not None and tls_only.accepted and tls_only.selected == winproto.PROTOCOL_SSL:
        return False, (
            f"Pedido só com TLS, sem CredSSP: o servidor {tls_only.describe()} — a tela de "
            "logon abre antes de qualquer autenticação"
        )
    answered = [n for n in (classic, tls_only) if n is not None]
    shown = "; ".join(n.describe() for n in answered) or "sem resposta às negociações"
    refused = [n for n in answered if n.failure in winproto.PREAUTH_FAILURES]
    if refused and not any(n.accepted for n in answered):
        return True, f"pedidos sem CredSSP: o servidor {refused[0].describe()}"
    return None, shown


# -- SMB -------------------------------------------------------------------------------
@check(
    id="net.smb",
    name="Compartilhamento de arquivos (SMB)",
    category=Category.NETWORK,
    consumes=facts.SERVICE,
    when=_service_is("smb"),
    description=(
        "Aponta SMB exposto à Internet e verifica, pelo NEGOTIATE, se o SMBv1 está ativo e se "
        "a assinatura das mensagens é obrigatória."
    ),
    findings=("net.smb.exposto", "net.smb.v1", "net.smb.assinatura_opcional"),
    order=30,
)
def check_smb(ctx: CheckContext, fact: Fact) -> None:
    host, port = host_port(fact)
    asset = service_asset(host, port)
    v1_talked, v1 = smb_negotiate(ctx, host, port, winproto.smb1_negotiate())
    ctx.check_cancel()
    _v2_talked, v2 = smb_negotiate(ctx, host, port, winproto.smb2_negotiate())
    smb1 = v1 if v1 is not None and v1.version == 1 else None
    if v2 is not None and v2.version != 2:
        v2 = None
    shown = v2 or smb1
    if shown is None:
        ctx.log(f"{asset}: a porta não respondeu ao NEGOTIATE do SMB; nada foi avaliado.")
        return
    if common.on_internet(host):
        ctx.report(
            "net.smb.exposto",
            asset=asset,
            evidence=(
                f"O SMB respondeu ao NEGOTIATE na porta {port}/tcp ({where(host)}); "
                f"dialeto {shown.dialect}."
            ),
            confidence=Confidence.CONFIRMED,
            tech=["windows"],
        )
    if smb1 is not None:
        _report_smb1(ctx, host, asset)
    elif v1_talked and v2 is not None:
        ctx.passed("net.smb.v1", "SMBv1 desativado (NEGOTIATE só com NT LM 0.12 recusado)", asset)
    _smb_signing(ctx, host, asset, shown)


def smb_negotiate(
    ctx: CheckContext, host: str, port: int, request: bytes
) -> tuple[bool, SmbNegotiation | None]:
    """(houve conexão?, negociação). Conexão sem resposta SMB = o dialeto foi recusado."""
    data = talk(ctx, host, port, request, limit=4096)
    if data is None:
        return False, None
    return True, winproto.parse_smb(data) if data else None


def _report_smb1(ctx: CheckContext, host: str, asset: str) -> None:
    ctx.report(
        "net.smb.v1",
        asset=asset,
        severity=common.by_exposure(
            host, internet=Severity.HIGH, internal=Severity.HIGH, local=Severity.MEDIUM
        ),
        evidence=(
            "O servidor aceitou um NEGOTIATE que oferecia só o dialeto SMB1 'NT LM 0.12' "
            f"(resposta com WordCount 0x11 e DialectIndex válido) — {where(host)}."
        ),
        confidence=Confidence.CONFIRMED,
        tech=["windows"],
    )


def _smb_signing(ctx: CheckContext, host: str, asset: str, result: SmbNegotiation) -> None:
    if result.signing_required:
        ctx.passed(
            "net.smb.assinatura_opcional",
            f"Assinatura SMB obrigatória (SMB {result.dialect})",
            asset,
        )
        return
    state = "habilitada, mas opcional" if result.signing_enabled else "desabilitada"
    ctx.report(
        "net.smb.assinatura_opcional",
        asset=asset,
        severity=common.by_exposure(
            host, internet=Severity.MEDIUM, internal=Severity.MEDIUM, local=Severity.LOW
        ),
        evidence=(
            f"NEGOTIATE SMB {result.dialect}: SecurityMode sem a exigência de assinatura "
            f"(assinatura {state}) — {where(host)}."
        ),
        details={"dialeto": result.dialect, "assinatura_habilitada": result.signing_enabled},
        confidence=Confidence.CONFIRMED,
        tech=["windows"],
    )


# -- VNC -------------------------------------------------------------------------------
@check(
    id="net.vnc",
    name="VNC (controle remoto de tela)",
    category=Category.NETWORK,
    consumes=facts.SERVICE,
    when=_service_is("vnc"),
    description=(
        "Lê a versão do protocolo RFB e os tipos de segurança oferecidos pelo VNC (sem escolher "
        "nenhum) e aponta VNC sem senha ou exposto à Internet."
    ),
    findings=("net.vnc.exposto", "net.vnc.sem_senha"),
    order=30,
)
def check_vnc(ctx: CheckContext, fact: Fact) -> None:
    host, port = host_port(fact)
    asset = service_asset(host, port)
    conn = Connection.open(host, port, connect_timeout(ctx), io_timeout(ctx))
    if conn is None:
        ctx.log(f"{asset}: a porta do VNC não aceitou conexão.")
        return
    with conn:
        version, security = rfb_security(conn)
    if version is None or security is None:
        ctx.log(f"{asset}: o servidor não completou o início do protocolo RFB (VNC).")
        return
    shown = f"RFB {version[0]}.{version[1]}"
    if security.no_auth:
        ctx.report(
            "net.vnc.sem_senha",
            asset=asset,
            severity=common.by_exposure(
                host, internet=Severity.CRITICAL, internal=Severity.HIGH, local=Severity.MEDIUM
            ),
            evidence=(
                f"{shown}: o servidor oferece o tipo de segurança 1 (None) — tipos: "
                f"{security.describe()} ({where(host)})."
            ),
            confidence=Confidence.CONFIRMED,
        )
        _report_vnc_exposure(ctx, host, port, shown, security)
        return
    later = probes.RFB_NEGOTIATED_LATER.intersection(security.types)
    if security.types and not later:
        ctx.passed("net.vnc.sem_senha", f"VNC exige autenticação ({security.describe()})", asset)
    elif security.types:
        ctx.log(
            f"{asset}: o VNC oferece {security.describe()}; nesses tipos a autenticação é "
            "negociada depois e não foi avaliada."
        )
    else:
        ctx.log(f"{asset}: o VNC recusou a conexão ({security.reason}).")
    _report_vnc_exposure(ctx, host, port, shown, security)


def _report_vnc_exposure(
    ctx: CheckContext, host: str, port: int, shown: str, security: RfbSecurity
) -> None:
    if common.on_internet(host):
        offered = security.describe() or f"recusou a conexão: {security.reason}"
        ctx.report(
            "net.vnc.exposto",
            asset=service_asset(host, port),
            evidence=f"{shown} acessível pela Internet na porta {port}/tcp; segurança: {offered}.",
            confidence=Confidence.CONFIRMED,
        )


def rfb_security(conn: Connection) -> tuple[tuple[int, int] | None, RfbSecurity | None]:
    """Versão do servidor e tipos de segurança (RFC 6143, 7.1.1 e 7.1.2); não escolhe nenhum."""
    version = rfb_version(conn.read_exact(12))
    if version is None:
        return None, None
    reply = probes.rfb_client_version(version)
    if not conn.send(reply):
        return version, None
    minor = int(reply[8:11])
    if minor >= 7:
        head = conn.read_exact(1)
        if not head:
            return version, None
        raw = head + (_reason(conn) if head[0] == 0 else conn.read_exact(head[0]))
    else:
        head = conn.read_exact(4)
        raw = head + (_reason(conn) if head == b"\x00\x00\x00\x00" else b"")
    return version, probes.parse_rfb_security(raw, minor)


def _reason(conn: Connection) -> bytes:
    """Tamanho (U32) e texto do motivo de uma recusa (no máximo 300 bytes lidos)."""
    size = conn.read_exact(4)
    if len(size) < 4:
        return size
    return size + conn.read_exact(min(int.from_bytes(size, "big"), 300))


# -- AJP -------------------------------------------------------------------------------
@check(
    id="net.ajp",
    name="Conector AJP (Tomcat)",
    category=Category.NETWORK,
    consumes=facts.SERVICE,
    when=_service_is("ajp"),
    description=(
        "Aponta o conector AJP do Tomcat acessível pela rede (resposta ao CPing), o caminho "
        "da falha Ghostcat (CVE-2020-1938)."
    ),
    findings=("net.ajp.exposto",),
    order=40,
)
def check_ajp(ctx: CheckContext, fact: Fact) -> None:
    host, port = host_port(fact)
    report_ajp(ctx, host, port, tomcat_version(ctx, host))


@check(
    id="net.ajp.versao",
    name="Versão do Tomcat com AJP acessível",
    category=Category.NETWORK,
    consumes=facts.TECH,
    when=lambda fact: fact.data.get("name") == "tomcat" and bool(fact.data.get("version")),
    description=(
        "Quando a versão do Tomcat é descoberta depois do conector AJP, confere se ela está na "
        "faixa afetada pela Ghostcat (CVE-2020-1938) e atualiza o achado do conector."
    ),
    findings=("net.ajp.exposto",),
    order=40,
)
def check_ajp_version(ctx: CheckContext, fact: Fact) -> None:
    host = str(fact.data.get("host"))
    version = str(fact.data.get("version"))
    if not ghostcat_affected(version):
        return
    for service in ctx.facts(facts.SERVICE):
        if service.data.get("service") == "ajp" and service.data.get("host") == host:
            report_ajp(ctx, host, int(service.data.get("port") or 0), version)


def report_ajp(ctx: CheckContext, host: str, port: int, version: str) -> None:
    """Achado do conector AJP; a faixa de versão só eleva a prioridade e cita o CVE."""
    asset = service_asset(host, port)
    exposure = common.exposure_of(host)
    if exposure is Exposure.LOCAL:
        ctx.log(f"{asset}: AJP respondendo nesta máquina (sem exposição de rede para avaliar).")
        return
    internet = exposure is Exposure.INTERNET
    vulnerable = bool(version) and ghostcat_affected(version)
    cves = [GHOSTCAT] if vulnerable else []
    kev = vulndb.any_kev(cves)
    if vulnerable:
        severity = Severity.CRITICAL if internet or kev else Severity.HIGH
        detail = f"O Tomcat {version} identificado no mesmo servidor está na faixa afetada pela {GHOSTCAT}."
    else:
        known = f"Tomcat {version} identificado" if version else "Versão do Tomcat não identificada"
        fixed_version = bool(version)
        if fixed_version:
            severity = Severity.MEDIUM if internet else Severity.LOW
            tail = " A versão não está na faixa do Ghostcat, mas o CPing não prova que o segredo (secret) do AJP está configurado."
        else:
            severity = Severity.HIGH if internet else Severity.MEDIUM
            tail = ""
        detail = f"{known}; a {GHOSTCAT} foi corrigida no 7.0.100, 8.5.51 e 9.0.31." + tail
    ctx.report(
        "net.ajp.exposto",
        asset=asset,
        severity=severity,
        evidence=f"O conector AJP respondeu ao CPing com CPong ({where(host)}). {detail}",
        details={"tomcat": version or None},
        # o CPong é comprovado; a faixa vem da versão divulgada (distribuições fazem backport)
        confidence=Confidence.FIRM if vulnerable else Confidence.CONFIRMED,
        cves=cves,
        kev=kev,
        tech=["tomcat"],
    )


def tomcat_version(ctx: CheckContext, host: str) -> str:
    """Versão do Tomcat já identificada no mesmo host (cabeçalho, página de erro...), se houver."""
    for fact in ctx.facts(facts.TECH):
        data = fact.data
        if data.get("host") == host and data.get("name") == "tomcat" and data.get("version"):
            return str(data["version"])
    return ""


def ghostcat_affected(version: str) -> bool:
    return any(in_range(version, introduced=low, fixed=high) for low, high in GHOSTCAT_RANGES)
