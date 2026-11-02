"""Hardening desta máquina (Linux): SSH, firewall, atualizações, defesas e bancos em escuta.

Tudo é só leitura e passa por :class:`~.linux_sistema.SistemaLinux`, que os testes trocam
por um Linux falso. Leitura negada pelo sistema vira "não verificado" no registro de
atividade, nunca um achado. As demais checagens de Linux ficam em ``linux_kernel.py``
(parâmetros do kernel) e ``linux_acesso.py`` (contas, sudo e permissões).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ...core import facts
from ...core.context import CheckContext
from ...core.models import Category, Confidence, Fact, Severity
from ...core.registry import check
from . import comum, kb_linux, linux_kb_sistema, linux_sshd  # noqa: F401
from . import linux_analise as analise
from . import linux_sistema as so
from .linux_sistema import SistemaLinux
from .linux_sshd import ConfigSshd
from .sistema import AcessoNegado

MAX_TENTATIVAS_SSH = 4
TEMPO_PACOTES = 60.0
LIMITE_PACOTES = 50
#: cache de pacotes mais velho que isto não prova que não há atualizações
IDADE_MAXIMA_CACHE = 14
#: até este número de pendências de segurança o achado é MÉDIO; acima, ALTO
POUCAS_PENDENCIAS = 5
APT_CHECK = "/usr/lib/update-notifier/apt-check"
LISTAS_APT = "/var/lib/apt/lists"
AVISO_REINICIO = ("/var/run/reboot-required", "/run/reboot-required")
#: o que cria o aviso de reinício no Debian/Ubuntu: sem isso, a ausência do aviso não prova nada
CRIADORES_AVISO = (
    "/usr/share/update-notifier/notify-reboot-required",
    "/usr/bin/unattended-upgrade",
)
ENFORCE_SELINUX = "/sys/fs/selinux/enforce"
APPARMOR = "/sys/module/apparmor/parameters/enabled"
#: portas padrão de bancos, as mesmas do catálogo data/net_ports.json (registro IANA e documentação)
BANCOS = {
    1433: ("SQL Server", "mssql"),
    1521: ("Oracle", "oracle"),
    3306: ("MySQL/MariaDB", "mysql"),
    5432: ("PostgreSQL", "postgresql"),
    5984: ("CouchDB", "couchdb"),
    6379: ("Redis", "redis"),
    8086: ("InfluxDB", "influxdb"),
    9042: ("Cassandra", "cassandra"),
    9200: ("Elasticsearch", "elasticsearch"),
    11211: ("Memcached", "memcached"),
    27017: ("MongoDB", "mongodb"),
}
#: programa, unidade do systemd e nome das ferramentas que bloqueiam quem erra a senha
PROTECOES_SSH = (
    ("fail2ban-server", "fail2ban", "fail2ban"),
    ("crowdsec", "crowdsec", "CrowdSec"),
    ("sshguard", "sshguard", "SSHGuard"),
)


# -- SSH ---------------------------------------------------------------------------------
@dataclass(frozen=True)
class _OpcaoSsh:
    chave: str  # em minúsculas, como no "sshd -T"
    nome: str  # como se escreve no sshd_config
    achado: str
    aprovado: str  # texto do ponto forte

    def insegura(self, valor: str) -> bool:
        if self.chave == "maxauthtries":
            return valor.isdigit() and int(valor) > MAX_TENTATIVAS_SSH
        return valor.lower() == "yes"

    def segura(self, valor: str) -> bool:
        return valor.isdigit() if self.chave == "maxauthtries" else not self.insegura(valor)


_OPCOES_SSH = (
    _OpcaoSsh(
        "permitrootlogin",
        "PermitRootLogin",
        "host.linux.ssh.root_permitido",
        "SSH não aceita login de root com senha",
    ),
    _OpcaoSsh(
        "passwordauthentication",
        "PasswordAuthentication",
        "host.linux.ssh.senha_permitida",
        "SSH não aceita login com senha",
    ),
    _OpcaoSsh(
        "permitemptypasswords",
        "PermitEmptyPasswords",
        "host.linux.ssh.senha_vazia",
        "SSH recusa contas com senha vazia",
    ),
    _OpcaoSsh(
        "x11forwarding",
        "X11Forwarding",
        "host.linux.ssh.x11_forwarding",
        "SSH não encaminha janelas gráficas (X11)",
    ),
    _OpcaoSsh(
        "maxauthtries",
        "MaxAuthTries",
        "host.linux.ssh.tentativas_excessivas",
        "SSH limita as tentativas de login por conexão",
    ),
)


def _config_ssh(ctx: CheckContext) -> ConfigSshd | None:
    """Configuração efetiva do SSH (calculada uma vez); None se o servidor não está instalado."""
    sis = so.obter(ctx)

    def carregar() -> tuple[ConfigSshd | None, bool]:
        if sis.programa("sshd") is None:
            return None, False
        try:
            return linux_sshd.configuracao(sis), False
        except AcessoNegado:
            return None, True

    config, negado = ctx.memo("host.linux:sshd", carregar)
    if negado:
        raise AcessoNegado(linux_sshd.ARQUIVO)
    return config


def _ssh_parado(sis: SistemaLinux) -> bool:
    """O systemd confirma que nenhuma unidade do SSH está ativa."""
    return all(so.servico_ativo(sis, nome) is False for nome in ("ssh", "sshd", "ssh.socket"))


def _verificar_ssh(ctx: CheckContext) -> None:
    sis = so.obter(ctx)
    config = _config_ssh(ctx)
    if config is None:
        if sis.programa("sshd") is not None:
            comum.nao_verificado(
                ctx, "SSH", "o sshd está instalado, mas o sshd_config não foi encontrado"
            )
        else:
            ctx.log("SSH: servidor OpenSSH não encontrado nesta máquina")
        return
    for caminho in config.ilegiveis:
        comum.nao_verificado(ctx, f"SSH: {caminho}")
    aviso = (
        " O serviço SSH está parado agora: isso vale quando ele for iniciado."
        if _ssh_parado(sis)
        else ""
    )
    pam = _senha_por_pam(config)
    senha_ligada = config.efetivo("passwordauthentication").valor.lower() == "yes" or pam
    asset = comum.ativo(ctx)
    parado = bool(aviso)
    for opcao in _OPCOES_SSH:
        valor = config.efetivo(opcao.chave)
        via_pam = opcao.chave == "passwordauthentication" and pam and valor.valor.lower() != "yes"
        if via_pam or opcao.insegura(valor.valor):
            raiz_com_senha = opcao.chave == "permitrootlogin" and senha_ligada
            severidade = Severity.HIGH if raiz_com_senha else None
            if parado:  # sem serviço em execução não há exposição até ele ser iniciado
                severidade = Severity.MEDIUM if raiz_com_senha else Severity.LOW
            complemento = (
                " Mesmo assim o sshd aceita senha pelo PAM (UsePAM yes e KbdInteractiveAuthentication yes)."
                if via_pam
                else ""
            )
            ctx.report(
                opcao.achado,
                asset=asset,
                severity=severidade,
                evidence=f"{opcao.nome} {valor.valor} ({valor.origem}).{complemento}{aviso}",
                details={
                    "opcao": opcao.nome,
                    "valor": valor.valor,
                    "origem": valor.origem,
                    "fonte": config.fonte,
                    "blocos_match_ignorados": config.condicionais,
                    "arquivos_ilegiveis": config.ilegiveis,
                },
                confidence=(
                    Confidence.TENTATIVE
                    if via_pam or parado
                    else _confianca_ssh(config, valor.certo)
                ),
                tech=so.tecnologias(sis, "openssh"),
            )
        elif valor.certo and opcao.segura(valor.valor):
            ctx.passed(f"{opcao.achado}", f"{opcao.aprovado} ({opcao.nome} {valor.valor})", asset)


def _senha_por_pam(config: ConfigSshd) -> bool:
    """Com PasswordAuthentication no, o keyboard-interactive via PAM ainda pode pedir senha."""
    pam = config.efetivo("usepam").valor.lower() == "yes"
    teclado = "yes" in (
        config.efetivo("kbdinteractiveauthentication").valor.lower(),
        config.efetivo("challengeresponseauthentication").valor.lower(),
    )
    metodos = config.efetivo("authenticationmethods").valor.lower()
    return pam and teclado and "publickey" not in metodos


def _confianca_ssh(config: ConfigSshd, certo: bool) -> Confidence:
    if not certo:
        return Confidence.TENTATIVE
    return Confidence.CONFIRMED if config.fonte == "sshd -T" else Confidence.FIRM


@check(
    id="host.linux.ssh",
    name="Configuração efetiva do SSH (Linux)",
    category=Category.HOST,
    consumes=facts.LOCAL,
    description=(
        "Confere a configuração efetiva do OpenSSH (sshd -T com root; sem root, o sshd_config e "
        "seus Include, valendo a primeira ocorrência de cada opção): login de root, senha, senha "
        "vazia, encaminhamento X11 e tentativas por conexão."
    ),
    findings=tuple(opcao.achado for opcao in _OPCOES_SSH),
    platforms=comum.LINUX,
)
def check_ssh(ctx: CheckContext, fact: Fact) -> None:
    comum.executar(ctx, "Configuração do SSH", _verificar_ssh)


# -- firewall ----------------------------------------------------------------------------
@dataclass(frozen=True)
class EstadoFirewall:
    ativo: bool | None  # None: não deu para saber
    fonte: str
    certo: bool = True  # False: conclusão indireta, sem ler as regras do kernel


#: serviço que carrega um arquivo de regras: só conta se o arquivo tiver filtro de entrada
_SERVICOS_COM_REGRAS: tuple[tuple[str, str, Callable[[str], bool]], ...] = (
    ("nftables", "/etc/nftables.conf", analise.nft_filtra_entrada),
    ("netfilter-persistent", "/etc/iptables/rules.v4", analise.iptables_filtra_entrada),
    ("iptables", "/etc/sysconfig/iptables", analise.iptables_filtra_entrada),
)


def _firewall_por_regras(sis: SistemaLinux) -> EstadoFirewall | None:
    """Com root, as regras do kernel dão a resposta definitiva; None se não deu para lê-las."""
    if not sis.root():
        return None
    leu = False
    nft = sis.comando("nft", "list", "ruleset", tempo=20.0)
    if nft is not None and nft.codigo == 0:
        leu = True
        if analise.nft_filtra_entrada(nft.saida):
            return EstadoFirewall(True, "regras do nftables")
    ipt = sis.comando("iptables", "-S", tempo=20.0)
    if ipt is not None and ipt.codigo == 0:
        leu = True
        if analise.iptables_filtra_entrada(ipt.saida):
            return EstadoFirewall(True, "regras do iptables")
    return EstadoFirewall(False, "nenhuma regra de entrada no kernel") if leu else None


def _ler_tolerante(sis: SistemaLinux, caminho: str) -> str | None:
    try:
        return sis.ler(caminho)
    except AcessoNegado:
        return None


def _firewall_por_servicos(sis: SistemaLinux) -> EstadoFirewall:
    """Sem root: estado do ufw e dos serviços de firewall (indício, não as regras em si)."""
    ufw = so.servico_ativo(sis, "ufw")
    firewalld = so.servico_ativo(sis, "firewalld")
    conf_ufw = _ler_tolerante(sis, "/etc/ufw/ufw.conf")
    if conf_ufw and analise.ufw_habilitado(conf_ufw) and ufw is not False:
        return EstadoFirewall(True, "ufw")
    if firewalld:
        return EstadoFirewall(True, "firewalld")
    respondeu = ufw is not None or firewalld is not None
    for unidade, arquivo, filtra in _SERVICOS_COM_REGRAS:
        estado = so.servico_ativo(sis, unidade)
        respondeu = respondeu or estado is not None
        if not estado:
            continue
        regras = _ler_tolerante(sis, arquivo)
        if regras is None:
            return EstadoFirewall(None, f"{unidade} ativo, mas {arquivo} não pôde ser lido")
        if filtra(regras):
            return EstadoFirewall(True, unidade)
    if respondeu:
        return EstadoFirewall(False, "ufw, firewalld e nftables sem filtro ativo", certo=False)
    return EstadoFirewall(None, "sem root e sem resposta do systemctl")


def estado_firewall(ctx: CheckContext) -> EstadoFirewall:
    """Se a máquina filtra as conexões de entrada (calculado uma vez por auditoria)."""
    sis = so.obter(ctx)
    return ctx.memo(
        "host.linux:firewall", lambda: _firewall_por_regras(sis) or _firewall_por_servicos(sis)
    )


def _verificar_firewall(ctx: CheckContext) -> None:
    sis = so.obter(ctx)
    if so.fora_de_escopo(ctx, sis, "Firewall"):
        return
    estado = estado_firewall(ctx)
    asset = comum.ativo(ctx)
    if estado.ativo:
        ctx.passed("host.linux.firewall", f"Firewall ativo ({estado.fonte})", asset)
    elif estado.ativo is None:
        comum.nao_verificado(ctx, "Firewall", estado.fonte)
    else:
        ctx.report(
            "host.linux.firewall.inativo",
            asset=asset,
            evidence=estado.fonte,
            severity=None if estado.certo else Severity.LOW,
            details={"regras_lidas": estado.certo},
            confidence=Confidence.CONFIRMED if estado.certo else Confidence.TENTATIVE,
            tech=so.tecnologias(sis),
        )


@check(
    id="host.linux.firewall",
    name="Firewall da máquina (Linux)",
    category=Category.HOST,
    consumes=facts.LOCAL,
    description=(
        "Com root, lê as regras do kernel (nftables, iptables); sem root, usa o estado do ufw, do "
        "firewalld e dos serviços que carregam regras."
    ),
    findings=("host.linux.firewall.inativo",),
    platforms=comum.LINUX,
)
def check_firewall(ctx: CheckContext, fact: Fact) -> None:
    comum.executar(ctx, "Firewall", _verificar_firewall)


# -- atualizações ------------------------------------------------------------------------
@dataclass(frozen=True)
class Pendencias:
    seguranca: int
    total: int | None
    fonte: str
    pacotes: tuple[str, ...] = ()


def _cache_velho(sis: SistemaLinux, marca: str) -> bool:
    """O carimbo do último ``apt update`` bem-sucedido tem mais de ``IDADE_MAXIMA_CACHE`` dias?"""
    idade = sis.idade_dias(marca)
    return idade is not None and idade > IDADE_MAXIMA_CACHE


def _pendencias_apt(sis: SistemaLinux) -> Pendencias | None:
    """apt-check (Ubuntu) ou, sem ele, a simulação do apt-get; None se não deu para saber."""
    if not any("Packages" in nome for nome in sis.listar(LISTAS_APT) or []):
        return None  # sem as listas de pacotes (nunca rodou apt update), o cache não diz nada
    if _cache_velho(sis, "/var/lib/apt/periodic/update-success-stamp"):
        return None  # cache de meses atrás não prova que está tudo atualizado
    verificacao = sis.comando(APT_CHECK, tempo=TEMPO_PACOTES)
    contagem = analise.apt_check(verificacao.erro) if verificacao is not None else None
    if contagem is not None:
        return Pendencias(contagem[1], contagem[0], "apt-check")
    simulacao = sis.comando("apt-get", "-s", "dist-upgrade", tempo=TEMPO_PACOTES)
    if simulacao is None or simulacao.codigo != 0:
        return None
    todos, seguranca = analise.apt_simulacao(simulacao.saida)
    return Pendencias(len(seguranca), len(todos), "apt-get -s", tuple(seguranca))


def _pendencias_dnf(sis: SistemaLinux) -> Pendencias | None:
    """``dnf check-update --security`` no cache local: saída 100 = há pendências; 0 = não há."""
    for subcomando in ("check-update", "check-upgrade"):  # o dnf5 documenta só check-upgrade
        resultado = sis.comando("dnf", "-q", "-C", subcomando, "--security", tempo=TEMPO_PACOTES)
        if resultado is None:
            return None
        fonte = f"dnf {subcomando} --security"
        if resultado.codigo == 0:
            geral = sis.comando("dnf", "-q", "-C", subcomando, tempo=TEMPO_PACOTES)
            if geral is not None and geral.codigo == 100:
                return None  # há atualizações, mas sem dados de segurança (ex.: CentOS Stream)
            return Pendencias(0, None, fonte)
        if resultado.codigo == 100:
            pacotes = analise.dnf_pacotes(resultado.saida)
            return Pendencias(max(len(pacotes), 1), None, fonte, tuple(pacotes))
    return None


def _pendencias(sis: SistemaLinux) -> Pendencias | None:
    distro = so.familia(sis)
    if distro == "debian" or (not distro and sis.programa("apt-get")):
        return _pendencias_apt(sis)
    if distro == "rhel" or (not distro and sis.programa("dnf")):
        return _pendencias_dnf(sis)
    return None


def _verificar_pendencias(ctx: CheckContext) -> None:
    sis = so.obter(ctx)
    pendencias = _pendencias(sis)
    if pendencias is None:
        comum.nao_verificado(ctx, "Atualizações pendentes", "cache de pacotes indisponível")
        return
    asset = comum.ativo(ctx)
    if pendencias.seguranca == 0:
        ctx.passed(
            "host.linux.atualizacoes.pendentes",
            f"Nenhuma atualização de segurança pendente no cache local ({pendencias.fonte})",
            asset,
        )
        return
    quantidade = pendencias.seguranca
    texto = (
        "1 atualização de segurança pendente"
        if quantidade == 1
        else f"{quantidade} atualizações de segurança pendentes"
    )
    de_quantas = f" (de {pendencias.total} atualizações disponíveis)" if pendencias.total else ""
    ctx.report(
        "host.linux.atualizacoes.pendentes",
        asset=asset,
        title=texto.capitalize(),
        severity=Severity.MEDIUM if quantidade <= POUCAS_PENDENCIAS else None,
        confidence=Confidence.FIRM if pendencias.total is not None else Confidence.TENTATIVE,
        evidence=f"{texto}{de_quantas}, segundo {pendencias.fonte}",
        details={
            "seguranca": quantidade,
            "total": pendencias.total,
            "fonte": pendencias.fonte,
            "pacotes": list(pendencias.pacotes[:LIMITE_PACOTES]),
        },
        tech=so.tecnologias(sis),
    )


def _verificar_automaticas(ctx: CheckContext) -> None:
    sis = so.obter(ctx)
    if so.familia(sis) != "debian" or so.em_conteiner(sis):
        return
    motivo = _motivo_sem_automaticas(ctx, sis)
    if motivo is None:
        return
    asset = comum.ativo(ctx)
    if motivo:
        ctx.report(
            "host.linux.atualizacoes.automaticas_desligadas",
            asset=asset,
            evidence=motivo,
            tech=so.tecnologias(sis),
        )
    else:
        ctx.passed(
            "host.linux.atualizacoes.automaticas",
            "Atualizações automáticas de segurança ativas (unattended-upgrades)",
            asset,
        )


def _motivo_sem_automaticas(ctx: CheckContext, sis: SistemaLinux) -> str | None:
    """Por que as automáticas estão desligadas; ``""`` se estão ligadas; None se não deu para saber."""
    if sis.programa("unattended-upgrade") is None:
        return "o pacote unattended-upgrades não está instalado"
    dump = sis.comando("apt-config", "dump", tempo=20.0)
    if dump is None or dump.codigo != 0:
        comum.nao_verificado(ctx, "Atualizações automáticas", "sem resposta do apt-config")
        return None
    if analise.apt_config(dump.saida, "APT::Periodic::Enable") == "0":
        return 'APT::Periodic::Enable "0" desliga as tarefas periódicas do apt'
    valor = analise.apt_config(dump.saida, "APT::Periodic::Unattended-Upgrade")
    if valor in (None, "", "0"):
        return f'APT::Periodic::Unattended-Upgrade "{valor or ""}" (a tarefa diária está desligada)'
    if so.unidade_desligada(sis, "apt-daily-upgrade.timer"):
        return "o timer apt-daily-upgrade.timer está desativado"
    return ""


def _verificar_reinicio(ctx: CheckContext) -> None:
    sis = so.obter(ctx)
    if so.em_conteiner(sis):
        return
    asset = comum.ativo(ctx)
    for aviso in AVISO_REINICIO:
        if sis.existe(aviso):
            pacotes = (sis.ler(f"{aviso}.pkgs") or "").split()
            ctx.report(
                "host.linux.atualizacoes.reinicio_pendente",
                asset=asset,
                evidence=f"{aviso} existe"
                + (f" (pacotes: {', '.join(pacotes[:10])})" if pacotes else ""),
                details={"pacotes": pacotes[:LIMITE_PACOTES]},
                confidence=Confidence.CONFIRMED,
                tech=so.tecnologias(sis),
            )
            return
    if so.familia(sis) == "rhel":
        _reinicio_rhel(ctx, sis, asset)
    elif any(sis.existe(criador) for criador in CRIADORES_AVISO):
        ctx.passed("host.linux.atualizacoes.reinicio", "Nenhum reinício pendente", asset)
    else:
        ctx.log("Reinício pendente: o aviso do sistema não é criado nesta máquina (não verificado)")


def _reinicio_rhel(ctx: CheckContext, sis: SistemaLinux, asset: str) -> None:
    resultado = sis.comando("needs-restarting", "-r", tempo=TEMPO_PACOTES)
    saida = resultado.saida if resultado is not None else ""
    if "Reboot is required" in saida:
        ctx.report(
            "host.linux.atualizacoes.reinicio_pendente",
            asset=asset,
            evidence="needs-restarting -r: Reboot is required",
            confidence=Confidence.CONFIRMED,
            tech=so.tecnologias(sis),
        )
    elif "Reboot should not be necessary" in saida:
        ctx.passed("host.linux.atualizacoes.reinicio", "Nenhum reinício pendente", asset)
    else:
        comum.nao_verificado(ctx, "Reinício pendente", "sem resposta do needs-restarting")


@check(
    id="host.linux.atualizacoes",
    name="Atualizações do sistema (Linux)",
    category=Category.HOST,
    consumes=facts.LOCAL,
    description=(
        "Conta as atualizações de segurança pendentes no cache local do gerenciador de pacotes "
        "(sem acessar a Internet), confere o unattended-upgrades e o aviso de reinício pendente."
    ),
    findings=(
        "host.linux.atualizacoes.pendentes",
        "host.linux.atualizacoes.automaticas_desligadas",
        "host.linux.atualizacoes.reinicio_pendente",
    ),
    platforms=comum.LINUX,
    timeout=300.0,
)
def check_atualizacoes(ctx: CheckContext, fact: Fact) -> None:
    comum.executar(ctx, "Atualizações pendentes", _verificar_pendencias)
    comum.executar(ctx, "Atualizações automáticas", _verificar_automaticas)
    comum.executar(ctx, "Reinício pendente", _verificar_reinicio)


# -- defesas: SELinux/AppArmor, auditd e bloqueio de tentativas ----------------------------
def _verificar_mac(ctx: CheckContext) -> None:
    sis = so.obter(ctx)
    if so.fora_de_escopo(ctx, sis, "SELinux/AppArmor"):
        return
    asset = comum.ativo(ctx)
    enforce = sis.ler(ENFORCE_SELINUX, limite=16)
    if enforce is not None and enforce.strip() == "1":
        ctx.passed("host.linux.mac", "SELinux ativo em modo enforcing", asset)
        return
    apparmor = (sis.ler(APPARMOR, limite=16) or "").strip()
    if apparmor.upper().startswith("Y"):
        ctx.passed("host.linux.mac", "AppArmor habilitado no kernel", asset)
        return
    if enforce is not None:
        evidencia = f"{ENFORCE_SELINUX} = {enforce.strip()}"
        titulo = "SELinux em modo permissivo: só registra, não bloqueia"
    elif sis.caminho("/sys/module").is_dir():
        evidencia = f"SELinux não carregado; {APPARMOR} = {apparmor or 'ausente'}"
        titulo = None
    else:
        comum.nao_verificado(ctx, "SELinux/AppArmor", "/sys não está disponível")
        return
    ctx.report(
        "host.linux.mac.desligado",
        asset=asset,
        title=titulo,
        evidence=evidencia,
        tech=so.tecnologias(sis),
    )


def _verificar_auditd(ctx: CheckContext) -> None:
    sis = so.obter(ctx)
    if so.fora_de_escopo(ctx, sis, "Auditoria (auditd)"):
        return
    asset = comum.ativo(ctx)
    evidencia = "programa auditd não encontrado nas pastas padrão"
    if sis.programa("auditd") is not None:
        ativo = so.servico_ativo(sis, "auditd")
        if ativo is None and (sis.existe("/run/auditd.pid") or sis.existe("/var/run/auditd.pid")):
            ativo = True
        if ativo:
            ctx.passed("host.linux.auditoria.auditd", "Serviço de auditoria (auditd) ativo", asset)
            return
        if ativo is None:
            comum.nao_verificado(ctx, "Auditoria (auditd)", "sem resposta do systemctl")
            return
        evidencia = "auditd instalado, mas o serviço está parado"
    ctx.report(
        "host.linux.auditoria.auditd_ausente",
        asset=asset,
        evidence=evidencia,
        tech=so.tecnologias(sis),
    )


def _verificar_bloqueio_ssh(ctx: CheckContext) -> None:
    sis = so.obter(ctx)
    if so.fora_de_escopo(ctx, sis, "Bloqueio de tentativas no SSH"):
        return
    config = _config_ssh(ctx)
    if config is None:
        return
    senha = config.efetivo("passwordauthentication")
    if senha.valor.lower() != "yes":
        return  # só com chave: adivinhar senha não é o risco aqui
    asset = comum.ativo(ctx)
    parada = ""
    for programa, unidade, nome in PROTECOES_SSH:
        if sis.programa(programa) is None:
            continue
        if so.servico_ativo(sis, unidade) is False:
            parada = nome
            continue
        ctx.passed("host.linux.ssh.protecao", f"{nome} presente contra tentativas de senha", asset)
        return
    ctx.report(
        "host.linux.auditoria.fail2ban_ausente",
        asset=asset,
        evidence=(
            f"{parada} instalado, mas o serviço está parado"
            if parada
            else "fail2ban, CrowdSec e SSHGuard não encontrados nas pastas padrão"
        ),
        confidence=Confidence.FIRM if senha.certo else Confidence.TENTATIVE,
        tech=so.tecnologias(sis),
    )


@check(
    id="host.linux.defesas",
    name="SELinux/AppArmor, auditoria e bloqueio de tentativas (Linux)",
    category=Category.HOST,
    consumes=facts.LOCAL,
    description=(
        "Confere se SELinux (enforcing) ou AppArmor estão ativos, se o auditd funciona e, quando "
        "o SSH aceita senha, se há fail2ban ou ferramenta equivalente."
    ),
    findings=(
        "host.linux.mac.desligado",
        "host.linux.auditoria.auditd_ausente",
        "host.linux.auditoria.fail2ban_ausente",
    ),
    platforms=comum.LINUX,
)
def check_defesas(ctx: CheckContext, fact: Fact) -> None:
    comum.executar(ctx, "SELinux/AppArmor", _verificar_mac)
    comum.executar(ctx, "Auditoria (auditd)", _verificar_auditd)
    comum.executar(ctx, "Bloqueio de tentativas no SSH", _verificar_bloqueio_ssh)


# -- bancos de dados em escuta ---------------------------------------------------------------
def _portas(sis: SistemaLinux, arquivo: str) -> set[int] | None:
    """Portas em escuta no arquivo; None se ele não existe ou não tem nenhuma linha de socket válida."""
    texto = sis.ler(arquivo)
    if texto is None or not analise.tem_sockets(texto):
        return None
    return analise.portas_em_todas_interfaces(texto)


def _verificar_bancos(ctx: CheckContext) -> None:
    sis = so.obter(ctx)
    if so.em_conteiner(sis):
        ctx.log("Bancos em escuta: dentro de um container, quem decide a exposição é o host")
        return
    ipv4, ipv6 = _portas(sis, "/proc/net/tcp"), _portas(sis, "/proc/net/tcp6")
    if ipv4 is None and ipv6 is None:
        comum.nao_verificado(ctx, "Bancos em escuta", "/proc/net/tcp não está disponível")
        return
    ipv4, ipv6 = ipv4 or set(), ipv6 or set()
    asset = comum.ativo(ctx)
    expostas = sorted((ipv4 | ipv6) & BANCOS.keys())
    if not expostas:
        ctx.passed(
            "host.linux.rede.bancos",
            "Nenhuma porta padrão de banco de dados em escuta em todas as interfaces",
            asset,
        )
        return
    wsl = so.em_wsl(sis)
    firewall = estado_firewall(ctx)
    atenuado = wsl or bool(firewall.ativo)
    for porta in expostas:
        nome, tecnologia = BANCOS[porta]
        enderecos = [e for e, grupo in (("0.0.0.0", ipv4), ("[::]", ipv6)) if porta in grupo]  # nosec B104
        ctx.report(
            "host.linux.rede.banco_exposto",
            asset=asset,
            title=f"Porta do {nome} ({porta}) em escuta em todas as interfaces",
            severity=Severity.MEDIUM if atenuado else None,
            confidence=Confidence.TENTATIVE,  # só a porta padrão: o programa não foi confirmado
            evidence=(
                f"Em escuta em {' e '.join(f'{e}:{porta}' for e in enderecos)} "
                f"({' e '.join(arq for arq, grupo in (('/proc/net/tcp', ipv4), ('/proc/net/tcp6', ipv6)) if porta in grupo)})"
            ),
            details={
                "porta": porta,
                "banco": nome,
                "firewall": firewall.fonte,
                "wsl": wsl,
            },
            discriminator=str(porta),
            tech=so.tecnologias(sis, tecnologia),
        )


@check(
    id="host.linux.rede",
    name="Bancos de dados em escuta na rede (Linux)",
    category=Category.HOST,
    consumes=facts.LOCAL,
    description=(
        "Lê /proc/net/tcp e tcp6 para encontrar portas padrão de bancos de dados em escuta em "
        "todas as interfaces, sem abrir nenhuma conexão."
    ),
    findings=("host.linux.rede.banco_exposto",),
    platforms=comum.LINUX,
)
def check_rede(ctx: CheckContext, fact: Fact) -> None:
    comum.executar(ctx, "Bancos em escuta", _verificar_bancos)
