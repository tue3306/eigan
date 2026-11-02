"""Cenários de risco: problemas que, juntos, valem mais que a soma das partes.

Cada cenário é uma regra declarativa. Ele é ativado quando **todos** os grupos de
requisitos encontram pelo menos um achado (cada grupo aceita alternativas em formato
glob, ex.: ``web.cookie.*``). Com ``escopo="host"`` os achados precisam estar no mesmo
host; com ``escopo="alvo"`` basta estarem na mesma auditoria.

A saída explica a cadeia de ataque e qual correção a quebra — é o tipo de raciocínio
que um analista faria, escrito como regra auditável em vez de "inteligência" opaca.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from fnmatch import fnmatchcase
from urllib.parse import urlsplit

from ..core.models import Finding, Severity
from .scoring import counts_toward_score


@dataclass(frozen=True)
class Scenario:
    id: str
    title: str
    severity: Severity
    requires: tuple[tuple[str, ...], ...]
    narrative: str
    breaker: str
    scope: str = "host"  # host | alvo

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "requires": [list(group) for group in self.requires],
            "narrative": self.narrative,
            "breaker": self.breaker,
            "scope": self.scope,
        }


SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        id="cenario.credenciais_texto_claro",
        title="Senhas e sessões podem ser capturadas na rede",
        severity=Severity.HIGH,
        requires=(
            ("web.https.ausente", "web.https.sem_redirecionamento"),
            ("web.formulario.senha_http", "web.formulario.envio_http", "web.cookie.sem_secure"),
        ),
        narrative=(
            "O site aceita conexões sem criptografia e, ao mesmo tempo, trafega senhas ou "
            "cookies de sessão. Em uma rede Wi-Fi pública ou comprometida, quem estiver no "
            "caminho lê as credenciais e assume a conta do usuário."
        ),
        breaker="Forçar HTTPS em todo o site (redirecionamento 301 + HSTS) quebra a cadeia.",
    ),
    Scenario(
        id="cenario.sequestro_de_sessao",
        title="Uma falha de XSS levaria ao roubo de sessão",
        severity=Severity.HIGH,
        requires=(
            ("web.cookie.sem_httponly",),
            ("web.csp.*",),
        ),
        narrative=(
            "O cookie de sessão pode ser lido por JavaScript e não há Content-Security-Policy "
            "para conter scripts injetados. Qualquer XSS no site vira sequestro de conta: o "
            "script lê o cookie e o envia para fora."
        ),
        breaker="Marcar o cookie de sessão como HttpOnly impede a leitura por script.",
    ),
    Scenario(
        id="cenario.codigo_e_segredos_expostos",
        title="Código-fonte e segredos ao alcance de qualquer um",
        severity=Severity.CRITICAL,
        requires=(
            ("web.exposicao.repositorio",),
            (
                "web.exposicao.env",
                "web.exposicao.config",
                "web.exposicao.credenciais",
                "web.exposicao.htpasswd",
                "web.exposicao.backup",
                "web.exposicao.dump_sql",
                "web.conteudo.segredo",
                "code.segredos.*",
            ),
        ),
        narrative=(
            "O repositório do site está publicado e há arquivos de configuração ou segredos "
            "expostos. Com o código e as credenciais em mãos, um atacante procura falhas com "
            "calma e entra pelos serviços cujas senhas encontrou."
        ),
        breaker=(
            "Bloquear o acesso às pastas de controle de versão e trocar todas as credenciais "
            "que estiveram expostas."
        ),
        scope="alvo",
    ),
    Scenario(
        id="cenario.versao_vulneravel_divulgada",
        title="Versão vulnerável anunciada ao atacante",
        severity=Severity.HIGH,
        requires=(
            ("web.divulgacao.*", "net.versao.fim_de_vida.*", "net.versao.ramo_antigo.*"),
            (
                "web.biblioteca.vulneravel*",
                "web.cms.versao_vulneravel",
                "net.versao.vulneravel.*",
                "net.ssh.regresshion",
            ),
        ),
        narrative=(
            "O servidor informa exatamente qual software e versão usa, e essa versão tem "
            "vulnerabilidades públicas. Ferramentas automáticas varrem a Internet atrás dessa "
            "combinação e atacam em minutos."
        ),
        breaker="Atualizar o componente vulnerável; esconder a versão é só um complemento.",
    ),
    Scenario(
        id="cenario.email_falsificavel",
        title="Qualquer pessoa pode enviar e-mail em nome do domínio",
        severity=Severity.HIGH,
        requires=(
            (
                "dns.email.spf_ausente",
                "dns.email.spf_invalido",
                "dns.email.spf_multiplo",
                "dns.email.spf_consultas",
                "dns.email.spf_permissivo",
                "dns.email.spf_neutro",
                "dns.email.spf_softfail",
            ),
            (
                "dns.email.dmarc_ausente",
                "dns.email.dmarc_invalido",
                "dns.email.dmarc_monitoramento",
                "dns.email.dmarc_parcial",
            ),
        ),
        narrative=(
            "Sem SPF válido e sem DMARC aplicado, os provedores não têm como recusar mensagens "
            "falsas com o remetente do domínio. É o cenário ideal para phishing contra clientes "
            "e fornecedores e para golpes de boleto ou pagamento."
        ),
        breaker="Publicar DMARC (começando com p=none e evoluindo para quarantine/reject) e SPF.",
        scope="alvo",
    ),
    Scenario(
        id="cenario.banco_de_dados_aberto",
        title="Banco de dados acessível e sem senha",
        severity=Severity.CRITICAL,
        requires=(
            ("net.banco.exposto",),
            (
                "net.redis.sem_senha",
                "net.mongodb.sem_senha",
                "net.elasticsearch.sem_senha",
                "net.memcached.sem_senha",
                "net.couchdb.sem_senha",
                "net.cassandra.sem_senha",
                "net.clickhouse.sem_senha",
                "net.influxdb.sem_senha",
                "net.etcd.sem_senha",
            ),
        ),
        narrative=(
            "Um serviço de dados está alcançável pela rede e responde sem pedir credenciais. "
            "É possível ler, alterar ou apagar os dados, e esse é um dos vetores mais comuns de "
            "vazamento e de sequestro de dados (ransomware)."
        ),
        breaker="Fechar a porta no firewall e exigir autenticação no serviço.",
    ),
    Scenario(
        id="cenario.movimentacao_lateral_windows",
        title="Rede Windows facilita a movimentação lateral",
        severity=Severity.HIGH,
        requires=(
            ("host.win.smb*", "net.smb.*"),
            ("host.win.ntlm*", "host.win.wdigest*", "host.win.llmnr*", "host.win.netbios*"),
        ),
        narrative=(
            "Protocolos legados de compartilhamento e de autenticação estão ativos. Um invasor "
            "que entra em uma máquina captura credenciais na rede (LLMNR/NetBIOS, NTLM fraco) e "
            "as reutiliza via SMB para pular de máquina em máquina."
        ),
        breaker="Desativar SMBv1 e os protocolos de resolução legados, e exigir NTLMv2.",
        scope="alvo",
    ),
    Scenario(
        id="cenario.acesso_remoto_exposto",
        title="Acesso remoto exposto com proteção fraca",
        severity=Severity.HIGH,
        requires=(
            ("net.rdp.*", "net.ssh.*", "net.vnc.*", "net.telnet.ativo"),
            (
                "host.win.rdp*",
                "host.linux.ssh.*senha*",
                "host.linux.ssh.*root*",
                "net.rdp.sem_nla",
                "net.vnc.sem_senha",
                "logs.*forca_bruta*",
                "logs.windows.rdp_apos_falhas",
                "logs.ssh.sucesso_apos_falhas",
            ),
        ),
        narrative=(
            "O serviço de acesso remoto está aberto e aceita autenticação fraca (senha, root ou "
            "RDP sem NLA). Robôs testam senhas o dia todo; uma senha fraca vira controle total "
            "da máquina."
        ),
        breaker="Restringir o acesso por VPN ou lista de IPs e exigir chave/NLA com MFA.",
        scope="alvo",
    ),
    Scenario(
        id="cenario.tls_legado",
        title="Criptografia antiga permite rebaixamento",
        severity=Severity.MEDIUM,
        requires=(
            ("tls.protocolo.*", "tls.versao.sem_tls12"),
            ("tls.cifra.*",),
        ),
        narrative=(
            "O servidor ainda negocia versões antigas de TLS e cifras fracas. Um atacante na "
            "rede força o uso da opção mais fraca e enfraquece a proteção da conexão."
        ),
        breaker="Aceitar só TLS 1.2 e 1.3 com cifras AEAD (perfil intermediário da Mozilla).",
    ),
    Scenario(
        id="cenario.painel_admin_atacavel",
        title="Painel administrativo exposto a tentativas de invasão",
        severity=Severity.HIGH,
        requires=(
            ("web.painel.*", "web.cms.login"),
            (
                "web.https.ausente",
                "web.cms.usuarios",
                "web.cms.xmlrpc",
                "logs.*forca_bruta*",
            ),
        ),
        narrative=(
            "A área administrativa está aberta para a Internet e há sinais que facilitam o "
            "ataque (usuários enumeráveis, ausência de HTTPS ou tentativas de senha nos logs). "
            "Quem acerta a senha do administrador controla o site inteiro."
        ),
        breaker="Restringir o painel por IP ou VPN e ativar autenticação em dois fatores.",
        scope="alvo",
    ),
    Scenario(
        id="cenario.debug_em_producao",
        title="Modo de depuração revela o funcionamento interno",
        severity=Severity.HIGH,
        requires=(
            ("web.debug.*", "web.erro.*", "code.config.debug*"),
            (
                "web.exposicao.*",
                "web.divulgacao.*",
                "code.segredos.*",
            ),
        ),
        narrative=(
            "A aplicação está em modo de depuração e expõe outros detalhes internos. Mensagens "
            "de erro completas mostram caminhos, consultas e variáveis, o que encurta muito o "
            "trabalho de quem procura uma falha explorável."
        ),
        breaker="Desligar o modo de depuração em produção e usar páginas de erro genéricas.",
        scope="alvo",
    ),
    Scenario(
        id="cenario.maquina_sem_defesas",
        title="Máquina sem as defesas básicas do sistema",
        severity=Severity.HIGH,
        requires=(
            ("host.win.firewall*", "host.linux.firewall*"),
            (
                "host.win.defender*",
                "host.win.antivirus*",
                "host.win.atualiza*",
                "host.linux.atualiza*",
                "host.win.bitlocker*",
                "host.win.uac*",
            ),
        ),
        narrative=(
            "O firewall está desligado e outra camada básica (antivírus, atualizações, UAC ou "
            "criptografia de disco) também falha. Uma única brecha ou um anexo malicioso não "
            "encontra barreira nenhuma."
        ),
        breaker="Religar o firewall do sistema e a proteção em tempo real.",
        scope="alvo",
    ),
    Scenario(
        id="cenario.invasao_em_andamento",
        title="Indícios de invasão em andamento",
        severity=Severity.CRITICAL,
        requires=(
            ("logs.*forca_bruta*", "logs.*varredura*"),
            (
                "logs.*sucesso*",
                "logs.*novo_usuario*",
                "logs.*admin*",
                "logs.*webshell*",
                "logs.windows.rdp_apos_falhas",
                "logs.windows.usuario_criado",
                "logs.windows.grupo_privilegiado",
            ),
        ),
        narrative=(
            "Os logs mostram tentativas em massa seguidas de eventos de sucesso ou de "
            "privilégio. Esse padrão é típico de uma invasão concluída: trate como incidente."
        ),
        breaker=(
            "Isolar o sistema, trocar as credenciais envolvidas e investigar os eventos a "
            "partir do primeiro sucesso."
        ),
        scope="alvo",
    ),
    Scenario(
        id="cenario.listagem_com_backup",
        title="Arquivos de backup encontráveis pela listagem de diretórios",
        severity=Severity.HIGH,
        requires=(
            ("web.exposicao.listagem",),
            ("web.exposicao.backup", "web.exposicao.dump_sql"),
        ),
        narrative=(
            "O servidor lista o conteúdo das pastas e há cópias de segurança acessíveis. Basta "
            "navegar pela listagem para baixar o banco de dados ou o código completo."
        ),
        breaker="Desativar a listagem de diretórios e retirar os backups da pasta pública.",
        scope="alvo",
    ),
    Scenario(
        id="cenario.clickjacking_login",
        title="Tela de login pode ser embutida em site falso",
        severity=Severity.MEDIUM,
        requires=(
            ("web.clickjacking.ausente",),
            ("web.formulario.*",),
        ),
        narrative=(
            "A página com formulário pode ser carregada dentro de outro site. Um site falso "
            "sobrepõe elementos invisíveis e induz o usuário a clicar ou digitar no lugar "
            "errado (clickjacking)."
        ),
        breaker="Enviar Content-Security-Policy frame-ancestors 'self' (ou X-Frame-Options).",
    ),
    Scenario(
        id="cenario.cms_desatualizado_e_visado",
        title="CMS desatualizado com porta de entrada à vista",
        severity=Severity.HIGH,
        requires=(
            ("web.cms.versao_vulneravel", "web.cms.desatualizado", "web.cms.fim_de_suporte"),
            ("web.cms.login", "web.cms.usuarios", "web.cms.xmlrpc"),
        ),
        narrative=(
            "O CMS roda uma versão com falhas conhecidas ou sem suporte, e a tela de login, a "
            "lista de usuários ou o XML-RPC estão acessíveis. Robôs procuram exatamente essa "
            "combinação: exploram a falha ou testam senhas nos usuários que o próprio site revela."
        ),
        breaker="Atualizar o CMS e os plugins; depois restringir o acesso ao painel e ao XML-RPC.",
    ),
    Scenario(
        id="cenario.cors_le_dados_autenticados",
        title="Outro site consegue ler dados de quem está logado",
        severity=Severity.HIGH,
        requires=(
            (
                "web.cors.reflete_origem_credenciais",
                "web.cors.null_credenciais",
                "web.cors.curinga_credenciais",
            ),
            ("web.cookie.sem_samesite", "web.cookie.samesite_none_sem_secure"),
        ),
        narrative=(
            "A API aceita requisições com credenciais vindas de outras origens e o cookie de "
            "sessão é enviado nessas requisições. Uma página maliciosa aberta por um usuário "
            "logado consegue ler as respostas da API em nome dele."
        ),
        breaker="Liberar no CORS só as origens confiáveis, em lista fixa, e usar SameSite=Lax.",
    ),
    Scenario(
        id="cenario.linux_caminho_curto_para_root",
        title="Quem entrar por SSH chega rápido a root",
        severity=Severity.HIGH,
        requires=(
            (
                "host.linux.ssh.senha_permitida",
                "host.linux.ssh.root_permitido",
                "host.linux.ssh.senha_vazia",
            ),
            (
                "host.linux.sudo.nopasswd_total",
                "host.linux.docker.socket_gravavel",
                "host.linux.suid.binario_arriscado",
                "host.linux.path.pasta_gravavel",
                "host.linux.cron.gravavel",
                "host.linux.arquivos.passwd_gravavel",
                "host.linux.arquivos.shadow_legivel",
            ),
        ),
        narrative=(
            "O SSH aceita senha ou login direto de root, e dentro do sistema há um atalho para "
            "virar administrador (sudo sem senha, socket do Docker, SUID arriscado ou arquivo "
            "gravável). Uma única senha fraca vira controle total da máquina."
        ),
        breaker="Exigir chave no SSH e remover o atalho de privilégio indicado no achado.",
        scope="alvo",
    ),
    Scenario(
        id="cenario.windows_credenciais_na_memoria",
        title="Senhas do Windows fáceis de extrair da memória",
        severity=Severity.HIGH,
        requires=(
            ("host.win.wdigest.senha_em_memoria",),
            (
                "host.win.lsa.sem_protecao",
                "host.win.uac.*",
                "host.win.defender.tempo_real_desligado",
            ),
        ),
        narrative=(
            "O WDigest guarda senhas em texto legível na memória e o processo LSASS não tem "
            "proteção extra. Quem obtém privilégio de administrador local extrai essas senhas e "
            "as reutiliza em outras máquinas da rede."
        ),
        breaker="Desligar o WDigest (UseLogonCredential=0) e ativar a proteção do LSA (RunAsPPL).",
        scope="alvo",
    ),
    Scenario(
        id="cenario.conteiner_escapa_para_o_host",
        title="Contêiner configurado para escapar para o host",
        severity=Severity.HIGH,
        requires=(
            (
                "code.iac.privilegiado",
                "code.iac.docker_sock",
                "code.iac.hostpath",
                "code.iac.namespace_host",
                "code.iac.capabilities_perigosas",
            ),
            ("code.iac.container_root", "code.iac.escalacao_privilegio"),
        ),
        narrative=(
            "O manifesto dá ao contêiner acesso amplo ao host e ele roda como root ou pode "
            "elevar privilégios. Uma falha na aplicação deixa de ficar presa ao contêiner e vira "
            "controle do servidor inteiro."
        ),
        breaker="Rodar como usuário comum e retirar privileged, hostPath e o socket do Docker.",
        scope="alvo",
    ),
    Scenario(
        id="cenario.email_interceptavel",
        title="E-mail do domínio pode ser lido no caminho",
        severity=Severity.MEDIUM,
        requires=(
            ("net.correio.sem_tls", "net.smtp.sem_starttls"),
            (
                "dns.email.mta_sts_ausente",
                "dns.email.mta_sts_nao_aplicado",
                "dns.email.mta_sts_invalido",
            ),
        ),
        narrative=(
            "O servidor de correio não oferece criptografia obrigatória e o domínio não publica "
            "MTA-STS. Quem estiver no caminho remove o STARTTLS e lê as mensagens em trânsito."
        ),
        breaker="Ativar STARTTLS com certificado válido e publicar MTA-STS em modo enforce.",
        scope="alvo",
    ),
    Scenario(
        id="cenario.rastros_apagados",
        title="Log apagado depois de atividade suspeita",
        severity=Severity.CRITICAL,
        requires=(
            ("logs.windows.log_apagado",),
            (
                "logs.windows.forca_bruta",
                "logs.windows.rdp_apos_falhas",
                "logs.windows.usuario_criado",
                "logs.windows.grupo_privilegiado",
                "logs.windows.servico_instalado",
                "logs.windows.comando_suspeito",
            ),
        ),
        narrative=(
            "O log de eventos foi limpo e há atividade suspeita registrada na mesma máquina. "
            "Apagar o log é o que um invasor faz para esconder o que fez, e por isso o intervalo "
            "sem registro merece tanta atenção quanto o que restou."
        ),
        breaker=(
            "Isolar a máquina, preservar o que restou dos logs e reconstruir a linha do tempo "
            "pelas fontes externas (SIEM, firewall, proxy)."
        ),
        scope="alvo",
    ),
)

_HOSTPORT = re.compile(r"^\[?([^\]/\\\s]+?)\]?:\d+(?:/\w+)?$")


def asset_host(asset: str) -> str:
    """Host de um ativo (URL, ``host:porta``, ``host:porta/tcp`` ou domínio)."""
    text = asset.strip()
    if "://" in text:
        return (urlsplit(text).hostname or text).lower()
    match = _HOSTPORT.match(text)
    if match:
        return match.group(1).lower()
    return text.lower()


@dataclass
class ScenarioMatch:
    scenario: Scenario
    findings: list[Finding]
    host: str = ""

    @property
    def fingerprints(self) -> list[str]:
        return [f.fingerprint for f in self.findings]

    def to_dict(self) -> dict[str, object]:
        data = self.scenario.to_dict()
        data.pop("requires")
        data.update(
            {
                "host": self.host,
                "findings": self.fingerprints,
                "assets": sorted({f.asset for f in self.findings}),
                "titles": sorted({f.title for f in self.findings}),
            }
        )
        return data


def _matches(finding: Finding, patterns: Iterable[str]) -> bool:
    return any(fnmatchcase(finding.check_id, pattern) for pattern in patterns)


def _match_group(findings: list[Finding], scenario: Scenario) -> list[Finding] | None:
    chosen: list[Finding] = []
    for group in scenario.requires:
        hits = [f for f in findings if _matches(f, group)]
        if not hits:
            return None
        chosen.extend(hits)
    # Um mesmo achado não pode satisfazer sozinho dois grupos.
    unique = {f.fingerprint: f for f in chosen}
    if len(unique) < len(scenario.requires):
        return None
    return list(unique.values())


def correlate(findings: Iterable[Finding]) -> list[ScenarioMatch]:
    active = [f for f in findings if counts_toward_score(f)]
    matches: list[ScenarioMatch] = []
    for scenario in SCENARIOS:
        if scenario.scope == "alvo":
            found = _match_group(active, scenario)
            if found:
                matches.append(ScenarioMatch(scenario, found))
            continue
        by_host: dict[str, list[Finding]] = defaultdict(list)
        for finding in active:
            by_host[asset_host(finding.asset)].append(finding)
        for host in sorted(by_host):
            found = _match_group(by_host[host], scenario)
            if found:
                matches.append(ScenarioMatch(scenario, found, host))
    matches.sort(key=lambda m: (-m.scenario.severity.rank, m.scenario.id, m.host))
    return matches


def all_patterns() -> list[tuple[str, str]]:
    """(cenário, padrão) — usado em teste para garantir que os padrões casam com a base."""
    return [(s.id, p) for s in SCENARIOS for group in s.requires for p in group]
