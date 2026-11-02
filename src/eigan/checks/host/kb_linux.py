"""Base de conhecimento do Linux: SSH, firewall e atualizações.

As demais entradas de Linux ficam em ``linux_kb_sistema.py`` (kernel, SELinux/AppArmor,
auditoria e portas) e ``linux_kb_acesso.py`` (contas, sudo e permissões), para manter cada
arquivo com menos de 600 linhas.
"""

from __future__ import annotations

from ...core import kb
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Severity

_MAN_SSHD = "https://man.openbsd.org/sshd_config"
_UBUNTU_SSH = "https://ubuntu.com/server/docs/how-to/security/openssh-server/"
_APLICAR_SSH = (
    "\n\n# o sshd usa a PRIMEIRA ocorrência de cada opção: este arquivo precisa vir antes\n"
    "# (Include no topo do sshd_config) ou a linha deve ser trocada no próprio sshd_config\n"
    "sudo sshd -t && sudo systemctl reload ssh   # RHEL/Fedora: sshd"
)


def _sshd(linhas: str) -> Fix:
    return Fix(
        "openssh",
        "OpenSSH (/etc/ssh/sshd_config.d/00-eigan.conf)",
        linhas + _APLICAR_SSH,
        "text",
    )


_PASSO_PRIMEIRA = (
    "Lembre que o sshd usa a PRIMEIRA ocorrência de cada opção: se o /etc/ssh/sshd_config "
    "começa com 'Include /etc/ssh/sshd_config.d/*.conf', crie nessa pasta um arquivo que "
    "venha antes dos outros na ordem alfabética (ex.: 00-eigan.conf); senão, altere a linha "
    "no próprio sshd_config."
)
_PASSO_VALIDAR = (
    "Valide com 'sudo sshd -t' e recarregue o serviço sem fechar a sessão atual; teste um "
    "novo login em outra janela antes de sair."
)

kb.register(
    KBEntry(
        id="host.linux.ssh.root_permitido",
        title="SSH aceita login direto como root",
        category=Category.HOST,
        severity=Severity.MEDIUM,
        summary="O servidor SSH permite entrar diretamente na conta root (PermitRootLogin yes).",
        explanation=(
            "Com PermitRootLogin yes, quem alcança a porta do SSH pode tentar entrar direto como "
            "root, a conta com poder total sobre a máquina, inclusive com senha. Desde o "
            "OpenSSH 7.0 o padrão é 'prohibit-password' (root só com chave); o 'yes' foi "
            "colocado de propósito ou veio de uma configuração antiga. O caminho recomendado é "
            "entrar com um usuário comum e usar o sudo, o que também deixa registrado quem fez "
            "cada ação."
        ),
        risk=(
            "Robôs na Internet testam senhas de root o tempo todo. Uma senha fraca ou vazada dá "
            "controle total da máquina de uma vez, e os registros não mostram qual pessoa entrou."
        ),
        steps=(
            "Garanta que existe um usuário comum com sudo e que você consegue entrar com ele "
            "(de preferência com chave SSH).",
            "Defina PermitRootLogin no (ou prohibit-password, se alguma automação precisa entrar "
            "como root usando chave).",
            _PASSO_PRIMEIRA,
            _PASSO_VALIDAR,
        ),
        examples=(_sshd("PermitRootLogin no"),),
        verify=(
            "sudo sshd -T | grep -i permitrootlogin deve mostrar 'no' (ou 'prohibit-password' / "
            "'without-password')."
        ),
        effort="baixo",
        fix_group="ssh",
        references=(_MAN_SSHD, "https://www.openssh.org/txt/release-7.0", _UBUNTU_SSH),
        cwe="CWE-250",
        owasp="A07:2021",
        cis=("4.7", "5.4"),
        tags=("ssh", "root", "linux"),
    ),
    KBEntry(
        id="host.linux.ssh.senha_permitida",
        title="SSH aceita login com senha",
        category=Category.HOST,
        severity=Severity.MEDIUM,
        summary="O servidor SSH aceita autenticação por senha (PasswordAuthentication yes).",
        explanation=(
            "Com a autenticação por senha ligada, quem alcança a porta do SSH pode tentar "
            "adivinhar a senha de qualquer conta. Chaves SSH (um par de chaves pública e privada) "
            "não podem ser adivinhadas assim e eliminam esse tipo de ataque. Atenção: quando a "
            "opção não aparece em nenhum arquivo, o padrão do OpenSSH é 'yes'."
        ),
        risk=(
            "Ataques de força bruta e de senhas vazadas contra o SSH acontecem sem parar na "
            "Internet. Basta uma conta com senha fraca para o invasor entrar na máquina."
        ),
        steps=(
            "No seu computador, crie um par de chaves (ssh-keygen -t ed25519) e copie a chave "
            "pública para o servidor (ssh-copy-id usuario@servidor).",
            "Confirme que consegue entrar com a chave, sem digitar a senha da conta.",
            "Defina PasswordAuthentication no e KbdInteractiveAuthentication no (a não ser que "
            "use um segundo fator pelo PAM, como código no celular).",
            _PASSO_PRIMEIRA,
            _PASSO_VALIDAR,
            "Se ainda não der para abandonar a senha, restrinja o acesso ao SSH por firewall ou "
            "VPN e instale uma proteção contra força bruta (fail2ban).",
        ),
        examples=(
            _sshd("PasswordAuthentication no\nKbdInteractiveAuthentication no"),
            Fix(
                "linux",
                "Criar e instalar a chave (no seu computador)",
                "ssh-keygen -t ed25519\nssh-copy-id usuario@servidor",
                "bash",
            ),
        ),
        verify=(
            "sudo sshd -T | grep -i passwordauthentication deve mostrar 'no'; "
            "'ssh -o PubkeyAuthentication=no usuario@servidor' deve ser recusado."
        ),
        effort="baixo",
        fix_group="ssh",
        references=(_MAN_SSHD, _UBUNTU_SSH),
        cwe="CWE-309",
        owasp="A07:2021",
        cis=("4.6",),
        tags=("ssh", "senha", "linux"),
    ),
    KBEntry(
        id="host.linux.ssh.senha_vazia",
        title="SSH aceita contas com senha vazia",
        category=Category.HOST,
        severity=Severity.HIGH,
        summary="O servidor SSH permite login em contas sem senha (PermitEmptyPasswords yes).",
        explanation=(
            "Com PermitEmptyPasswords yes, uma conta cuja senha está em branco entra pelo SSH sem "
            "digitar nada. O padrão do OpenSSH é 'no'; o 'yes' costuma ser resto de testes ou de "
            "instalações antigas."
        ),
        risk=(
            "Se existir (ou vier a existir) uma conta sem senha, ela vira uma porta aberta para a "
            "rede: basta saber o nome do usuário."
        ),
        steps=(
            "Defina PermitEmptyPasswords no.",
            "Procure contas sem senha (o EIGAN também verifica isso) e bloqueie-as com "
            "'sudo passwd -l usuario' ou defina uma senha.",
            _PASSO_PRIMEIRA,
            _PASSO_VALIDAR,
        ),
        examples=(_sshd("PermitEmptyPasswords no"),),
        verify="sudo sshd -T | grep -i permitemptypasswords deve mostrar 'no'.",
        effort="baixo",
        fix_group="ssh",
        references=(_MAN_SSHD,),
        cwe="CWE-521",
        owasp="A07:2021",
        cis=("5.2",),
        tags=("ssh", "senha", "linux"),
    ),
    KBEntry(
        id="host.linux.ssh.x11_forwarding",
        title="SSH permite encaminhamento X11",
        category=Category.HOST,
        severity=Severity.LOW,
        summary="O servidor SSH permite encaminhar janelas gráficas (X11Forwarding yes).",
        explanation=(
            "O encaminhamento X11 leva janelas gráficas do servidor para a tela de quem se "
            "conecta. Em servidores ele quase nunca é necessário. O padrão do OpenSSH é 'no', "
            "mas várias distribuições entregam 'yes' no arquivo de configuração. Segundo o "
            "manual do sshd_config, o risco é expor a tela (servidor X11) do cliente que pede o "
            "encaminhamento a ataques vindos do servidor."
        ),
        risk=(
            "Se o servidor for invadido, quem estiver nele pode tentar espionar ou manipular a "
            "tela e o teclado dos administradores que se conectam com encaminhamento X11."
        ),
        steps=(
            "Defina X11Forwarding no, a não ser que alguém realmente use aplicativos gráficos "
            "por SSH nesta máquina.",
            _PASSO_PRIMEIRA,
            "Valide com 'sudo sshd -t' e recarregue o serviço.",
        ),
        examples=(_sshd("X11Forwarding no"),),
        verify="sudo sshd -T | grep -i x11forwarding deve mostrar 'no'.",
        effort="baixo",
        fix_group="ssh",
        references=(_MAN_SSHD,),
        cwe="CWE-668",
        owasp="A05:2021",
        cis=("4.8",),
        tags=("ssh", "linux"),
    ),
    KBEntry(
        id="host.linux.ssh.tentativas_excessivas",
        title="SSH permite muitas tentativas de login por conexão",
        category=Category.HOST,
        severity=Severity.LOW,
        summary="MaxAuthTries está acima de 4: cada conexão pode testar várias senhas ou chaves.",
        explanation=(
            "MaxAuthTries define quantas tentativas de autenticação uma única conexão pode fazer "
            "antes de ser derrubada; o padrão do OpenSSH é 6. Com 4 ou menos, a adivinhação de "
            "senhas fica mais lenta e as falhas aparecem antes no log (o sshd registra as falhas "
            "a partir da metade desse limite), o que ajuda ferramentas como o fail2ban."
        ),
        risk=(
            "Mais tentativas por conexão facilitam ataques de adivinhação de senha e atrasam a "
            "detecção."
        ),
        steps=(
            "Defina MaxAuthTries 4 (ou menos).",
            "Se alguém tiver muitas chaves no agente SSH, oriente a indicar a chave certa "
            "(IdentitiesOnly yes no cliente) para não esgotar as tentativas.",
            _PASSO_PRIMEIRA,
            "Valide com 'sudo sshd -t' e recarregue o serviço.",
        ),
        examples=(_sshd("MaxAuthTries 4"),),
        verify="sudo sshd -T | grep -i maxauthtries deve mostrar 4 ou menos.",
        effort="baixo",
        fix_group="ssh",
        references=(_MAN_SSHD,),
        cwe="CWE-307",
        owasp="A07:2021",
        cis=("4.1",),
        tags=("ssh", "forca_bruta", "linux"),
    ),
    KBEntry(
        id="host.linux.firewall.inativo",
        title="Firewall do Linux desligado",
        category=Category.HOST,
        severity=Severity.MEDIUM,
        summary=(
            "Não há filtragem ativa das conexões que chegam à máquina (ufw, firewalld, nftables "
            "ou iptables)."
        ),
        explanation=(
            "O firewall do sistema decide quais conexões vindas da rede chegam aos serviços da "
            "máquina. Sem ele, qualquer programa que abrir uma porta — um banco de dados, um "
            "painel de testes, um serviço esquecido — fica acessível para toda a rede (e, em "
            "servidores com IP público, para a Internet). Sem root, o EIGAN não consegue ler as "
            "regras do kernel e se baseia no estado do ufw e dos serviços de firewall; nesse "
            "caso o achado aparece como indício."
        ),
        risk=(
            "Cada serviço exposto sem necessidade é uma chance a mais de invasão: basta uma "
            "falha ou uma senha fraca em qualquer um deles. Firewalls externos (da nuvem ou do "
            "roteador) ajudam, mas não protegem contra máquinas da mesma rede."
        ),
        steps=(
            "Liste o que precisa ficar acessível de fora (ex.: SSH na 22, HTTPS na 443).",
            "Debian/Ubuntu: use o ufw — libere primeiro o SSH (para não perder o acesso) e "
            "depois ative-o, com a política padrão de bloquear as entradas.",
            "RHEL/Fedora/Alma/Rocky: ative o firewalld e libere só os serviços necessários na "
            "zona ativa.",
            "Outras distribuições: crie um conjunto de regras nftables com política 'drop' na "
            "entrada.",
            "Atenção: portas publicadas pelo Docker passam por fora das regras do ufw; publique "
            "serviços de containers só em 127.0.0.1 quando não precisarem de acesso externo.",
        ),
        examples=(
            Fix(
                "debian",
                "Debian/Ubuntu (ufw)",
                "sudo ufw default deny incoming\nsudo ufw default allow outgoing\n"
                "sudo ufw allow 22/tcp\nsudo ufw enable\nsudo ufw status verbose",
                "bash",
            ),
            Fix(
                "rhel",
                "RHEL/Fedora/Alma/Rocky (firewalld)",
                "sudo systemctl unmask --now firewalld.service\n"
                "sudo systemctl enable --now firewalld.service\n"
                "sudo firewall-cmd --state\nsudo firewall-cmd --list-all",
                "bash",
            ),
            Fix(
                "linux",
                "nftables (/etc/nftables.conf)",
                "table inet filter {\n  chain input {\n"
                "    type filter hook input priority 0; policy drop;\n"
                "    ct state established,related accept\n    iifname lo accept\n"
                "    tcp dport 22 accept\n  }\n}\n\n"
                "sudo nft -f /etc/nftables.conf && sudo systemctl enable --now nftables",
                "text",
            ),
        ),
        verify=(
            "'sudo ufw status verbose' deve mostrar 'Status: active', ou 'sudo firewall-cmd "
            "--state' deve mostrar 'running', ou 'sudo nft list ruleset' deve ter a cadeia de "
            "entrada com 'policy drop'."
        ),
        effort="medio",
        fix_group="linux",
        references=(
            "https://ubuntu.com/server/docs/how-to/security/firewalls/",
            "https://firewalld.org/documentation/howto/enable-and-disable-firewalld.html",
            "https://wiki.nftables.org/wiki-nftables/index.php/Simple_ruleset_for_a_server",
            "https://docs.docker.com/engine/network/packet-filtering-firewalls/",
        ),
        cwe="CWE-693",
        owasp="A05:2021",
        cis=("4.4", "4.5"),
        tags=("firewall", "linux"),
    ),
    KBEntry(
        id="host.linux.atualizacoes.pendentes",
        title="Atualizações de segurança pendentes",
        category=Category.HOST,
        severity=Severity.HIGH,
        summary="Há atualizações de segurança disponíveis que ainda não foram instaladas.",
        explanation=(
            "As distribuições publicam correções de segurança com frequência. Enquanto elas não "
            "são instaladas, a máquina continua com falhas que já são públicas — e para muitas "
            "delas já existem ferramentas de ataque prontas. A contagem vem do cache local do "
            "gerenciador de pacotes (apt ou dnf), sem acessar a Internet; se o cache estiver "
            "velho, pode haver ainda mais pendências."
        ),
        risk=(
            "Falhas conhecidas em pacotes do sistema (kernel, OpenSSL, sudo, serviços de rede) "
            "permitem invasão pela rede ou ganho de root por quem já tem uma conta comum."
        ),
        steps=(
            "Atualize a lista de pacotes e instale as atualizações (comandos abaixo), de "
            "preferência numa janela de manutenção.",
            "Reinicie a máquina se o kernel ou bibliotecas centrais forem atualizados (o EIGAN "
            "avisa quando há reinício pendente).",
            "Ative as atualizações automáticas de segurança para não acumular pendências.",
        ),
        examples=(
            Fix("debian", "Debian/Ubuntu", "sudo apt update\nsudo apt upgrade", "bash"),
            Fix(
                "rhel",
                "RHEL/Fedora/Alma/Rocky",
                "sudo dnf upgrade --security\n# ou todas as atualizações:\nsudo dnf upgrade",
                "bash",
            ),
        ),
        verify=(
            "Ubuntu: '/usr/lib/update-notifier/apt-check --human-readable' deve mostrar 0 "
            "atualizações de segurança; RHEL e derivados: 'dnf check-update --security' não deve "
            "listar pacotes."
        ),
        effort="medio",
        fix_group="sistema",
        references=(
            "https://ubuntu.com/security/notices",
            "https://www.debian.org/security/",
            "https://dnf.readthedocs.io/en/latest/command_ref.html",
        ),
        cwe="CWE-1395",
        owasp="A06:2021",
        cis=("7.1", "7.3"),
        tags=("atualizacao", "linux"),
    ),
    KBEntry(
        id="host.linux.atualizacoes.automaticas_desligadas",
        title="Atualizações automáticas de segurança desligadas",
        category=Category.HOST,
        severity=Severity.LOW,
        summary="As atualizações automáticas de segurança (unattended-upgrades) não estão ativas.",
        explanation=(
            "No Debian e no Ubuntu, o unattended-upgrades instala sozinho as correções de "
            "segurança todos os dias; no Ubuntu ele vem instalado e ativo por padrão. Quando "
            "está desligado ou não instalado, as correções dependem de alguém lembrar de "
            "atualizar a máquina."
        ),
        risk=(
            "Correções de segurança atrasam semanas ou meses, deixando falhas públicas abertas "
            "por mais tempo."
        ),
        steps=(
            "Instale o pacote unattended-upgrades.",
            "Ative as tarefas periódicas em /etc/apt/apt.conf.d/20auto-upgrades (exemplo abaixo) "
            "ou rode 'sudo dpkg-reconfigure unattended-upgrades'.",
            "Confira se o timer apt-daily-upgrade.timer não foi desativado.",
            "Se a empresa exige janela de mudança, mantenha ao menos as atualizações de "
            "segurança automáticas e agende os reinícios.",
        ),
        examples=(
            Fix(
                "debian",
                "Debian/Ubuntu (/etc/apt/apt.conf.d/20auto-upgrades)",
                'APT::Periodic::Update-Package-Lists "1";\n'
                'APT::Periodic::Unattended-Upgrade "1";\n\n'
                "sudo apt install unattended-upgrades\n"
                "sudo systemctl enable --now apt-daily.timer apt-daily-upgrade.timer",
                "text",
            ),
        ),
        verify=(
            "'apt-config dump | grep Unattended-Upgrade' deve mostrar \"1\"; "
            "'sudo unattended-upgrade --dry-run -d' mostra o que seria instalado."
        ),
        effort="baixo",
        fix_group="sistema",
        references=(
            "https://ubuntu.com/server/docs/how-to/software/automatic-updates/",
            "https://wiki.debian.org/UnattendedUpgrades",
        ),
        cwe="CWE-1395",
        owasp="A06:2021",
        cis=("7.3",),
        tags=("atualizacao", "linux"),
    ),
    KBEntry(
        id="host.linux.atualizacoes.reinicio_pendente",
        title="Reinício pendente para aplicar atualizações",
        category=Category.HOST,
        severity=Severity.LOW,
        summary="O sistema precisa ser reiniciado para que atualizações já instaladas passem a valer.",
        explanation=(
            "Algumas atualizações (kernel, glibc, systemd e outras bibliotecas centrais) só "
            "entram em vigor depois de reiniciar. Até lá a máquina continua rodando o código "
            "antigo, ainda vulnerável, mesmo com os pacotes novos instalados. No Debian/Ubuntu "
            "isso é indicado pelo arquivo /var/run/reboot-required; no RHEL e derivados, pelo "
            "comando 'needs-restarting -r'."
        ),
        risk=(
            "As correções instaladas não protegem enquanto a máquina não reinicia: o kernel e os "
            "serviços em execução continuam com as falhas."
        ),
        steps=(
            "Veja quais pacotes pediram o reinício (/var/run/reboot-required.pkgs no Debian/"
            "Ubuntu ou 'sudo needs-restarting -r' no RHEL).",
            "Agende a reinicialização numa janela de manutenção e reinicie.",
            "Em servidores que não podem parar, avalie a correção do kernel em funcionamento "
            "(Livepatch no Ubuntu, kpatch no RHEL) — e ainda assim reinicie periodicamente.",
        ),
        examples=(
            Fix(
                "debian",
                "Debian/Ubuntu",
                "cat /var/run/reboot-required.pkgs\nsudo reboot",
                "bash",
            ),
            Fix("rhel", "RHEL/Fedora/Alma/Rocky", "sudo needs-restarting -r\nsudo reboot", "bash"),
        ),
        verify=(
            "Depois do reinício, /var/run/reboot-required não deve existir (Debian/Ubuntu) e "
            "'needs-restarting -r' deve responder 'Reboot should not be necessary' (RHEL)."
        ),
        effort="baixo",
        fix_group="sistema",
        references=(
            "https://dnf-plugins-core.readthedocs.io/en/latest/needs_restarting.html",
            "https://ubuntu.com/server/docs/how-to/software/automatic-updates/",
        ),
        cwe="CWE-1395",
        owasp="A06:2021",
        cis=("7.3",),
        tags=("atualizacao", "linux"),
    ),
)
