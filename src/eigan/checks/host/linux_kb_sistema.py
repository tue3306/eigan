"""Base de conhecimento do Linux: kernel (sysctl), SELinux/AppArmor, auditoria e portas de bancos."""

from __future__ import annotations

from ...core import kb
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Severity

_KERNEL = "https://docs.kernel.org/admin-guide/sysctl/kernel.html"
_FS = "https://docs.kernel.org/admin-guide/sysctl/fs.html"
_REDE = "https://docs.kernel.org/networking/ip-sysctl.html"
_KSPP = "https://kspp.github.io/Recommended_Settings"
_SYSCTL_D = "https://man7.org/linux/man-pages/man5/sysctl.d.5.html"
_APLICAR = "\n\n# aplicar sem reiniciar:\nsudo sysctl --system"
_PASSO_ARQUIVO = (
    "Crie o arquivo /etc/sysctl.d/99-zz-eigan.conf com a configuração abaixo: entre os arquivos "
    "dessa pasta, vale o valor do arquivo que vem por último na ordem alfabética."
)
_PASSO_APLICAR = (
    "Aplique sem reiniciar com 'sudo sysctl --system'. Se o valor antigo voltar, procure quem o "
    "define: grep -r nome_do_parametro /etc/sysctl.conf /etc/sysctl.d/ /usr/lib/sysctl.d/."
)


def _sysctl(linhas: str) -> Fix:
    return Fix("linux", "Linux (/etc/sysctl.d/99-zz-eigan.conf)", linhas + _APLICAR, "text")


kb.register(
    KBEntry(
        id="host.linux.kernel.aslr",
        title="Sorteio de endereços de memória (ASLR) reduzido ou desligado",
        category=Category.HOST,
        severity=Severity.MEDIUM,
        summary=(
            "kernel.randomize_va_space não está em 2: os programas carregam em endereços de "
            "memória mais previsíveis."
        ),
        explanation=(
            "O ASLR sorteia, a cada execução, onde cada programa coloca suas partes na memória. "
            "Com o valor 2 (completo), pilha, bibliotecas e heap mudam de lugar; com 1, o heap "
            "fica de fora; com 0, nada é sorteado. A documentação do kernel informa que, fora "
            "programas muito antigos, nada de atual quebra com o sorteio completo."
        ),
        risk=(
            "Explorar falhas de corrupção de memória fica bem mais fácil: o invasor sabe de "
            "antemão onde está o código que quer usar, e um ataque que falharia vira invasão ou "
            "ganho de root."
        ),
        steps=(
            _PASSO_ARQUIVO,
            _PASSO_APLICAR,
            "Se o valor continuar em 0, confira se o parâmetro 'norandmaps' está na linha de "
            "boot do kernel (cat /proc/cmdline) e remova-o da configuração do GRUB.",
        ),
        examples=(_sysctl("kernel.randomize_va_space = 2"),),
        verify="sysctl kernel.randomize_va_space deve mostrar 2.",
        effort="baixo",
        fix_group="linux",
        references=(_KERNEL, _KSPP),
        cwe="CWE-693",
        owasp="A05:2021",
        cis=("10.5",),
        tags=("kernel", "sysctl", "linux"),
    ),
    KBEntry(
        id="host.linux.kernel.redirecionamentos_icmp",
        title="Máquina aceita redirecionamentos ICMP",
        category=Category.HOST,
        severity=Severity.LOW,
        summary=(
            "O kernel aceita mensagens ICMP redirect, que podem mudar o caminho do tráfego desta "
            "máquina."
        ),
        explanation=(
            "Um ICMP redirect é uma mensagem de rede que diz 'para chegar àquele destino, use "
            "este outro roteador'. Servidores e estações costumam ter rotas fixas e não precisam "
            "dela. O EIGAN avalia cada interface pela regra da documentação do kernel: em IPv4, "
            "sem encaminhamento de pacotes, basta 'all' ou a própria interface estar ligada; com "
            "encaminhamento, as duas precisam estar. Em IPv6, vale o valor da interface quando "
            "ela não encaminha pacotes."
        ),
        risk=(
            "Quem está na mesma rede local pode enviar um redirect falso e fazer o tráfego desta "
            "máquina passar pelo computador dele, para espionar ou alterar conexões sem "
            "criptografia."
        ),
        steps=(
            _PASSO_ARQUIVO,
            _PASSO_APLICAR,
            "O exemplo usa curinga (*) para valer em todas as interfaces; 'default' vem primeiro "
            "para valer também nas interfaces criadas depois.",
        ),
        examples=(
            _sysctl(
                "net.ipv4.conf.default.accept_redirects = 0\n"
                "net.ipv4.conf.*.accept_redirects = 0\n"
                "net.ipv6.conf.default.accept_redirects = 0\n"
                "net.ipv6.conf.*.accept_redirects = 0"
            ),
        ),
        verify=(
            "sysctl net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects "
            "net.ipv6.conf.all.accept_redirects deve mostrar 0, assim como o valor de cada "
            "interface em /proc/sys/net/ipv4/conf/."
        ),
        effort="baixo",
        fix_group="linux",
        references=(_REDE, _SYSCTL_D),
        cwe="CWE-940",
        owasp="A05:2021",
        cis=("4.1",),
        tags=("kernel", "sysctl", "rede", "linux"),
    ),
    KBEntry(
        id="host.linux.kernel.envio_redirecionamentos",
        title="Máquina que encaminha pacotes envia redirecionamentos ICMP",
        category=Category.HOST,
        severity=Severity.LOW,
        summary=(
            "A máquina encaminha pacotes (como um roteador) e pode enviar ICMP redirects para as "
            "outras máquinas da rede."
        ),
        explanation=(
            "Só quem encaminha pacotes envia redirects, e esse é o caso desta máquina: ela é um "
            "roteador, um host de containers ou de máquinas virtuais. Fora de um roteador de "
            "verdade, essas mensagens não são necessárias. O envio fica ligado se 'all' ou a "
            "interface estiver em 1, que é o padrão do kernel."
        ),
        risk=(
            "Se esta máquina for invadida, o invasor pode usar os redirects para desviar o "
            "tráfego de outras máquinas da rede."
        ),
        steps=(
            "Se a máquina não precisa rotear pacotes, desligue o encaminhamento "
            "(net.ipv4.ip_forward = 0). Atenção: Docker, Kubernetes e VPNs precisam dele.",
            _PASSO_ARQUIVO,
            _PASSO_APLICAR,
        ),
        examples=(
            _sysctl("net.ipv4.conf.default.send_redirects = 0\nnet.ipv4.conf.*.send_redirects = 0"),
        ),
        verify=(
            "sysctl net.ipv4.conf.all.send_redirects net.ipv4.conf.default.send_redirects deve "
            "mostrar 0, assim como o valor de cada interface em /proc/sys/net/ipv4/conf/."
        ),
        effort="baixo",
        fix_group="linux",
        references=(_REDE, _SYSCTL_D),
        cwe="CWE-940",
        owasp="A05:2021",
        cis=("4.1",),
        tags=("kernel", "sysctl", "rede", "linux"),
    ),
    KBEntry(
        id="host.linux.kernel.source_route",
        title="Máquina aceita pacotes com rota definida pela origem",
        category=Category.HOST,
        severity=Severity.MEDIUM,
        summary=(
            "O kernel aceita pacotes IPv4 com a opção de roteamento pela origem "
            "(accept_source_route)."
        ),
        explanation=(
            "Com o roteamento pela origem, quem envia o pacote escolhe por onde ele passa na "
            "rede, em vez de deixar a decisão para os roteadores. O recurso é antigo e não tem "
            "uso legítimo em redes atuais. O kernel só aceita esses pacotes em uma interface "
            "quando 'all' e a própria interface estão em 1, e o systemd já desliga isso por "
            "padrão: aqui alguém ligou de propósito ou a configuração é antiga."
        ),
        risk=(
            "O invasor pode forçar o caminho dos pacotes para contornar firewalls e filtros "
            "baseados em rota, ou fazer o tráfego passar por uma máquina que ele controla."
        ),
        steps=(_PASSO_ARQUIVO, _PASSO_APLICAR),
        examples=(
            _sysctl(
                "net.ipv4.conf.default.accept_source_route = 0\n"
                "net.ipv4.conf.*.accept_source_route = 0"
            ),
        ),
        verify="sysctl net.ipv4.conf.all.accept_source_route deve mostrar 0.",
        effort="baixo",
        fix_group="linux",
        references=(_REDE, _SYSCTL_D),
        cwe="CWE-940",
        owasp="A05:2021",
        cis=("4.1",),
        tags=("kernel", "sysctl", "rede", "linux"),
    ),
    KBEntry(
        id="host.linux.kernel.syncookies",
        title="Proteção SYN cookies desligada",
        category=Category.HOST,
        severity=Severity.MEDIUM,
        summary="net.ipv4.tcp_syncookies está em 0: a máquina fica mais frágil a inundação de SYN.",
        explanation=(
            "Em um ataque de inundação de SYN, o atacante abre milhares de conexões pela metade "
            "até lotar a fila de conexões do servidor. Com os SYN cookies, o kernel continua "
            "atendendo quando a fila enche. O padrão do kernel é 1; o valor 0 foi definido de "
            "propósito ou por um ajuste antigo."
        ),
        risk=(
            "Com pouco tráfego, um atacante pode impedir novas conexões aos serviços desta "
            "máquina, tirando sites e sistemas do ar."
        ),
        steps=(_PASSO_ARQUIVO, _PASSO_APLICAR),
        examples=(_sysctl("net.ipv4.tcp_syncookies = 1"),),
        verify="sysctl net.ipv4.tcp_syncookies deve mostrar 1.",
        effort="baixo",
        fix_group="linux",
        references=(_REDE,),
        cwe="CWE-400",
        owasp="A05:2021",
        cis=("4.1",),
        tags=("kernel", "sysctl", "rede", "linux"),
    ),
    KBEntry(
        id="host.linux.kernel.ponteiros_expostos",
        title="Endereços do kernel sem restrição (kptr_restrict)",
        category=Category.HOST,
        severity=Severity.LOW,
        summary=(
            "kernel.kptr_restrict está em 0: não há a restrição recomendada para endereços do "
            "kernel em /proc."
        ),
        explanation=(
            "Alguns arquivos de /proc mostram endereços de memória do kernel. Com o valor 0, o "
            "kernel apenas embaralha (hash) esses endereços antes de exibi-los; com 1, usuários "
            "sem o privilégio CAP_SYSLOG veem zeros; com 2, todos veem zeros. O projeto de "
            "proteção do kernel (KSPP) recomenda 2, ou 1 quando o root precisa dos valores."
        ),
        risk=(
            "Conhecer endereços do kernel ajuda a transformar uma falha do kernel em ganho de "
            "root. É uma defesa em profundidade: sozinha não permite invasão."
        ),
        steps=(_PASSO_ARQUIVO, _PASSO_APLICAR),
        examples=(_sysctl("kernel.kptr_restrict = 1"),),
        verify="sysctl kernel.kptr_restrict deve mostrar 1 ou 2.",
        effort="baixo",
        fix_group="linux",
        references=(_KERNEL, _KSPP),
        cwe="CWE-200",
        owasp="A05:2021",
        cis=("10.5",),
        tags=("kernel", "sysctl", "linux"),
    ),
    KBEntry(
        id="host.linux.kernel.dmesg_aberto",
        title="Qualquer usuário pode ler o log do kernel (dmesg)",
        category=Category.HOST,
        severity=Severity.LOW,
        summary="kernel.dmesg_restrict está em 0: usuários comuns podem ler as mensagens do kernel.",
        explanation=(
            "O comando dmesg mostra o log do kernel, que pode trazer endereços de memória e "
            "detalhes do hardware e dos drivers. Com o valor 1, só quem tem o privilégio "
            "CAP_SYSLOG consegue ler esse log."
        ),
        risk=(
            "Um invasor com uma conta comum (por exemplo, depois de invadir um site) coleta "
            "informações que ajudam a explorar falhas do kernel e a ganhar root."
        ),
        steps=(_PASSO_ARQUIVO, _PASSO_APLICAR),
        examples=(_sysctl("kernel.dmesg_restrict = 1"),),
        verify="sysctl kernel.dmesg_restrict deve mostrar 1; 'dmesg' sem sudo deve ser recusado.",
        effort="baixo",
        fix_group="linux",
        references=(_KERNEL, _KSPP),
        cwe="CWE-200",
        owasp="A05:2021",
        cis=("10.5",),
        tags=("kernel", "sysctl", "linux"),
    ),
    KBEntry(
        id="host.linux.kernel.links_desprotegidos",
        title="Proteção de links simbólicos ou físicos desligada",
        category=Category.HOST,
        severity=Severity.MEDIUM,
        summary=(
            "fs.protected_symlinks ou fs.protected_hardlinks está em 0: ataques com links em "
            "pastas como /tmp ficam possíveis."
        ),
        explanation=(
            "Uma técnica antiga de ataque é criar, em uma pasta que todos podem usar (como "
            "/tmp), um link com o nome de um arquivo que um programa de root vai abrir. O "
            "programa acaba escrevendo em outro arquivo, escolhido pelo invasor. Com esses dois "
            "parâmetros em 1, o kernel recusa esses links. O systemd já os liga por padrão: o "
            "valor 0 foi definido de propósito ou é de uma instalação antiga."
        ),
        risk=(
            "Um usuário comum pode enganar programas e serviços que rodam como root para "
            "sobrescrever arquivos do sistema, o que costuma levar a ganho de root."
        ),
        steps=(_PASSO_ARQUIVO, _PASSO_APLICAR),
        examples=(_sysctl("fs.protected_symlinks = 1\nfs.protected_hardlinks = 1"),),
        verify=(
            "sudo sysctl fs.protected_symlinks fs.protected_hardlinks deve mostrar 1 nos dois "
            "parâmetros."
        ),
        effort="baixo",
        fix_group="linux",
        references=(_FS, _KSPP),
        cwe="CWE-59",
        owasp="A05:2021",
        cis=("10.5",),
        tags=("kernel", "sysctl", "linux"),
    ),
    KBEntry(
        id="host.linux.mac.desligado",
        title="SELinux e AppArmor sem proteção ativa",
        category=Category.HOST,
        severity=Severity.LOW,
        summary=(
            "Nem o SELinux em modo enforcing nem o AppArmor estão ativos: os programas não têm "
            "limites além das permissões comuns."
        ),
        explanation=(
            "SELinux e AppArmor limitam o que cada programa pode fazer, mesmo quando ele roda "
            "como root: um servidor web invadido, por exemplo, não consegue ler arquivos fora do "
            "que sua regra permite. O AppArmor vem ativo por padrão no Ubuntu e no Debian 10 ou "
            "mais novo; o SELinux, em modo enforcing, no RHEL. No modo permissivo, o SELinux "
            "apenas registra as violações, sem bloquear nada."
        ),
        risk=(
            "Quando um serviço é invadido, nada além das permissões comuns segura o invasor: ele "
            "tem tudo o que o serviço tem, e o dano se espalha mais fácil pela máquina."
        ),
        steps=(
            "Debian/Ubuntu: instale os pacotes apparmor e apparmor-utils e retire 'apparmor=0' "
            "da linha GRUB_CMDLINE_LINUX em /etc/default/grub, se estiver lá.",
            "RHEL e derivados: não desligue o SELinux; para investigar um problema em produção, "
            "use o modo permissivo por pouco tempo.",
            "RHEL e derivados, voltando de 'disabled': passe primeiro por SELINUX=permissive e "
            "reetiquete os arquivos (fixfiles -F onboot) antes de reiniciar; depois use "
            "SELINUX=enforcing em /etc/selinux/config.",
            "Reinicie a máquina e confirme o estado.",
        ),
        examples=(
            Fix(
                "debian",
                "Debian/Ubuntu (AppArmor)",
                "sudo apt install apparmor apparmor-utils\n"
                "# retire apparmor=0 de GRUB_CMDLINE_LINUX em /etc/default/grub\n"
                "sudo update-grub\nsudo reboot\n\n# depois de reiniciar:\nsudo aa-status",
                "bash",
            ),
            Fix(
                "rhel",
                "RHEL/Fedora/Alma/Rocky (SELinux)",
                "# 1) /etc/selinux/config: SELINUX=permissive\nsudo fixfiles -F onboot\n"
                "sudo reboot\n\n# 2) confira os bloqueios que seriam feitos e, se estiver tudo "
                "certo,\n#    use SELINUX=enforcing em /etc/selinux/config\nsudo reboot\n"
                "getenforce",
                "bash",
            ),
        ),
        verify=(
            "'getenforce' deve mostrar Enforcing (SELinux), ou "
            "'cat /sys/module/apparmor/parameters/enabled' deve mostrar Y (AppArmor)."
        ),
        effort="medio",
        fix_group="linux",
        references=(
            "https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/changing-selinux-states-and-modes_using-selinux",
            "https://ubuntu.com/server/docs/how-to/security/apparmor/",
            "https://wiki.debian.org/AppArmor/HowToUse",
        ),
        cwe="CWE-693",
        owasp="A05:2021",
        cis=("4.1", "10.5"),
        tags=("selinux", "apparmor", "linux"),
    ),
    KBEntry(
        id="host.linux.auditoria.auditd_ausente",
        title="Auditoria do sistema (auditd) ausente ou parada",
        category=Category.HOST,
        severity=Severity.LOW,
        summary="O serviço auditd não está em funcionamento: o kernel não registra eventos de auditoria.",
        explanation=(
            "O auditd grava eventos de segurança do sistema: quem alterou um arquivo importante, "
            "quem usou um comando privilegiado, quais contas foram mudadas. Esses registros "
            "ficam separados dos logs comuns e são a base para investigar um incidente e para "
            "atender exigências de auditoria."
        ),
        risk=(
            "Depois de uma invasão fica difícil, ou impossível, saber o que foi feito, quando e "
            "por qual conta. Sem essa resposta, a limpeza e a comunicação do incidente (inclusive "
            "à ANPD, pela LGPD) ficam incompletas."
        ),
        steps=(
            "Instale o pacote (auditd no Debian/Ubuntu, audit no RHEL e derivados).",
            "Ative o serviço para iniciar com o sistema.",
            "Coloque as regras em /etc/audit/rules.d/ e carregue-as com 'sudo augenrules --load'.",
            "Envie os registros para fora da máquina, para que um invasor não consiga apagá-los.",
        ),
        examples=(
            Fix(
                "debian",
                "Debian/Ubuntu",
                "sudo apt install auditd\nsudo systemctl enable --now auditd\nsudo auditctl -s",
                "bash",
            ),
            Fix(
                "rhel",
                "RHEL/Fedora/Alma/Rocky",
                "sudo dnf install audit\nsudo systemctl enable --now auditd\nsudo auditctl -s",
                "bash",
            ),
        ),
        verify="'systemctl is-active auditd' deve mostrar active.",
        effort="medio",
        fix_group="linux",
        references=(
            "https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening",
        ),
        cwe="CWE-778",
        owasp="A09:2021",
        cis=("8.2", "8.5"),
        tags=("auditoria", "logs", "linux"),
    ),
    KBEntry(
        id="host.linux.auditoria.fail2ban_ausente",
        title="Sem bloqueio automático de tentativas de senha no SSH",
        category=Category.HOST,
        severity=Severity.INFO,
        summary=(
            "O SSH aceita senha e não há fail2ban, CrowdSec ou SSHGuard em funcionamento para "
            "bloquear quem erra muitas vezes."
        ),
        explanation=(
            "Ferramentas como o fail2ban leem os registros de login e bloqueiam por um tempo os "
            "endereços que erram a senha repetidamente. Elas não substituem as chaves SSH, mas "
            "reduzem muito o volume de tentativas enquanto a autenticação por senha continuar "
            "ligada."
        ),
        risk=(
            "Robôs podem testar senhas sem parar, limitados apenas pelo MaxAuthTries de cada "
            "conexão; uma senha fraca acaba sendo descoberta."
        ),
        steps=(
            "A melhor correção é desligar a senha no SSH e usar só chaves: nesse caso, este "
            "aviso some.",
            "Se precisar manter a senha, instale o fail2ban. No RHEL e derivados, o pacote vem "
            "do repositório EPEL.",
            "Ligue a proteção do SSH em /etc/fail2ban/jail.local (não altere o jail.conf, que é "
            "substituído nas atualizações).",
        ),
        examples=(
            Fix(
                "linux",
                "fail2ban (/etc/fail2ban/jail.local)",
                "[sshd]\nenabled = true\nmaxretry = 5\nfindtime = 10m\nbantime = 10m\n\n"
                "sudo systemctl enable --now fail2ban\nsudo fail2ban-client status sshd",
                "text",
            ),
            Fix("debian", "Debian/Ubuntu", "sudo apt install fail2ban", "bash"),
        ),
        verify="'sudo fail2ban-client status sshd' deve mostrar a proteção do SSH em funcionamento.",
        effort="baixo",
        fix_group="ssh",
        references=("https://raw.githubusercontent.com/fail2ban/fail2ban/master/config/jail.conf",),
        cwe="CWE-307",
        owasp="A07:2021",
        cis=("13.3",),
        tags=("ssh", "forca_bruta", "linux"),
    ),
    KBEntry(
        id="host.linux.rede.banco_exposto",
        title="Banco de dados escutando em todas as interfaces de rede",
        category=Category.HOST,
        severity=Severity.HIGH,
        summary=(
            "Um programa está aguardando conexões na porta padrão de um banco de dados em todos "
            "os endereços de rede da máquina (0.0.0.0 ou ::)."
        ),
        explanation=(
            "Quando um banco de dados escuta em 0.0.0.0 ou ::, ele aceita conexões vindas de "
            "qualquer rede ligada à máquina, e não só dos programas locais. Se o sistema que usa "
            "o banco está na mesma máquina, o certo é escutar apenas em 127.0.0.1. A informação "
            "vem da tabela de conexões do kernel (/proc/net/tcp e tcp6). Sem um firewall "
            "confirmado, o achado é de severidade alta; com firewall ativo, é média."
        ),
        risk=(
            "O banco fica ao alcance de varreduras e de ataques de senha pela rede, e qualquer "
            "falha ou senha fraca vira vazamento direto de dados pessoais e do negócio (LGPD). "
            "Em Redis, MongoDB e similares sem senha, basta alcançar a porta para ler ou apagar "
            "os dados."
        ),
        steps=(
            "Descubra qual programa usa a porta: 'sudo ss -ltnp'.",
            "Se o acesso é só local, configure o banco para escutar em 127.0.0.1 (exemplos "
            "abaixo) e reinicie o serviço.",
            "Se outra máquina precisa de acesso, escute apenas no endereço da rede interna e "
            "libere no firewall só os IPs dessa máquina.",
            "Em containers Docker, publique a porta só para a própria máquina: "
            "-p 127.0.0.1:5432:5432. Portas publicadas sem isso ficam abertas para fora e "
            "passam por fora do ufw.",
        ),
        examples=(
            Fix(
                "postgresql",
                "PostgreSQL (postgresql.conf)",
                "listen_addresses = 'localhost'",
                "ini",
            ),
            Fix("mysql", "MySQL/MariaDB ([mysqld] em my.cnf)", "bind_address = 127.0.0.1", "ini"),
            Fix("redis", "Redis (redis.conf)", "bind 127.0.0.1", "text"),
            Fix("mongodb", "MongoDB (mongod.conf)", "net:\n  bindIp: 127.0.0.1", "yaml"),
            Fix(
                "linux",
                "Conferir o que está em escuta",
                "sudo ss -ltnp\n# 127.0.0.1:porta = só local; 0.0.0.0:porta ou [::]:porta = toda a rede",
                "bash",
            ),
        ),
        verify="'sudo ss -ltn' não deve mais mostrar a porta do banco em 0.0.0.0 nem em [::].",
        effort="baixo",
        fix_group="servicos",
        references=(
            "https://www.postgresql.org/docs/current/runtime-config-connection.html",
            "https://dev.mysql.com/doc/refman/8.4/en/server-system-variables.html",
            "https://redis.io/docs/latest/operate/oss_and_stack/management/security/",
            "https://www.mongodb.com/docs/manual/core/security-mongodb-configuration/",
            "https://docs.docker.com/engine/network/port-publishing/",
        ),
        cwe="CWE-668",
        owasp="A05:2021",
        cis=("4.4", "12.2"),
        lgpd=True,
        tags=("banco", "rede", "linux"),
    ),
)
