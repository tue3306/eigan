"""Base de conhecimento do Linux: contas, sudo e permissões de arquivos."""

from __future__ import annotations

from ...core import kb
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Severity

_PASSWD = "https://man7.org/linux/man-pages/man5/passwd.5.html"
_SHADOW = "https://man7.org/linux/man-pages/man5/shadow.5.html"
_SUDOERS = "https://www.sudo.ws/docs/man/sudoers.man/"
_CRON = "https://manpages.debian.org/bookworm/cron/cron.8.en.html"
_DOCKER_POS = "https://docs.docker.com/engine/install/linux-postinstall/"
_DOCKER_SEG = "https://docs.docker.com/engine/security/"

kb.register(
    KBEntry(
        id="host.linux.contas.uid0_extra",
        title="Outra conta com poderes de root (UID 0)",
        category=Category.HOST,
        severity=Severity.HIGH,
        summary="Além de root, existe outra conta com UID 0 em /etc/passwd.",
        explanation=(
            "O Linux decide os poderes de uma conta pelo número dela (UID), não pelo nome: "
            "qualquer conta com UID 0 é root, tenha o nome que tiver. Criar uma segunda conta "
            "assim é uma técnica conhecida de invasores para manter o acesso sem chamar atenção. "
            "Mesmo quando foi criada de propósito, ela dificulta saber quem fez o quê, porque os "
            "registros mostram apenas UID 0."
        ),
        risk=(
            "Uma conta escondida pode dar controle total da máquina. Se ela é desconhecida, trate "
            "como possível invasão."
        ),
        steps=(
            "Liste as contas com UID 0 (comando abaixo) e descubra quem criou cada uma e por quê.",
            "Se ninguém conhece a conta, trate como incidente: guarde os registros (last, "
            "/var/log/auth.log ou /var/log/secure) antes de mudar qualquer coisa.",
            "Se a conta não é necessária, remova a linha dela ou troque o UID com 'sudo vipw' e "
            "'sudo vipw -s' (usermod e userdel costumam recusar, porque o UID é o mesmo dos "
            "processos de root).",
            "Para dar privilégio a uma pessoa, use uma conta comum com sudo.",
        ),
        examples=(
            Fix(
                "linux",
                "Linux",
                "awk -F: '$3 == 0 {print $1}' /etc/passwd\nsudo vipw\nsudo vipw -s",
                "bash",
            ),
        ),
        verify="awk -F: '$3 == 0 {print $1}' /etc/passwd deve mostrar apenas root.",
        effort="medio",
        fix_group="linux",
        references=(_PASSWD, "https://man7.org/linux/man-pages/man7/credentials.7.html"),
        cwe="CWE-269",
        owasp="A01:2021",
        cis=("5.4",),
        tags=("contas", "root", "linux"),
    ),
    KBEntry(
        id="host.linux.contas.senha_vazia",
        title="Conta sem senha",
        category=Category.HOST,
        severity=Severity.HIGH,
        summary="Uma conta tem o campo de senha vazio: é possível entrar nela sem digitar senha.",
        explanation=(
            "Campo de senha vazio em /etc/shadow (ou em /etc/passwd) significa que a conta não "
            "tem senha, e não que está bloqueada. As contas bloqueadas de propósito têm '!' ou "
            "'*' nesse campo e não aparecem aqui. Por padrão, o módulo pam_unix recusa senha "
            "em branco, mas a opção nullok, comum em /etc/pam.d, libera esse acesso."
        ),
        risk=(
            "Quem souber o nome da conta pode entrar nela ou trocar de usuário sem nenhuma senha, "
            "conforme a configuração do PAM e do SSH (PermitEmptyPasswords)."
        ),
        steps=(
            "Bloqueie a conta ('sudo passwd -l conta') ou defina uma senha forte "
            "('sudo passwd conta').",
            "Procure a opção nullok em /etc/pam.d e, se ninguém precisa dela, retire-a.",
            "Confirme que o SSH está com PermitEmptyPasswords no.",
        ),
        examples=(
            Fix(
                "linux",
                "Linux",
                "sudo awk -F: '$2 == \"\" {print $1}' /etc/shadow\nsudo passwd -l nome_da_conta\n"
                "grep -rn nullok /etc/pam.d/",
                "bash",
            ),
        ),
        verify="sudo awk -F: '$2 == \"\" {print $1}' /etc/shadow não deve mostrar nenhuma conta.",
        effort="baixo",
        fix_group="linux",
        references=(_SHADOW, _PASSWD, "https://man7.org/linux/man-pages/man8/pam_unix.8.html"),
        cwe="CWE-258",
        owasp="A07:2021",
        cis=("5.2",),
        tags=("contas", "senha", "linux"),
    ),
    KBEntry(
        id="host.linux.arquivos.shadow_legivel",
        title="Arquivo de senhas (/etc/shadow) legível por qualquer usuário",
        category=Category.HOST,
        severity=Severity.HIGH,
        summary=(
            "Qualquer usuário da máquina pode ler o arquivo com os resumos (hashes) das senhas."
        ),
        explanation=(
            "/etc/shadow e /etc/gshadow guardam os resumos das senhas das contas e dos grupos. "
            "O manual é direto: esse arquivo não pode ser lido por usuários comuns se a segurança "
            "das senhas deve ser mantida."
        ),
        risk=(
            "Qualquer conta comum, ou um programa invadido, copia os resumos e tenta descobrir as "
            "senhas fora da máquina, sem limite de tentativas e sem deixar rastro, inclusive a "
            "senha de root."
        ),
        steps=(
            "Corrija as permissões (comandos abaixo, conforme a distribuição).",
            "Considere que os resumos podem ter sido copiados: troque as senhas das contas "
            "privilegiadas.",
            "Investigue o que mudou as permissões (script de instalação, restauração de backup, "
            "imagem da máquina).",
        ),
        examples=(
            Fix(
                "debian",
                "Debian/Ubuntu",
                "sudo chown root:shadow /etc/shadow /etc/gshadow\n"
                "sudo chmod 640 /etc/shadow /etc/gshadow",
                "bash",
            ),
            Fix(
                "rhel",
                "RHEL/Fedora/Alma/Rocky",
                "sudo chown root:root /etc/shadow /etc/gshadow\n"
                "sudo chmod 000 /etc/shadow /etc/gshadow",
                "bash",
            ),
        ),
        verify="'ls -l /etc/shadow' não deve mostrar permissão de leitura para 'outros'.",
        effort="baixo",
        fix_group="linux",
        references=(_SHADOW,),
        cwe="CWE-732",
        owasp="A05:2021",
        cis=("3.3",),
        lgpd=True,
        tags=("contas", "permissoes", "linux"),
    ),
    KBEntry(
        id="host.linux.arquivos.passwd_gravavel",
        title="Arquivo de contas alterável por qualquer usuário",
        category=Category.HOST,
        severity=Severity.CRITICAL,
        summary=(
            "Qualquer usuário da máquina pode alterar um arquivo de contas (/etc/passwd, "
            "/etc/group, /etc/shadow ou /etc/gshadow)."
        ),
        explanation=(
            "Esses arquivos definem quem existe no sistema, os grupos e as senhas. O manual do "
            "/etc/passwd é claro: leitura para todos, mas escrita só para o superusuário. Com "
            "escrita aberta, a segurança de todas as contas depende da boa vontade de quem tem "
            "acesso à máquina."
        ),
        risk=(
            "Qualquer conta comum, ou um programa invadido, vira root na hora: basta incluir uma "
            "conta com UID 0, trocar a senha de root ou se colocar no grupo sudo."
        ),
        steps=(
            "Corrija as permissões agora (comandos abaixo).",
            "Confira se alguma conta foi criada ou alterada: compare com os backups /etc/passwd- "
            "e /etc/shadow- e procure outras contas com UID 0.",
            "Se houver sinal de alteração, trate como invasão: guarde os registros e troque as "
            "senhas.",
        ),
        examples=(
            Fix(
                "linux",
                "Linux",
                "sudo chown root:root /etc/passwd /etc/group\n"
                "sudo chmod 644 /etc/passwd /etc/group\n"
                "sudo chmod o-rwx /etc/shadow /etc/gshadow\n"
                "sudo pwck -r\nsudo diff /etc/passwd- /etc/passwd",
                "bash",
            ),
        ),
        verify="'ls -l /etc/passwd /etc/group' não deve mostrar permissão de escrita para 'outros'.",
        effort="baixo",
        fix_group="linux",
        references=(_PASSWD, _SHADOW),
        cwe="CWE-732",
        owasp="A05:2021",
        cis=("3.3",),
        tags=("contas", "permissoes", "linux"),
    ),
    KBEntry(
        id="host.linux.sudo.nopasswd_total",
        title="sudo libera todos os comandos sem pedir senha",
        category=Category.HOST,
        severity=Severity.MEDIUM,
        summary="Uma regra do sudo dá todos os comandos, como root, sem pedir senha (NOPASSWD: ALL).",
        explanation=(
            "Com uma regra NOPASSWD: ALL, a conta vira root sem confirmar nada. O manual do sudo "
            "avisa que usar ALL em comandos é perigoso, porque permite executar qualquer coisa no "
            "sistema. A senha pedida pelo sudo é o que separa 'invadiu a conta' de 'invadiu a "
            "máquina'. Imagens de nuvem costumam trazer uma regra assim para o usuário padrão: "
            "procure em /etc/sudoers.d."
        ),
        risk=(
            "Quem roubar a chave SSH ou a sessão dessa conta, ou invadir um programa que roda com "
            "ela, vira root sem precisar de mais nada."
        ),
        steps=(
            "Abra o arquivo indicado no achado com 'sudo visudo -f arquivo' (o visudo confere a "
            "sintaxe antes de salvar).",
            "Retire o NOPASSWD das contas de pessoas e confirme que elas têm senha.",
            "Para automação, troque ALL pela lista exata de comandos necessários.",
            "Mantenha outra sessão com root aberta até testar, para não perder o acesso.",
        ),
        examples=(
            Fix(
                "linux",
                "Regras do sudo (sudo visudo -f /etc/sudoers.d/exemplo)",
                "# pessoas: pedir a senha\n%sudo ALL=(ALL:ALL) ALL\n\n"
                "# automação: só o comando necessário\n"
                "deploy ALL=(root) NOPASSWD: /usr/bin/systemctl restart minha-app\n\n"
                "sudo visudo -c",
                "text",
            ),
        ),
        verify="'sudo -l -U conta' não deve mostrar 'NOPASSWD: ALL'; 'sudo visudo -c' deve aprovar.",
        effort="baixo",
        fix_group="linux",
        references=(_SUDOERS,),
        cwe="CWE-269",
        owasp="A01:2021",
        cis=("5.4",),
        tags=("sudo", "root", "linux"),
    ),
    KBEntry(
        id="host.linux.path.pasta_gravavel",
        title="Pasta do PATH gravável por qualquer usuário",
        category=Category.HOST,
        severity=Severity.HIGH,
        summary=(
            "Uma pasta listada no PATH pode ser alterada por qualquer usuário: dá para colocar lá "
            "um programa falso."
        ),
        explanation=(
            "O PATH é a lista de pastas onde o sistema procura os programas digitados sem o "
            "caminho completo. Se qualquer usuário pode gravar em uma dessas pastas, ele pode "
            "criar um programa com o nome de um comando comum (ls, tar, systemctl). Quem rodar "
            "esse comando depois executa o programa falso com os próprios privilégios. "
            "O EIGAN confere o PATH do processo da auditoria, /etc/environment, /etc/login.defs "
            "e o secure_path do sudo (quando o arquivo pode ser lido)."
        ),
        risk=(
            "Um usuário comum pode executar código como outro usuário, inclusive root, quando um "
            "administrador ou uma tarefa automática roda um comando sem o caminho completo."
        ),
        steps=(
            "Tire a permissão de escrita para 'outros' da pasta ('sudo chmod o-w pasta').",
            "Se a pasta precisa ser compartilhada (como /tmp), retire-a do PATH em vez de mudar "
            "as permissões dela.",
            "Revise o PATH definido em /etc/environment, /etc/profile.d e no secure_path do sudo.",
        ),
        examples=(
            Fix(
                "linux",
                "Linux",
                "# conferir cada pasta do PATH (o último grupo de 'rwx' é o de 'outros')\n"
                "echo \"$PATH\" | tr ':' '\\n' | xargs -d '\\n' ls -ld\n"
                "sudo chmod o-w /caminho/da/pasta",
                "bash",
            ),
        ),
        verify="Nenhuma pasta do PATH deve ter 'w' na permissão de 'outros' (ls -ld pasta).",
        effort="baixo",
        fix_group="linux",
        references=("https://cwe.mitre.org/data/definitions/427.html", _SUDOERS),
        cwe="CWE-427",
        owasp="A05:2021",
        cis=("4.1",),
        tags=("path", "permissoes", "linux"),
    ),
    KBEntry(
        id="host.linux.suid.binario_arriscado",
        title="Bit SUID em um programa que permite virar root",
        category=Category.HOST,
        severity=Severity.HIGH,
        summary=(
            "Um shell, interpretador, editor ou utilitário comum está com o bit SUID de root: "
            "qualquer usuário que o execute age como root."
        ),
        explanation=(
            "O bit SUID faz um programa rodar com os poderes do dono do arquivo, e não de quem o "
            "executou. Ele existe para poucos programas feitos para isso (passwd, sudo). Em "
            "programas que abrem arquivos ou executam outros comandos, como interpretadores, "
            "editores e o find, ele dá root a qualquer usuário; o projeto GTFOBins documenta "
            "esses caminhos. Esse bit nesses programas não vem de fábrica nas distribuições, e "
            "uma cópia SUID de um shell é um rastro clássico de invasão."
        ),
        risk=(
            "Qualquer conta comum, ou um programa invadido, vira root com um único comando. Se "
            "ninguém sabe explicar o bit, trate como possível invasão."
        ),
        steps=(
            "Descubra de onde vem o arquivo ('dpkg -S caminho' ou 'rpm -qf caminho') e quem "
            "colocou o bit.",
            "Retire o bit com 'sudo chmod u-s caminho'.",
            "Se alguém precisa do programa com privilégio, crie uma regra do sudo só para esse "
            "uso.",
            "Revise a lista completa de programas SUID da máquina.",
        ),
        examples=(
            Fix(
                "linux",
                "Linux",
                "# listar programas com SUID nesta partição\n"
                "sudo find / -xdev -type f -perm -4000 -ls\n"
                "sudo chmod u-s /caminho/do/programa",
                "bash",
            ),
        ),
        verify="'ls -l programa' não deve mostrar 's' na permissão do dono.",
        effort="baixo",
        fix_group="linux",
        references=(
            "https://man7.org/linux/man-pages/man2/execve.2.html",
            "https://gtfobins.org/",
        ),
        cwe="CWE-250",
        owasp="A05:2021",
        cis=("4.1", "5.4"),
        tags=("suid", "root", "linux"),
    ),
    KBEntry(
        id="host.linux.cron.gravavel",
        title="Tarefa agendada (cron) alterável por qualquer usuário",
        category=Category.HOST,
        severity=Severity.HIGH,
        summary="Um arquivo ou pasta do cron do sistema pode ser alterado por qualquer usuário.",
        explanation=(
            "As tarefas do cron do sistema costumam rodar como root. O manual do cron exige que "
            "/etc/crontab e os arquivos de /etc/cron.d pertençam ao root e não tenham escrita "
            "para grupo e outros; os que descumprem isso são ignorados, o que também pode parar "
            "tarefas sem aviso. Os scripts de /etc/cron.daily e pastas parecidas são executados "
            "pelo run-parts, cujo manual só exige que os arquivos sejam executáveis e tenham "
            "nome válido."
        ),
        risk=(
            "Um usuário comum altera o script, ou coloca um novo na pasta, e o código dele roda "
            "como root na próxima execução da tarefa."
        ),
        steps=(
            "Confira o conteúdo do arquivo: pode já haver comandos colocados por um invasor.",
            "Corrija dono e permissões (comandos abaixo).",
            "Confira também as pastas: elas não podem ter escrita para 'outros'.",
            "Se o arquivo veio de um pacote, instale de novo o pacote ou compare com o original.",
        ),
        examples=(
            Fix(
                "linux",
                "Linux",
                "sudo chown root:root /caminho/do/arquivo\nsudo chmod go-w /caminho/do/arquivo\n"
                "# conferir tudo de uma vez\n"
                "sudo find /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily "
                "/etc/cron.weekly /etc/cron.monthly -perm -o+w -ls",
                "bash",
            ),
        ),
        verify=(
            "'sudo find /etc/crontab /etc/cron.* -perm -o+w' não deve mostrar nenhum arquivo nem "
            "pasta."
        ),
        effort="baixo",
        fix_group="linux",
        references=(
            _CRON,
            "https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html",
            "https://raw.githubusercontent.com/cronie-crond/cronie/master/src/database.c",
        ),
        cwe="CWE-732",
        owasp="A05:2021",
        cis=("3.3", "4.1"),
        tags=("cron", "permissoes", "linux"),
    ),
    KBEntry(
        id="host.linux.docker.socket_gravavel",
        title="Socket do Docker aberto para qualquer usuário",
        category=Category.HOST,
        severity=Severity.HIGH,
        summary=(
            "Qualquer usuário da máquina pode comandar o Docker, porque o arquivo docker.sock tem "
            "escrita para todos."
        ),
        explanation=(
            "O Docker recebe comandos por um arquivo especial (socket), e o serviço sempre roda "
            "como root. Por isso, a própria documentação do Docker diz que o grupo docker dá "
            "privilégios de root e que só pessoas de confiança podem controlar o serviço. O "
            "padrão é o socket com dono root, grupo docker e modo 0660. Com escrita para todos "
            "(como 'chmod 666 /var/run/docker.sock', receita comum na Internet), a barreira deixa "
            "de existir."
        ),
        risk=(
            "Qualquer conta comum, ou um programa invadido, cria um container com a pasta / da "
            "máquina montada e vira root na hora: lê todos os dados e altera o que quiser."
        ),
        steps=(
            "Volte o socket para o padrão (comandos abaixo).",
            "Encontre o que mudou a permissão (scripts, /etc/rc.local, SocketMode em uma "
            "configuração própria da unidade docker.socket) para o problema não voltar no "
            "próximo reinício.",
            "Dê acesso ao Docker só para quem precisa, pelo grupo docker, sabendo que isso "
            "equivale a dar root. Para reduzir esse risco, avalie o Docker em modo rootless.",
        ),
        examples=(
            Fix(
                "linux",
                "Linux",
                "sudo chown root:docker /var/run/docker.sock\n"
                "sudo chmod 660 /var/run/docker.sock\n"
                "# o que define o modo no próximo reinício (deve ser SocketMode=0660)\n"
                "systemctl cat docker.socket | grep -i socketmode",
                "bash",
            ),
        ),
        verify="'ls -l /var/run/docker.sock' deve mostrar srw-rw---- root docker.",
        effort="baixo",
        fix_group="linux",
        references=(
            _DOCKER_POS,
            _DOCKER_SEG,
            "https://raw.githubusercontent.com/moby/moby/master/contrib/init/systemd/docker.socket",
        ),
        cwe="CWE-732",
        owasp="A05:2021",
        cis=("3.3", "4.1"),
        tags=("docker", "permissoes", "linux"),
    ),
)
