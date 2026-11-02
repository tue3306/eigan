"""Base de conhecimento: indícios nos logs de autenticação do Linux."""

from __future__ import annotations

from ...core.kb import Fix
from ...core.models import Severity
from .kb_base import ref_attack, registrar

_SSHD = "https://man.openbsd.org/sshd_config"
_SUDOERS = "https://www.sudo.ws/docs/man/sudoers.man/"
_SSH_FIX = (
    Fix(
        "openssh",
        "OpenSSH (/etc/ssh/sshd_config)",
        "PasswordAuthentication no\nPermitRootLogin no\nMaxAuthTries 3\nLoginGraceTime 30\n"
        "# depois: sudo sshd -t && sudo systemctl reload sshd",
        "bash",
    ),
    Fix(
        "linux",
        "Bloquear o IP (ufw)",
        "sudo ufw deny from 203.0.113.10 to any port 22 proto tcp",
        "bash",
    ),
)

registrar(
    "logs.ssh.forca_bruta",
    "Força bruta no SSH",
    Severity.MEDIUM,
    "Um mesmo IP errou a senha do SSH muitas vezes em pouco tempo.",
    "O log de autenticação mostra uma sequência de 'Failed password' vinda do mesmo endereço. "
    "É a assinatura de robôs que testam senhas em servidores expostos à Internet.",
    "Se alguma senha for fraca ou reaproveitada, o atacante entra com a conta do usuário e passa "
    "a controlar o servidor. Mesmo sem sucesso, o volume de tentativas consome recursos.",
    (
        "Desative a senha no SSH e exija chave pública (PasswordAuthentication no).",
        "Instale o fail2ban ou o CrowdSec para bloquear automaticamente IPs que erram a senha.",
        "Limite o acesso ao SSH por firewall (VPN ou lista de IPs conhecidos).",
        "Confira se algum login foi aceito pelo mesmo IP (veja o achado de sucesso após falhas).",
    ),
    "Reinicie o SSH e tente logar com senha: deve ser recusado. Acompanhe "
    "'grep \"Failed password\" /var/log/auth.log' nos próximos dias: o volume deve cair.",
    (_SSHD, *ref_attack("T1110.001", "T1021.004")),
    exemplos=_SSH_FIX,
    cwe="CWE-307",
    owasp="A07:2021",
    cis=("5.2", "6.5", "8.11"),
    tags=("ssh", "forca-bruta"),
)

registrar(
    "logs.ssh.sucesso_apos_falhas",
    "Login SSH aceito depois de várias falhas do mesmo IP",
    Severity.CRITICAL,
    "O mesmo endereço errou a senha várias vezes e depois conseguiu entrar.",
    "O log mostra falhas de senha seguidas de um 'Accepted' vindo do mesmo IP. Isso é o padrão "
    "de uma força bruta que deu certo (ou de alguém que descobriu a senha por outro meio).",
    "A conta deve ser tratada como comprometida: o atacante pode ler dados, instalar backdoors, "
    "criar contas e usar o servidor para atacar outras máquinas.",
    (
        "Liste as sessões abertas (who, last, ss -tnp) e encerre a do IP suspeito.",
        "Bloqueie o IP e desative a conta envolvida até concluir a investigação.",
        "Procure persistência: novas chaves em ~/.ssh/authorized_keys, cron, serviços e usuários novos.",
        "Troque a senha da conta e de qualquer outra que use a mesma senha; passe a exigir chave.",
    ),
    "Confirme com 'last -i' e 'journalctl -u ssh' que não há novas sessões do IP e que as chaves "
    "autorizadas são só as esperadas.",
    (_SSHD, *ref_attack("T1110.001", "T1078", "T1021.004")),
    exemplos=_SSH_FIX,
    cwe="CWE-307",
    owasp="A07:2021",
    cis=("5.2", "6.5", "8.11"),
    tags=("ssh", "comprometimento"),
)

registrar(
    "logs.ssh.usuarios_invalidos",
    "Tentativas de login SSH com usuários que não existem",
    Severity.LOW,
    "Um IP tentou entrar no SSH com vários nomes de usuário inexistentes.",
    "Mensagens 'Invalid user' mostram alguém testando nomes comuns (admin, oracle, test, ubuntu). "
    "É reconhecimento: o atacante descobre quais contas existem antes de testar senhas.",
    "Sozinho não causa dano, mas indica que o SSH está exposto e sendo varrido. Se algum nome "
    "existir de verdade, passa a ser alvo de força bruta.",
    (
        "Restrinja quem pode usar o SSH (AllowUsers ou AllowGroups em sshd_config).",
        "Mude o acesso para chave pública e bloqueie o IP automaticamente com fail2ban.",
    ),
    "Reaplique a configuração e confira em auth.log que usuários fora da lista são recusados "
    "logo no início.",
    (_SSHD, *ref_attack("T1110.001")),
    exemplos=_SSH_FIX,
    esforco="baixo",
    cwe="CWE-307",
    owasp="A07:2021",
    cis=("5.2", "8.11"),
    tags=("ssh", "reconhecimento"),
)

registrar(
    "logs.ssh.forca_bruta_distribuida",
    "Força bruta distribuída no SSH (muitos IPs, poucas tentativas cada)",
    Severity.MEDIUM,
    "Muitos IPs diferentes erraram a senha do SSH poucas vezes cada um.",
    "Para fugir de bloqueios por IP, botnets espalham as tentativas entre dezenas de endereços. "
    "Cada IP erra poucas vezes, mas juntos somam centenas de falhas.",
    "Ferramentas que bloqueiam um IP depois de N erros não pegam esse ataque. Uma senha fraca "
    "acaba descoberta com o tempo.",
    (
        "Desative a autenticação por senha no SSH (chave pública ou certificado).",
        "Limite o SSH por firewall a VPN ou IPs conhecidos.",
        "Use o CrowdSec, que compartilha listas de IPs maliciosos, em vez de só contar erros locais.",
    ),
    "Com a senha desativada, o log deve mostrar 'Permission denied (publickey)' e nenhum "
    "'Failed password'.",
    (_SSHD, *ref_attack("T1110.003", "T1021.004")),
    exemplos=_SSH_FIX,
    cwe="CWE-307",
    owasp="A07:2021",
    cis=("5.2", "6.5", "8.11"),
    tags=("ssh", "forca-bruta"),
)

registrar(
    "logs.sudo.falhas",
    "Várias falhas de senha no sudo",
    Severity.LOW,
    "Um usuário errou a senha do sudo repetidas vezes.",
    "O sudo registra cada senha errada. Muitas falhas seguidas podem ser um usuário distraído "
    "ou alguém que obteve acesso à conta e tenta virar administrador.",
    "Se for um invasor com a conta de um usuário comum, acertar o sudo dá controle total da máquina.",
    (
        "Pergunte ao dono da conta se foi ele; se não foi, trate a conta como comprometida.",
        "Revise as sessões abertas e os últimos comandos do usuário (history, auditd).",
        "Restrinja o sudo a comandos necessários e exija MFA para administradores.",
    ),
    "Confira em 'sudo journalctl _COMM=sudo' que as falhas pararam e que o usuário confirma "
    "a origem.",
    (_SUDOERS, *ref_attack("T1548.003")),
    exemplos=(
        Fix(
            "linux",
            "Restringir o sudo (/etc/sudoers.d/ops)",
            "ops ALL=(root) /usr/bin/systemctl restart nginx",
            "bash",
        ),
    ),
    esforco="baixo",
    cwe="CWE-250",
    owasp="A01:2021",
    cis=("5.4", "8.11"),
    tags=("sudo",),
)

registrar(
    "logs.sudo.nao_autorizado",
    "Usuário sem permissão tentou usar o sudo",
    Severity.MEDIUM,
    "O sudo recusou usuários que não estão autorizados (NOT in sudoers).",
    "Mensagens 'user NOT in sudoers' ou 'command not allowed' mostram contas comuns tentando "
    "executar comandos como administrador sem ter permissão.",
    "Pode ser curiosidade, erro de configuração ou um invasor testando escalada de privilégios "
    "a partir de uma conta comprometida (aplicação web, por exemplo).",
    (
        "Identifique o usuário e o comando tentado nas amostras do achado.",
        "Se a conta é de serviço (www-data, postgres), investigue a aplicação: pode estar comprometida.",
        "Mantenha o princípio do menor privilégio no sudoers e revise o arquivo com visudo -c.",
    ),
    "Rode 'sudo visudo -c' e acompanhe o log: novas recusas devem ter explicação conhecida.",
    (_SUDOERS, *ref_attack("T1548.003")),
    esforco="baixo",
    cwe="CWE-269",
    owasp="A01:2021",
    cis=("5.4", "8.11"),
    tags=("sudo", "escalada"),
)

registrar(
    "logs.linux.novo_usuario",
    "Conta de usuário criada no Linux",
    Severity.MEDIUM,
    "O log registra a criação de uma nova conta (useradd).",
    "Criar usuários é normal em administração, mas é também a forma mais simples de um atacante "
    "garantir uma porta de volta ao sistema.",
    "Uma conta criada sem o seu conhecimento permite acesso persistente, mesmo depois de trocar "
    "as senhas das contas antigas.",
    (
        "Confirme com a equipe se a criação foi planejada (chamado, automação).",
        "Se não foi, bloqueie a conta (usermod -L), encerre as sessões e examine o que ela fez.",
        "Verifique /etc/passwd, /etc/shadow e ~/.ssh/authorized_keys de todas as contas.",
    ),
    "Compare 'getent passwd' com a lista de usuários esperados: não deve haver contas "
    "desconhecidas.",
    ("https://man7.org/linux/man-pages/man8/useradd.8.html", *ref_attack("T1136.001")),
    exemplos=(Fix("linux", "Bloquear uma conta", "sudo usermod -L -e 1 nome_da_conta", "bash"),),
    esforco="baixo",
    cwe="CWE-284",
    owasp="A01:2021",
    cis=("5.4", "8.11"),
    tags=("persistencia",),
)

registrar(
    "logs.linux.grupo_admin",
    "Usuário adicionado a grupo administrativo no Linux",
    Severity.HIGH,
    "Alguém foi colocado em um grupo com poderes de administrador (sudo, wheel...).",
    "O log mostra usermod, gpasswd ou useradd adicionando uma conta aos grupos sudo, wheel, "
    "admin, root ou docker. Quem está nesses grupos vira administrador na prática.",
    "É a forma clássica de escalar privilégios depois de uma invasão. O grupo docker, por "
    "exemplo, equivale a root na máquina.",
    (
        "Confirme com quem fez a mudança e se há chamado que a justifique.",
        "Se não for legítima, remova o usuário do grupo (gpasswd -d) e investigue a conta.",
        "Revise a lista atual de membros dos grupos privilegiados.",
    ),
    "Execute 'getent group sudo wheel admin docker' e compare com a lista autorizada.",
    ("https://man7.org/linux/man-pages/man8/usermod.8.html", *ref_attack("T1098", "T1548.003")),
    exemplos=(Fix("linux", "Remover do grupo", "sudo gpasswd -d usuario sudo", "bash"),),
    esforco="baixo",
    cwe="CWE-269",
    owasp="A01:2021",
    cis=("5.4", "8.11"),
    tags=("persistencia", "escalada"),
)

registrar(
    "logs.linux.admin_uid_zero",
    "Conta com UID 0 criada ou alterada",
    Severity.CRITICAL,
    "Uma conta recebeu UID 0, o identificador do administrador (root).",
    "Qualquer conta com UID 0 tem os mesmos poderes de root, mesmo com outro nome. Atacantes "
    "criam 'root escondidos' assim para não depender do sudo.",
    "Controle total e silencioso do servidor, difícil de notar numa revisão rápida de usuários.",
    (
        "Liste as contas com UID 0: awk -F: '$3==0' /etc/passwd. Só 'root' deve aparecer.",
        "Bloqueie imediatamente qualquer outra conta com UID 0 e investigue o que ela fez.",
        "Trate o servidor como comprometido: considere reconstruí-lo a partir de uma imagem limpa.",
    ),
    "O comando awk -F: '$3==0' /etc/passwd deve listar apenas root.",
    ("https://man7.org/linux/man-pages/man8/usermod.8.html", *ref_attack("T1098", "T1136.001")),
    exemplos=(Fix("linux", "Procurar UID 0", "awk -F: '$3==0 {print $1}' /etc/passwd", "bash"),),
    esforco="alto",
    cwe="CWE-269",
    owasp="A01:2021",
    cis=("5.4", "8.11"),
    tags=("persistencia", "escalada"),
)
