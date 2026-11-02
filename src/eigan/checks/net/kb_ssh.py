"""Base de conhecimento: configuração criptográfica do servidor SSH."""

from __future__ import annotations

from ...core import kb
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Severity

#: lista suportada pelo OpenSSH 7.4 ou mais novo (teste com "sshd -t" antes de reiniciar)
_SSHD_MODERN = (
    "# OpenSSH 7.4 ou mais novo; antes da 9.6, retire também o chacha20-poly1305 (Terrapin)\n"
    "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,"
    "diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,"
    "diffie-hellman-group-exchange-sha256\n"
    "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,"
    "aes256-ctr,aes192-ctr,aes128-ctr\n"
    "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com\n"
    "HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256"
)
_SSHD_APPLY = Fix(
    "openssh",
    "OpenSSH (/etc/ssh/sshd_config)",
    _SSHD_MODERN + "\n\n# valide e aplique (na família Red Hat o serviço se chama sshd):\n"
    "sudo sshd -t && sudo systemctl reload ssh",
    "text",
)
_SSHD_WINDOWS = Fix(
    "windows",
    "OpenSSH no Windows (C:\\ProgramData\\ssh\\sshd_config)",
    "# mesmas linhas KexAlgorithms/Ciphers/MACs/HostKeyAlgorithms acima, depois:\n"
    "Restart-Service sshd",
    "powershell",
)

kb.register(
    KBEntry(
        id="net.ssh.protocolo_v1",
        title="Servidor SSH aceita o protocolo SSH-1",
        category=Category.NETWORK,
        severity=Severity.HIGH,
        summary="O servidor anuncia suporte ao SSH versão 1, um protocolo quebrado e abandonado.",
        explanation=(
            "O SSH-1 tem falhas de projeto conhecidas (integridade fraca, ataques de inserção e "
            "de sequestro de sessão). Ele foi substituído pelo SSH-2 (RFC 4253) e versões atuais "
            "do OpenSSH nem o incluem mais."
        ),
        risk="Sessões interceptadas ou adulteradas por quem estiver no caminho da rede.",
        steps=(
            "Atualize o servidor SSH para uma versão atual, que só fala SSH-2.",
            "Em versões antigas, defina 'Protocol 2' no sshd_config e reinicie o serviço.",
        ),
        examples=(
            Fix("openssh", "OpenSSH antigo (/etc/ssh/sshd_config)", "Protocol 2", "text"),
            Fix("cisco", "Cisco IOS", "ip ssh version 2", "text"),
        ),
        verify="O banner do servidor deve começar com 'SSH-2.0-' (e não 'SSH-1.99-' ou 'SSH-1.5-').",
        effort="baixo",
        fix_group="ssh",
        references=(
            "https://www.rfc-editor.org/rfc/rfc4253",
            "https://www.openssh.org/txt/release-7.4",
        ),
        cwe="CWE-327",
        owasp="A02:2021",
        cis=("4.1", "12.6"),
        tags=("ssh", "legado"),
    ),
    KBEntry(
        id="net.ssh.algoritmos_fracos",
        title="SSH oferece algoritmos criptográficos fracos",
        category=Category.NETWORK,
        severity=Severity.MEDIUM,
        summary="O servidor SSH aceita algoritmos quebrados (SHA-1 em troca de chaves, RC4, 3DES, MD5, DSA...).",
        explanation=(
            "Antes do login, o servidor SSH anuncia os algoritmos que aceita. Alguns deles já "
            "não protegem como deveriam: grupos Diffie-Hellman de 1024 bits com SHA-1, cifras "
            "de 64 bits ou RC4 e MACs com MD5. A RFC 9142 e a RFC 8758 recomendam não usá-los. "
            "A severidade sobe para alta quando a lista inclui algo sem proteção real, como "
            "'none', DES, RC4, MD5, módulo de 1024 bits ou chaves DSA."
        ),
        risk=(
            "Um atacante com recursos pode forçar a negociação de um algoritmo fraco e "
            "decifrar ou adulterar a sessão; equipamentos antigos que dependem deles atrasam "
            "a modernização."
        ),
        steps=(
            "Liste o que o servidor aceita hoje: 'sshd -T | grep -E \"kexalgorithms|ciphers|macs|hostkeyalgorithms\"'.",
            "Defina listas explícitas só com algoritmos modernos (exemplo abaixo).",
            "Valide com 'sshd -t' antes de recarregar e mantenha a sessão atual aberta até testar "
            "um novo login, para não perder o acesso.",
        ),
        examples=(_SSHD_APPLY, _SSHD_WINDOWS),
        verify="Rode o EIGAN de novo (ou 'ssh -vv servidor'): os algoritmos fracos não devem mais aparecer.",
        effort="baixo",
        fix_group="ssh",
        references=(
            "https://www.rfc-editor.org/rfc/rfc9142",
            "https://www.rfc-editor.org/rfc/rfc8758",
        ),
        cwe="CWE-327",
        owasp="A02:2021",
        cis=("3.10", "4.1"),
        tags=("ssh", "criptografia"),
    ),
    KBEntry(
        id="net.ssh.algoritmos_obsoletos",
        title="SSH oferece algoritmos obsoletos",
        category=Category.NETWORK,
        severity=Severity.LOW,
        summary="O servidor SSH ainda aceita algoritmos em desuso (modo CBC, HMAC-SHA1, assinatura ssh-rsa com SHA-1).",
        explanation=(
            "Esses algoritmos não estão quebrados de forma prática, mas são desaconselhados: "
            "o modo CBC teve ataques históricos, o SHA-1 é considerado fraco para assinaturas "
            "e o OpenSSH 8.8 desativou o 'ssh-rsa' (RSA com SHA-1) por padrão."
        ),
        risk="Margem de segurança menor e risco de rebaixamento da negociação no futuro.",
        steps=(
            "Remova os algoritmos obsoletos das listas do sshd_config (exemplo abaixo). No OpenSSH "
            "7.5 ou mais novo também dá para só retirar do padrão: 'Ciphers -*-cbc'.",
            "Confirme que os clientes usados na empresa suportam os algoritmos modernos.",
        ),
        examples=(_SSHD_APPLY, _SSHD_WINDOWS),
        verify="'sshd -T' deve listar só algoritmos modernos.",
        effort="baixo",
        fix_group="ssh",
        references=(
            "https://www.rfc-editor.org/rfc/rfc9142",
            "https://www.openssh.org/txt/release-8.8",
            "https://www.openssh.org/txt/release-7.5",
        ),
        cwe="CWE-327",
        owasp="A02:2021",
        cis=("4.1",),
        tags=("ssh", "criptografia"),
    ),
    KBEntry(
        id="net.ssh.terrapin",
        title="SSH vulnerável ao ataque Terrapin (CVE-2023-48795)",
        category=Category.NETWORK,
        severity=Severity.MEDIUM,
        summary="O servidor oferece ChaCha20-Poly1305 (ou CBC com MAC EtM) sem a contramedida 'strict KEX'.",
        explanation=(
            "O Terrapin permite que um atacante no meio da conexão apague mensagens do início "
            "da sessão SSH sem ser percebido — por exemplo, desativando extensões de segurança. "
            "A correção é o 'strict KEX', presente no OpenSSH 9.6 e nas versões corrigidas de "
            "outras implementações; ele só vale quando cliente e servidor o suportam. O EIGAN vê "
            "apenas o lado do servidor: atualize também os clientes. CTR com EtM é afetado só em "
            "teoria e AES-GCM não é afetado, por isso não entram neste achado."
        ),
        risk=(
            "Rebaixamento silencioso de proteções da sessão SSH por um atacante em posição de "
            "interceptação (rede comprometida, Wi-Fi hostil)."
        ),
        steps=(
            "Atualize o servidor SSH (OpenSSH 9.6 ou mais novo, ou a versão corrigida do seu fornecedor/distribuição).",
            "Enquanto não atualiza, remova chacha20-poly1305@openssh.com e as cifras CBC (ou os MACs "
            "*-etm@openssh.com), mantendo AES-GCM e CTR. Confirme antes que seus clientes suportam "
            "o que restar, para não perder o acesso.",
            "Atualize também os clientes SSH, já que a proteção exige os dois lados.",
        ),
        examples=(
            Fix(
                "openssh",
                "Mitigação temporária (/etc/ssh/sshd_config)",
                "Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n"
                "MACs hmac-sha2-512,hmac-sha2-256\n\nsudo sshd -t && sudo systemctl reload ssh",
                "text",
            ),
            Fix(
                "linux",
                "Atualizar o OpenSSH (Debian/Ubuntu)",
                "sudo apt update && sudo apt install --only-upgrade openssh-server",
                "bash",
            ),
        ),
        verify="O KEXINIT do servidor deve anunciar 'kex-strict-s-v00@openssh.com' (ou não oferecer as combinações afetadas).",
        effort="baixo",
        fix_group="ssh",
        references=(
            "https://terrapin-attack.com/",
            "https://nvd.nist.gov/vuln/detail/CVE-2023-48795",
            "https://www.openssh.org/txt/release-9.6",
            "https://datatracker.ietf.org/doc/html/draft-miller-sshm-strict-kex",
        ),
        cwe="CWE-354",
        owasp="A02:2021",
        cis=("7.4",),
        tags=("ssh", "terrapin"),
    ),
    KBEntry(
        id="net.ssh.regresshion",
        title="OpenSSH em versão afetada pelo regreSSHion (CVE-2024-6387)",
        category=Category.NETWORK,
        severity=Severity.HIGH,
        summary=(
            "A versão anunciada do OpenSSH está na faixa da falha regreSSHion, que pode permitir "
            "executar comandos como root sem login."
        ),
        explanation=(
            "O regreSSHion é uma condição de corrida no tratador de sinal do sshd, que roda quando "
            "o tempo de login (LoginGraceTime) se esgota. Afeta o OpenSSH portátil de 8.5p1 a 9.7p1 "
            "e, salvo correções antigas, versões anteriores à 4.4p1. A exploração foi demonstrada em "
            "Linux/glibc de 32 bits e é considerada possível em 64 bits. O OpenBSD não é afetado e a "
            "Microsoft informa que o Windows também não. O EIGAN só lê o banner: distribuições "
            "corrigem a falha sem mudar a versão, então, quando o banner não permite concluir "
            "(família Red Hat, por exemplo), o achado aparece como indício."
        ),
        risk=(
            "Execução remota de código como root, sem autenticação, em um servidor exposto: "
            "comprometimento total da máquina e acesso aos dados e às chaves dela."
        ),
        steps=(
            "Atualize o pacote do servidor SSH: OpenSSH 9.8p1 ou mais novo, ou a revisão corrigida da "
            "distribuição (Ubuntu 22.04: 1:8.9p1-3ubuntu0.10; 23.10: 1:9.3p1-1ubuntu3.6; 24.04: "
            "1:9.6p1-3ubuntu13.3; Debian 12: 1:9.2p1-2+deb12u3).",
            "Reinicie o serviço depois da atualização: o processo antigo continua vulnerável até lá.",
            "Na família Red Hat, o banner não mostra a revisão: confira com 'rpm -q openssh-server' e "
            "com o aviso de segurança da distribuição.",
            "Se não puder atualizar agora, use 'LoginGraceTime 0' no sshd_config: isso elimina a "
            "execução de código, mas facilita a negação de serviço (esgotamento de MaxStartups).",
            "Restrinja a porta do SSH a endereços confiáveis (VPN ou lista de permissão no firewall).",
        ),
        examples=(
            Fix(
                "linux",
                "Debian/Ubuntu: atualizar e reiniciar",
                "sudo apt update && sudo apt install --only-upgrade openssh-server\n"
                "dpkg -l openssh-server\nsudo systemctl restart ssh",
                "bash",
            ),
            Fix(
                "linux",
                "Família Red Hat: atualizar e conferir",
                "sudo dnf upgrade openssh-server\nrpm -q openssh-server\nsudo systemctl restart sshd",
                "bash",
            ),
            Fix(
                "openssh",
                "Mitigação temporária (/etc/ssh/sshd_config)",
                "LoginGraceTime 0\n\n# valide e aplique:\nsudo sshd -t && sudo systemctl reload ssh",
                "text",
            ),
        ),
        verify=(
            "O banner deve mostrar 9.8p1 ou mais novo, ou a revisão corrigida da distribuição, e a "
            "versão do pacote instalado deve bater com a do processo em execução (reinicie o sshd)."
        ),
        effort="baixo",
        fix_group="ssh",
        references=(
            "https://www.openssh.org/txt/release-9.8",
            "https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-6387",
            "https://ubuntu.com/security/notices/USN-6859-1",
            "https://lists.debian.org/debian-security-announce/2024/msg00135.html",
            "https://security-tracker.debian.org/tracker/CVE-2024-6387",
            "https://access.redhat.com/security/cve/CVE-2024-6387",
        ),
        cwe="CWE-364",
        owasp="A06:2021",
        cis=("7.3", "7.4"),
        tags=("ssh", "cve", "regresshion"),
    ),
    KBEntry(
        id="net.ssh.sem_pos_quantico",
        title="SSH sem troca de chaves pós-quântica",
        category=Category.NETWORK,
        severity=Severity.INFO,
        summary="O servidor SSH não oferece troca de chaves híbrida pós-quântica (sntrup761x25519 ou mlkem768x25519).",
        explanation=(
            "Quem grava o tráfego hoje pode tentar decifrá-lo no futuro, quando existirem "
            "computadores quânticos capazes disso (capturar agora, decifrar depois). Para evitar "
            "esse risco, o OpenSSH usa troca de chaves híbrida por padrão desde a versão 9.0 "
            "(sntrup761x25519) e a 10.0 (mlkem768x25519); a partir da 10.1, o cliente ssh avisa "
            "quando a conexão não usa uma delas. Isto não é uma falha atual: é inventário para "
            "planejar a modernização."
        ),
        risk="Sessões gravadas hoje podem ser decifradas no futuro, se o conteúdo ainda tiver valor.",
        steps=(
            "Atualize o OpenSSH (9.0 ou mais novo; de preferência 9.9 ou mais novo, que traz o "
            "mlkem768x25519-sha256).",
            "Se o sshd_config define KexAlgorithms, inclua os algoritmos híbridos no início da lista.",
        ),
        examples=(
            Fix(
                "openssh",
                "OpenSSH 9.9 ou mais novo (/etc/ssh/sshd_config)",
                "KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512,"
                "sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org\n\n"
                "# valide e aplique:\nsudo sshd -t && sudo systemctl reload ssh",
                "text",
            ),
        ),
        verify="O KEXINIT do servidor deve anunciar 'mlkem768x25519-sha256' ou 'sntrup761x25519-sha512@openssh.com'.",
        effort="medio",
        fix_group="ssh",
        references=(
            "https://www.openssh.org/txt/release-9.0",
            "https://www.openssh.org/txt/release-9.9",
            "https://www.openssh.org/txt/release-10.0",
            "https://www.openssh.org/txt/release-10.1",
        ),
        cwe="CWE-327",
        owasp="A02:2021",
        cis=("3.10",),
        tags=("ssh", "criptografia", "pos-quantico"),
    ),
)
