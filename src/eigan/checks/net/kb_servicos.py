"""Base de conhecimento: protocolos em texto puro (Telnet, FTP, e-mail) e resolvedor DNS aberto."""

from __future__ import annotations

from ...core import kb
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Severity

_FIREWALL_23 = (
    Fix("linux", "Linux (ufw)", "sudo ufw deny 23/tcp\nsudo ufw status numbered", "bash"),
    Fix(
        "windows",
        "Windows (PowerShell, firewall)",
        'New-NetFirewallRule -DisplayName "Bloquear Telnet" -Direction Inbound '
        "-Protocol TCP -LocalPort 23 -Action Block",
        "powershell",
    ),
)

kb.register(
    KBEntry(
        id="net.telnet.ativo",
        title="Telnet ativo (acesso remoto sem criptografia)",
        category=Category.NETWORK,
        severity=Severity.HIGH,
        summary="O servidor aceita conexões Telnet: usuário, senha e comandos trafegam em texto puro.",
        explanation=(
            "Telnet é um protocolo de acesso remoto da década de 1970 que não tem criptografia "
            "nenhuma. Tudo o que é digitado — inclusive o login e a senha — passa pela rede "
            "exatamente como foi escrito. O substituto seguro é o SSH."
        ),
        risk=(
            "Qualquer pessoa no caminho da conexão (Wi-Fi, provedor, rede interna comprometida) "
            "lê as credenciais e assume o equipamento. Serviços Telnet expostos também são alvo "
            "constante de robôs que testam senhas padrão (como as botnets de IoT)."
        ),
        steps=(
            "Confirme quem usa o Telnet e migre esse acesso para SSH.",
            "Desative o serviço Telnet (telnetd, inetd/xinetd, recurso do Windows ou do equipamento).",
            "Bloqueie a porta 23/tcp no firewall, principalmente para a Internet.",
            "Troque as senhas que já trafegaram por Telnet: considere-as expostas.",
        ),
        examples=(
            Fix(
                "linux",
                "Linux (Debian/Ubuntu)",
                "sudo systemctl disable --now inetd xinetd 2>/dev/null\n"
                "sudo apt purge telnetd inetutils-telnetd\nsudo apt install openssh-server",
                "bash",
            ),
            Fix(
                "windows",
                "Windows Server (PowerShell)",
                "Uninstall-WindowsFeature -Name Telnet-Server",
                "powershell",
            ),
            Fix(
                "cisco",
                "Cisco IOS (linhas VTY só com SSH)",
                "line vty 0 15\n transport input ssh\n login local",
                "text",
            ),
            *_FIREWALL_23,
        ),
        verify="Teste de fora: 'telnet servidor 23' deve falhar (conexão recusada ou sem resposta).",
        effort="baixo",
        fix_group="servicos",
        references=(
            "https://www.rfc-editor.org/rfc/rfc854",
            "https://cwe.mitre.org/data/definitions/319.html",
        ),
        cwe="CWE-319",
        owasp="A02:2021",
        cis=("4.8", "12.6"),
        tags=("texto-puro", "acesso-remoto"),
    ),
    KBEntry(
        id="net.ftp.sem_tls",
        title="FTP sem criptografia (sem AUTH TLS)",
        category=Category.NETWORK,
        severity=Severity.MEDIUM,
        summary="O servidor FTP não oferece TLS: logins e arquivos trafegam em texto puro.",
        explanation=(
            "O FTP clássico envia usuário, senha e o conteúdo dos arquivos sem criptografia. "
            "A extensão AUTH TLS (FTPS, RFC 4217) protege a conexão, mas este servidor não a "
            "anunciou. A alternativa mais simples costuma ser o SFTP, que usa o SSH."
        ),
        risk=(
            "Credenciais capturadas na rede dão acesso aos arquivos do servidor — e, muitas "
            "vezes, à mesma conta usada em outros sistemas. Arquivos em trânsito podem ser lidos "
            "ou alterados (por exemplo, trocando um instalador por uma versão maliciosa)."
        ),
        steps=(
            "Prefira SFTP (SSH) e desative o FTP se ninguém depende dele.",
            "Se o FTP for necessário, instale um certificado e exija TLS no login e nos dados.",
            "Restrinja a porta 21/tcp no firewall aos endereços que realmente usam o serviço.",
        ),
        examples=(
            Fix(
                "vsftpd",
                "vsftpd (/etc/vsftpd.conf)",
                "ssl_enable=YES\nforce_local_logins_ssl=YES\nforce_local_data_ssl=YES\n"
                "rsa_cert_file=/etc/ssl/certs/ftp.pem\n"
                "rsa_private_key_file=/etc/ssl/private/ftp.key",
                "text",
            ),
            Fix(
                "proftpd",
                "ProFTPD (mod_tls)",
                "<IfModule mod_tls.c>\n  TLSEngine on\n  TLSRequired on\n"
                "  TLSProtocol TLSv1.2 TLSv1.3\n"
                "  TLSRSACertificateFile /etc/ssl/certs/proftpd.crt\n"
                "  TLSRSACertificateKeyFile /etc/ssl/private/proftpd.key\n</IfModule>",
                "apache",
            ),
            Fix(
                "iis-ftp",
                "IIS FTP (PowerShell, exigir SSL)",
                "Import-Module WebAdministration\n"
                "$site = 'IIS:\\Sites\\Default FTP Site'\n"
                "Set-ItemProperty $site -Name ftpServer.security.ssl.controlChannelPolicy -Value 1\n"
                "Set-ItemProperty $site -Name ftpServer.security.ssl.dataChannelPolicy -Value 1",
                "powershell",
            ),
        ),
        verify="'openssl s_client -connect servidor:21 -starttls ftp' deve concluir o handshake TLS.",
        effort="medio",
        fix_group="servicos",
        references=(
            "https://www.rfc-editor.org/rfc/rfc4217",
            "https://security.appspot.com/vsftpd/vsftpd_conf.html",
            "https://github.com/proftpd/proftpd/blob/master/doc/contrib/mod_tls.html",
        ),
        cwe="CWE-319",
        owasp="A02:2021",
        cis=("3.10", "12.6"),
        lgpd=True,
        tags=("texto-puro", "ftp"),
    ),
    KBEntry(
        id="net.ftp.anonimo",
        title="FTP aceita login anônimo",
        category=Category.NETWORK,
        severity=Severity.HIGH,
        summary="Qualquer pessoa entra no FTP com o usuário 'anonymous', sem senha real.",
        explanation=(
            "O login anônimo é um recurso antigo para distribuir arquivos públicos. Habilitado "
            "por engano (ou esquecido), ele expõe o conteúdo do servidor a qualquer um — e, se a "
            "escrita também estiver liberada, permite que estranhos depositem arquivos."
        ),
        risk=(
            "Vazamento de documentos, backups e configurações; uso do servidor para hospedar "
            "malware ou conteúdo ilegal quando o upload anônimo é permitido."
        ),
        steps=(
            "Desative o acesso anônimo na configuração do servidor FTP.",
            "Se for um repositório público intencional, deixe-o somente leitura e sem dados internos.",
            "Revise o conteúdo que ficou exposto e os logs de acesso anônimo.",
        ),
        examples=(
            Fix(
                "vsftpd",
                "vsftpd (/etc/vsftpd.conf)",
                "anonymous_enable=NO\nanon_upload_enable=NO",
                "text",
            ),
            Fix(
                "proftpd",
                "ProFTPD",
                "# remova (ou comente) o bloco <Anonymous ~ftp> ... </Anonymous> do proftpd.conf\n"
                "sudo systemctl restart proftpd",
                "bash",
            ),
            Fix(
                "iis-ftp",
                "IIS FTP (PowerShell)",
                "Import-Module WebAdministration\n"
                "Set-ItemProperty 'IIS:\\Sites\\Default FTP Site' "
                "-Name ftpServer.security.authentication.anonymousAuthentication.enabled -Value $false",
                "powershell",
            ),
        ),
        verify="Conecte com 'ftp servidor' e tente o usuário anonymous: o login deve ser recusado (530).",
        effort="baixo",
        fix_group="autenticacao",
        references=(
            "https://www.rfc-editor.org/rfc/rfc1635",
            "https://cwe.mitre.org/data/definitions/284.html",
        ),
        cwe="CWE-284",
        owasp="A01:2021",
        cis=("3.3", "4.7"),
        lgpd=True,
        tags=("ftp", "anonimo"),
    ),
    KBEntry(
        id="net.smtp.sem_starttls",
        title="Servidor SMTP sem STARTTLS",
        category=Category.NETWORK,
        severity=Severity.MEDIUM,
        summary="O servidor de e-mail não oferece STARTTLS: mensagens (e senhas, no envio) vão sem criptografia.",
        explanation=(
            "STARTTLS (RFC 3207) é o comando que liga a criptografia numa conexão SMTP. Sem ele, "
            "os e-mails trocados com outros servidores — e as credenciais de quem envia pela "
            "porta 587 — trafegam em texto puro."
        ),
        risk=(
            "Leitura e alteração de e-mails em trânsito e captura de senhas de envio. Outros "
            "provedores podem rebaixar a reputação do domínio por não aceitar TLS."
        ),
        steps=(
            "Instale um certificado válido para o nome do servidor de e-mail (ex.: Let's Encrypt).",
            "Ative o TLS no servidor SMTP (porta 25 em modo oportunista; 587 com TLS obrigatório).",
            "Exija TLS antes da autenticação (AUTH) para os usuários que enviam e-mail.",
        ),
        examples=(
            Fix(
                "postfix",
                "Postfix (/etc/postfix/main.cf)",
                "smtpd_tls_cert_file = /etc/letsencrypt/live/mail.exemplo.com.br/fullchain.pem\n"
                "smtpd_tls_key_file = /etc/letsencrypt/live/mail.exemplo.com.br/privkey.pem\n"
                "smtpd_tls_security_level = may\nsmtpd_tls_auth_only = yes",
                "text",
            ),
            Fix(
                "exim",
                "Exim (configuração principal)",
                "tls_advertise_hosts = *\n"
                "tls_certificate = /etc/letsencrypt/live/mail.exemplo.com.br/fullchain.pem\n"
                "tls_privatekey = /etc/letsencrypt/live/mail.exemplo.com.br/privkey.pem",
                "text",
            ),
            Fix(
                "exchange",
                "Exchange (PowerShell)",
                "Enable-ExchangeCertificate -Thumbprint <impressao-do-certificado> -Services SMTP",
                "powershell",
            ),
        ),
        verify="'openssl s_client -connect servidor:25 -starttls smtp' deve concluir o handshake TLS.",
        effort="medio",
        fix_group="servicos",
        references=(
            "https://www.rfc-editor.org/rfc/rfc3207",
            "https://www.postfix.org/TLS_README.html",
        ),
        cwe="CWE-319",
        owasp="A02:2021",
        cis=("3.10",),
        lgpd=True,
        tags=("email", "texto-puro"),
    ),
    KBEntry(
        id="net.correio.sem_tls",
        title="POP3/IMAP sem criptografia",
        category=Category.NETWORK,
        severity=Severity.MEDIUM,
        summary="A caixa postal (POP3 ou IMAP) aceita conexões sem TLS: senhas e e-mails trafegam em texto puro.",
        explanation=(
            "POP3 (porta 110) e IMAP (porta 143) sem TLS enviam o login e o conteúdo das "
            "mensagens às claras. A RFC 8314 considera esse uso obsoleto: o correto é TLS "
            "implícito (portas 995 e 993) ou, no mínimo, STARTTLS obrigatório."
        ),
        risk="Captura das senhas de e-mail e leitura das mensagens por quem estiver no caminho da rede.",
        steps=(
            "Configure TLS no servidor de caixa postal com um certificado válido.",
            "Ofereça as portas 993 (IMAPS) e 995 (POP3S) e oriente os clientes a usá-las.",
            "Proíba login em texto puro e, quando possível, feche as portas 110 e 143.",
        ),
        examples=(
            Fix(
                "dovecot",
                "Dovecot 2.3 (/etc/dovecot/conf.d/10-ssl.conf e 10-auth.conf)",
                "ssl = required\n"
                "ssl_cert = </etc/letsencrypt/live/mail.exemplo.com.br/fullchain.pem\n"
                "ssl_key = </etc/letsencrypt/live/mail.exemplo.com.br/privkey.pem\n"
                "disable_plaintext_auth = yes",
                "text",
            ),
            Fix("linux", "Linux (ufw)", "sudo ufw deny 110/tcp\nsudo ufw deny 143/tcp", "bash"),
        ),
        verify="'openssl s_client -connect servidor:993' deve funcionar e as portas 110/143 não devem aceitar login sem TLS.",
        effort="medio",
        fix_group="servicos",
        references=(
            "https://www.rfc-editor.org/rfc/rfc8314",
            "https://www.rfc-editor.org/rfc/rfc2595",
        ),
        cwe="CWE-319",
        owasp="A02:2021",
        cis=("3.10",),
        lgpd=True,
        tags=("email", "texto-puro"),
    ),
    KBEntry(
        id="net.dns.resolvedor_aberto",
        title="Resolvedor DNS aberto para a Internet",
        category=Category.NETWORK,
        severity=Severity.MEDIUM,
        summary="O servidor DNS responde consultas recursivas de qualquer endereço da Internet.",
        explanation=(
            "Um resolvedor recursivo deveria atender só os clientes da própria organização. "
            "Aberto para todos, ele resolve nomes para qualquer um — inclusive para atacantes, "
            "que o usam como amplificador de ataques de negação de serviço (DDoS)."
        ),
        risk=(
            "O servidor vira peça de ataques de amplificação contra terceiros (consumindo a sua "
            "banda e prejudicando a reputação dos seus IPs) e fica mais exposto a envenenamento "
            "de cache."
        ),
        steps=(
            "Se o servidor só responde pelos seus domínios (autoritativo), desligue a recursão.",
            "Se ele é o resolvedor da empresa, permita recursão apenas para as redes internas.",
            "Bloqueie a porta 53 (UDP e TCP) vinda da Internet quando o servidor não for público.",
        ),
        examples=(
            Fix(
                "bind",
                "BIND (named.conf)",
                "options {\n    recursion yes;\n"
                "    allow-recursion { 127.0.0.1; 10.0.0.0/8; 192.168.0.0/16; };\n};\n"
                "# servidor apenas autoritativo: recursion no;",
                "text",
            ),
            Fix(
                "unbound",
                "Unbound (unbound.conf)",
                "server:\n    access-control: 0.0.0.0/0 refuse\n"
                "    access-control: 10.0.0.0/8 allow\n    access-control: 127.0.0.0/8 allow",
                "text",
            ),
            Fix(
                "windows",
                "Windows DNS Server (PowerShell)",
                "Set-DnsServerRecursion -Enable $false",
                "powershell",
            ),
        ),
        verify="De um endereço externo, 'dig @servidor example.com' deve responder REFUSED (ou sem a flag 'ra').",
        effort="baixo",
        fix_group="dns",
        references=(
            "https://www.cisa.gov/news-events/alerts/2013/03/29/dns-amplification-attacks",
            "https://www.rfc-editor.org/rfc/rfc5358",
        ),
        cwe="CWE-406",
        owasp="A05:2021",
        cis=("4.2", "12.2"),
        tags=("dns", "amplificacao"),
    ),
)
