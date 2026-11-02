"""Base de conhecimento: acesso remoto e compartilhamento (RDP, SMB, VNC) e conector AJP."""

from __future__ import annotations

from ...core import kb
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Severity

_RDP_FIREWALL = Fix(
    "windows",
    "Windows (PowerShell, só a rede administrativa)",
    'Set-NetFirewallRule -Name "RemoteDesktop-UserMode-In-TCP" -RemoteAddress "10.0.0.0/8"',
    "powershell",
)
_RDP_NLA = Fix(
    "windows",
    "Windows (PowerShell, exigir NLA)",
    "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\"
    "WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1",
    "powershell",
)

kb.register(
    KBEntry(
        id="net.rdp.exposto",
        title="Área de Trabalho Remota (RDP) exposta à Internet",
        category=Category.NETWORK,
        severity=Severity.HIGH,
        summary="A porta do RDP (3389) responde para a Internet.",
        explanation=(
            "O RDP é a porta de entrada preferida em ataques de ransomware: robôs testam senhas "
            "o tempo todo e falhas graves do serviço (como a BlueKeep, CVE-2019-0708) já "
            "permitiram invasão sem senha. Ele não deveria ficar aberto diretamente para a "
            "Internet."
        ),
        risk=(
            "Invasão por senha fraca ou vazada, exploração de vulnerabilidades do serviço e "
            "acesso interativo ao servidor — o primeiro passo de muitos ataques de ransomware."
        ),
        steps=(
            "Tire o RDP da Internet: use VPN, Gateway de Área de Trabalho Remota ou bastion com MFA.",
            "Se precisar manter, restrinja a porta a endereços conhecidos no firewall.",
            "Exija NLA, bloqueie contas após tentativas erradas e mantenha o Windows atualizado.",
        ),
        examples=(_RDP_FIREWALL, _RDP_NLA),
        verify="De um endereço externo, a porta 3389 deve aparecer filtrada.",
        effort="medio",
        fix_group="servicos",
        references=(
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708",
            "https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-plan-access-from-anywhere",
        ),
        cwe="CWE-284",
        owasp="A05:2021",
        cis=("4.4", "6.3", "12.2"),
        tags=("rdp", "acesso-remoto", "ransomware"),
    ),
    KBEntry(
        id="net.rdp.sem_nla",
        title="RDP sem autenticação em nível de rede (NLA)",
        category=Category.NETWORK,
        severity=Severity.HIGH,
        summary="O servidor RDP aceita sessões sem exigir NLA: a tela de login fica acessível antes da autenticação.",
        explanation=(
            "Com NLA (Network Level Authentication), o usuário prova quem é antes de o servidor "
            "abrir uma sessão gráfica. Sem NLA, qualquer um recebe a tela de logon — gastando "
            "recursos do servidor e alcançando código que roda antes da autenticação, onde "
            "estavam falhas como a BlueKeep. A segurança 'RDP padrão' (sem TLS) também usa "
            "criptografia antiga."
        ),
        risk="Ataques de força bruta mais baratos, negação de serviço e exploração de falhas pré-autenticação.",
        steps=(
            "Ative 'Exigir autenticação de usuário para conexões remotas usando NLA' (GPO ou registro).",
            "Configure a camada de segurança como TLS (SecurityLayer = 2).",
            "Em servidores xrdp (Linux), restrinja o acesso por firewall/VPN e use security_layer=tls.",
        ),
        examples=(
            _RDP_NLA,
            Fix(
                "gpo",
                "Política de Grupo",
                "Configuração do Computador > Modelos Administrativos > Componentes do Windows > "
                "Serviços de Área de Trabalho Remota > Host da Sessão > Segurança > "
                "'Exigir autenticação de usuário para conexões remotas usando NLA' = Habilitado",
                "text",
            ),
            Fix("xrdp", "xrdp (/etc/xrdp/xrdp.ini)", "[Globals]\nsecurity_layer=tls", "text"),
        ),
        verify="Conectar com um cliente RDP com NLA desligado deve ser recusado pelo servidor.",
        effort="baixo",
        fix_group="windows",
        references=(
            "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/1b3920e7-0116-4345-bc45-f2c4ad012761",
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708",
        ),
        cwe="CWE-306",
        owasp="A07:2021",
        cis=("4.1", "12.6"),
        tags=("rdp", "nla"),
    ),
    KBEntry(
        id="net.smb.exposto",
        title="Compartilhamento de arquivos (SMB) exposto à Internet",
        category=Category.NETWORK,
        severity=Severity.HIGH,
        summary="A porta 445 (SMB) responde para a Internet.",
        explanation=(
            "O SMB é o protocolo de compartilhamento de arquivos do Windows (e do Samba). Ele "
            "foi feito para redes internas; exposto na Internet, virou vetor de ataques em "
            "massa como o WannaCry e o NotPetya."
        ),
        risk=(
            "Exploração de falhas do SMB sem senha, roubo de hashes de senha (NTLM) e força bruta "
            "contra contas do domínio."
        ),
        steps=(
            "Bloqueie as portas 445 e 139 no firewall de borda (entrada e saída para a Internet).",
            "Para acesso remoto a arquivos, use VPN ou serviços próprios (SharePoint/OneDrive, SFTP).",
            "Mantenha o Windows/Samba atualizado e o SMBv1 desativado.",
        ),
        examples=(
            Fix(
                "windows",
                "Windows (PowerShell)",
                'New-NetFirewallRule -DisplayName "Bloquear SMB externo" -Direction Inbound '
                "-Protocol TCP -LocalPort 445 -RemoteAddress Internet -Action Block",
                "powershell",
            ),
            Fix("linux", "Samba (ufw)", "sudo ufw deny 445/tcp\nsudo ufw deny 139/tcp", "bash"),
        ),
        verify="De um endereço externo, a porta 445 deve aparecer filtrada.",
        effort="baixo",
        fix_group="servicos",
        references=(
            "https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-secure-traffic",
            "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010",
        ),
        cwe="CWE-284",
        owasp="A05:2021",
        cis=("4.4", "12.2"),
        tags=("smb", "exposicao"),
    ),
    KBEntry(
        id="net.smb.v1",
        title="SMBv1 habilitado",
        category=Category.NETWORK,
        severity=Severity.HIGH,
        summary="O servidor aceita o dialeto SMB 1.0 (NT LM 0.12), obsoleto e inseguro.",
        explanation=(
            "O SMBv1 tem mais de 30 anos, não tem as proteções das versões 2 e 3 e foi o "
            "protocolo explorado pelo EternalBlue (MS17-010), usado pelo WannaCry. Desde o "
            "Windows 10 e o Windows Server versão 1709 ele não vem instalado em instalações "
            "novas, mas continua ativo em sistemas antigos, em atualizações de versões "
            "anteriores em que alguém o manteve e em equipamentos com Samba desatualizado. "
            "A Microsoft recomenda removê-lo."
        ),
        risk="Exploração remota de falhas do SMBv1, propagação de ransomware em 'worm' e ataques de rebaixamento.",
        steps=(
            "Verifique se algum equipamento antigo (impressora, scanner, NAS) ainda depende do SMBv1 e atualize-o.",
            "Desative o SMBv1 no servidor e remova o recurso do Windows.",
            "No Samba, defina o protocolo mínimo como SMB2 ou superior.",
        ),
        examples=(
            Fix(
                "windows",
                "Windows (PowerShell)",
                "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force\n"
                "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol",
                "powershell",
            ),
            Fix("samba", "Samba (smb.conf)", "[global]\n   server min protocol = SMB2_10", "text"),
        ),
        verify="'Get-SmbServerConfiguration | Select EnableSMB1Protocol' deve mostrar False.",
        effort="baixo",
        fix_group="windows",
        references=(
            "https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3",
            "https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/smbv1-not-installed-by-default-in-windows",
            "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010",
        ),
        cwe="CWE-327",
        owasp="A06:2021",
        cis=("4.8", "12.6"),
        tags=("smb", "smbv1", "legado"),
    ),
    KBEntry(
        id="net.smb.assinatura_opcional",
        title="Assinatura SMB não obrigatória",
        category=Category.NETWORK,
        severity=Severity.MEDIUM,
        summary="O servidor SMB aceita sessões sem assinatura digital das mensagens.",
        explanation=(
            "A assinatura SMB garante que cada mensagem veio de quem diz ter vindo e não foi "
            "alterada. Quando ela é só opcional, um atacante na rede interna pode retransmitir "
            "(relay) autenticações NTLM para este servidor e agir em nome da vítima. "
            "Controladores de domínio exigem assinatura por padrão, e o Windows 11 24H2 (Pro, "
            "Enterprise e Education) passou a exigi-la nas conexões de entrada e de saída; o "
            "Windows Server 2025, porém, exige por padrão só nas conexões de saída — servidores "
            "de arquivos e versões anteriores precisam ser configurados."
        ),
        risk="Ataques de relay NTLM e adulteração de arquivos em trânsito dentro da rede.",
        steps=(
            "Exija assinatura no servidor ('Servidor de rede Microsoft: assinar comunicações digitalmente (sempre)').",
            "Exigir assinatura desativa o acesso de convidado (guest): confirme antes que nenhum "
            "equipamento depende dele.",
            "Teste com clientes antigos antes de aplicar em massa; prefira Kerberos a NTLM.",
        ),
        examples=(
            Fix(
                "windows",
                "Windows (PowerShell)",
                "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force",
                "powershell",
            ),
            Fix("samba", "Samba (smb.conf)", "[global]\n   server signing = mandatory", "text"),
        ),
        verify="'Get-SmbServerConfiguration | Select RequireSecuritySignature' deve mostrar True.",
        effort="baixo",
        fix_group="windows",
        references=(
            "https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview",
            "https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing",
        ),
        cwe="CWE-345",
        owasp="A08:2021",
        cis=("4.1",),
        tags=("smb", "relay"),
    ),
    KBEntry(
        id="net.vnc.exposto",
        title="VNC acessível pela rede",
        category=Category.NETWORK,
        severity=Severity.HIGH,
        summary="Um servidor VNC (controle remoto de tela) responde pela rede.",
        explanation=(
            "O VNC dá controle total da tela e do teclado. A autenticação clássica do VNC usa "
            "senhas de até 8 caracteres e, na maioria dos servidores, a sessão não é criptografada."
        ),
        risk="Força bruta da senha curta, captura da sessão na rede e controle da máquina por terceiros.",
        steps=(
            "Faça o VNC escutar só em localhost e acesse por túnel SSH ou VPN.",
            "Se precisar expor, use um servidor com TLS (VeNCrypt) e senhas fortes, restrito por firewall.",
        ),
        examples=(
            Fix(
                "linux",
                "TigerVNC só em localhost + túnel SSH",
                "# no servidor: ~/.config/tigervnc/config (versões antigas: ~/.vnc/config)\n"
                "localhost\n\n"
                "# no computador do administrador:\n"
                "ssh -L 5901:localhost:5901 usuario@servidor\n"
                "# depois conecte o cliente VNC em localhost:5901",
                "bash",
            ),
            Fix("linux", "Linux (ufw)", "sudo ufw deny 5900:5910/tcp", "bash"),
        ),
        verify="De outro computador, a porta 5900 deve aparecer fechada; o acesso só funciona pelo túnel.",
        effort="baixo",
        fix_group="servicos",
        references=("https://www.rfc-editor.org/rfc/rfc6143",),
        cwe="CWE-284",
        owasp="A05:2021",
        cis=("4.4", "12.6"),
        tags=("vnc", "acesso-remoto"),
    ),
    KBEntry(
        id="net.vnc.sem_senha",
        title="VNC sem senha",
        category=Category.NETWORK,
        severity=Severity.CRITICAL,
        summary="O servidor VNC oferece o tipo de segurança 'None': qualquer um assume a tela sem senha.",
        explanation=(
            "No protocolo RFB, o tipo de segurança 1 ('None') significa que o servidor não pede "
            "autenticação nenhuma. Quem conectar vê e controla a sessão gráfica como se estivesse "
            "na frente do computador."
        ),
        risk="Controle imediato da máquina, roubo de dados abertos na tela e instalação de malware.",
        steps=(
            "Configure autenticação no servidor VNC (senha ou, melhor, VeNCrypt com usuário do sistema).",
            "Restrinja o VNC a localhost e acesse por túnel SSH/VPN.",
            "Verifique se houve acessos indevidos (logs do servidor VNC e do sistema).",
        ),
        examples=(
            Fix(
                "linux",
                "TigerVNC (senha + TLS, só em localhost)",
                "vncpasswd\n\n"
                "# ~/.config/tigervnc/config (ou /etc/tigervnc/vncserver-config-defaults)\n"
                "securitytypes=vncauth,tlsvnc\nlocalhost",
                "bash",
            ),
            Fix(
                "x11vnc",
                "x11vnc",
                "x11vnc -storepasswd\nx11vnc -rfbauth ~/.vnc/passwd -localhost",
                "bash",
            ),
        ),
        verify="Um cliente VNC deve pedir senha (ou recusar) ao conectar.",
        effort="baixo",
        fix_group="autenticacao",
        references=(
            "https://www.rfc-editor.org/rfc/rfc6143",
            "https://www.iana.org/assignments/rfb/rfb.xhtml",
        ),
        cwe="CWE-306",
        owasp="A07:2021",
        cis=("4.7", "12.6"),
        lgpd=True,
        tags=("vnc", "sem-senha"),
    ),
    KBEntry(
        id="net.ajp.exposto",
        title="Conector AJP do Tomcat acessível pela rede (risco Ghostcat)",
        category=Category.NETWORK,
        severity=Severity.HIGH,
        summary="A porta AJP (8009) do Tomcat respondeu ao CPing vindo de fora do servidor.",
        explanation=(
            "O AJP é o protocolo entre um proxy (Apache/IIS) e o Tomcat e confia muito em quem "
            "está do outro lado. Exposto, ele permitiu a falha Ghostcat (CVE-2020-1938): leitura "
            "de arquivos da aplicação e, em alguns cenários, execução de código. A CISA inclui "
            "essa falha no catálogo de vulnerabilidades exploradas ativamente (KEV) desde "
            "03/03/2022. As versões corrigidas (7.0.100, 8.5.51 e 9.0.31) também endureceram o "
            "conector: ele passou a escutar só em loopback e a exigir segredo por padrão."
        ),
        risk="Leitura de arquivos de configuração e código-fonte (com senhas) e possível execução remota de código.",
        steps=(
            "Remova o conector AJP do server.xml se nenhum proxy o usa.",
            "Se for usado, faça-o escutar em 127.0.0.1 e exija um segredo (secretRequired/secret).",
            "Atualize o Tomcat (7.0.100, 8.5.51, 9.0.31 ou posteriores corrigem a Ghostcat).",
            "Bloqueie a porta 8009 no firewall.",
        ),
        examples=(
            Fix(
                "tomcat",
                "Tomcat (server.xml)",
                '<Connector protocol="AJP/1.3" address="127.0.0.1" port="8009"\n'
                '           redirectPort="8443" secretRequired="true" secret="<segredo-longo>" />',
                "xml",
            ),
            Fix(
                "apache",
                "Apache (mod_proxy_ajp com segredo)",
                "ProxyPass / ajp://127.0.0.1:8009/ secret=<segredo-longo>",
                "apache",
            ),
        ),
        verify="De outro computador, a porta 8009 deve aparecer fechada.",
        effort="baixo",
        fix_group="servicos",
        references=(
            "https://tomcat.apache.org/tomcat-9.0-doc/config/ajp.html",
            "https://tomcat.apache.org/security-9.html",
            "https://tomcat.apache.org/connectors-doc/ajp/ajpv13a.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2020-1938",
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        ),
        cwe="CWE-284",
        owasp="A05:2021",
        cis=("4.8", "12.2"),
        tags=("tomcat", "ajp", "ghostcat"),
    ),
)
