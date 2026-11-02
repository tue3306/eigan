"""Base de conhecimento do Windows: proteções, compartilhamento, acesso remoto e credenciais.

Caminhos de registro, valores e padrões conferidos na documentação da Microsoft e nos
guias DISA STIG citados em ``references``. Caminhos de política de grupo ficam em inglês,
como na documentação oficial.
"""

from __future__ import annotations

from ...core import kb
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Severity

kb.register(
    KBEntry(
        id="host.win.firewall.desligado",
        title="Firewall do Windows desligado",
        category=Category.HOST,
        severity=Severity.HIGH,
        summary="Um ou mais perfis do Firewall do Windows estão desligados.",
        explanation=(
            "O firewall é o porteiro da máquina: decide quais conexões vindas da rede podem chegar "
            "aos programas. O Windows tem um perfil para cada tipo de rede (Domínio, Privado e "
            "Público), e cada um liga ou desliga separadamente. Com um perfil desligado, tudo o que "
            "estiver escutando na rede fica acessível enquanto a máquina estiver naquele tipo de rede."
        ),
        risk=(
            "Compartilhamento de arquivos, Área de Trabalho Remota, bancos de dados e outros serviços "
            "ficam ao alcance de qualquer máquina da mesma rede, inclusive em Wi-Fi público. É assim "
            "que ransomware e worms pulam de uma máquina infectada para as vizinhas."
        ),
        steps=(
            "Abra Segurança do Windows > Firewall e proteção de rede e ligue o firewall nos perfis "
            "indicados na evidência. Ou rode, como administrador, o comando do exemplo, que liga os "
            "três de uma vez.",
            "Se a evidência apontar uma chave HKLM\\SOFTWARE\\Policies\\..., o desligamento vem de uma "
            "política de grupo: corrija em Computer Configuration > Windows Settings > Security Settings "
            "> Windows Defender Firewall with Advanced Security, senão ele volta a desligar.",
            "Se um programa parar de funcionar, crie uma regra de entrada só para a porta dele, restrita "
            "aos endereços necessários, em vez de desligar o firewall.",
        ),
        verify=(
            "Rode 'Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, Enabled': os "
            "três perfis devem mostrar True. Depois rode a auditoria de novo."
        ),
        examples=(
            Fix(
                "windows",
                "PowerShell (administrador)",
                "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True\n\n"
                "# conferir o estado que está valendo\n"
                "Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name, Enabled",
                "powershell",
            ),
            Fix(
                "windows",
                "Liberar só uma porta, só para a rede interna",
                "New-NetFirewallRule -DisplayName 'App interna' -Direction Inbound -Protocol TCP "
                "-LocalPort 8443 -RemoteAddress 192.168.0.0/24 -Action Allow",
                "powershell",
            ),
        ),
        effort="baixo",
        fix_group="windows",
        references=(
            "https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/",
            "https://learn.microsoft.com/en-us/powershell/module/netsecurity/set-netfirewallprofile",
            "https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule",
        ),
        cwe="CWE-284",
        owasp="A05:2021",
        cis=("4.4", "4.5"),
        tags=("firewall",),
    ),
    KBEntry(
        id="host.win.antivirus.ausente",
        title="Nenhum antivírus ativo nesta máquina",
        category=Category.HOST,
        severity=Severity.HIGH,
        summary="O Microsoft Defender Antivirus está desligado e nenhum outro antivírus foi encontrado.",
        explanation=(
            "O Windows já traz um antivírus, o Microsoft Defender. No Windows 10 e 11 ele só desliga "
            "sozinho quando outro antivírus assume a proteção, e volta se esse outro expirar ou for "
            "removido. Aqui ele está desligado e a Central de Segurança do Windows não mostra outro "
            "produto. No Windows Server a Central de Segurança não existe: nesse caso o achado vem como "
            "indício, e vale conferir se há um antivírus de outro fabricante."
        ),
        risk=(
            "Sem antivírus, um anexo ou instalador malicioso roda sem nenhum obstáculo. Vírus, ladrões "
            "de senha e ransomware conhecidos há anos não são nem detectados."
        ),
        steps=(
            "Confirme se a empresa usa outro antivírus. Se usar, ele deveria aparecer em Segurança do "
            "Windows > Proteção contra vírus e ameaças; sem isso, reinstale-o ou corrija a licença.",
            "Se não usar, religue o Defender: abra Segurança do Windows > Proteção contra vírus e "
            "ameaças e ative as proteções.",
            "Se o Defender não ligar, procure a política 'Turn off Microsoft Defender Antivirus' em "
            "Computer Configuration > Administrative Templates > Windows Components > Microsoft "
            "Defender Antivirus e deixe em Not Configured.",
            "Se ninguém da equipe desligou o antivírus, trate como incidente: desligar a proteção é um "
            "dos primeiros passos de um invasor.",
        ),
        verify=(
            "Rode 'Get-MpComputerStatus | Select-Object AMRunningMode, AntivirusEnabled, "
            "RealTimeProtectionEnabled': o esperado é Normal, True e True (ou outro antivírus ativo). "
            "Depois rode a auditoria de novo."
        ),
        examples=(
            Fix(
                "windows",
                "PowerShell",
                "# situação atual\n"
                "Get-MpComputerStatus | Select-Object AMRunningMode, AMServiceEnabled, AntivirusEnabled, "
                "RealTimeProtectionEnabled\n\n"
                "# antivírus registrados na Central de Segurança (só Windows cliente)\n"
                "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | "
                "Select-Object displayName",
                "powershell",
            ),
        ),
        effort="baixo",
        fix_group="windows",
        references=(
            "https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-compatibility",
            "https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows",
            "https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus",
        ),
        cwe="CWE-693",
        owasp="A05:2021",
        cis=("10.1",),
        tags=("antivirus", "defender"),
    ),
    KBEntry(
        id="host.win.defender.tempo_real_desligado",
        title="Proteção em tempo real do Microsoft Defender desligada",
        category=Category.HOST,
        severity=Severity.HIGH,
        summary="O Defender está instalado, mas não examina os arquivos no momento em que são usados.",
        explanation=(
            "A proteção em tempo real examina cada arquivo aberto, baixado ou executado. Desligada, o "
            "Defender só encontra alguma coisa quando uma verificação manual ou agendada roda, e aí o "
            "programa malicioso já pode ter feito o estrago."
        ),
        risk=(
            "Um arquivo malicioso roda sem ser barrado. Desligar essa proteção também é uma técnica comum "
            "de invasores antes de instalar ferramentas de ataque."
        ),
        steps=(
            "Abra Segurança do Windows > Proteção contra vírus e ameaças > Gerenciar configurações e "
            "ligue a Proteção em tempo real.",
            "Se a opção estiver travada, procure a política 'Turn off real-time protection' em Computer "
            "Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus "
            "> Real-time Protection e deixe em Not Configured.",
            "Se ninguém da equipe desligou, verifique o histórico de proteção e trate como incidente.",
        ),
        verify="'(Get-MpComputerStatus).RealTimeProtectionEnabled' deve responder True.",
        examples=(
            Fix(
                "windows",
                "PowerShell (administrador)",
                "Set-MpPreference -DisableRealtimeMonitoring $false\n"
                "(Get-MpComputerStatus).RealTimeProtectionEnabled",
                "powershell",
            ),
        ),
        effort="baixo",
        fix_group="windows",
        references=(
            "https://learn.microsoft.com/en-us/defender-endpoint/configure-real-time-protection-microsoft-defender-antivirus",
            "https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus",
        ),
        cwe="CWE-693",
        owasp="A05:2021",
        cis=("10.1",),
        tags=("antivirus", "defender"),
    ),
    KBEntry(
        id="host.win.defender.assinaturas_antigas",
        title="Assinaturas do Microsoft Defender desatualizadas",
        category=Category.HOST,
        severity=Severity.MEDIUM,
        summary="As definições de vírus do Defender têm mais de 7 dias.",
        explanation=(
            "O antivírus reconhece ameaças pelas definições (assinaturas), publicadas várias vezes por "
            "semana. O próprio Defender considera desatualizadas, por padrão, as definições com mais de 7 "
            "dias. Atraso assim costuma indicar máquina sem acesso às atualizações ou serviço parado."
        ),
        risk="Ameaças novas passam sem ser reconhecidas, justamente as mais usadas em ataques em andamento.",
        steps=(
            "Abra Segurança do Windows > Proteção contra vírus e ameaças > Atualizações de proteção e "
            "clique em Verificar se há atualizações, ou rode o comando do exemplo.",
            "Se a atualização falhar, confira a conexão com a Internet (ou o WSUS da empresa) e se o "
            "serviço Windows Update não está desativado.",
        ),
        verify="'(Get-MpComputerStatus).AntivirusSignatureAge' deve voltar a 0 ou 1 dia.",
        examples=(
            Fix(
                "windows",
                "PowerShell (administrador)",
                "Update-MpSignature\n"
                "Get-MpComputerStatus | Select-Object AntivirusSignatureAge, AntivirusSignatureLastUpdated",
                "powershell",
            ),
        ),
        effort="baixo",
        fix_group="windows",
        references=(
            "https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-updates",
            "https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-microsoftdefenderantivirus",
        ),
        cwe="CWE-693",
        owasp="A05:2021",
        cis=("10.1",),
        tags=("antivirus", "defender", "atualizacao"),
    ),
    KBEntry(
        id="host.win.smb.v1_ligado",
        title="Compartilhamento de arquivos aceita SMBv1",
        category=Category.HOST,
        severity=Severity.HIGH,
        summary="O servidor de arquivos do Windows ainda aceita a versão 1 do protocolo SMB, de 1990.",
        explanation=(
            "SMB é o protocolo do compartilhamento de arquivos do Windows. A versão 1 não tem as proteções "
            "das versões novas e a Microsoft recomenda não usá-la: ela nem vem instalada no Windows 11 nem "
            "no Windows Server 2019 ou mais novo. Se está ligada aqui, foi herdada de uma instalação "
            "antiga ou alguém a ativou."
        ),
        risk=(
            "O SMBv1 foi a porta de entrada do ransomware WannaCry, pela falha do boletim MS17-010, que "
            "permite executar código sem senha. Mesmo com a correção instalada, o protocolo não tem "
            "assinatura forte nem criptografia, e facilita interceptar e alterar o tráfego."
        ),
        steps=(
            "Antes de desligar, descubra quem ainda usa: ligue a auditoria com "
            "'Set-SmbServerConfiguration -AuditSmb1Access $true' e acompanhe o evento 3000 no log "
            "Microsoft-Windows-SMBServer/Audit por alguns dias.",
            "Atualize ou substitua o que depender de SMBv1 (impressoras e scanners antigos, sistemas sem "
            "suporte).",
            "Desligue o protocolo no servidor e remova o recurso opcional com os comandos do exemplo.",
        ),
        verify="'Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol' deve responder False.",
        examples=(
            Fix(
                "windows",
                "PowerShell (administrador)",
                "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force\n"
                "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart\n\n"
                "# conferir\n"
                "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol",
                "powershell",
            ),
            Fix(
                "windows",
                "Registro (sistemas antigos, sem o cmdlet)",
                'Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" '
                "-Name SMB1 -Type DWORD -Value 0 -Force",
                "powershell",
            ),
        ),
        effort="medio",
        fix_group="windows",
        references=(
            "https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3",
            "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010",
        ),
        cwe="CWE-477",
        owasp="A06:2021",
        cis=("4.8", "12.6"),
        tags=("smb", "protocolo-legado"),
    ),
    KBEntry(
        id="host.win.smb.assinatura_nao_exigida",
        title="Assinatura SMB não é exigida",
        category=Category.HOST,
        severity=Severity.MEDIUM,
        summary="O compartilhamento de arquivos aceita conexões sem assinatura digital das mensagens.",
        explanation=(
            "A assinatura SMB garante que cada mensagem veio de quem diz ter vindo e não foi alterada. Só o "
            "valor RequireSecuritySignature conta nas versões atuais do protocolo: EnableSecuritySignature "
            "é ignorado a partir do SMB2. A assinatura deixa de ser usada quando nenhum dos dois lados da "
            "conexão a exige. O Windows 11 24H2 e o Windows Server 2025 passaram a exigi-la por padrão, mas "
            "versões anteriores, instalações atualizadas e algumas edições continuam sem exigir."
        ),
        risk=(
            "Quem está na mesma rede pode retransmitir a autenticação de um usuário para esta máquina "
            "(ataque de relay NTLM) e entrar como ele, sem conhecer a senha, ou alterar arquivos em trânsito."
        ),
        steps=(
            "Teste antes: dispositivos antigos e servidores de arquivos de terceiros (NAS) podem não suportar "
            "assinatura e perder o acesso.",
            "Exija a assinatura com os comandos do exemplo, ou pela política em Computer Configuration > "
            "Windows Settings > Security Settings > Local Policies > Security Options: 'Microsoft network "
            "server: Digitally sign communications (always)' e 'Microsoft network client: Digitally sign "
            "communications (always)'.",
        ),
        verify=(
            "'Get-SmbServerConfiguration | Select-Object RequireSecuritySignature' e o mesmo com "
            "Get-SmbClientConfiguration devem responder True."
        ),
        examples=(
            Fix(
                "windows",
                "PowerShell (administrador)",
                "Set-SmbServerConfiguration -RequireSecuritySignature $true -Force\n"
                "Set-SmbClientConfiguration -RequireSecuritySignature $true -Force",
                "powershell",
            ),
        ),
        effort="medio",
        fix_group="windows",
        references=(
            "https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview",
            "https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing",
        ),
        cwe="CWE-345",
        owasp="A05:2021",
        cis=("12.6",),
        tags=("smb", "relay"),
    ),
    KBEntry(
        id="host.win.rdp.sem_nla",
        title="Área de Trabalho Remota sem autenticação em nível de rede (NLA)",
        category=Category.HOST,
        severity=Severity.HIGH,
        summary="O acesso remoto está ligado e mostra a tela de entrada do Windows antes de pedir a senha.",
        explanation=(
            "Com NLA, quem se conecta precisa provar quem é antes de o servidor abrir uma sessão. Sem NLA, "
            "qualquer um que alcance a porta 3389 recebe uma sessão e a tela de entrada do Windows, sem "
            "nenhuma credencial."
        ),
        risk=(
            "Falhas do serviço de Área de Trabalho Remota ficam ao alcance de quem não tem conta. A tela de "
            "entrada exposta facilita tentativas de senha e consome recursos da máquina a cada conexão."
        ),
        steps=(
            "Abra Configurações > Sistema > Área de Trabalho Remota e ligue a exigência de autenticação em "
            "nível de rede, ou rode o comando do exemplo como administrador.",
            "Se a evidência apontar HKLM\\SOFTWARE\\Policies\\..., corrija pela política 'Require user "
            "authentication for remote connections by using Network Level Authentication', em Computer "
            "Configuration > Administrative Templates > Windows Components > Remote Desktop Services > "
            "Remote Desktop Session Host > Security.",
            "Se o acesso remoto não é usado, desligue-o. Se é usado, não deixe a porta 3389 aberta para a "
            "Internet: exija VPN.",
        ),
        verify=(
            "Conecte-se a partir de outra máquina: a senha deve ser pedida antes de aparecer a tela remota. "
            "Depois rode a auditoria de novo."
        ),
        examples=(
            Fix(
                "windows",
                "PowerShell (administrador)",
                "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' "
                "-Name UserAuthentication -Value 1",
                "powershell",
            ),
            Fix(
                "windows",
                "Desligar o acesso remoto, se não for usado",
                "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' "
                "-Name fDenyTSConnections -Value 1",
                "powershell",
            ),
        ),
        effort="baixo",
        fix_group="windows",
        references=(
            "https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-terminalserver",
            "https://learn.microsoft.com/en-us/troubleshoot/azure/virtual-machines/windows/cannot-connect-rdp-azure-vm",
            "https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remotepc/remote-desktop-allow-access",
        ),
        cwe="CWE-306",
        owasp="A07:2021",
        cis=("4.6", "12.6"),
        tags=("rdp", "acesso-remoto"),
    ),
    KBEntry(
        id="host.win.uac.desligado",
        title="Controle de Conta de Usuário (UAC) desligado",
        category=Category.HOST,
        severity=Severity.HIGH,
        summary="Programas abertos por administradores rodam com todos os privilégios, sem pedir nada.",
        explanation=(
            "O UAC faz até um administrador trabalhar com privilégios comuns, e só eleva um programa depois "
            "de uma confirmação. Com EnableLUA em 0 esse mecanismo inteiro deixa de existir: tudo o que um "
            "administrador abre já roda com poder total."
        ),
        risk=(
            "Um anexo ou página maliciosa aberta por um administrador ganha controle total da máquina de "
            "imediato: instala programas, desliga o antivírus e rouba credenciais sem nenhum aviso."
        ),
        steps=(
            "Rode o comando do exemplo como administrador e reinicie a máquina: a mudança só vale depois disso.",
            "Se a política de grupo controla o valor, corrija 'User Account Control: Run all administrators "
            "in Admin Approval Mode' em Computer Configuration > Windows Settings > Security Settings > "
            "Local Policies > Security Options.",
            "Se um programa antigo só funciona sem UAC, atualize-o ou isole-o em vez de deixar a proteção "
            "desligada para a máquina inteira.",
        ),
        verify=(
            "Depois de reiniciar, abrir um programa como administrador deve mostrar a tela de confirmação. "
            "EnableLUA deve valer 1."
        ),
        examples=(
            Fix(
                "windows",
                "PowerShell (administrador)",
                "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
                "-Name EnableLUA -Value 1\n"
                "Restart-Computer",
                "powershell",
            ),
        ),
        effort="baixo",
        fix_group="windows",
        references=(
            "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration",
        ),
        cwe="CWE-250",
        owasp="A05:2021",
        cis=("5.4",),
        tags=("uac", "privilegio"),
    ),
    KBEntry(
        id="host.win.uac.eleva_sem_perguntar",
        title="UAC eleva privilégios de administradores sem perguntar",
        category=Category.HOST,
        severity=Severity.MEDIUM,
        summary="Programas ganham privilégios de administrador sem nenhuma confirmação na tela.",
        explanation=(
            "O valor ConsentPromptBehaviorAdmin define o que o Windows faz quando um administrador precisa "
            "de privilégios elevados. O padrão é 5 (pedir confirmação para programas fora do Windows) e o "
            "mais restrito é 2 (pedir sempre, em área de trabalho segura). Com 0, a elevação acontece "
            "calada, e o usuário nem fica sabendo."
        ),
        risk=(
            "Um programa malicioso aberto por um administrador sobe para privilégio total sem o aviso que "
            "daria a chance de recusar."
        ),
        steps=(
            "Volte o valor para 5 (padrão) ou 2 (mais restrito) com o comando do exemplo.",
            "Se a política de grupo controla o valor, corrija 'User Account Control: Behavior of the elevation "
            "prompt for administrators in Admin Approval Mode' em Computer Configuration > Windows Settings "
            "> Security Settings > Local Policies > Security Options.",
        ),
        verify="Abrir um programa como administrador deve mostrar a tela de confirmação do UAC.",
        examples=(
            Fix(
                "windows",
                "PowerShell (administrador)",
                "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
                "-Name ConsentPromptBehaviorAdmin -Value 5",
                "powershell",
            ),
        ),
        effort="baixo",
        fix_group="windows",
        references=(
            "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration",
        ),
        cwe="CWE-250",
        owasp="A05:2021",
        cis=("5.4",),
        tags=("uac", "privilegio"),
    ),
    KBEntry(
        id="host.win.wdigest.senha_em_memoria",
        title="WDigest guarda senhas em texto puro na memória",
        category=Category.HOST,
        severity=Severity.HIGH,
        summary="O Windows está configurado para manter as senhas de quem entrou legíveis na memória.",
        explanation=(
            "WDigest é um método de autenticação antigo que precisa da senha em texto puro. Desde o Windows "
            "8.1 e o Server 2012 R2 o sistema não guarda mais essa senha, a menos que UseLogonCredential "
            "esteja em 1, como aqui. Esse valor raramente é necessário hoje e costuma ser ligado por "
            "invasores para colher senhas."
        ),
        risk=(
            "Quem obtém privilégio de administrador lê a memória do processo LSASS e recupera a senha de "
            "todos que entraram na máquina, com ferramentas prontas. Com essas senhas, o ataque se espalha "
            "por outras máquinas e serviços."
        ),
        steps=(
            "Se ninguém da equipe ligou esse valor de propósito, trate como possível invasão: verifique os "
            "administradores locais e os programas agendados.",
            "Mude o valor para 0 com o comando do exemplo.",
            "Reinicie a máquina ou peça para os usuários saírem e entrarem de novo: as senhas já na memória "
            "só somem assim.",
            "Troque as senhas das contas que usaram a máquina enquanto o valor estava ligado.",
        ),
        verify="UseLogonCredential deve valer 0 (ou não existir) e este achado some na próxima auditoria.",
        examples=(
            Fix(
                "windows",
                "Prompt ou PowerShell (administrador)",
                "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest "
                "/v UseLogonCredential /t REG_DWORD /d 0 /f",
                "powershell",
            ),
        ),
        effort="baixo",
        fix_group="windows",
        references=(
            "https://learn.microsoft.com/en-us/archive/blogs/kfalde/kb2871997-and-wdigest-part-1",
            "https://attack.mitre.org/techniques/T1003/001/",
        ),
        cwe="CWE-522",
        owasp="A07:2021",
        cis=("4.1",),
        tags=("credenciais", "lsass"),
    ),
    KBEntry(
        id="host.win.lsa.sem_protecao",
        title="Proteção adicional da LSA desligada",
        category=Category.HOST,
        severity=Severity.MEDIUM,
        summary="O processo que guarda as credenciais (LSASS) não roda como processo protegido.",
        explanation=(
            "O LSASS é o processo do Windows que valida logins e mantém credenciais em memória. Com a proteção "
            "adicional (RunAsPPL), programas comuns, mesmo de administrador, não conseguem ler a memória "
            "dele nem injetar código. O valor 1 grava a escolha no firmware (bloqueio UEFI); o valor 2 não "
            "grava e só vale a partir do Windows 11 22H2. Quando o valor não existe e não há registro de "
            "início protegido, o achado vem como indício, pois o Windows pode ter ligado a proteção sozinho."
        ),
        risk=(
            "Um invasor com privilégio de administrador lê a memória do LSASS e extrai hashes e tíquetes de "
            "quem entrou na máquina, para usar em outras máquinas da rede."
        ),
        steps=(
            "Liste plug-ins e drivers carregados no LSASS (cartão inteligente, filtros de senha, "
            "criptografia). Eles precisam ser assinados pela Microsoft, ou deixam de carregar.",
            "Teste primeiro em modo de auditoria (AuditLevel=8 em Image File Execution Options\\LSASS.exe) e "
            "acompanhe os eventos 3065 e 3066 em Microsoft > Windows > CodeIntegrity > Operational.",
            "Ligue a proteção com o comando do exemplo, ou pela política 'Configures LSASS to run as a "
            "protected process' em Computer Configuration > Administrative Templates > System > Local "
            "Security Authority, e reinicie.",
            "Atenção: o valor 1 grava um bloqueio no firmware (UEFI) que apagar o valor do registro não "
            "desfaz; para reverter é preciso a ferramenta de remoção da Microsoft. Em Windows 11 22H2 ou "
            "mais novo, prefira começar com o valor 2 (sem bloqueio).",
        ),
        verify=(
            "Depois de reiniciar, procure no log System o evento 12 da fonte WinInit: 'LSASS.exe was started "
            "as a protected process with level: 4'."
        ),
        examples=(
            Fix(
                "windows",
                "Prompt ou PowerShell (administrador)",
                "# 2 = sem bloqueio UEFI, reversível (só Windows 11 22H2 ou mais novo)\n"
                "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL /t REG_DWORD /d 2 /f\n"
                "# 1 = com bloqueio UEFI, NÃO reversível pelo registro (só por decisão deliberada)",
                "powershell",
            ),
            Fix(
                "windows",
                "Conferir no log depois de reiniciar",
                "Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Wininit'; Id=12} "
                "-MaxEvents 1 | Select-Object TimeCreated, Message",
                "powershell",
            ),
        ),
        effort="medio",
        fix_group="windows",
        references=(
            "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection",
            "https://attack.mitre.org/techniques/T1003/001/",
        ),
        cwe="CWE-522",
        owasp="A07:2021",
        cis=("4.1", "10.5"),
        tags=("credenciais", "lsass"),
    ),
    KBEntry(
        id="host.win.ntlm.nivel_fraco",
        title="Windows aceita enviar autenticação LM ou NTLMv1",
        category=Category.HOST,
        severity=Severity.HIGH,
        summary="O nível de autenticação LAN Manager permite os protocolos antigos e quebráveis LM ou NTLMv1.",
        explanation=(
            "LmCompatibilityLevel define quais respostas de autenticação o Windows usa na rede. Abaixo de 3 ele "
            "ainda envia LM ou NTLMv1, protocolos antigos cujas respostas são fáceis de quebrar. A Microsoft "
            "recomenda usar somente NTLMv2 (nível 3); os níveis 4 e 5 também recusam os protocolos antigos "
            "nos controladores de domínio."
        ),
        risk=(
            "Quem captura o tráfego ou engana a máquina para se autenticar com ele quebra a resposta em pouco "
            "tempo e descobre a senha ou o hash, servindo para entrar em outras máquinas da rede."
        ),
        steps=(
            "Confira se algum sistema muito antigo ainda depende de LM ou NTLMv1: máquinas sem NTLMv2 perdem "
            "o acesso.",
            "Defina o nível 5 com o comando do exemplo; se algo parar de funcionar, use o mínimo de 3 enquanto "
            "corrige.",
            "Em domínio, aplique pela política 'Network security: LAN Manager authentication level' em "
            "Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options.",
        ),
        verify="LmCompatibilityLevel deve valer 3 ou mais. A mudança vale sem reiniciar.",
        examples=(
            Fix(
                "windows",
                "Prompt ou PowerShell (administrador)",
                "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v LmCompatibilityLevel /t REG_DWORD /d 5 /f",
                "powershell",
            ),
        ),
        effort="medio",
        fix_group="windows",
        references=(
            "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level",
        ),
        cwe="CWE-757",
        owasp="A07:2021",
        cis=("4.1", "12.6"),
        tags=("ntlm", "credenciais", "protocolo-legado"),
    ),
    KBEntry(
        id="host.win.llmnr.ligado",
        title="Resolução de nomes LLMNR não foi desativada",
        category=Category.HOST,
        severity=Severity.MEDIUM,
        summary="A máquina pergunta à rede local por nomes que o DNS não resolve, e acredita em quem responder.",
        explanation=(
            "Quando o DNS não acha um nome, o Windows pergunta a toda a rede local pelo protocolo LLMNR, sem "
            "nenhuma forma de conferir quem responde. O recurso vem ligado por padrão e só é desligado pela "
            "política 'Turn off multicast name resolution'."
        ),
        risk=(
            "Um invasor na mesma rede responde 'sou eu' a essas perguntas, recebe a tentativa de login da "
            "vítima e captura o hash da senha para quebrar ou retransmitir. Essa é uma das técnicas mais "
            "usadas para ganhar a primeira credencial dentro de uma rede corporativa."
        ),
        steps=(
            "Confirme que os nomes da rede interna resolvem no DNS: nenhum sistema atual deveria depender de "
            "LLMNR.",
            "Em domínio, ligue a política 'Turn off multicast name resolution' em Computer Configuration > "
            "Administrative Templates > Network > DNS Client. Numa máquina avulsa, use o comando do exemplo.",
        ),
        verify="EnableMulticast deve valer 0 e a porta UDP 5355 deixa de responder depois de reiniciar o cliente DNS.",
        examples=(
            Fix(
                "windows",
                "Prompt ou PowerShell (administrador)",
                'reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient" '
                "/v EnableMulticast /t REG_DWORD /d 0 /f",
                "powershell",
            ),
        ),
        effort="baixo",
        fix_group="windows",
        references=(
            "https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-dnsclient",
            "https://attack.mitre.org/techniques/T1557/001/",
        ),
        cwe="CWE-290",
        owasp="A05:2021",
        cis=("4.8", "12.6"),
        tags=("llmnr", "credenciais", "protocolo-legado"),
    ),
    KBEntry(
        id="host.win.netbios.ligado",
        title="NetBIOS sobre TCP/IP ligado em placa de rede",
        category=Category.HOST,
        severity=Severity.LOW,
        summary="A máquina ainda fala NetBIOS, um protocolo antigo de nomes sem nenhuma autenticação.",
        explanation=(
            "NetBIOS é um sistema de nomes anterior ao DNS, usado por redes Windows muito antigas. Em cada placa "
            "de rede, TcpipNetbiosOptions diz o que fazer: 0 segue o servidor DHCP (e liga se ele não disser "
            "nada), 1 liga e 2 desliga. Como no LLMNR, a máquina acredita em quem responder."
        ),
        risk=(
            "Um invasor na mesma rede responde às consultas de nome no lugar da máquina certa e captura o hash "
            "da senha de quem tenta se conectar. As portas 137 a 139 ainda revelam o nome da máquina e do "
            "grupo de trabalho."
        ),
        steps=(
            "Confira se há sistemas muito antigos que só encontram esta máquina pelo nome NetBIOS.",
            "Desligue em cada placa: Propriedades da placa > Protocolo IP Versão 4 > Avançado > WINS > "
            "'Desabilitar NetBIOS sobre TCP/IP', ou rode o comando do exemplo como administrador.",
            "Em redes com DHCP, a opção também pode ser enviada pelo servidor DHCP para todas as máquinas.",
        ),
        verify="A porta TCP 139 deixa de escutar ('netstat -ano') e TcpipNetbiosOptions passa a valer 2.",
        examples=(
            Fix(
                "windows",
                "PowerShell (administrador)",
                "Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | "
                "Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=[uint32]2}",
                "powershell",
            ),
        ),
        effort="baixo",
        fix_group="windows",
        references=(
            "https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/settcpipnetbios-method-in-class-win32-networkadapterconfiguration",
            "https://attack.mitre.org/techniques/T1557/001/",
        ),
        cwe="CWE-290",
        owasp="A05:2021",
        cis=("4.8", "12.6"),
        tags=("netbios", "credenciais", "protocolo-legado"),
    ),
)
