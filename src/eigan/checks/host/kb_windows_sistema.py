"""Base de conhecimento do Windows: mídia removível, contas, atualizações, disco e serviços.

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
        id="host.win.autorun.ligado",
        title="AutoRun e AutoPlay não foram desativados",
        category=Category.HOST,
        severity=Severity.LOW,
        summary="O Windows ainda pode oferecer ou iniciar programas de mídias conectadas à máquina.",
        explanation=(
            "AutoPlay começa a ler uma mídia assim que ela é conectada, e AutoRun executa os comandos do "
            "arquivo autorun.inf que estiver nela. Desde o Windows Vista o padrão é perguntar ao usuário em "
            "vez de executar sozinho, o que reduz o risco, mas não o elimina: basta um clique na janela "
            "oferecida. O guia DISA STIG exige desligar os dois."
        ),
        risk=(
            "Um pen-drive ou disco com conteúdo malicioso, largado de propósito ou vindo de outra máquina "
            "infectada, fica a um clique de rodar. É um caminho clássico de vírus em redes isoladas."
        ),
        steps=(
            "Em domínio, em Computer Configuration > Administrative Templates > Windows Components > AutoPlay "
            "Policies, defina 'Turn off AutoPlay' como Enabled: All Drives e 'Set the default behavior for "
            "AutoRun' como Enabled: Do not execute any autorun commands.",
            "Numa máquina avulsa, rode os comandos do exemplo como administrador.",
        ),
        verify="NoDriveTypeAutoRun deve valer 255 (0xFF) e NoAutorun deve valer 1.",
        examples=(
            Fix(
                "windows",
                "Prompt ou PowerShell (administrador)",
                "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer "
                "/v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f\n"
                "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer "
                "/v NoAutorun /t REG_DWORD /d 1 /f",
                "powershell",
            ),
        ),
        effort="baixo",
        fix_group="windows",
        references=(
            "https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-autoplay",
            "https://stigaview.com/products/win11/v2r8/WN11-CC-000185",
            "https://stigaview.com/products/win11/v2r8/WN11-CC-000190",
        ),
        cwe="CWE-829",
        owasp="A05:2021",
        cis=("4.1",),
        tags=("autorun", "midia-removivel"),
    ),
    KBEntry(
        id="host.win.conta.convidado_ativa",
        title="Conta de convidado do Windows ativa",
        category=Category.HOST,
        severity=Severity.MEDIUM,
        summary="A conta interna de convidado (SID terminado em -501) está habilitada.",
        explanation=(
            "A conta de convidado existe em todo Windows para dar acesso a quem não tem conta própria, e vem "
            "desativada de fábrica. Ativa, ela costuma não ter senha e não identifica quem usou a máquina. O "
            "nome muda com o idioma (Guest, Convidado), por isso o EIGAN a reconhece pelo SID."
        ),
        risk=(
            "Qualquer pessoa, ou um programa vindo da rede, consegue entrar sem credencial própria, ler o que "
            "estiver aberto a todos e usar a máquina sem deixar rastro de quem foi."
        ),
        steps=(
            "Desative a conta com o comando do exemplo.",
            "Em domínio, defina 'Accounts: Guest account status' como Disabled em Computer Configuration > "
            "Windows Settings > Security Settings > Local Policies > Security Options.",
            "Quem precisa de acesso eventual deve ganhar uma conta própria, com senha e privilégios mínimos.",
        ),
        verify="'Get-LocalUser | Where-Object { $_.SID.Value -like \"*-501\" }' deve mostrar Enabled = False.",
        examples=(
            Fix(
                "windows",
                "PowerShell (administrador)",
                "Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | Disable-LocalUser",
                "powershell",
            ),
        ),
        effort="baixo",
        fix_group="windows",
        references=(
            "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/accounts-guest-account-status",
            "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.localaccounts/disable-localuser",
        ),
        cwe="CWE-284",
        owasp="A07:2021",
        cis=("4.7",),
        tags=("contas",),
    ),
    KBEntry(
        id="host.win.senha.comprimento_curto",
        title="Política de senhas aceita senhas curtas",
        category=Category.HOST,
        severity=Severity.MEDIUM,
        summary="O comprimento mínimo de senha das contas locais é menor que 8 caracteres.",
        explanation=(
            "Esta política define o menor tamanho de senha aceito nas contas locais da máquina. A Microsoft "
            "recomenda no mínimo 8 caracteres, e o valor 0 significa que a conta pode ficar sem senha. Contas "
            "Microsoft e de domínio seguem a política de quem as administra."
        ),
        risk=(
            "Senhas curtas caem em poucos minutos em ataques de dicionário ou tentativa e erro, e uma conta "
            "sem senha nem precisa ser adivinhada."
        ),
        steps=(
            "Defina o comprimento mínimo com o comando do exemplo: pelo menos 8; a linha de base de segurança "
            "da Microsoft usa valores maiores, e frases longas são mais fáceis de lembrar.",
            "Em domínio, ajuste em Computer Configuration > Windows Settings > Security Settings > Account "
            "Policies > Password Policy > Minimum password length.",
            "Peça a troca das senhas que estiverem abaixo do novo mínimo: a regra só vale na próxima troca.",
        ),
        verify="'net accounts' deve mostrar o novo valor na linha do comprimento mínimo de senha.",
        examples=(
            Fix(
                "windows",
                "Prompt ou PowerShell (administrador)",
                "net accounts /minpwlen:12",
                "powershell",
            ),
        ),
        effort="baixo",
        fix_group="windows",
        references=(
            "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/minimum-password-length",
            "https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines",
        ),
        cwe="CWE-521",
        owasp="A07:2021",
        cis=("5.2",),
        tags=("contas", "senha"),
    ),
    KBEntry(
        id="host.win.senha.sem_bloqueio",
        title="Contas nunca são bloqueadas por tentativas de senha erradas",
        category=Category.HOST,
        severity=Severity.MEDIUM,
        summary="Não há limite de tentativas de login: dá para testar senhas sem parar.",
        explanation=(
            "O limite de bloqueio define depois de quantas senhas erradas a conta fica travada por um tempo. "
            "Com 0, ela nunca trava. A linha de base de segurança da Microsoft recomenda 10 tentativas: o "
            "suficiente para os erros normais e pouco para um ataque. A própria Microsoft só aceita o 0 com "
            "senhas complexas de 8 ou mais caracteres e um alerta de tentativas falhas em funcionamento."
        ),
        risk=(
            "Um invasor com acesso à máquina ou à rede testa milhares de senhas por compartilhamento de arquivos "
            "ou Área de Trabalho Remota, sem que a conta trave."
        ),
        steps=(
            "Defina o limite com o comando do exemplo. A conta Administrador interna fica fora do bloqueio: "
            "proteja-a com uma senha forte.",
            "Em domínio, ajuste em Computer Configuration > Windows Settings > Security Settings > Account "
            "Policies > Account Lockout Policy.",
            "Combine com um processo para destravar contas: um limite baixo demais permite que alguém trave "
            "contas de propósito.",
        ),
        verify="'net accounts' deve mostrar o novo limite na linha do limite de bloqueio.",
        examples=(
            Fix(
                "windows",
                "Prompt ou PowerShell (administrador)",
                "net accounts /lockoutthreshold:10 /lockoutduration:10 /lockoutwindow:10",
                "powershell",
            ),
        ),
        effort="baixo",
        fix_group="windows",
        references=(
            "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/account-lockout-threshold",
        ),
        cwe="CWE-307",
        owasp="A07:2021",
        cis=("4.1",),
        tags=("contas", "senha"),
    ),
    KBEntry(
        id="host.win.powershell2.presente",
        title="Mecanismo do PowerShell 2.0 presente",
        category=Category.HOST,
        severity=Severity.LOW,
        summary="A versão antiga do PowerShell ainda pode ser usada, escapando do registro de scripts.",
        explanation=(
            "O PowerShell 2.0 é anterior aos recursos que permitem à equipe de segurança enxergar o que um "
            "script faz, como o registro de blocos de script e a varredura antimalware (AMSI), trazidos pelo "
            "PowerShell 5. Por isso a Microsoft o retirou do Windows 11 24H2 e do Windows Server 2025. Em "
            "versões anteriores ele continua disponível como recurso opcional."
        ),
        risk=(
            "Depois de entrar na máquina, um invasor pede a versão antiga ('powershell -Version 2') e roda seus "
            "scripts sem deixar os mesmos rastros e sem passar pelo antivírus. Sozinho, isso não abre a porta: "
            "dificulta descobrir e barrar quem já entrou."
        ),
        steps=(
            "Confira se algum script antigo pede a versão 2 de propósito e migre-o para o PowerShell 5.1 ou 7.",
            "Remova o recurso com o comando do exemplo.",
        ),
        verify=(
            "'Get-CimInstance -ClassName Win32_OptionalFeature -Filter \"Name LIKE 'MicrosoftWindowsPowerShellV2%'\"' "
            "deve mostrar InstallState diferente de 1, ou nada."
        ),
        examples=(
            Fix(
                "windows",
                "PowerShell (administrador)",
                "Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart",
                "powershell",
            ),
        ),
        effort="baixo",
        fix_group="windows",
        references=(
            "https://support.microsoft.com/help/5065506",
            "https://devblogs.microsoft.com/powershell/powershell-the-blue-team/",
        ),
        cwe="CWE-477",
        owasp="A09:2021",
        cis=("4.8",),
        tags=("powershell", "protocolo-legado"),
    ),
    KBEntry(
        id="host.win.atualizacoes.antigas",
        title="Windows sem atualizações recentes",
        category=Category.HOST,
        severity=Severity.MEDIUM,
        summary="A atualização mais nova instalada nesta máquina tem mais de 60 dias.",
        explanation=(
            "A Microsoft publica correções de segurança todo mês, na segunda terça-feira. Mais de 60 dias sem "
            "instalar nada significa ter perdido ao menos um ciclo inteiro. A data vem da lista de atualizações "
            "instaladas do próprio Windows (Get-HotFix)."
        ),
        risk=(
            "As falhas corrigidas nos últimos meses continuam abertas aqui, e já são públicas. Atacantes "
            "automatizam a exploração poucos dias depois da publicação de cada correção."
        ),
        steps=(
            "Abra Configurações > Windows Update, clique em Verificar se há atualizações, instale tudo e reinicie.",
            "Se a atualização falhar, confira espaço em disco, conexão e, em empresas, se o WSUS ou o Intune "
            "estão aprovando as atualizações para esta máquina.",
            "Deixe as atualizações automáticas ligadas e defina um horário de reinício para não adiar de novo.",
        ),
        verify="'Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 3' deve mostrar datas recentes.",
        examples=(
            Fix(
                "windows",
                "PowerShell",
                "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5 HotFixID, InstalledOn",
                "powershell",
            ),
        ),
        effort="medio",
        fix_group="sistema",
        references=(
            "https://support.microsoft.com/en-us/windows/install-windows-updates-3c5ae7fc-9fb6-9af1-1984-b5e0412c556a",
            "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-hotfix",
            "https://learn.microsoft.com/en-us/windows/deployment/update/waas-overview",
        ),
        cwe="CWE-1104",
        owasp="A06:2021",
        cis=("7.3",),
        tags=("atualizacao",),
    ),
    KBEntry(
        id="host.win.atualizacoes.servico_desligado",
        title="Serviço Windows Update desativado",
        category=Category.HOST,
        severity=Severity.HIGH,
        summary="O serviço wuauserv está desativado: a máquina não consegue instalar atualizações.",
        explanation=(
            "O serviço Windows Update (wuauserv) é quem baixa e instala as correções do sistema, inclusive em "
            "empresas que usam WSUS ou Intune. Desativado (Start = 4), nenhuma correção chega, mesmo que o "
            "usuário clique em atualizar. O padrão é início manual: ele liga sozinho quando precisa."
        ),
        risk=(
            "Toda falha descoberta a partir de agora fica aberta nesta máquina. Desativar esse serviço também é "
            "um truque usado por programas maliciosos para impedir a própria remoção."
        ),
        steps=(
            "Religue o serviço com o comando do exemplo e instale as atualizações pendentes.",
            "Se ele voltar a ser desativado, procure a causa: política de grupo, programa de 'otimização' ou "
            "malware.",
        ),
        verify="'Get-Service wuauserv | Select-Object Status, StartType' deve mostrar StartType diferente de Disabled.",
        examples=(
            Fix(
                "windows",
                "PowerShell (administrador)",
                "Set-Service -Name wuauserv -StartupType Manual\nStart-Service -Name wuauserv",
                "powershell",
            ),
        ),
        effort="baixo",
        fix_group="sistema",
        references=(
            "https://learn.microsoft.com/en-us/windows/deployment/update/how-windows-update-works",
            "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-service",
        ),
        cwe="CWE-1104",
        owasp="A06:2021",
        cis=("7.3",),
        tags=("atualizacao",),
    ),
    KBEntry(
        id="host.win.bitlocker.desligado",
        title="BitLocker desligado no disco do sistema",
        category=Category.HOST,
        severity=Severity.MEDIUM,
        summary="O disco onde o Windows está instalado não está protegido por criptografia.",
        explanation=(
            "O BitLocker criptografa o disco inteiro: sem a chave, os dados são ilegíveis. A proteção conta como "
            "desligada quando o disco não está totalmente criptografado ou quando a chave fica disponível em "
            "claro, como durante uma suspensão. O BitLocker existe nas edições Pro, Enterprise e Education; o "
            "Windows Home oferece a Criptografia do dispositivo, se o hardware suportar."
        ),
        risk=(
            "Se a máquina for perdida ou roubada, ou o disco for retirado, qualquer um lê arquivos, senhas salvas "
            "e dados pessoais de clientes e colaboradores, o que pode configurar incidente de segurança sob a "
            "LGPD."
        ),
        steps=(
            "Guarde a chave de recuperação fora desta máquina (conta da empresa, cofre de senhas ou impressa em "
            "local seguro) antes de ligar qualquer coisa: sem ela, os dados podem ser perdidos.",
            "Ligue pelo Painel de Controle > Criptografia de Unidade de Disco BitLocker, ou com os comandos do "
            "exemplo. No Windows Home, use Configurações > Privacidade e segurança > Criptografia do dispositivo.",
            "Se a proteção estiver só suspensa (o disco já está criptografado), retome-a com Resume-BitLocker.",
        ),
        verify="'manage-bde -status C:' deve mostrar a proteção ligada, e a criptografia em 100%.",
        examples=(
            Fix(
                "windows",
                "PowerShell (administrador)",
                "# situação atual\n"
                "manage-bde -status C:\n\n"
                "# ligar com TPM e criar uma senha de recuperação (anote-a em local seguro)\n"
                "Add-BitLockerKeyProtector -MountPoint 'C:' -RecoveryPasswordProtector\n"
                "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector\n\n"
                "# proteção suspensa: retomar\n"
                "Resume-BitLocker -MountPoint 'C:'",
                "powershell",
            ),
        ),
        effort="medio",
        fix_group="windows",
        references=(
            "https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/",
            "https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide",
            "https://learn.microsoft.com/en-us/windows/win32/secprov/getprotectionstatus-win32-encryptablevolume",
            "https://support.microsoft.com/en-us/windows/device-encryption-in-windows-cf7e2b6f-3e70-4882-9532-18633605b7df",
        ),
        cwe="CWE-311",
        owasp="A02:2021",
        cis=("3.11",),
        lgpd=True,
        tags=("criptografia", "bitlocker"),
    ),
    KBEntry(
        id="host.win.secureboot.desligado",
        title="Inicialização Segura (Secure Boot) desligada",
        category=Category.HOST,
        severity=Severity.MEDIUM,
        summary="A máquina inicia sem conferir a assinatura do carregador do sistema.",
        explanation=(
            "A Inicialização Segura faz o firmware da máquina (UEFI) só aceitar carregadores de sistema "
            "assinados por quem ele confia. Ela é a base de outras proteções: com ela desligada, um programa "
            "malicioso pode se instalar antes do próprio Windows, onde o antivírus não enxerga."
        ),
        risk=(
            "Um rootkit de inicialização sobrevive a formatações do sistema e fica invisível para as ferramentas "
            "do Windows. Quem tem acesso físico também pode iniciar a máquina por um pen-drive não autorizado."
        ),
        steps=(
            "Faça backup e, se o disco usa BitLocker, tenha a chave de recuperação em mãos: mudar o firmware pode "
            "pedi-la na próxima inicialização.",
            "Abra 'msinfo32' e veja o Modo da BIOS: precisa ser UEFI. Em modo herdado (Legacy), converta o disco "
            "para GPT antes (ferramenta mbr2gpt).",
            "Reinicie, entre na configuração do firmware (geralmente F2, F10, F12 ou Del, conforme o fabricante) "
            "e ligue a opção Secure Boot.",
        ),
        verify="'Confirm-SecureBootUEFI' como administrador deve responder True; 'msinfo32' deve mostrar o estado Ligado.",
        examples=(
            Fix(
                "windows",
                "PowerShell (administrador)",
                "# True = ligada; False = desligada; erro = máquina sem UEFI\n"
                "Confirm-SecureBootUEFI\n\n"
                "# sem administrador\n"
                "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State').UEFISecureBootEnabled",
                "powershell",
            ),
        ),
        effort="medio",
        fix_group="windows",
        references=(
            "https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot",
            "https://learn.microsoft.com/en-us/powershell/module/secureboot/confirm-securebootuefi",
            "https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-secure-boot-key-creation-and-management-guidance",
        ),
        cwe="CWE-693",
        owasp="A05:2021",
        cis=("4.1", "10.5"),
        tags=("inicializacao", "firmware"),
    ),
    KBEntry(
        id="host.win.registro_remoto.ligado",
        title="Serviço Registro Remoto em execução",
        category=Category.HOST,
        severity=Severity.MEDIUM,
        summary="O registro do Windows pode ser consultado e alterado pela rede por quem tiver permissão.",
        explanation=(
            "O serviço RemoteRegistry permite que outras máquinas leiam e alterem as configurações desta "
            "pela rede. No Windows 10 e 11 ele vem desativado. Já no Windows Server ele inicia sozinho e a "
            "Microsoft recomenda não desativá-lo, pois ferramentas de administração dependem dele: nesse caso "
            "o achado é só informativo, e a proteção certa é limitar quem alcança a máquina."
        ),
        risk=(
            "Com uma credencial roubada, um invasor consulta e muda configurações à distância, inclusive para "
            "se manter na máquina e se mover para outras."
        ),
        steps=(
            "Windows 10 e 11: se nenhuma ferramenta de administração precisa dele, pare e desative o serviço com "
            "o comando do exemplo.",
            "Windows Server: mantenha o serviço, mas limite pelo firewall quem alcança a máquina às estações de "
            "administração.",
        ),
        verify="'Get-Service RemoteRegistry | Select-Object Status, StartType' deve mostrar Stopped e Disabled.",
        examples=(
            Fix(
                "windows",
                "PowerShell (administrador)",
                "Stop-Service -Name RemoteRegistry\nSet-Service -Name RemoteRegistry -StartupType Disabled",
                "powershell",
            ),
        ),
        effort="baixo",
        fix_group="windows",
        references=(
            "https://learn.microsoft.com/en-us/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server",
            "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-service",
        ),
        cwe="CWE-284",
        owasp="A05:2021",
        cis=("4.8",),
        tags=("servicos",),
    ),
    KBEntry(
        id="host.win.portas.expostas",
        title="Serviços sensíveis escutando em todas as interfaces de rede",
        category=Category.HOST,
        severity=Severity.LOW,
        summary="Há portas de risco abertas para qualquer endereço, e só o firewall decide quem as alcança.",
        explanation=(
            "Um programa que escuta em 0.0.0.0 ou [::] aceita conexões por todas as placas de rede da máquina, e "
            "não só por ela mesma. Isso não prova que a porta esteja acessível de fora, pois o firewall pode "
            "bloquear, mas deixa toda a proteção por conta dele. As portas 135, 139 e 445 são do próprio Windows "
            "e aparecem na maioria das máquinas: sozinhas, são apenas informativas."
        ),
        risk=(
            "Se o firewall for desligado ou alguma regra for aberta demais, bancos de dados e serviços de "
            "administração ficam alcançáveis pela rede, muitas vezes com autenticação fraca ou sem nenhuma."
        ),
        steps=(
            "Veja na evidência o número do processo (PID) de cada porta e descubra o programa com o comando do "
            "exemplo.",
            "Se o serviço só atende à própria máquina, configure-o para escutar em 127.0.0.1.",
            "Se ele não é usado, pare e desative. Se precisa de rede, restrinja pelo firewall quem pode se conectar.",
        ),
        verify="'netstat -ano' não deve mais mostrar a porta em 0.0.0.0 ou [::], ou o firewall deve restringir os endereços.",
        examples=(
            Fix(
                "windows",
                "PowerShell",
                "# quem está escutando na porta 3306\n"
                "Get-NetTCPConnection -State Listen -LocalPort 3306 | ForEach-Object { Get-Process -Id $_.OwningProcess }",
                "powershell",
            ),
            Fix(
                "windows",
                "Liberar a porta só para a rede interna (administrador)",
                "New-NetFirewallRule -DisplayName 'MySQL interno' -Direction Inbound -Protocol TCP "
                "-LocalPort 3306 -RemoteAddress 192.168.0.0/24 -Action Allow",
                "powershell",
            ),
        ),
        effort="medio",
        fix_group="servicos",
        references=(
            "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netstat",
            "https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule",
        ),
        cwe="CWE-668",
        owasp="A05:2021",
        cis=("4.4", "4.8"),
        tags=("servicos", "portas"),
    ),
)
