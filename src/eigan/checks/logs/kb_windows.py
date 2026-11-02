"""Base de conhecimento: indícios nos eventos de segurança do Windows."""

from __future__ import annotations

from ...core.kb import Fix
from ...core.models import Severity
from .kb_base import ref_attack, registrar

_MS = "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/"
_EXPORTAR = Fix(
    "windows",
    "Exportar o log para análise (PowerShell)",
    "wevtutil qe Security /f:xml /c:50000 > Security.xml",
    "powershell",
)

registrar(
    "logs.windows.forca_bruta",
    "Força bruta contra contas do Windows (evento 4625)",
    Severity.MEDIUM,
    "Uma mesma origem acumulou muitos logons com falha no Windows.",
    "O evento 4625 registra cada logon que falhou. Muitas falhas da mesma origem em minutos "
    "indicam adivinhação de senha, normalmente contra RDP ou SMB expostos.",
    "Se uma senha for fraca, o atacante entra como o usuário e se espalha pela rede (ransomware "
    "costuma começar assim).",
    (
        "Retire o RDP da Internet: use VPN ou gateway com MFA.",
        "Ative o bloqueio de conta (Account Lockout Policy) e Autenticação em Nível de Rede (NLA).",
        "Bloqueie o IP no firewall e confirme se houve logon bem-sucedido (evento 4624) da origem.",
    ),
    "Reexporte o log depois de alguns dias: as falhas da origem bloqueada devem ter parado.",
    (_MS + "event-4625", *ref_attack("T1110.001", "T1110.003")),
    exemplos=(
        _EXPORTAR,
        Fix(
            "windows",
            "Política de bloqueio de conta",
            "net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30",
            "powershell",
        ),
    ),
    cwe="CWE-307",
    owasp="A07:2021",
    cis=("5.2", "6.5", "8.11"),
    tags=("windows", "forca-bruta"),
)

registrar(
    "logs.windows.rdp_apos_falhas",
    "Logon remoto (RDP) aceito depois de várias falhas do mesmo IP",
    Severity.CRITICAL,
    "A origem errou a senha várias vezes e depois entrou por área de trabalho remota.",
    "O log tem eventos 4625 seguidos de um 4624 com tipo de logon 10 (RemoteInteractive) "
    "vindos do mesmo endereço: o padrão de uma força bruta que funcionou.",
    "O atacante tem uma sessão interativa como o usuário. Dali ele desativa antivírus, rouba "
    "credenciais e implanta ransomware.",
    (
        "Encerre a sessão (query user / logoff) e desabilite a conta envolvida.",
        "Isole a máquina e procure persistência: contas novas, serviços, tarefas agendadas.",
        "Redefina as senhas da conta e das que ela usava; exija MFA no acesso remoto.",
    ),
    "Confirme com 'query user' e com o log Security que não há sessões do IP e que a conta foi "
    "redefinida.",
    (_MS + "event-4624", *ref_attack("T1110.001", "T1078", "T1021.001")),
    exemplos=(_EXPORTAR,),
    esforco="alto",
    cwe="CWE-307",
    owasp="A07:2021",
    cis=("5.2", "6.5", "8.11"),
    tags=("windows", "rdp", "comprometimento"),
)

registrar(
    "logs.windows.usuario_criado",
    "Conta de usuário criada no Windows (evento 4720)",
    Severity.MEDIUM,
    "O log registra a criação de uma conta de usuário.",
    "O evento 4720 mostra quem criou qual conta. Criar contas é rotina de RH e TI, mas também "
    "a forma mais comum de manter acesso depois de uma invasão.",
    "Uma conta desconhecida dá ao atacante acesso persistente, mesmo depois de trocar as "
    "senhas existentes.",
    (
        "Compare com chamados e rotinas de provisionamento: quem criou, quando e por quê.",
        "Se a criação não for legítima, desabilite a conta, termine as sessões dela e investigue.",
        "Revise as contas locais: Get-LocalUser e o grupo Administradores.",
    ),
    "Get-LocalUser (ou 'net user') deve listar apenas contas conhecidas.",
    (_MS + "event-4720", *ref_attack("T1136.001", "T1136.002")),
    exemplos=(
        Fix("windows", "Desabilitar a conta", "Disable-LocalUser -Name 'nome'", "powershell"),
    ),
    esforco="baixo",
    cwe="CWE-284",
    owasp="A01:2021",
    cis=("5.4", "8.11"),
    tags=("windows", "persistencia"),
)

registrar(
    "logs.windows.grupo_privilegiado",
    "Membro adicionado a grupo privilegiado do Windows (eventos 4728, 4732, 4756)",
    Severity.HIGH,
    "Alguém foi colocado em um grupo com poderes administrativos.",
    "Os eventos 4728, 4732 e 4756 registram a inclusão em grupos de segurança. Para grupos "
    "como Administradores, Domain Admins, Enterprise Admins, Schema Admins ou Operadores de "
    "Backup, isso equivale a dar a chave do ambiente.",
    "Escalada de privilégio e controle total do computador ou do domínio.",
    (
        "Confirme com quem fez a mudança e se havia chamado.",
        "Se não for legítima, remova a conta do grupo e investigue o que ela fez.",
        "Restrinja administradores ao mínimo e use contas separadas para administração.",
    ),
    "Get-LocalGroupMember Administradores (ou Get-ADGroupMember) deve listar só os autorizados.",
    (_MS + "event-4732", *ref_attack("T1098", "T1098.007")),
    exemplos=(
        Fix(
            "windows",
            "Remover do grupo",
            "Remove-LocalGroupMember -Group 'Administradores' -Member 'usuario'",
            "powershell",
        ),
    ),
    esforco="baixo",
    cwe="CWE-269",
    owasp="A01:2021",
    cis=("5.4", "8.11"),
    tags=("windows", "escalada"),
)

registrar(
    "logs.windows.log_apagado",
    "Log de eventos do Windows apagado (evento 1102)",
    Severity.HIGH,
    "O log Security foi limpo, o que apaga o histórico de auditoria.",
    "O evento 1102 é gravado quando alguém limpa o log de segurança. Fora de uma manutenção "
    "planejada, atacantes fazem isso para esconder o que fizeram.",
    "Você perde as provas de um possível incidente, e a limpeza costuma vir depois de uma invasão.",
    (
        "Descubra quem limpou (campo Subject do evento) e se foi uma ação autorizada.",
        "Recupere o histórico em outras fontes: SIEM, backups, firewall, EDR, logs de rede.",
        "Encaminhe os logs do Windows para um coletor central (Windows Event Forwarding ou SIEM).",
    ),
    "Confira se o encaminhamento de logs está ativo e se o log Security tem tamanho e retenção "
    "adequados.",
    (_MS + "event-1102", *ref_attack("T1685.005")),
    exemplos=(
        Fix(
            "windows",
            "Aumentar o tamanho do log Security",
            "wevtutil sl Security /ms:1073741824",
            "powershell",
        ),
    ),
    esforco="medio",
    cwe="CWE-778",
    owasp="A09:2021",
    cis=("8.2", "8.5", "8.11"),
    tags=("windows", "evasao"),
)

registrar(
    "logs.windows.servico_instalado",
    "Serviço instalado no Windows (eventos 4697 e 7045)",
    Severity.MEDIUM,
    "Um novo serviço foi registrado; se o caminho for suspeito, pode ser persistência ou movimento lateral.",
    "Os eventos 4697 (Security) e 7045 (System) registram a instalação de serviços. Serviços "
    "rodam como SYSTEM; ferramentas como PsExec instalam um serviço temporário para executar "
    "comandos em outra máquina.",
    "Um serviço malicioso dá execução com privilégio máximo e sobrevive a reinícios.",
    (
        "Confira se a instalação tem justificativa (software legítimo, atualização).",
        "Se o executável está em shell, Temp, AppData, ProgramData ou compartilhamento, trate como malicioso.",
        "Pare e remova o serviço, guarde o arquivo para análise e procure outras máquinas com o mesmo.",
    ),
    "Get-Service e 'sc qc <nome>' não devem mostrar o serviço suspeito depois da remoção.",
    (_MS + "event-4697", *ref_attack("T1543.003", "T1569.002")),
    exemplos=(
        Fix(
            "windows",
            "Remover um serviço",
            "sc.exe stop NomeDoServico\nsc.exe delete NomeDoServico",
            "powershell",
        ),
    ),
    esforco="medio",
    cwe="CWE-506",
    owasp="A08:2021",
    cis=("8.11", "10.1"),
    tags=("windows", "persistencia"),
)

registrar(
    "logs.windows.comando_suspeito",
    "Linha de comando suspeita registrada (evento 4688)",
    Severity.MEDIUM,
    "Um processo foi iniciado com argumentos típicos de malware (powershell -enc, certutil -urlcache, mshta...).",
    "O evento 4688 grava a linha de comando de cada processo. Ferramentas do próprio Windows "
    "(LOLBins) como powershell, certutil, mshta, rundll32 e regsvr32 são usadas para baixar e "
    "executar código sem instalar nada. Administradores também usam algumas, por isso o "
    "achado é uma pista, não um veredito.",
    "Execução de código malicioso que escapa de antivírus baseados em arquivo.",
    (
        "Veja quem rodou, de qual processo-pai e em que máquina (campos do evento).",
        "Decodifique o comando em base64 num ambiente isolado antes de concluir qualquer coisa.",
        "Se for malicioso, isole a máquina e procure o mesmo comando em outras.",
        "Ative o bloqueio de scripts (AppLocker, WDAC, Constrained Language Mode) e o registro do PowerShell.",
    ),
    "Com a auditoria de criação de processo e de linha de comando ativa, eventos novos devem "
    "trazer o comando completo para investigação.",
    (
        _MS + "event-4688",
        "https://lolbas-project.github.io/",
        *ref_attack("T1059.001", "T1218.005"),
    ),
    exemplos=(
        Fix(
            "windows",
            "Registrar a linha de comando nos eventos 4688",
            "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit "
            "/v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f",
            "powershell",
        ),
    ),
    cwe="CWE-94",
    owasp="A08:2021",
    cis=("8.5", "10.5", "8.11"),
    tags=("windows", "lolbin"),
)
