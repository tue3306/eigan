"""Base de conhecimento: indícios nos logs de acesso de servidores web."""

from __future__ import annotations

from ...core.kb import Fix
from ...core.models import Severity
from .kb_base import ref_attack, registrar

_OWASP = "https://owasp.org/www-community/attacks/"
_AVISO_SUCESSO = (
    "Se o achado informar respostas 2xx ao ataque, o pedido foi atendido: isso não prova que "
    "deu certo, mas obriga a conferir os logs da aplicação e do banco."
)
_WAF = (
    Fix(
        "nginx",
        "nginx: bloquear o IP",
        "# em http { } ou server { }\ndeny 203.0.113.10;",
        "nginx",
    ),
    Fix(
        "apache",
        "Apache: bloquear o IP",
        "<RequireAll>\n    Require all granted\n    Require not ip 203.0.113.10\n</RequireAll>",
        "apache",
    ),
    Fix(
        "iis",
        "IIS: restringir por IP (web.config)",
        '<system.webServer><security><ipSecurity allowUnlisted="true">\n'
        '  <add ipAddress="203.0.113.10" allowed="false" />\n'
        "</ipSecurity></security></system.webServer>",
        "xml",
    ),
)


def _ataque(
    id: str,
    titulo: str,
    severidade: Severity,
    explicacao: str,
    risco: str,
    passos: tuple[str, ...],
    referencias: tuple[str, ...],
    *,
    cwe: str,
    owasp: str = "A03:2021",
    exemplos: tuple[Fix, ...] = _WAF,
) -> None:
    registrar(
        id,
        titulo,
        severidade,
        f"Os logs de acesso trazem requisições com assinatura de {titulo.split(' (')[0].lower()}.",
        f"{explicacao} {_AVISO_SUCESSO}",
        risco,
        passos,
        "Reproduza as mesmas requisições em ambiente de teste e confirme que a aplicação as recusa "
        "(400/403) sem erro de servidor; no log, o IP bloqueado não deve mais aparecer.",
        referencias,
        exemplos=exemplos,
        cwe=cwe,
        owasp=owasp,
        cis=("16.12", "8.11", "13.1"),
        tags=("web", "ataque"),
    )


_ataque(
    "logs.web.sqli",
    "Tentativas de injeção de SQL",
    Severity.MEDIUM,
    "Há URLs com trechos típicos de injeção de SQL (UNION SELECT, ' OR 1=1, SLEEP(), --).",
    "Se a aplicação montar consultas juntando texto, o atacante lê ou apaga o banco de dados "
    "inteiro, inclusive senhas e dados pessoais.",
    (
        "Use consultas parametrizadas (prepared statements) em todo acesso ao banco.",
        "Dê ao usuário do banco da aplicação só as permissões necessárias.",
        "Ative um WAF com as regras do OWASP Core Rule Set para barrar o padrão.",
        "Nos logs da aplicação, procure erros de SQL nos mesmos horários.",
    ),
    (_OWASP + "SQL_Injection", *ref_attack("T1190")),
    cwe="CWE-89",
)
_ataque(
    "logs.web.xss",
    "Tentativas de XSS (script injetado em parâmetros)",
    Severity.LOW,
    "Há URLs com <script>, onerror= ou javascript: nos parâmetros, típicos de Cross-Site Scripting.",
    "Se a página devolver o parâmetro sem filtro, o script roda no navegador da vítima e rouba "
    "sessão, faz ações em seu nome ou desfigura a página.",
    (
        "Escape toda saída de dados do usuário no HTML (use o escape do framework).",
        "Defina uma Content-Security-Policy restritiva e cookies HttpOnly e Secure.",
        "Teste as páginas que receberam o parâmetro para ver se ele volta sem escape.",
    ),
    (_OWASP + "xss/", *ref_attack("T1190")),
    cwe="CWE-79",
)
_ataque(
    "logs.web.traversal",
    "Tentativas de path traversal (../)",
    Severity.MEDIUM,
    "Há URLs com ../ (inclusive codificados como %2e%2e%2f) tentando sair da pasta do site.",
    "Se a aplicação aceitar o caminho, o atacante lê arquivos de configuração, chaves e senhas "
    "de qualquer pasta do servidor.",
    (
        "Valide nomes de arquivo contra uma lista permitida e normalize o caminho antes de abrir.",
        "Rode o serviço web com um usuário sem acesso a arquivos sensíveis.",
        "Atualize o servidor e frameworks: vários CVEs recentes de traversal afetam versões antigas.",
    ),
    (_OWASP + "Path_Traversal", *ref_attack("T1190")),
    cwe="CWE-22",
    owasp="A01:2021",
)
_ataque(
    "logs.web.lfi",
    "Tentativas de inclusão de arquivo local (LFI)",
    Severity.MEDIUM,
    "Há URLs pedindo arquivos do sistema (/etc/passwd, win.ini, php://filter) por parâmetros.",
    "Se a aplicação incluir o arquivo pedido, o atacante lê segredos e, em muitos casos, "
    "consegue executar código no servidor.",
    (
        "Nunca use um parâmetro do usuário como caminho de arquivo; mapeie nomes para arquivos fixos.",
        "Desative allow_url_include e restrinja open_basedir no PHP.",
        "Revise os arquivos que a aplicação consegue ler e remova segredos do disco do site.",
    ),
    (_OWASP + "Path_Traversal", *ref_attack("T1190")),
    cwe="CWE-98",
    owasp="A01:2021",
)
_ataque(
    "logs.web.rfi",
    "Tentativas de inclusão de arquivo remoto (RFI)",
    Severity.MEDIUM,
    "Há URLs com um endereço http(s) ou ftp passado como arquivo a ser incluído.",
    "Se a aplicação baixar e executar o arquivo, o atacante roda código próprio no servidor.",
    (
        "Desative allow_url_include e allow_url_fopen no PHP, se não forem necessários.",
        "Valide parâmetros de arquivo contra uma lista permitida.",
        "Libere saída para a Internet a partir do servidor web só para o que for necessário.",
    ),
    (_OWASP + "Code_Injection", *ref_attack("T1190", "T1105")),
    cwe="CWE-98",
)
_ataque(
    "logs.web.cmdi",
    "Tentativas de injeção de comandos",
    Severity.HIGH,
    "Há URLs com operadores de shell (;, |, `, $()) seguidos de comandos como cat, wget ou curl.",
    "Se a aplicação passar o parâmetro a um comando do sistema, o atacante executa qualquer "
    "comando no servidor.",
    (
        "Evite chamar o shell; use bibliotecas da linguagem ou execute programas com lista de argumentos.",
        "Valide a entrada contra uma lista permitida e rode o serviço com o menor privilégio.",
        "Examine o servidor atrás de processos, arquivos e conexões de saída estranhos.",
    ),
    (_OWASP + "Command_Injection", *ref_attack("T1190", "T1059.004")),
    cwe="CWE-78",
)
_ataque(
    "logs.web.log4shell",
    "Tentativas de exploração do Log4Shell (CVE-2021-44228)",
    Severity.HIGH,
    "Há requisições com ${jndi:ldap://...} na URL ou em cabeçalhos como User-Agent.",
    "Versões 2.0 a 2.14.1 do Apache Log4j 2 executam código remoto ao registrar essa cadeia. "
    "Scanners de toda a Internet ainda a testam, e a maioria das tentativas é só varredura.",
    (
        "Atualize o Log4j 2 para uma versão corrigida (2.17.1 ou superior).",
        "Inventarie aplicações Java (inclusive produtos de terceiros) que usam Log4j.",
        "Bloqueie saída LDAP/RMI do servidor para a Internet e procure conexões de saída nos horários.",
    ),
    (
        "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        "https://www.cisa.gov/news-events/news/apache-log4j-vulnerability-guidance",
        *ref_attack("T1190"),
    ),
    cwe="CWE-917",
    owasp="A06:2021",
)
_ataque(
    "logs.web.shellshock",
    "Tentativas de exploração do Shellshock (CVE-2014-6271)",
    Severity.HIGH,
    "Há requisições com () { :; }; em cabeçalhos, usadas contra scripts CGI com Bash.",
    "Versões antigas do Bash executam comandos colocados depois da definição de função em "
    "variáveis de ambiente, que o CGI cria a partir dos cabeçalhos.",
    (
        "Atualize o Bash (versões antigas são vulneráveis) e desative CGI que não for usado.",
        "Procure scripts CGI e confirme que não rodam com privilégios altos.",
    ),
    (
        "https://nvd.nist.gov/vuln/detail/CVE-2014-6271",
        *ref_attack("T1190", "T1059.004"),
    ),
    cwe="CWE-78",
    owasp="A06:2021",
)
_ataque(
    "logs.web.ssrf_metadados",
    "Tentativas de SSRF contra o serviço de metadados da nuvem",
    Severity.HIGH,
    "Há requisições que mandam o servidor acessar 169.254.169.254, o endereço de metadados da nuvem.",
    "Se a aplicação buscar a URL recebida, o atacante lê credenciais temporárias da máquina "
    "e passa a agir na conta de nuvem.",
    (
        "Exija o IMDSv2 (token de sessão) na AWS e limite o salto de rede (hop limit 1).",
        "Na aplicação, valide URLs de saída contra uma lista permitida e bloqueie IPs internos.",
        "Revise as permissões do papel da instância e rotacione credenciais se houve sucesso.",
    ),
    (
        "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-IMDS-existing-instances.html",
        _OWASP + "Server_Side_Request_Forgery",
        *ref_attack("T1190", "T1552.005"),
    ),
    cwe="CWE-918",
    owasp="A10:2021",
    exemplos=(
        Fix(
            "linux",
            "AWS CLI: exigir IMDSv2",
            "aws ec2 modify-instance-metadata-options --instance-id i-0123456789abcdef0 "
            "--http-tokens required --http-put-response-hop-limit 1",
            "bash",
        ),
    ),
)

registrar(
    "logs.web.sondagem_shell",
    "Procura por web shells",
    Severity.MEDIUM,
    "Um IP pediu nomes de arquivo típicos de web shells (c99.php, wso.php, shell.php...).",
    "Depois de invadir um site, atacantes deixam um 'web shell', página que executa comandos. "
    "Outros robôs varrem a Internet atrás dessas páginas para assumir sites já comprometidos.",
    "Se o arquivo existir, quem conhecer o nome controla o servidor. Se só houver 404, é uma "
    "varredura sem sucesso.",
    (
        "Procure no disco do site arquivos com esses nomes ou PHP/ASPX recentes que você não criou.",
        "Bloqueie a execução de scripts em pastas de upload.",
    ),
    "Pesquise o nome em todo o site (find . -name 'c99*.php'): não deve existir.",
    (
        _OWASP.replace("attacks/", "vulnerabilities/") + "Unrestricted_File_Upload",
        *ref_attack("T1505.003"),
    ),
    exemplos=_WAF,
    cwe="CWE-434",
    owasp="A05:2021",
    cis=("8.11", "13.1"),
    tags=("web", "webshell"),
)

registrar(
    "logs.web.webshell",
    "Possível web shell acessado",
    Severity.CRITICAL,
    "Um web shell conhecido recebeu respostas de sucesso: o site pode estar comprometido.",
    "Os logs mostram requisições a nomes de web shell (ou com parâmetros de comando como "
    "?cmd=) que o servidor respondeu com 2xx. Isso indica que o arquivo existe.",
    "O invasor executa comandos, lê o banco, altera páginas e usa o servidor para atacar outros.",
    (
        "Isole o servidor, preserve uma cópia dos arquivos do site e dos logs.",
        "Localize e remova o arquivo, mas descubra como ele chegou (upload, plugin vulnerável).",
        "Restaure o site a partir de um backup anterior ao incidente e atualize plugins e frameworks.",
        "Troque senhas do banco, do painel e chaves de API guardadas no servidor.",
    ),
    "Compare os arquivos do site com um backup limpo (diff -r) e confirme que o IP não obtém mais 2xx.",
    (
        _OWASP.replace("attacks/", "vulnerabilities/") + "Unrestricted_File_Upload",
        *ref_attack("T1505.003"),
    ),
    esforco="alto",
    cwe="CWE-434",
    owasp="A05:2021",
    cis=("8.11", "13.1"),
    tags=("web", "webshell", "comprometimento"),
)

registrar(
    "logs.web.arquivo_sensivel",
    "Arquivos sensíveis foram acessados com sucesso",
    Severity.HIGH,
    "Alguém baixou com sucesso arquivos que nunca deveriam ser públicos (.env, .git, backups).",
    "Os logs mostram respostas 2xx para caminhos como /.env, /.git/config, backup.sql ou "
    "wp-config.php.bak, cujo conteúdo costuma ter senhas e chaves.",
    "Quem baixou o arquivo passa a ter as senhas e chaves nele: banco, e-mail, nuvem. "
    "Dados pessoais vazados exigem comunicação à ANPD e aos titulares (LGPD).",
    (
        "Remova o arquivo do diretório público e bloqueie o acesso a dotfiles e backups no servidor.",
        "Considere todos os segredos do arquivo como vazados: troque-os.",
        "Verifique nos logs do banco e da nuvem se as credenciais antigas foram usadas.",
    ),
    "Peça a URL no navegador: deve dar 403 ou 404.",
    ("https://owasp.org/Top10/A05_2021-Security_Misconfiguration/", *ref_attack("T1552")),
    exemplos=(
        Fix(
            "nginx",
            "nginx: negar arquivos ocultos e backups",
            r"location ~ /\.(?!well-known) { deny all; }"
            "\n"
            r"location ~* \.(bak|sql|old|swp|zip|tar|gz)$ { deny all; }",
            "nginx",
        ),
        Fix(
            "apache",
            "Apache: negar arquivos ocultos",
            '<FilesMatch "^\\.(?!well-known)">\n    Require all denied\n</FilesMatch>',
            "apache",
        ),
    ),
    cwe="CWE-538",
    owasp="A05:2021",
    cis=("3.3", "8.11"),
    tags=("web", "vazamento"),
)

registrar(
    "logs.web.varredura_scanner",
    "Varredura por ferramenta automatizada (sqlmap, nikto, nuclei...)",
    Severity.LOW,
    "O User-Agent de um IP identifica uma ferramenta de varredura ou de ataque.",
    "Ferramentas como sqlmap, nikto, nuclei, masscan, gobuster ou wpscan anunciam o nome no "
    "User-Agent. Pode ser seu próprio teste de segurança ou alguém procurando falhas.",
    "A varredura costuma ser o primeiro passo de uma invasão: o atacante lista o que há "
    "para explorar. O User-Agent é falsificável, então a ausência dele não prova nada.",
    (
        "Confirme se a varredura foi autorizada (teste de invasão, scanner interno).",
        "Se não foi, bloqueie o IP e atualize o que a ferramenta procura (versões, painéis expostos).",
        "Ative limite de requisições (rate limiting) e um WAF.",
    ),
    "O IP deve receber 403 e a ferramenta não deve mais aparecer nos logs.",
    ("https://github.com/coreruleset/coreruleset", *ref_attack("T1595.002")),
    exemplos=_WAF,
    esforco="baixo",
    owasp="A05:2021",
    cwe="CWE-200",
    tags=("web", "reconhecimento"),
)

registrar(
    "logs.web.varredura_404",
    "Rajada de páginas inexistentes (varredura de diretórios)",
    Severity.LOW,
    "Um IP gerou muitos erros 404 em poucos minutos, procurando páginas e arquivos.",
    "Ferramentas de força bruta de diretórios (dirbuster, gobuster, ffuf) testam milhares de "
    "nomes de caminho para descobrir painéis, backups e scripts esquecidos.",
    "O que for encontrado vira alvo do próximo passo. Os 404 mostram que a maioria não existe, "
    "mas um único 200 nesse meio já é uma descoberta.",
    (
        "Veja nos logs se o mesmo IP recebeu algum 200 em caminhos suspeitos.",
        "Bloqueie o IP e configure limite de requisições por IP.",
        "Remova do servidor painéis, backups e arquivos de teste desnecessários.",
    ),
    "Com o limite ativo, o mesmo IP deve receber 429/403 depois de poucas requisições.",
    ("https://owasp.org/www-project-web-security-testing-guide/", *ref_attack("T1595.003")),
    exemplos=(
        Fix(
            "nginx",
            "nginx: limite de requisições",
            "limit_req_zone $binary_remote_addr zone=geral:10m rate=10r/s;\n"
            "server { location / { limit_req zone=geral burst=20 nodelay; } }",
            "nginx",
        ),
        *_WAF,
    ),
    esforco="baixo",
    owasp="A05:2021",
    cwe="CWE-200",
    tags=("web", "reconhecimento"),
)

registrar(
    "logs.web.forca_bruta",
    "Força bruta em tela de login (401 repetidos, POST em /login)",
    Severity.MEDIUM,
    "Um IP fez muitas tentativas falhas de login no site em pouco tempo.",
    "Os logs mostram muitos 401 (ou POSTs em /login e wp-login.php sem sucesso) do mesmo IP. "
    "É o comportamento de robôs de adivinhação de senha ou de credential stuffing.",
    "Contas com senha fraca ou vazada em outros sites são invadidas, e o atacante passa a "
    "agir como o usuário ou administrador.",
    (
        "Ative bloqueio temporário após N erros e CAPTCHA no login.",
        "Exija MFA, principalmente para administradores.",
        "Restrinja o painel administrativo a IPs conhecidos ou VPN.",
        "Verifique se algum login do mesmo IP foi bem-sucedido.",
    ),
    "Faça 10 tentativas erradas de teste: o site deve bloquear ou atrasar a resposta.",
    ("https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks", *ref_attack("T1110")),
    exemplos=_WAF,
    cwe="CWE-307",
    owasp="A07:2021",
    cis=("6.3", "8.11"),
    tags=("web", "forca-bruta"),
)
