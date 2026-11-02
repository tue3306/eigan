"""Base de conhecimento: versões vulneráveis e ramos sem suporte (checagem ``net.versions``).

As faixas de versão, os CVEs e as datas ficam em ``eigan/data/net_vulns.json``; aqui
ficam a explicação, o risco e o passo a passo da correção de cada família de achado.
"""

from __future__ import annotations

from ...core import kb
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Severity

KEV_CATALOG = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

#: todos os achados que ``net.versions`` pode reportar (o id vem do campo ``achado`` da regra)
FINDINGS = (
    "net.versao.vulneravel.apache_traversal",
    "net.versao.vulneravel.openssl_heartbleed",
    "net.versao.vulneravel.vsftpd_backdoor",
    "net.versao.vulneravel.proftpd_mod_copy",
    "net.versao.vulneravel.exim_rce",
    "net.versao.vulneravel.php_cgi_windows",
    "net.versao.vulneravel.iis_webdav",
    "net.versao.vulneravel.jenkins_cli",
    "net.versao.fim_de_vida.php",
    "net.versao.fim_de_vida.apache",
    "net.versao.fim_de_vida.iis",
    "net.versao.ramo_antigo.nginx",
    "net.versao.ramo_antigo.openssh",
)


def _apt(tech: str, package: str, *lines: str) -> Fix:
    """Exemplo para Debian/Ubuntu: atualiza o pacote e roda os comandos seguintes."""
    upgrade = f"sudo apt update && sudo apt install --only-upgrade {package}"
    return Fix(tech, "Debian/Ubuntu", "\n".join((upgrade, *lines)), "bash")


def _dnf(tech: str, package: str, *lines: str) -> Fix:
    """Exemplo para a família Red Hat: atualiza o pacote e roda os comandos seguintes."""
    upgrade = f"sudo dnf upgrade {package}"
    return Fix(tech, "Família Red Hat", "\n".join((upgrade, *lines)), "bash")


kb.register(
    KBEntry(
        id="net.versao.vulneravel.apache_traversal",
        title="Apache httpd 2.4.49 ou 2.4.50 com falha de path traversal",
        category=Category.NETWORK,
        severity=Severity.CRITICAL,
        summary="A versão anunciada do Apache httpd tem a falha de path traversal explorada em ataques reais.",
        explanation=(
            "Uma mudança na normalização de caminhos do Apache 2.4.49 permite pedir arquivos fora "
            "das pastas configuradas por diretivas como Alias, e a correção da 2.4.50 ficou "
            "incompleta. Se esses arquivos não estiverem protegidos pelo 'Require all denied' "
            "(padrão), o servidor os entrega; com CGI ativo nesses caminhos, o atacante também "
            "executa comandos. O EIGAN só lê a versão anunciada e não testa a falha."
        ),
        risk=(
            "Leitura de arquivos do servidor (senhas, chaves, código) e, com CGI ativo, execução "
            "remota de comandos. A falha está no catálogo CISA KEV, com uso em ransomware."
        ),
        steps=(
            "Atualize para o Apache httpd 2.4.51 ou mais novo (de preferência a versão atual do ramo 2.4).",
            "Confira se tudo que está fora do site tem 'Require all denied' e desative CGI onde não for necessário.",
            "Procure nos logs de acesso pedidos com '.%2e/' ou '%%32%65' em /cgi-bin/ ou /icons/: "
            "são sinais de tentativa de ataque.",
        ),
        examples=(
            _apt("apache", "apache2", "apache2 -v", "sudo systemctl restart apache2"),
            _dnf("apache", "httpd", "httpd -v", "sudo systemctl restart httpd"),
            Fix(
                "apache",
                "Apache no Windows",
                "httpd.exe -v\n# troque os binários pelo pacote atual do seu fornecedor "
                "(Apache Lounge, XAMPP...)\nRestart-Service Apache2.4",
                "powershell",
            ),
            Fix(
                "apache",
                "Apache (httpd.conf): negar o acesso fora do site",
                "<Directory />\n    AllowOverride None\n    Require all denied\n</Directory>",
                "apache",
            ),
        ),
        verify="O cabeçalho Server (ou 'apachectl -v' no servidor) deve mostrar 2.4.51 ou mais novo.",
        effort="baixo",
        fix_group="atualizacao",
        references=(
            "https://httpd.apache.org/security/vulnerabilities_24.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-42013",
            KEV_CATALOG,
        ),
        cwe="CWE-22",
        owasp="A06:2021",
        cis=("7.4",),
        lgpd=True,
        tags=("versao", "cve", "apache"),
    ),
    KBEntry(
        id="net.versao.vulneravel.openssl_heartbleed",
        title="OpenSSL em versão na faixa do Heartbleed",
        category=Category.NETWORK,
        severity=Severity.CRITICAL,
        summary="A versão anunciada do OpenSSL está na faixa do Heartbleed (CVE-2014-0160), que permite ler a memória do servidor.",
        explanation=(
            "O Heartbleed é um erro na extensão heartbeat do TLS: sem validar o tamanho pedido, o "
            "OpenSSL devolve trechos da memória do processo a cada pedido. Afeta o OpenSSL 1.0.1 a "
            "1.0.1f e o 1.0.2-beta1. O EIGAN não testa a falha, porque isso exigiria enviar o "
            "heartbeat malformado: só lê a versão anunciada. Por isso é um indício: pacotes de "
            "distribuição, como o 1.0.1e-fips, costumam ter a correção sem mudar o número."
        ),
        risk=(
            "Vazamento de chaves privadas do certificado, senhas e cookies de sessão, sem rastro "
            "nos logs comuns. A falha está no catálogo CISA KEV."
        ),
        steps=(
            "No servidor, confira a versão e a data de compilação do OpenSSL: 'openssl version -a'.",
            "Atualize para um OpenSSL atual ou para o pacote corrigido da distribuição e reinicie "
            "todos os serviços que usam TLS.",
            "Se o servidor esteve vulnerável e exposto, troque a chave privada, emita um novo "
            "certificado, revogue o antigo e invalide sessões e senhas.",
        ),
        examples=(
            Fix(
                "openssl",
                "Debian/Ubuntu",
                "openssl version -a\nsudo apt update && sudo apt install --only-upgrade openssl\n"
                "# reinicie quem usa a biblioteca, por exemplo:\nsudo systemctl restart apache2",
                "bash",
            ),
            Fix(
                "openssl",
                "Família Red Hat: conferir a correção no pacote",
                "rpm -q --changelog openssl | grep CVE-2014-0160\nsudo yum update openssl",
                "bash",
            ),
        ),
        verify="A versão deve ser 1.0.1g ou mais nova, ou o changelog do pacote instalado deve citar o CVE-2014-0160.",
        effort="medio",
        fix_group="atualizacao",
        references=(
            "https://openssl-library.org/news/secadv/20140407.txt",
            "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
            KEV_CATALOG,
        ),
        cwe="CWE-125",
        owasp="A06:2021",
        cis=("7.4",),
        lgpd=True,
        tags=("versao", "cve", "openssl", "heartbleed"),
    ),
    KBEntry(
        id="net.versao.vulneravel.vsftpd_backdoor",
        title="vsftpd 2.3.4: versão ligada à backdoor de 2011",
        category=Category.NETWORK,
        severity=Severity.HIGH,
        summary="O servidor FTP anuncia o vsftpd 2.3.4, versão cujo pacote foi adulterado com uma backdoor em 2011.",
        explanation=(
            "O pacote do vsftpd 2.3.4 baixado entre 30/06/2011 e 03/07/2011 continha uma backdoor "
            "que abre um shell na porta 6200/tcp. O banner é igual nas cópias limpa e adulterada, "
            "e o EIGAN nunca tenta acionar a backdoor. Por isso é um indício a conferir: mesmo uma "
            "cópia limpa dessa versão é antiga demais e deve ser substituída."
        ),
        risk="Se a cópia instalada for a adulterada, qualquer pessoa na rede consegue um shell no servidor.",
        steps=(
            "Confira a origem do programa: pacote da distribuição ('dpkg -V vsftpd' ou 'rpm -V vsftpd') "
            "ou compilado a partir do pacote baixado em 2011.",
            "No próprio servidor, veja se há algo escutando na porta 6200/tcp, sem tentar acionar a backdoor.",
            "Atualize para a versão atual do vsftpd, vinda da distribuição ou do site oficial.",
            "Se a cópia for a adulterada, trate o servidor como comprometido: investigue e reinstale.",
        ),
        examples=(
            _apt("vsftpd", "vsftpd", "ss -ltnp | grep 6200", "sudo systemctl restart vsftpd"),
            _dnf("vsftpd", "vsftpd", "ss -ltnp | grep 6200", "sudo systemctl restart vsftpd"),
        ),
        verify="O banner FTP deve mostrar uma versão diferente da 2.3.4 e nada deve escutar na porta 6200/tcp.",
        effort="medio",
        fix_group="atualizacao",
        references=(
            "https://nvd.nist.gov/vuln/detail/CVE-2011-2523",
            "https://www.openwall.com/lists/oss-security/2011/07/11/5",
            "https://security-tracker.debian.org/tracker/CVE-2011-2523",
        ),
        cwe="CWE-506",
        owasp="A08:2021",
        cis=("7.4",),
        tags=("versao", "cve", "ftp", "backdoor"),
    ),
    KBEntry(
        id="net.versao.vulneravel.proftpd_mod_copy",
        title="ProFTPD 1.3.5 com mod_copy vulnerável",
        category=Category.NETWORK,
        severity=Severity.CRITICAL,
        summary="O servidor FTP anuncia o ProFTPD 1.3.5, cujo módulo mod_copy aceita copiar arquivos sem login (CVE-2015-3306).",
        explanation=(
            "No ProFTPD 1.3.5, os comandos SITE CPFR e SITE CPTO do módulo mod_copy funcionam antes "
            "do login: qualquer pessoa pode copiar arquivos no servidor, por exemplo para uma pasta "
            "publicada na web. O módulo vem ativo por padrão nessa versão, mas alguns pacotes o "
            "deixam desligado. O EIGAN só lê o banner e nunca envia esses comandos."
        ),
        risk=(
            "Leitura e gravação de arquivos sem autenticação, o que pode virar execução de comandos "
            "se o arquivo for parar em uma pasta da web. A falha está no catálogo CISA KEV."
        ),
        steps=(
            "Atualize para o ProFTPD 1.3.5a ou mais novo, ou para o pacote corrigido da distribuição "
            "(no Debian, o aviso DSA-3263).",
            "Confira se o módulo está ativo: 'proftpd -vv' lista os módulos carregados.",
            "Enquanto não atualiza, desligue o módulo: comente 'LoadModule mod_copy.c' no modules.conf "
            "e reinicie. Se ele foi compilado junto, só a atualização resolve.",
        ),
        examples=(
            _apt(
                "proftpd",
                "proftpd-basic",
                "proftpd -vv | grep -i mod_copy",
                "sudo systemctl restart proftpd",
            ),
            Fix(
                "proftpd",
                "Desligar o módulo (/etc/proftpd/modules.conf)",
                "# LoadModule mod_copy.c",
                "text",
            ),
            Fix(
                "proftpd",
                "ProFTPD 1.3.5a ou mais novo (proftpd.conf), se não usa o módulo",
                "<IfModule mod_copy.c>\n  CopyEngine off\n</IfModule>",
                "text",
            ),
        ),
        verify="O banner deve mostrar 1.3.5a ou mais novo, ou 'proftpd -vv' não deve listar o mod_copy.",
        effort="baixo",
        fix_group="atualizacao",
        references=(
            "https://nvd.nist.gov/vuln/detail/CVE-2015-3306",
            "https://github.com/proftpd/proftpd/blob/v1.3.5a/NEWS",
            "https://www.debian.org/security/2015/dsa-3263",
            KEV_CATALOG,
        ),
        cwe="CWE-284",
        owasp="A06:2021",
        cis=("7.4",),
        lgpd=True,
        tags=("versao", "cve", "ftp"),
    ),
    KBEntry(
        id="net.versao.vulneravel.exim_rce",
        title="Exim 4.87 a 4.91 com falha de execução de comandos",
        category=Category.NETWORK,
        severity=Severity.CRITICAL,
        summary="O servidor de e-mail anuncia uma versão do Exim afetada pelo CVE-2019-10149, que pode executar comandos remotamente.",
        explanation=(
            "As versões 4.87 a 4.91 validam mal o endereço do destinatário na função "
            "deliver_message(), o que pode levar à execução remota de comandos; a gravidade depende "
            "da configuração do servidor. A 4.92 não é afetada e o projeto publicou correção para as "
            "versões desde a 4.87, que distribuições aplicam sem mudar o número. O banner SMTP só "
            "mostra a versão, então confira o pacote instalado."
        ),
        risk=(
            "Um atacante pode executar comandos no servidor de e-mail só enviando uma mensagem, sem "
            "login, e ler ou desviar correspondências. A falha está no catálogo CISA KEV."
        ),
        steps=(
            "Atualize para o Exim 4.92 ou mais novo (de preferência a versão atual), ou para o pacote "
            "corrigido da distribuição.",
            "Confira a versão com 'exim -bV' e, em pacotes, o changelog do CVE-2019-10149.",
            "Procure no spool e nos logs sinais de exploração, como destinatários com '${run{'.",
        ),
        examples=(
            Fix(
                "exim",
                "Debian/Ubuntu",
                "sudo apt update && sudo apt install --only-upgrade exim4\nexim -bV | head -n 1\n"
                "apt-get changelog exim4 | grep CVE-2019-10149",
                "bash",
            ),
            Fix(
                "exim",
                "Família Red Hat (EPEL)",
                "sudo dnf upgrade exim\nrpm -q --changelog exim | grep CVE-2019-10149",
                "bash",
            ),
        ),
        verify="O banner SMTP deve mostrar 4.92 ou mais novo, ou o changelog do pacote deve citar o CVE-2019-10149.",
        effort="baixo",
        fix_group="atualizacao",
        references=(
            "https://www.exim.org/static/doc/security/CVE-2019-10149.txt",
            "https://nvd.nist.gov/vuln/detail/CVE-2019-10149",
            "https://www.debian.org/security/2019/dsa-4456",
            KEV_CATALOG,
        ),
        cwe="CWE-78",
        owasp="A06:2021",
        cis=("7.4",),
        tags=("versao", "cve", "email"),
    ),
    KBEntry(
        id="net.versao.vulneravel.php_cgi_windows",
        title="PHP em Windows com possível injeção de argumentos no PHP-CGI",
        category=Category.NETWORK,
        severity=Severity.CRITICAL,
        summary="O servidor Windows anuncia uma versão do PHP afetada pelo CVE-2024-4577 quando roda como CGI.",
        explanation=(
            "Em Windows, a conversão de caracteres 'Best-Fit' pode transformar um caractere comum em "
            "hífen, e o PHP-CGI passa a tratá-lo como argumento de linha de comando. Foi confirmado "
            "com as páginas de código 932 (japonês), 936 (chinês simplificado) e 950 (chinês "
            "tradicional), sem descartar outras. Só vale quando o PHP roda como CGI, por exemplo pelo "
            "'ScriptAlias /php-cgi/' do XAMPP, o que o banner não revela: por isso é um indício."
        ),
        risk=(
            "Execução remota de comandos no servidor Windows, sem login. A falha está no catálogo "
            "CISA KEV, com uso em ransomware."
        ),
        steps=(
            "Atualize o PHP para 8.3.8, 8.2.20, 8.1.29 ou mais novo. Os ramos 8.0, 7 e 5 não têm "
            "correção: migre para um ramo com suporte.",
            "Confira se o PHP roda como CGI. No XAMPP, comente a linha 'ScriptAlias /php-cgi/' do "
            "httpd-xampp.conf, que vem ativa por padrão.",
            "Prefira Mod-PHP, FastCGI ou PHP-FPM em vez de CGI.",
            "Se não puder atualizar agora, use a regra de reescrita abaixo: é uma mitigação temporária, "
            "só para os idiomas confirmados.",
        ),
        examples=(
            Fix(
                "php",
                "XAMPP (apache/conf/extra/httpd-xampp.conf)",
                '# comente esta linha e reinicie o Apache:\n# ScriptAlias /php-cgi/ "C:/xampp/php/"',
                "apache",
            ),
            Fix(
                "php",
                "Apache: mitigação temporária",
                "RewriteEngine On\nRewriteCond %{QUERY_STRING} ^%ad [NC]\nRewriteRule .? - [F,L]",
                "apache",
            ),
        ),
        verify="'php -v' deve mostrar uma versão corrigida e o caminho /php-cgi/ não deve mais responder.",
        effort="baixo",
        fix_group="atualizacao",
        references=(
            "https://nvd.nist.gov/vuln/detail/CVE-2024-4577",
            "https://github.com/php/php-src/security/advisories/GHSA-3qgc-jrrr-25jv",
            "https://devco.re/blog/2024/06/06/security-alert-cve-2024-4577-php-cgi-argument-injection-vulnerability-en/",
            KEV_CATALOG,
        ),
        cwe="CWE-78",
        owasp="A06:2021",
        cis=("7.4",),
        tags=("versao", "cve", "php", "windows"),
    ),
    KBEntry(
        id="net.versao.vulneravel.iis_webdav",
        title="IIS 6.0 com WebDAV vulnerável",
        category=Category.NETWORK,
        severity=Severity.CRITICAL,
        summary="O servidor anuncia o IIS 6.0 com WebDAV, afetado pelo CVE-2017-7269 (execução remota de comandos).",
        explanation=(
            "A função ScStoragePathFromUrl do WebDAV do IIS 6.0, no Windows Server 2003 R2, tem um "
            "estouro de buffer acionado por um cabeçalho 'If:' longo em uma requisição PROPFIND. A "
            "falha já era explorada em 2016. O EIGAN pede só um OPTIONS comum, para saber se o WebDAV "
            "está ativo, e nunca envia o PROPFIND: quando o OPTIONS não responde, o achado aparece "
            "como indício."
        ),
        risk=(
            "Execução remota de comandos sem login, em um sistema que não recebe mais atualizações. "
            "A falha está no catálogo CISA KEV."
        ),
        steps=(
            "Migre o site para uma versão do Windows Server com suporte: o Windows Server 2003 saiu de "
            "suporte em 14/07/2015.",
            "Até lá, desative o WebDAV no Gerenciador do IIS e isole o servidor da Internet.",
        ),
        examples=(
            Fix(
                "iis",
                "IIS 6.0 (Gerenciador do IIS)",
                "Extensões do serviço Web > WebDAV > Proibir\n\n"
                "# confira: a resposta não deve mais trazer DAV nem PROPFIND\n"
                "curl -si -X OPTIONS http://servidor/",
                "text",
            ),
        ),
        verify="A resposta ao OPTIONS não deve trazer 'DAV:' nem citar PROPFIND; o ideal é não usar mais o IIS 6.0.",
        effort="alto",
        fix_group="atualizacao",
        references=(
            "https://nvd.nist.gov/vuln/detail/CVE-2017-7269",
            "https://www.cve.org/CVERecord?id=CVE-2017-7269",
            "https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2003-",
            KEV_CATALOG,
        ),
        cwe="CWE-120",
        owasp="A06:2021",
        cis=("2.2", "7.4"),
        tags=("versao", "cve", "iis", "webdav"),
    ),
    KBEntry(
        id="net.versao.vulneravel.jenkins_cli",
        title="Jenkins com leitura de arquivos pela CLI",
        category=Category.NETWORK,
        severity=Severity.CRITICAL,
        summary="O cabeçalho X-Jenkins mostra uma versão afetada pelo CVE-2024-23897, que permite ler arquivos do controlador.",
        explanation=(
            "A CLI do Jenkins usa uma biblioteca que troca '@' seguido de um caminho pelo conteúdo do "
            "arquivo. Quem tem a permissão Overall/Read lê arquivos inteiros; sem ela, ainda lê as "
            "primeiras linhas. Com chaves e segredos obtidos assim, o aviso oficial descreve vários "
            "caminhos até a execução remota de código. Afeta o Jenkins semanal até 2.441 e o LTS até "
            "2.426.2. Desativar a CLI é só um paliativo, e o EIGAN não consegue ver se isso foi feito."
        ),
        risk=(
            "Roubo de segredos do Jenkins (credenciais de deploy, chaves) e execução de código no "
            "controlador, com acesso à cadeia de entrega. A falha está no catálogo CISA KEV, com uso "
            "em ransomware."
        ),
        steps=(
            "Atualize: semanal para 2.442 ou mais novo; LTS para 2.426.3, 2.440.1 ou mais novo.",
            "Se não puder atualizar agora, desative o acesso à CLI como descreve o aviso oficial: não "
            "exige reiniciar, mas é só provisório.",
            "Não deixe o Jenkins aberto à Internet: use VPN ou uma lista de permissão no firewall.",
            "Se esteve exposto, troque as credenciais guardadas e revise os trabalhos e usuários.",
        ),
        examples=(
            Fix(
                "jenkins",
                "Debian/Ubuntu",
                "sudo apt update && sudo apt install --only-upgrade jenkins\n"
                "sudo systemctl restart jenkins",
                "bash",
            ),
            _dnf("jenkins", "jenkins", "sudo systemctl restart jenkins"),
            Fix(
                "jenkins",
                "Docker",
                "docker pull jenkins/jenkins:lts\n# recrie o contêiner com a imagem nova, mantendo o volume de dados",
                "bash",
            ),
        ),
        verify="'curl -sI https://jenkins.exemplo/ | grep -i x-jenkins' deve mostrar uma versão corrigida.",
        effort="baixo",
        fix_group="atualizacao",
        references=(
            "https://www.jenkins.io/security/advisory/2024-01-24/",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-23897",
            KEV_CATALOG,
        ),
        cwe="CWE-27",
        owasp="A06:2021",
        cis=("7.4",),
        lgpd=True,
        tags=("versao", "cve", "jenkins"),
    ),
    KBEntry(
        id="net.versao.fim_de_vida.php",
        title="PHP em ramo sem suporte",
        category=Category.NETWORK,
        severity=Severity.HIGH,
        summary="O ramo do PHP anunciado pelo servidor chegou ao fim da vida e não recebe mais correções de segurança do projeto.",
        explanation=(
            "Cada ramo do PHP recebe correções de segurança por um prazo publicado em php.net. Depois "
            "disso, falhas novas ficam abertas. Distribuições podem manter o pacote por mais tempo com "
            "correções próprias: quando a versão anunciada traz marca de distribuição (por exemplo, "
            "7.4.3-4ubuntu2), o achado aparece como indício."
        ),
        risk=(
            "Falhas públicas do PHP ficam sem correção, e a aplicação inteira roda sobre uma base que "
            "ninguém mais conserta."
        ),
        steps=(
            "Confira a versão em uso: 'php -v' (e a página de informações do site, se houver).",
            "Teste a aplicação em um ramo com suporte (veja php.net/supported-versions.php).",
            "Atualize o PHP no servidor e reinicie o serviço web ou o PHP-FPM.",
            "Oculte a versão com 'expose_php = Off'. Isso só reduz a exposição e não substitui a atualização.",
        ),
        examples=(
            Fix(
                "php",
                "Debian/Ubuntu (exemplo com PHP 8.4)",
                "php -v\nsudo apt update && sudo apt install php8.4-fpm php8.4-cli\n"
                "sudo systemctl restart php8.4-fpm",
                "bash",
            ),
            Fix(
                "php",
                "Windows",
                "php -v\n# baixe o ramo com suporte em https://windows.php.net/download/ e aponte o "
                "site para a pasta nova\niisreset",
                "powershell",
            ),
            Fix("php", "php.ini", "expose_php = Off", "ini"),
        ),
        verify="'php -v' e o cabeçalho X-Powered-By (se ainda existir) devem mostrar um ramo listado como suportado em php.net.",
        effort="alto",
        fix_group="atualizacao",
        references=("https://www.php.net/eol.php", "https://www.php.net/supported-versions.php"),
        cwe="CWE-1104",
        owasp="A06:2021",
        cis=("2.2", "7.4"),
        tags=("versao", "fim-de-vida", "php"),
    ),
    KBEntry(
        id="net.versao.fim_de_vida.apache",
        title="Apache httpd em ramo sem suporte",
        category=Category.NETWORK,
        severity=Severity.HIGH,
        summary="O ramo do Apache httpd anunciado (2.2, 2.0 ou 1.3) não recebe mais versões nem correções de segurança.",
        explanation=(
            "O projeto Apache informa que o ramo 2.2 chegou ao fim da vida em dezembro de 2017 e que "
            "os ramos 2.0 e 1.3 não têm novas versões desde 2013 e 2010. As páginas de segurança deles "
            "avisam que falhas posteriores nem são mais investigadas. Distribuições podem manter "
            "pacotes antigos com correções próprias: com marca de distribuição no banner (por exemplo, "
            "'(CentOS)'), o achado aparece como indício."
        ),
        risk="Falhas públicas posteriores ao fim da vida ficam sem correção, em um serviço exposto na rede.",
        steps=(
            "Planeje a migração para o Apache httpd 2.4 atual.",
            "Revise a configuração: a sintaxe de controle de acesso mudou (guia oficial em "
            "httpd.apache.org/docs/2.4/upgrading.html).",
            "Se o Apache antigo vem de um sistema sem suporte, atualize também o sistema operacional.",
        ),
        examples=(
            Fix(
                "apache",
                "Debian/Ubuntu",
                "apache2 -v\nsudo apt update && sudo apt install --only-upgrade apache2\n"
                "sudo apache2ctl configtest && sudo systemctl restart apache2",
                "bash",
            ),
            _dnf(
                "apache",
                "httpd",
                "httpd -v",
                "sudo apachectl configtest && sudo systemctl restart httpd",
            ),
            Fix(
                "apache",
                "Controle de acesso: de 2.2 para 2.4",
                "# Apache 2.2\nOrder allow,deny\nAllow from all\n\n# Apache 2.4\nRequire all granted",
                "apache",
            ),
        ),
        verify="O cabeçalho Server (ou 'apachectl -v' no servidor) deve mostrar uma versão 2.4 atual.",
        effort="alto",
        fix_group="atualizacao",
        references=(
            "https://httpd.apache.org/security/vulnerabilities_22.html",
            "https://httpd.apache.org/security/vulnerabilities_20.html",
            "https://httpd.apache.org/security/vulnerabilities_13.html",
            "https://httpd.apache.org/docs/2.4/upgrading.html",
        ),
        cwe="CWE-1104",
        owasp="A06:2021",
        cis=("2.2", "7.4"),
        tags=("versao", "fim-de-vida", "apache"),
    ),
    KBEntry(
        id="net.versao.fim_de_vida.iis",
        title="IIS em versão sem suporte",
        category=Category.NETWORK,
        severity=Severity.HIGH,
        summary="A versão anunciada do IIS só existe em versões do Windows que já saíram de suporte.",
        explanation=(
            "O IIS faz parte do Windows e segue o ciclo de vida dele: o IIS 6.0 vem no Windows Server "
            "2003 (fim em 14/07/2015), o 7.0 e o 7.5 no 2008 e no 2008 R2 (14/01/2020) e o 8.0 e o 8.5 "
            "no 2012 e no 2012 R2 (10/10/2023). Até as atualizações pagas (ESU) desses sistemas já "
            "terminaram: as do 2012 R2 acabaram em outubro de 2026."
        ),
        risk="O servidor web e o próprio sistema ficam sem correções para falhas novas, em um serviço exposto na rede.",
        steps=(
            "Confirme a versão do Windows e do IIS no servidor.",
            "Migre o site para uma versão do Windows Server com suporte.",
            "Até a migração, isole o servidor da Internet e reduza os módulos do IIS ao mínimo.",
        ),
        examples=(
            Fix(
                "iis",
                "PowerShell: conferir as versões",
                "(Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\InetStp).VersionString\n"
                "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').ProductName",
                "powershell",
            ),
        ),
        verify="O cabeçalho Server deve mostrar Microsoft-IIS/10.0 em uma versão do Windows Server com suporte.",
        effort="alto",
        fix_group="atualizacao",
        references=(
            "https://learn.microsoft.com/en-us/lifecycle/products/internet-information-services-iis",
            "https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2003-",
            "https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2008",
            "https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2008-r2",
            "https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2012-r2",
        ),
        cwe="CWE-1104",
        owasp="A06:2021",
        cis=("2.2", "7.3"),
        tags=("versao", "fim-de-vida", "iis", "windows"),
    ),
    KBEntry(
        id="net.versao.ramo_antigo.nginx",
        title="nginx em ramo muito antigo",
        category=Category.NETWORK,
        severity=Severity.MEDIUM,
        summary="A versão anunciada do nginx é do ramo 1.14 ou anterior: a última versão desse ramo é de dezembro de 2018.",
        explanation=(
            "O nginx.org publica as correções só nos ramos atuais: os avisos de segurança indicam a "
            "partir de qual versão cada falha foi resolvida (a CVE-2021-23017, por exemplo, só a partir "
            "da 1.20.1). Ramos antigos ficam de fora. O projeto não publica uma data de fim de vida, e "
            "distribuições como o RHEL 8 mantêm o nginx 1.14 com correções próprias. Por isso o achado "
            "é um indício: confira de onde vem o pacote."
        ),
        risk="Falhas corrigidas depois do fim do ramo podem continuar abertas, em um serviço exposto na rede.",
        steps=(
            "Confira a origem do pacote: 'nginx -v' e o gerenciador de pacotes da distribuição.",
            "Se o pacote não tiver suporte do fornecedor, atualize para um ramo atual, pelo repositório "
            "da distribuição ou do nginx.org.",
            "Oculte a versão com 'server_tokens off;'. Isso só reduz a exposição e não substitui a atualização.",
        ),
        examples=(
            Fix(
                "nginx",
                "Debian/Ubuntu",
                "nginx -v\nsudo apt update && sudo apt install --only-upgrade nginx\n"
                "sudo nginx -t && sudo systemctl restart nginx",
                "bash",
            ),
            _dnf(
                "nginx",
                "nginx",
                "nginx -v",
                "rpm -q nginx",
                "sudo nginx -t && sudo systemctl restart nginx",
            ),
            Fix("nginx", "nginx.conf (bloco http)", "server_tokens off;", "nginx"),
        ),
        verify="'nginx -v' deve mostrar um ramo atual (veja nginx.org/en/download.html) ou o pacote deve ter suporte do fornecedor.",
        effort="medio",
        fix_group="atualizacao",
        references=(
            "https://nginx.org/en/CHANGES-1.14",
            "https://nginx.org/en/download.html",
            "https://nginx.org/en/security_advisories.html",
            "https://nginx.org/en/linux_packages.html",
        ),
        cwe="CWE-1104",
        owasp="A06:2021",
        cis=("2.2", "7.4"),
        tags=("versao", "ramo-antigo", "nginx"),
    ),
    KBEntry(
        id="net.versao.ramo_antigo.openssh",
        title="OpenSSH muito antigo",
        category=Category.NETWORK,
        severity=Severity.MEDIUM,
        summary="A versão anunciada do OpenSSH é anterior à 7.4, lançada em dezembro de 2016.",
        explanation=(
            "A versão 7.4 removeu do servidor o protocolo SSH-1 e trouxe várias correções de segurança, "
            "e outras vieram depois (lista em openssh.org/security.html). Quem ficou antes dela também "
            "não tem os algoritmos modernos. O projeto não publica uma data de fim de vida, e "
            "distribuições podem manter pacotes antigos com correções próprias: com marca de "
            "distribuição no banner, ou sem o sufixo 'p' do OpenSSH portátil (como na família Red Hat), "
            "o achado aparece como indício."
        ),
        risk="Falhas conhecidas e criptografia ultrapassada em um serviço de administração remota do servidor.",
        steps=(
            "Confira a versão e a origem do pacote: 'ssh -V' no servidor e o gerenciador de pacotes.",
            "Atualize o OpenSSH; em geral isso pede atualizar o sistema operacional, porque versões tão "
            "antigas costumam vir de sistemas já sem suporte.",
            "Restrinja a porta do SSH a endereços confiáveis enquanto a atualização não acontece.",
        ),
        examples=(
            _apt(
                "openssh", "openssh-server", "ssh -V", "sudo sshd -t && sudo systemctl restart ssh"
            ),
            _dnf(
                "openssh",
                "openssh-server",
                "ssh -V",
                "rpm -q openssh-server",
                "sudo sshd -t && sudo systemctl restart sshd",
            ),
        ),
        verify="O banner do servidor deve mostrar OpenSSH 7.4 ou mais novo; de preferência uma versão atual.",
        effort="medio",
        fix_group="atualizacao",
        references=(
            "https://www.openssh.org/txt/release-7.4",
            "https://www.openssh.org/security.html",
            "https://www.openssh.org/releasenotes.html",
        ),
        cwe="CWE-1104",
        owasp="A06:2021",
        cis=("2.2", "7.4"),
        tags=("versao", "ramo-antigo", "ssh"),
    ),
)
