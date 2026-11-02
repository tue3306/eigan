"""Base de conhecimento dos arquivos de configuração inseguros (servidores web e frameworks)."""

from __future__ import annotations

from ...core import kb
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Severity
from .config_common import (
    ACTUATOR,
    COOKIE,
    DEBUG,
    ERRORS,
    HOSTS,
    LISTING,
    SECRET_KEY,
    TLS_OLD,
    TRACE,
    URL_INCLUDE,
    VERSION,
)

_DJANGO = "https://docs.djangoproject.com/en/5.2/ref/settings/"
_DJANGO_CHECKLIST = "https://docs.djangoproject.com/en/5.2/howto/deployment/checklist/"
_ASPNET = "https://learn.microsoft.com/en-us/previous-versions/dotnet/netframework-4.0/"
_APACHE_CORE = "https://httpd.apache.org/docs/2.4/mod/core.html"

kb.register(
    KBEntry(
        id=VERSION,
        title="Configuração divulga a versão do servidor",
        category=Category.CODE,
        severity=Severity.LOW,
        summary=(
            "O arquivo de configuração faz o servidor web ou o PHP anunciar o produto e a versão "
            "exata nas respostas."
        ),
        explanation=(
            "server_tokens on (nginx), ServerTokens Full/OS/Minor/Minimal e ServerSignature On "
            "(Apache) e expose_php = On (PHP) colocam nome e versão do software no cabeçalho "
            "Server, no X-Powered-By ou no rodapé das páginas de erro. No nginx e no Apache a "
            "divulgação é o comportamento padrão quando a diretiva não aparece na configuração "
            "principal; no PHP, expose_php vem ligado por padrão."
        ),
        risk=(
            "Quem ataca cruza a versão com as listas públicas de vulnerabilidades e escolhe o "
            "exploit certo sem tentativa e erro. Ocultar a versão não corrige falhas, mas reduz o "
            "reconhecimento barato e os ataques automatizados."
        ),
        steps=(
            "nginx: coloque server_tokens off; no bloco http (vale para todos os sites).",
            "Apache: use ServerTokens Prod e ServerSignature Off na configuração principal "
            "(ServerTokens não vale dentro de VirtualHost nem no .htaccess).",
            "PHP: defina expose_php = Off no php.ini (essa diretiva só pode ser mudada ali).",
            "Recarregue o serviço (nginx -s reload, apachectl graceful, reinício do PHP-FPM).",
            "Continue atualizando o software: esconder a versão não substitui a atualização.",
        ),
        examples=(
            Fix("nginx", "nginx (nginx.conf)", "http {\n    server_tokens off;\n}", "nginx"),
            Fix(
                "apache",
                "Apache (httpd.conf / apache2.conf)",
                "ServerTokens Prod\nServerSignature Off",
                "apache",
            ),
            Fix("php", "PHP (php.ini)", "expose_php = Off", "ini"),
        ),
        verify=(
            "Depois de recarregar: curl -sI https://seu-site/ | grep -iE '^(server|x-powered-by):' "
            "— não deve aparecer número de versão nem X-Powered-By com o PHP."
        ),
        effort="baixo",
        fix_group="divulgacao",
        references=(
            "https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens",
            f"{_APACHE_CORE}#servertokens",
            f"{_APACHE_CORE}#serversignature",
            "https://www.php.net/manual/en/ini.core.php#ini.expose-php",
            "https://cwe.mitre.org/data/definitions/497.html",
        ),
        cwe="CWE-497",
        owasp="A05:2021",
        cis=("4.1", "16.7"),
        tags=("configuracao", "divulgacao"),
    ),
    KBEntry(
        id=LISTING,
        title="Configuração liga a listagem de diretórios",
        category=Category.CODE,
        severity=Severity.LOW,
        summary=(
            "O servidor web foi configurado para mostrar a lista de arquivos das pastas que não "
            "têm página inicial."
        ),
        explanation=(
            "autoindex on (nginx), Options Indexes ou Options All (Apache e .htaccess) e "
            '<directoryBrowse enabled="true" /> (IIS) fazem o servidor montar uma página com '
            "todos os arquivos da pasta quando não existe index.html ou index.php. Nos três a "
            "listagem vem desligada por padrão: ela só aparece porque alguém a ligou."
        ),
        risk=(
            "Qualquer pessoa navega pelas pastas e baixa arquivos que não têm link: backups, "
            "exportações, planilhas, documentos internos e arquivos de configuração."
        ),
        steps=(
            "nginx: troque autoindex on; por autoindex off; (ou apague a linha).",
            "Apache: use Options -Indexes, ou liste só as opções necessárias, sem Indexes nem All.",
            'IIS: defina <directoryBrowse enabled="false" /> no web.config.',
            "Se a pasta precisa mesmo de listagem (arquivos públicos), deixe nela só o que é público.",
            "Revise o que já esteve listado e retire os arquivos que não deveriam estar ali.",
        ),
        examples=(
            Fix(
                "nginx",
                "nginx (http, server ou location)",
                "location /arquivos/ {\n    autoindex off;\n}",
                "nginx",
            ),
            Fix(
                "apache",
                "Apache (config ou .htaccess)",
                '<Directory "/var/www/html">\n    Options -Indexes +FollowSymLinks\n</Directory>',
                "apache",
            ),
            Fix(
                "iis",
                "IIS (web.config)",
                '<system.webServer>\n  <directoryBrowse enabled="false" />\n</system.webServer>',
                "xml",
            ),
        ),
        verify="Abra no navegador uma pasta sem página inicial: deve responder 403 ou 404, não a lista.",
        effort="baixo",
        fix_group="exposicao",
        references=(
            f"{_APACHE_CORE}#options",
            "https://nginx.org/en/docs/http/ngx_http_autoindex_module.html",
            "https://learn.microsoft.com/en-us/iis/configuration/system.webserver/directorybrowse",
            "https://cwe.mitre.org/data/definitions/548.html",
        ),
        cwe="CWE-548",
        owasp="A05:2021",
        cis=("4.1", "3.3"),
        tags=("configuracao", "exposicao"),
    ),
    KBEntry(
        id=TLS_OLD,
        title="Configuração aceita protocolos SSL/TLS antigos",
        category=Category.CODE,
        severity=Severity.MEDIUM,
        summary=(
            "A configuração do servidor web habilita SSLv2, SSLv3, TLS 1.0 ou TLS 1.1, versões "
            "obsoletas do protocolo."
        ),
        explanation=(
            "ssl_protocols (nginx) e SSLProtocol (Apache mod_ssl) definem as versões aceitas. O "
            "SSL 2.0 foi proibido pela RFC 6176, o SSL 3.0 pela RFC 7568 e o TLS 1.0 e 1.1 foram "
            "descontinuados pela RFC 8996 (2021). O recomendado hoje é aceitar só TLS 1.2 e "
            "TLS 1.3, que é o padrão das versões atuais do nginx. No Apache 2.4 o padrão "
            "(all -SSLv3) ainda inclui TLS 1.0 e 1.1 quando o OpenSSL os suporta."
        ),
        risk=(
            "Protocolos antigos têm falhas conhecidas (POODLE no SSLv3, BEAST no TLS 1.0) e só "
            "negociam cifras fracas: um atacante na rede pode forçar o rebaixamento ou decifrar "
            "parte do tráfego. Também reprovam requisitos de conformidade como o PCI DSS."
        ),
        steps=(
            "nginx: ssl_protocols TLSv1.2 TLSv1.3; nos blocos http ou server.",
            "Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3 em cada VirtualHost com SSL e na "
            "configuração principal.",
            "Use o gerador de configuração da Mozilla (perfil intermediate) para ajustar também "
            "as cifras.",
            "Recarregue o serviço e teste a conexão com um cliente forçando TLS 1.1.",
        ),
        examples=(
            Fix("nginx", "nginx", "ssl_protocols TLSv1.2 TLSv1.3;", "nginx"),
            Fix("apache", "Apache (mod_ssl)", "SSLProtocol -all +TLSv1.2 +TLSv1.3", "apache"),
        ),
        verify=(
            "openssl s_client -connect seu-site:443 -tls1_1 deve falhar na negociação; com "
            "-tls1_2 deve conectar."
        ),
        effort="baixo",
        fix_group="tls",
        references=(
            "https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_protocols",
            "https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslprotocol",
            "https://www.rfc-editor.org/rfc/rfc8996",
            "https://www.rfc-editor.org/rfc/rfc7568",
            "https://ssl-config.mozilla.org/",
            "https://cwe.mitre.org/data/definitions/327.html",
        ),
        cwe="CWE-327",
        owasp="A02:2021",
        cis=("3.10",),
        tags=("configuracao", "tls"),
    ),
    KBEntry(
        id=TRACE,
        title="Configuração habilita o método TRACE",
        category=Category.CODE,
        severity=Severity.LOW,
        summary="O Apache está configurado com TraceEnable On (ou extended) e responde ao método TRACE.",
        explanation=(
            "TRACE devolve ao cliente a própria requisição recebida, com os cabeçalhos. Só serve "
            "para diagnóstico e, combinado com outras falhas, já permitiu ler cookies HttpOnly "
            "(Cross-Site Tracing). Com TraceEnable Off o Apache responde 405 a esse método."
        ),
        risk=(
            "Vazamento de cabeçalhos internos e de autenticação quando combinado com XSS ou "
            "proxies; aparece como reprovação em auditorias de conformidade."
        ),
        steps=(
            "Troque por TraceEnable Off na configuração principal do Apache e nos VirtualHosts.",
            "Se houver proxy ou balanceador na frente, bloqueie o TRACE nele também.",
            "Recarregue o Apache (apachectl graceful).",
        ),
        examples=(
            Fix("apache", "Apache", "TraceEnable Off", "apache"),
            Fix(
                "iis",
                "IIS (web.config, em <requestFiltering>)",
                '<verbs><add verb="TRACE" allowed="false" /></verbs>',
                "xml",
            ),
        ),
        verify="curl -si -X TRACE https://seu-site/ deve responder 405 (Method Not Allowed).",
        effort="baixo",
        fix_group="metodos",
        references=(
            f"{_APACHE_CORE}#traceenable",
            "https://owasp.org/www-community/attacks/Cross_Site_Tracing",
            "https://cwe.mitre.org/data/definitions/693.html",
        ),
        cwe="CWE-693",
        owasp="A05:2021",
        cis=("4.8",),
        tags=("configuracao", "metodos"),
    ),
    KBEntry(
        id=DEBUG,
        title="Modo de depuração ligado na configuração",
        category=Category.CODE,
        severity=Severity.MEDIUM,
        summary=(
            "A configuração deixa a aplicação em modo de depuração (DEBUG = True, debug=True, "
            'APP_DEBUG=true, compilation debug="true" ou trace aberto a qualquer computador).'
        ),
        explanation=(
            "Em modo de depuração os frameworks mostram páginas de erro com rastreamento de "
            "pilha, trechos de código, variáveis e configurações. No Flask o depurador do "
            "Werkzeug permite executar código Python pelo navegador. No Django, DEBUG = True "
            'também guarda na memória todas as consultas SQL. No ASP.NET, debug="true" compila '
            'binários de depuração e <trace localOnly="false"> deixa o Trace.axd aberto a '
            "qualquer computador. Arquivos de configuração de desenvolvimento (dev, local, test) "
            "não entram nesta checagem."
        ),
        risk=(
            "Quem provoca um erro vê caminhos, versões, consultas, variáveis de ambiente e às "
            "vezes senhas; com o depurador do Werkzeug exposto, consegue executar comandos no "
            "servidor."
        ),
        steps=(
            "Django: DEBUG = False em produção, lido de variável de ambiente.",
            "Flask: não use app.run(debug=True) em produção; sirva com Gunicorn, uWSGI ou "
            "Waitress, sem --debug.",
            "Laravel/Symfony: APP_DEBUG=false (ou 0) no .env do servidor de produção.",
            'ASP.NET: <compilation debug="false"> e <trace enabled="false" localOnly="true" /> '
            "(ou uma transformação Web.Release.config que remova o debug).",
            "Separe as configurações de desenvolvimento e de produção; no Django, rode "
            "python manage.py check --deploy antes de publicar.",
        ),
        examples=(
            Fix(
                "django",
                "Django (settings.py)",
                'import os\n\nDEBUG = os.environ.get("DJANGO_DEBUG", "0") == "1"',
                "python",
            ),
            Fix(
                "flask",
                "Flask",
                'if __name__ == "__main__":\n    app.run()  # sem debug=True\n'
                "# produção: gunicorn -w 4 app:app",
                "python",
            ),
            Fix(
                "laravel",
                "Laravel / Symfony (.env de produção)",
                "APP_ENV=production\nAPP_DEBUG=false",
                "ini",
            ),
            Fix(
                "aspnet",
                "ASP.NET (web.config)",
                '<system.web>\n  <compilation debug="false" />\n'
                '  <trace enabled="false" localOnly="true" />\n</system.web>',
                "xml",
            ),
        ),
        verify=(
            "Provoque um erro em produção (endereço inexistente ou parâmetro inválido): deve "
            "aparecer uma página genérica, sem rastreamento de pilha nem variáveis. No Django, "
            "python manage.py check --deploy não deve listar security.W018."
        ),
        effort="baixo",
        fix_group="debug",
        references=(
            f"{_DJANGO}#debug",
            _DJANGO_CHECKLIST,
            "https://flask.palletsprojects.com/en/stable/debugging/",
            "https://laravel.com/docs/11.x/configuration#debug-mode",
            f"{_ASPNET}s10awwz0(v=vs.100)",
            f"{_ASPNET}6915t83k(v=vs.100)",
            "https://cwe.mitre.org/data/definitions/489.html",
        ),
        cwe="CWE-489",
        owasp="A05:2021",
        cis=("4.1", "16.7"),
        lgpd=True,
        tags=("configuracao", "debug"),
    ),
    KBEntry(
        id=ERRORS,
        title="Erros detalhados exibidos aos visitantes",
        category=Category.CODE,
        severity=Severity.MEDIUM,
        summary=(
            "A configuração manda mostrar a mensagem técnica completa dos erros para qualquer "
            "visitante."
        ),
        explanation=(
            'display_errors = On (PHP), <customErrors mode="Off"> (ASP.NET), <httpErrors '
            'errorMode="Detailed"> (IIS) e config.consider_all_requests_local = true no '
            "ambiente de produção do Rails fazem as falhas aparecerem para o visitante com "
            "mensagem técnica, caminhos de arquivos e, muitas vezes, o rastreamento de pilha. A "
            "documentação do PHP diz que display_errors nunca deve ser usado em produção."
        ),
        risk=(
            "As mensagens revelam a estrutura interna (caminhos, consultas SQL, nomes de tabelas, "
            "versões), o que facilita explorar injeções e outras falhas, e às vezes trazem dados "
            "pessoais ou senhas."
        ),
        steps=(
            "PHP: display_errors = Off e log_errors = On no php.ini de produção (o modelo "
            "php.ini-production já vem assim).",
            'ASP.NET: <customErrors mode="RemoteOnly"> ou "On", com uma página de erro própria.',
            'IIS: <httpErrors errorMode="DetailedLocalOnly"> (o padrão) ou "Custom".',
            "Rails: config.consider_all_requests_local = false em config/environments/production.rb.",
            "Mande os detalhes para o log do servidor, nunca para a resposta.",
        ),
        examples=(
            Fix(
                "php",
                "PHP (php.ini)",
                "display_errors = Off\ndisplay_startup_errors = Off\nlog_errors = On",
                "ini",
            ),
            Fix(
                "aspnet",
                "ASP.NET (web.config)",
                '<system.web>\n  <customErrors mode="RemoteOnly" defaultRedirect="~/erro.html" />\n</system.web>',
                "xml",
            ),
            Fix(
                "iis",
                "IIS (web.config)",
                '<system.webServer>\n  <httpErrors errorMode="DetailedLocalOnly" />\n</system.webServer>',
                "xml",
            ),
            Fix(
                "rails",
                "Rails (config/environments/production.rb)",
                "config.consider_all_requests_local = false",
                "ruby",
            ),
        ),
        verify=(
            "Provoque um erro em produção e confira que a resposta mostra só uma página genérica; "
            "os detalhes devem aparecer apenas no log."
        ),
        effort="baixo",
        fix_group="debug",
        references=(
            "https://www.php.net/manual/en/errorfunc.configuration.php#ini.display-errors",
            f"{_ASPNET}h0hfz6fc(v=vs.100)",
            "https://learn.microsoft.com/en-us/iis/configuration/system.webserver/httperrors/",
            "https://guides.rubyonrails.org/configuring.html",
            "https://cwe.mitre.org/data/definitions/209.html",
        ),
        cwe="CWE-209",
        owasp="A05:2021",
        cis=("4.1", "16.7"),
        tags=("configuracao", "debug"),
    ),
    KBEntry(
        id=URL_INCLUDE,
        title="PHP permite incluir arquivos por URL (allow_url_include)",
        category=Category.CODE,
        severity=Severity.HIGH,
        summary=(
            "O php.ini liga allow_url_include, que deixa include e require carregarem código de "
            "endereços remotos."
        ),
        explanation=(
            "Com allow_url_include = On, include, include_once, require e require_once aceitam "
            "URLs (http://, ftp:// e outros wrappers de URL). Basta um parâmetro mal validado em "
            "um include para o servidor baixar e executar código PHP de um site do atacante "
            "(inclusão remota de arquivo). A diretiva vem desligada por padrão, foi descontinuada "
            "no PHP 7.4 e só tem efeito junto com allow_url_fopen."
        ),
        risk=(
            "Execução de código no servidor (controle da aplicação e dos dados) a partir de "
            "qualquer falha de inclusão de arquivo."
        ),
        steps=(
            "Defina allow_url_include = Off no php.ini (ou apague a linha: o padrão já é Off).",
            "Se possível, desligue também allow_url_fopen e use cURL ou Guzzle para baixar dados.",
            "Revise os include/require que usam variáveis e troque por listas de arquivos permitidos.",
            "Reinicie o PHP-FPM ou o Apache para aplicar.",
        ),
        examples=(
            Fix("php", "PHP (php.ini)", "allow_url_include = Off\nallow_url_fopen = Off", "ini"),
            Fix(
                "php",
                "PHP (include com lista de páginas permitidas)",
                "$paginas = ['inicio' => 'inicio.php', 'contato' => 'contato.php'];\n"
                "include __DIR__ . '/paginas/' . ($paginas[$_GET['p'] ?? ''] ?? 'inicio.php');",
                "php",
            ),
        ),
        verify="php -i | grep allow_url_include (ou phpinfo()) deve mostrar Off.",
        effort="baixo",
        fix_group="configuracao",
        references=(
            "https://www.php.net/manual/en/filesystem.configuration.php#ini.allow-url-include",
            "https://www.php.net/manual/en/function.include.php",
            "https://cwe.mitre.org/data/definitions/98.html",
        ),
        cwe="CWE-98",
        owasp="A05:2021",
        cis=("4.1", "16.7"),
        tags=("configuracao", "php"),
    ),
    KBEntry(
        id=HOSTS,
        title="Django aceita qualquer Host (ALLOWED_HOSTS com '*')",
        category=Category.CODE,
        severity=Severity.MEDIUM,
        summary="ALLOWED_HOSTS contém '*', então o Django aceita requisições com qualquer cabeçalho Host.",
        explanation=(
            "ALLOWED_HOSTS é a lista de nomes que o site atende; o Django a usa para validar o "
            "cabeçalho Host e barrar ataques de cabeçalho Host. Com '*' qualquer valor passa e, "
            "como avisa a documentação, a validação do Host fica por sua conta. Links absolutos "
            "gerados pela aplicação (redefinição de senha, e-mails) podem passar a apontar para o "
            "domínio do atacante."
        ),
        risk=(
            "Envenenamento do cabeçalho Host: e-mails de redefinição de senha com link para um "
            "site falso, envenenamento de cache e contorno de regras que dependem do domínio."
        ),
        steps=(
            "Liste apenas os domínios reais do site em ALLOWED_HOSTS.",
            "Leia a lista de uma variável de ambiente em vez de deixá-la fixa no código.",
            "Para aceitar subdomínios, use '.exemplo.com.br' (com ponto inicial), nunca '*'.",
            "Rode python manage.py check --deploy antes de publicar.",
        ),
        examples=(
            Fix(
                "django",
                "Django (settings.py)",
                'ALLOWED_HOSTS = ["exemplo.com.br", "www.exemplo.com.br"]\n'
                '# ou: [h for h in os.environ.get("DJANGO_ALLOWED_HOSTS", "").split(",") if h]',
                "python",
            ),
        ),
        verify="curl -si -H 'Host: atacante.example' https://seu-site/ deve responder 400 (Bad Request).",
        effort="baixo",
        fix_group="configuracao",
        references=(
            f"{_DJANGO}#allowed-hosts",
            "https://docs.djangoproject.com/en/5.2/topics/security/#host-header-validation",
            "https://cwe.mitre.org/data/definitions/20.html",
        ),
        cwe="CWE-20",
        owasp="A05:2021",
        cis=("4.1", "16.7"),
        tags=("configuracao", "django"),
    ),
    KBEntry(
        id=SECRET_KEY,
        title="Chave secreta do Django escrita no código",
        category=Category.CODE,
        severity=Severity.HIGH,
        summary=(
            "SECRET_KEY está fixa no arquivo de configuração em vez de vir do ambiente ou de um "
            "cofre de segredos."
        ),
        explanation=(
            "O Django usa a SECRET_KEY para assinar sessões, cookies, tokens de redefinição de "
            "senha e mensagens: quem conhece a chave consegue forjar esses dados. A documentação "
            "avisa que rodar o Django com uma SECRET_KEY conhecida anula muitas proteções e pode "
            "levar a escalada de privilégios e execução remota de código. Chaves com o prefixo "
            "django-insecure- são as geradas pelo startproject, próprias só para desenvolvimento."
        ),
        risk=(
            "Forjar sessões de qualquer usuário (inclusive administradores), gerar links de "
            "redefinição de senha válidos e, em algumas configurações, executar código no servidor."
        ),
        steps=(
            'Gere uma chave nova: python -c "from django.core.management.utils import '
            'get_random_secret_key; print(get_random_secret_key())"',
            'Leia a chave do ambiente (SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]), sem valor '
            "padrão escrito no código.",
            "Considere a chave antiga comprometida e troque-a; se precisar de transição, use "
            "SECRET_KEY_FALLBACKS por pouco tempo.",
            "Se o repositório é compartilhado, remova a chave também do histórico.",
        ),
        examples=(
            Fix(
                "django",
                "Django (settings.py)",
                'import os\n\nSECRET_KEY = os.environ["DJANGO_SECRET_KEY"]',
                "python",
            ),
            Fix(
                "linux",
                "Linux (systemd, arquivo de ambiente com permissão 600)",
                "[Service]\nEnvironmentFile=/etc/minha-app/segredos.env",
                "ini",
            ),
        ),
        verify=(
            "python manage.py check --deploy não deve listar security.W009 e a busca por "
            "SECRET_KEY no repositório não deve encontrar valores."
        ),
        effort="baixo",
        fix_group="segredos",
        references=(
            f"{_DJANGO}#secret-key",
            _DJANGO_CHECKLIST,
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/321.html",
        ),
        cwe="CWE-321",
        owasp="A02:2021",
        cis=("3.11", "16.12"),
        tags=("configuracao", "segredos", "django"),
    ),
    KBEntry(
        id=COOKIE,
        title="Cookies de sessão sem proteção na configuração",
        category=Category.CODE,
        severity=Severity.MEDIUM,
        summary=(
            "A configuração desliga (ou não liga) as proteções Secure e HttpOnly dos cookies de "
            "sessão e de CSRF."
        ),
        explanation=(
            "No Django, SESSION_COOKIE_SECURE e CSRF_COOKIE_SECURE vêm False por padrão e "
            "precisam ser True em sites HTTPS; SESSION_COOKIE_HTTPONLY = False deixa o "
            'JavaScript ler o cookie de sessão. No ASP.NET, <httpCookies requireSSL="false"> e '
            'httpOnlyCookies="false" (os dois são false por padrão) fazem os cookies irem por '
            "HTTP sem criptografia e ficarem acessíveis a scripts."
        ),
        risk=(
            "Sem Secure, o cookie de sessão pode vazar numa conexão HTTP (Wi-Fi público, "
            "rebaixamento de protocolo); sem HttpOnly, um XSS rouba a sessão com document.cookie."
        ),
        steps=(
            "Django: SESSION_COOKIE_SECURE = True, CSRF_COOKIE_SECURE = True e mantenha "
            "SESSION_COOKIE_HTTPONLY = True (o padrão).",
            'ASP.NET: <httpCookies requireSSL="true" httpOnlyCookies="true" /> e requireSSL="true" '
            "também em <forms>, se usar autenticação por formulário.",
            "Sirva o site só por HTTPS (redirecionamento e HSTS).",
            "Depois da mudança, peça novo login: sessões antigas podem ter vazado.",
        ),
        examples=(
            Fix(
                "django",
                "Django (settings.py)",
                "SESSION_COOKIE_SECURE = True\nCSRF_COOKIE_SECURE = True\nSESSION_COOKIE_HTTPONLY = True",
                "python",
            ),
            Fix(
                "aspnet",
                "ASP.NET (web.config)",
                '<system.web>\n  <httpCookies requireSSL="true" httpOnlyCookies="true" />\n</system.web>',
                "xml",
            ),
        ),
        verify=(
            "Faça login e abra as ferramentas do navegador (F12 > Application > Cookies): o "
            "cookie de sessão deve estar com Secure e HttpOnly marcados."
        ),
        effort="baixo",
        fix_group="cookies",
        references=(
            f"{_DJANGO}#session-cookie-secure",
            f"{_DJANGO}#csrf-cookie-secure",
            f"{_ASPNET}ms228262(v=vs.100)",
            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/614.html",
        ),
        cwe="CWE-614",
        owasp="A05:2021",
        cis=("3.10",),
        tags=("configuracao", "cookies"),
    ),
    KBEntry(
        id=ACTUATOR,
        title="Spring Boot Actuator exposto pela configuração",
        category=Category.CODE,
        severity=Severity.HIGH,
        summary=(
            "A configuração do Spring Boot publica pela web endpoints sensíveis do Actuator "
            "(include=*, env, heapdump, shutdown...)."
        ),
        explanation=(
            "Por padrão o Spring Boot expõe por HTTP só o endpoint health. "
            "management.endpoints.web.exposure.include=* (ou uma lista com env, heapdump, "
            "threaddump, configprops, logfile, shutdown...) publica endpoints que mostram a "
            "configuração, as variáveis, a memória da aplicação ou até desligam o serviço. A "
            "documentação lembra que endpoints podem conter informação sensível; se o Spring "
            "Security não protege esses caminhos, qualquer pessoa os acessa. Perfis de "
            "desenvolvimento (application-dev, -local, -test) não entram nesta checagem."
        ),
        risk=(
            "Heap dump com senhas, tokens e sessões em memória; /env e /configprops revelam a "
            "configuração; /shutdown derruba a aplicação; outros endpoints alteram o comportamento."
        ),
        steps=(
            "Exponha só o necessário: management.endpoints.web.exposure.include=health (e info).",
            "Mova o Actuator para uma porta interna (management.server.port e "
            "management.server.address=127.0.0.1).",
            "Proteja /actuator/** com o Spring Security (papel de operação).",
            "Não libere shutdown nem heapdump sem necessidade e mantenha show-values=never.",
            "Se env ou heapdump estiveram públicos, troque as senhas e chaves da aplicação.",
        ),
        examples=(
            Fix(
                "spring",
                "Spring Boot (application.properties)",
                "management.endpoints.web.exposure.include=health\n"
                "management.server.port=8081\nmanagement.server.address=127.0.0.1",
                "properties",
            ),
            Fix(
                "spring",
                "Spring Boot (application.yml)",
                'management:\n  endpoints:\n    web:\n      exposure:\n        include: "health"',
                "yaml",
            ),
        ),
        verify=(
            "curl -s https://seu-site/actuator deve responder 404 ou listar só health; "
            "/actuator/env deve responder 401, 403 ou 404."
        ),
        effort="baixo",
        fix_group="debug",
        references=(
            "https://docs.spring.io/spring-boot/reference/actuator/endpoints.html",
            "https://docs.spring.io/spring-boot/3.3/reference/actuator/endpoints.html",
            "https://cwe.mitre.org/data/definitions/497.html",
        ),
        cwe="CWE-497",
        owasp="A05:2021",
        cis=("4.1", "4.8"),
        lgpd=True,
        tags=("configuracao", "debug", "spring"),
    ),
)
