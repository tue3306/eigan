"""Base de conhecimento: páginas de diagnóstico, painéis, documentação de API e metarquivos."""

from __future__ import annotations

from ...core import kb
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Severity

_WSTG = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/"
WSTG_PLATFORM = (
    _WSTG
    + "02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration"
)
WSTG_METAFILES = (
    _WSTG + "01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage"
)
WSTG_ADMIN = (
    _WSTG
    + "02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces"
)

kb.register(
    KBEntry(
        id="web.exposicao.phpinfo",
        title="Página phpinfo() exposta",
        category=Category.WEB,
        severity=Severity.MEDIUM,
        summary="Uma página de diagnóstico do PHP mostra a configuração completa do servidor.",
        explanation=(
            "A função phpinfo() lista a versão do PHP, módulos, caminhos de pastas, variáveis de "
            "ambiente e cabeçalhos da requisição. Costuma ser criada para um teste rápido e "
            "esquecida. Às vezes as variáveis de ambiente incluem senhas e chaves."
        ),
        risk="Mapa detalhado do servidor e possíveis segredos em variáveis de ambiente.",
        steps=(
            "Apague o arquivo de teste (phpinfo.php, info.php, test.php...).",
            "Se precisar do diagnóstico, gere-o na linha de comando (php -i), nunca pela web.",
            "Opcional: bloqueie a função no php.ini.",
        ),
        examples=(
            Fix("generico", "Apagar o arquivo (Linux)", "rm /var/www/html/phpinfo.php", "bash"),
            Fix("php", "PHP (php.ini)", "disable_functions = phpinfo", "ini"),
            Fix(
                "nginx",
                "nginx (dentro de server {})",
                r"location ~* /(phpinfo|info|test)\.php$ { deny all; }",
                "nginx",
            ),
            Fix(
                "apache",
                "Apache (config ou .htaccess)",
                r'RedirectMatch 404 "/(phpinfo|info|test)\.php$"',
                "apache",
            ),
        ),
        verify="curl -si https://seu-site/phpinfo.php deve responder 404.",
        effort="baixo",
        fix_group="debug",
        references=("https://www.php.net/manual/en/function.phpinfo.php", WSTG_PLATFORM),
        cwe="CWE-497",
        owasp="A05:2021",
        cis=("4.1", "4.8"),
        tags=("debug", "php"),
    ),
    KBEntry(
        id="web.exposicao.status",
        title="Página de status do servidor web exposta",
        category=Category.WEB,
        severity=Severity.MEDIUM,
        summary="A página de status do servidor web (Apache, nginx, PHP-FPM) ou as métricas internas podem ser vistas por qualquer pessoa.",
        explanation=(
            "O server-status do Apache mostra em tempo real as requisições em andamento: "
            "endereços IP dos visitantes, sites e URLs acessadas (às vezes com tokens na URL). O "
            "server-info mostra a configuração. O stub_status do nginx, o status do PHP-FPM e as "
            "métricas do Prometheus revelam contadores e nomes internos."
        ),
        risk="Vazamento de URLs internas, IPs de clientes e parâmetros sensíveis; ajuda a planejar ataques.",
        steps=(
            "Restrinja a página de status ao endereço local ou à rede de monitoramento.",
            "Se não usa, desative o módulo (Apache: mod_status e mod_info).",
        ),
        examples=(
            Fix(
                "apache",
                "Apache (restringir ao servidor local)",
                '<Location "/server-status">\n    Require local\n</Location>',
                "apache",
            ),
            Fix(
                "apache",
                "Apache (desativar o módulo)",
                "sudo a2dismod status info && sudo systemctl reload apache2",
                "bash",
            ),
            Fix(
                "nginx",
                "nginx (dentro de server {})",
                "location = /nginx_status { stub_status; allow 127.0.0.1; deny all; }",
                "nginx",
            ),
        ),
        verify="curl -si https://seu-site/server-status deve responder 403 ou 404.",
        effort="baixo",
        fix_group="debug",
        references=(
            "https://httpd.apache.org/docs/2.4/mod/mod_status.html",
            "https://nginx.org/en/docs/http/ngx_http_stub_status_module.html",
        ),
        cwe="CWE-497",
        owasp="A05:2021",
        cis=("4.1", "4.8"),
        lgpd=True,
        tags=("debug",),
    ),
    KBEntry(
        id="web.exposicao.actuator",
        title="Spring Boot Actuator exposto",
        category=Category.WEB,
        severity=Severity.HIGH,
        summary="Endpoints de gerenciamento do Spring Boot (Actuator) respondem pela Internet.",
        explanation=(
            "O Actuator traz endpoints de operação: /env (variáveis e propriedades), /heapdump "
            "(cópia da memória da aplicação, com senhas e sessões), /configprops, /mappings, "
            "/loggers. São feitos para a equipe de operação e não devem ficar públicos."
        ),
        risk=(
            "Um heap dump entrega senhas, tokens e dados de usuários em memória; /env e "
            "/configprops revelam a configuração; alguns endpoints permitem alterar o "
            "comportamento da aplicação."
        ),
        steps=(
            "Exponha pela web só o necessário (normalmente health), sem detalhes.",
            "Mova o Actuator para uma porta de gerenciamento interna ou proteja-o com Spring Security.",
            "Se o heapdump ou o env estiveram públicos, troque as senhas e chaves da aplicação.",
        ),
        examples=(
            Fix(
                "spring",
                "Spring Boot (application.properties)",
                "management.endpoints.web.exposure.include=health\nmanagement.endpoint.health.show-details=never",
                "properties",
            ),
            Fix(
                "spring",
                "Spring Boot (porta de gerenciamento interna)",
                "management.server.port=8081\nmanagement.server.address=127.0.0.1",
                "properties",
            ),
        ),
        verify="curl -si https://seu-site/actuator deve responder 404, ou listar só health.",
        effort="baixo",
        fix_group="debug",
        references=(
            "https://docs.spring.io/spring-boot/reference/actuator/endpoints.html",
            "https://cwe.mitre.org/data/definitions/497.html",
        ),
        cwe="CWE-497",
        owasp="A05:2021",
        cis=("4.1", "4.8"),
        lgpd=True,
        tags=("debug", "java"),
    ),
    KBEntry(
        id="web.exposicao.diagnostico",
        title="Ferramenta de depuração exposta",
        category=Category.WEB,
        severity=Severity.HIGH,
        summary="Uma ferramenta de depuração (ELMAH, Trace.axd, Symfony Profiler, Telescope, Ignition, Jolokia, pprof) está pública.",
        explanation=(
            "Essas ferramentas registram tudo o que acontece na aplicação: requisições com "
            "cabeçalhos e cookies, consultas ao banco, exceções e variáveis. São úteis no "
            "desenvolvimento, mas em produção qualquer pessoa pode ler sessões de outros usuários."
        ),
        risk="Roubo de sessões (cookies registrados), vazamento de dados pessoais e de detalhes internos.",
        steps=(
            "Desative a ferramenta em produção ou restrinja-a ao acesso local.",
            "Coloque a aplicação em modo de produção (sem depuração).",
            "Se havia sessões registradas, encerre-as (troque a chave de sessão).",
        ),
        examples=(
            Fix(
                "aspnet",
                "ASP.NET (web.config — ELMAH)",
                '<elmah><security allowRemoteAccess="false" /></elmah>',
                "xml",
            ),
            Fix(
                "aspnet",
                "ASP.NET (web.config — Trace.axd)",
                '<trace enabled="false" localOnly="true" />',
                "xml",
            ),
            Fix("symfony", "Symfony (.env.local)", "APP_ENV=prod\nAPP_DEBUG=0", "ini"),
            Fix("laravel", "Laravel (.env)", "TELESCOPE_ENABLED=false", "ini"),
            Fix(
                "laravel",
                "Laravel (.env — desliga a página de erro do Ignition)",
                "APP_ENV=production\nAPP_DEBUG=false",
                "ini",
            ),
            Fix(
                "generico",
                "Jolokia (jolokia-access.xml)",
                "<restrict><remote><host>127.0.0.1</host></remote></restrict>",
                "xml",
            ),
            Fix(
                "generico",
                "Go (net/http/pprof)",
                '// Exponha o pprof só em uma porta interna, nunca no servidor público:\ngo http.ListenAndServe("127.0.0.1:6060", nil)',
                "go",
            ),
        ),
        verify="Abra a URL da ferramenta: deve responder 403 ou 404.",
        effort="baixo",
        fix_group="debug",
        references=(
            "https://symfony.com/doc/current/profiler.html",
            "https://laravel.com/docs/telescope",
            "https://elmah.github.io/",
            "https://pkg.go.dev/net/http/pprof",
            "https://cwe.mitre.org/data/definitions/215.html",
        ),
        cwe="CWE-215",
        owasp="A05:2021",
        cis=("4.1", "16.7"),
        lgpd=True,
        tags=("debug",),
    ),
    KBEntry(
        id="web.exposicao.api_docs",
        title="Documentação da API pública",
        category=Category.WEB,
        severity=Severity.LOW,
        summary="A especificação (OpenAPI/Swagger) ou a interface de documentação da API está pública.",
        explanation=(
            "A documentação lista todas as rotas, parâmetros e modelos de dados da API, inclusive "
            "rotas administrativas e internas. Para APIs públicas isso pode ser intencional; para "
            "APIs internas, é um mapa pronto para o atacante."
        ),
        risk="Reconhecimento facilitado: rotas esquecidas, internas ou sem autenticação ficam visíveis.",
        steps=(
            "Confirme se a documentação precisa ser pública.",
            "Se não precisa, desative-a em produção ou exija autenticação.",
            "Revise se as rotas listadas exigem autenticação e autorização.",
        ),
        examples=(
            Fix(
                "spring",
                "Spring (springdoc, application.properties)",
                "springdoc.api-docs.enabled=false\nspringdoc.swagger-ui.enabled=false",
                "properties",
            ),
            Fix(
                "aspnet",
                "ASP.NET Core (Program.cs)",
                "if (app.Environment.IsDevelopment()) { app.UseSwagger(); app.UseSwaggerUI(); }",
                "csharp",
            ),
            Fix(
                "express",
                "Node.js (swagger-ui-express)",
                "if (process.env.NODE_ENV !== 'production') app.use('/docs', swaggerUi.serve, swaggerUi.setup(spec));",
                "javascript",
            ),
            Fix(
                "fastapi",
                "FastAPI",
                "app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)",
                "python",
            ),
        ),
        verify="Abra /swagger.json, /openapi.json e /swagger-ui.html: devem responder 401, 403 ou 404.",
        effort="baixo",
        fix_group="exposicao",
        references=(
            "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/",
            "https://cwe.mitre.org/data/definitions/200.html",
        ),
        cwe="CWE-200",
        owasp="A05:2021",
        cis=("4.1", "16.7"),
        tags=("api",),
    ),
    KBEntry(
        id="web.exposicao.graphql",
        title="Introspecção do GraphQL habilitada",
        category=Category.WEB,
        severity=Severity.LOW,
        summary="A API GraphQL responde à consulta de introspecção, que devolve o esquema completo.",
        explanation=(
            "A introspecção lista todos os tipos, campos, consultas e mutações da API. É prática "
            "no desenvolvimento; em produção, entrega o mapa de dados e de operações — inclusive "
            "mutações administrativas que não aparecem no site."
        ),
        risk="Facilita achar operações sem autorização e campos com dados sensíveis.",
        steps=(
            "Desative a introspecção em produção (a menos que a API seja pública por desenho).",
            "Desative também as interfaces de teste (GraphiQL, Playground) em produção.",
            "Garanta autorização por campo/operação; não conte com o esquema ser secreto.",
        ),
        examples=(
            Fix(
                "express",
                "Apollo Server (Node.js)",
                "new ApolloServer({ schema, introspection: process.env.NODE_ENV !== 'production' })",
                "javascript",
            ),
            Fix(
                "spring",
                "Spring for GraphQL (application.properties)",
                "spring.graphql.schema.introspection.enabled=false",
                "properties",
            ),
            Fix(
                "generico",
                "graphql-js / servidores baseados nele (regra de validação)",
                "validationRules: [NoSchemaIntrospectionCustomRule]  // import { NoSchemaIntrospectionCustomRule } from 'graphql'",
                "javascript",
            ),
        ),
        verify=(
            "curl -s -X POST -H 'Content-Type: application/json' -d '{\"query\":\"{__schema{queryType{name}}}\"}' "
            "https://seu-site/graphql deve devolver erro, não o esquema."
        ),
        effort="baixo",
        fix_group="exposicao",
        references=(
            "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
            "https://graphql.org/learn/introspection/",
        ),
        cwe="CWE-200",
        owasp="A05:2021",
        cis=("4.1", "16.7"),
        tags=("api", "graphql"),
    ),
    KBEntry(
        id="web.painel.exposto",
        title="Painel administrativo acessível pela Internet",
        category=Category.WEB,
        severity=Severity.MEDIUM,
        summary="A tela de acesso de um painel administrativo (banco de dados, servidor, CMS) está aberta para a Internet.",
        explanation=(
            "Painéis como phpMyAdmin, Adminer, Tomcat Manager, console H2 e áreas administrativas "
            "de CMS dão controle total sobre o banco ou o servidor. Abertos para a Internet, "
            "recebem tentativas de senha o tempo todo e são os primeiros alvos quando surge uma "
            "falha nova no produto."
        ),
        risk="Invasão por senha fraca, vazada ou padrão, ou por falha do próprio painel: controle do banco/servidor.",
        steps=(
            "Restrinja o painel por IP (rede da empresa) ou deixe-o acessível só pela VPN.",
            "Exija autenticação de dois fatores (MFA) para administradores.",
            "Se o painel não é usado, remova-o do servidor.",
            "Troque senhas padrão e use senhas longas e únicas.",
        ),
        examples=(
            Fix(
                "nginx",
                "nginx (restringir por IP)",
                "location /phpmyadmin/ { allow 203.0.113.0/24; deny all; }",
                "nginx",
            ),
            Fix(
                "apache",
                "Apache (restringir por IP)",
                '<Location "/phpmyadmin">\n    Require ip 203.0.113.0/24\n</Location>',
                "apache",
            ),
            Fix(
                "iis",
                "IIS (web.config da pasta do painel)",
                '<security><ipSecurity allowUnlisted="false"><add ipAddress="203.0.113.0" subnetMask="255.255.255.0" allowed="true" /></ipSecurity></security>',
                "xml",
            ),
            Fix(
                "tomcat",
                "Tomcat (META-INF/context.xml do manager)",
                '<Valve className="org.apache.catalina.valves.RemoteAddrValve" allow="127\\.\\d+\\.\\d+\\.\\d+|::1" />',
                "xml",
            ),
            Fix(
                "wordpress",
                "WordPress (.htaccess dentro de wp-admin)",
                "Require ip 203.0.113.0/24",
                "apache",
            ),
            Fix(
                "cloudflare",
                "Cloudflare Zero Trust (Access)",
                "Crie uma aplicação do Access para o caminho do painel e exija login + MFA.",
                "text",
            ),
        ),
        verify="De uma rede externa, a URL do painel deve responder 403/404 ou exigir a VPN.",
        effort="medio",
        fix_group="admin",
        references=(
            WSTG_ADMIN,
            "https://docs.phpmyadmin.net/en/latest/setup.html#securing-your-phpmyadmin-installation",
            "https://tomcat.apache.org/tomcat-10.1-doc/manager-howto.html",
            "https://developer.wordpress.org/advanced-administration/security/hardening/",
        ),
        cwe="CWE-284",
        owasp="A05:2021",
        cis=("6.5", "4.1"),
        tags=("admin",),
    ),
    KBEntry(
        id="web.exposicao.listagem",
        title="Listagem de diretório habilitada",
        category=Category.WEB,
        severity=Severity.LOW,
        summary="O servidor mostra a lista de arquivos de uma pasta quando não há página inicial nela.",
        explanation=(
            "Com a listagem ligada, qualquer pessoa navega pelas pastas do site e vê todos os "
            "arquivos, inclusive os que não têm link: backups, planilhas, documentos internos e "
            "arquivos de configuração."
        ),
        risk="Descoberta e download de arquivos que não deveriam ser públicos.",
        steps=(
            "Desligue a listagem de diretórios no servidor web (exemplos abaixo).",
            "Revise as pastas que estavam listadas e retire o que não deveria estar lá.",
        ),
        examples=(
            Fix("apache", "Apache (config ou .htaccess)", "Options -Indexes", "apache"),
            Fix("litespeed", "LiteSpeed (.htaccess)", "Options -Indexes", "apache"),
            Fix("nginx", "nginx (http, server ou location)", "autoindex off;", "nginx"),
            Fix(
                "iis",
                "IIS (web.config, em <system.webServer>)",
                '<directoryBrowse enabled="false" />',
                "xml",
            ),
            Fix(
                "express",
                "Node.js / Express (serve-index)",
                "// remova app.use(serveIndex(...)) — sirva só arquivos com express.static",
                "javascript",
            ),
            Fix(
                "tomcat",
                "Tomcat (web.xml, servlet default)",
                "<init-param><param-name>listings</param-name><param-value>false</param-value></init-param>",
                "xml",
            ),
        ),
        verify="Abra a pasta listada no navegador: deve responder 403 ou 404.",
        effort="baixo",
        fix_group="exposicao",
        references=(
            "https://httpd.apache.org/docs/2.4/mod/core.html#options",
            "https://nginx.org/en/docs/http/ngx_http_autoindex_module.html",
            "https://learn.microsoft.com/en-us/iis/configuration/system.webserver/directorybrowse",
            "https://cwe.mitre.org/data/definitions/548.html",
        ),
        cwe="CWE-548",
        owasp="A05:2021",
        cis=("4.1", "3.3"),
        tags=("exposicao",),
    ),
    KBEntry(
        id="web.exposicao.pagina_padrao",
        title="Página padrão de instalação do servidor",
        category=Category.WEB,
        severity=Severity.LOW,
        summary="O endereço mostra a página de boas-vindas da instalação do servidor web.",
        explanation=(
            "A página padrão (It works!, Welcome to nginx, IIS, Tomcat) indica um servidor "
            "instalado e esquecido, ou um site apontado para o lugar errado. Servidores "
            "esquecidos raramente recebem atualizações e revelam o produto usado."
        ),
        risk="Servidor sem dono e sem atualização exposto à Internet; revela o produto do servidor.",
        steps=(
            "Confirme se este endereço deveria estar no ar.",
            "Se não deveria, desligue o serviço ou feche a porta no firewall.",
            "Se deveria, publique o site correto e remova o conteúdo padrão da instalação.",
        ),
        examples=(
            Fix(
                "apache",
                "Apache (Debian/Ubuntu)",
                "sudo a2dissite 000-default && sudo systemctl reload apache2",
                "bash",
            ),
            Fix(
                "nginx",
                "nginx (Debian/Ubuntu)",
                "sudo rm /etc/nginx/sites-enabled/default && sudo systemctl reload nginx",
                "bash",
            ),
            Fix(
                "iis",
                "IIS (PowerShell)",
                "Remove-Item C:\\inetpub\\wwwroot\\iisstart.*",
                "powershell",
            ),
            Fix(
                "tomcat",
                "Tomcat",
                "rm -rf $CATALINA_HOME/webapps/ROOT $CATALINA_HOME/webapps/docs $CATALINA_HOME/webapps/examples",
                "bash",
            ),
        ),
        verify="Abra o endereço: deve mostrar o site correto (ou não responder).",
        effort="baixo",
        fix_group="divulgacao",
        references=(WSTG_PLATFORM,),
        cwe="CWE-200",
        owasp="A05:2021",
        cis=("4.1", "4.8"),
        tags=("divulgacao",),
    ),
    KBEntry(
        id="web.robots.sensivel",
        title="robots.txt cita caminhos sensíveis",
        category=Category.WEB,
        severity=Severity.INFO,
        summary="O robots.txt lista áreas que parecem internas (admin, backup, config...).",
        explanation=(
            "O robots.txt só pede aos buscadores que não indexem certas pastas; ele não protege "
            "nada e qualquer pessoa pode lê-lo. Listar ali áreas internas aponta exatamente onde "
            "procurar."
        ),
        risk="Atalho para o reconhecimento; o risco real depende de essas áreas estarem protegidas.",
        steps=(
            "Garanta que as áreas citadas exigem autenticação ou não estão publicadas.",
            "Prefira não listar caminhos internos no robots.txt (use autenticação e noindex).",
        ),
        examples=(
            Fix(
                "generico",
                "Cabeçalho para não indexar uma área (em vez de citá-la)",
                "X-Robots-Tag: noindex",
                "text",
            ),
        ),
        verify="curl -s https://seu-site/robots.txt e revise os caminhos citados.",
        effort="baixo",
        fix_group="divulgacao",
        references=(WSTG_METAFILES, "https://www.rfc-editor.org/rfc/rfc9309"),
        cwe="CWE-200",
        owasp="A05:2021",
        cis=("4.1",),
        tags=("divulgacao",),
    ),
    KBEntry(
        id="web.securitytxt.ausente",
        title="Sem security.txt",
        category=Category.WEB,
        severity=Severity.INFO,
        summary="O site não publica o arquivo /.well-known/security.txt com o contato de segurança.",
        explanation=(
            "O security.txt (RFC 9116) diz a pesquisadores e a quem encontrar uma falha como "
            "avisar a sua equipe. Sem ele, avisos importantes se perdem em canais genéricos ou "
            "nem chegam."
        ),
        risk="Falhas encontradas por terceiros demoram a chegar à equipe certa.",
        steps=(
            "Crie /.well-known/security.txt com Contact (e-mail ou formulário) e Expires (até 1 ano).",
            "Opcional: inclua Policy (política de divulgação) e Preferred-Languages: pt, en.",
        ),
        examples=(
            Fix(
                "generico",
                "Conteúdo de /.well-known/security.txt",
                "Contact: mailto:seguranca@exemplo.com.br\nExpires: 2027-10-31T23:59:59Z\nPreferred-Languages: pt, en",
                "text",
            ),
        ),
        verify="curl -s https://seu-site/.well-known/security.txt deve mostrar Contact e Expires.",
        effort="baixo",
        fix_group="conteudo",
        references=("https://www.rfc-editor.org/rfc/rfc9116", "https://securitytxt.org/"),
        cwe="CWE-1059",
        owasp="A05:2021",
        cis=("7.1",),
        tags=("securitytxt",),
    ),
    KBEntry(
        id="web.securitytxt.expirado",
        title="security.txt vencido",
        category=Category.WEB,
        severity=Severity.LOW,
        summary="O security.txt passou da data do campo Expires e deve ser considerado desatualizado.",
        explanation=(
            "O campo Expires diz até quando as informações valem. Vencido, quem quer avisar sobre "
            "uma falha não sabe se o contato ainda funciona — e o arquivo indica que ninguém está "
            "cuidando dele."
        ),
        risk="Avisos de falhas podem ir para um contato que não existe mais.",
        steps=(
            "Confirme que o contato ainda funciona.",
            "Atualize o Expires (no máximo 1 ano à frente) e agende a renovação.",
        ),
        examples=(
            Fix(
                "generico",
                "Linha a atualizar no security.txt",
                "Expires: 2027-10-31T23:59:59Z",
                "text",
            ),
        ),
        verify="curl -s https://seu-site/.well-known/security.txt | grep -i expires",
        effort="baixo",
        fix_group="conteudo",
        references=("https://www.rfc-editor.org/rfc/rfc9116",),
        cwe="CWE-1059",
        owasp="A05:2021",
        cis=("7.1",),
        tags=("securitytxt",),
    ),
    KBEntry(
        id="web.securitytxt.invalido",
        title="security.txt incompleto",
        category=Category.WEB,
        severity=Severity.INFO,
        summary="O security.txt não tem um dos campos obrigatórios (Contact ou Expires).",
        explanation=(
            "A RFC 9116 exige ao menos um Contact e exatamente um Expires. Sem eles, ferramentas "
            "e pesquisadores não confiam no arquivo."
        ),
        risk="O canal de aviso de falhas pode ser ignorado ou mal interpretado.",
        steps=("Inclua Contact e Expires no arquivo.",),
        examples=(
            Fix(
                "generico",
                "Campos obrigatórios",
                "Contact: mailto:seguranca@exemplo.com.br\nExpires: 2027-10-31T23:59:59Z",
                "text",
            ),
        ),
        verify="curl -s https://seu-site/.well-known/security.txt",
        effort="baixo",
        fix_group="conteudo",
        references=("https://www.rfc-editor.org/rfc/rfc9116",),
        cwe="CWE-1059",
        owasp="A05:2021",
        cis=("7.1",),
        tags=("securitytxt",),
    ),
)
