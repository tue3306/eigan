"""Base de conhecimento: arquivos sensíveis publicados por engano (checagem ``web.exposure``)."""

from __future__ import annotations

from ...core import kb
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Severity

WSTG_BACKUP = (
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/"
    "02-Configuration_and_Deployment_Management_Testing/"
    "04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"
)
SECRETS_CHEATSHEET = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"
)

#: bloquear arquivos/pastas ocultos (.git, .env, .svn...) mantendo /.well-known
HIDDEN_FIXES = (
    Fix(
        "nginx",
        "nginx (dentro de server {})",
        r"location ~ /\.(?!well-known) { deny all; }",
        "nginx",
    ),
    Fix("apache", "Apache (config ou .htaccess)", r"RedirectMatch 404 /\.(?!well-known)", "apache"),
    Fix("litespeed", "LiteSpeed (.htaccess)", r"RedirectMatch 404 /\.(?!well-known)", "apache"),
    Fix(
        "iis",
        "IIS (web.config, em <requestFiltering>)",
        '<hiddenSegments><add segment=".git" /><add segment=".svn" /><add segment=".env" /></hiddenSegments>',
        "xml",
    ),
    Fix(
        "express",
        "Node.js / Express",
        "app.use(express.static('public', { dotfiles: 'deny' }));",
        "javascript",
    ),
    Fix(
        "cloudflare",
        "Cloudflare (WAF > Custom rules)",
        '(http.request.uri.path contains "/.git" or http.request.uri.path contains "/.env") -> Block',
        "text",
    ),
)
#: bloquear cópias de segurança e despejos pelo nome do arquivo
BACKUP_FIXES = (
    Fix(
        "nginx",
        "nginx (dentro de server {}; para zip, tar e gz, restrinja à pasta afetada, senão downloads legítimos e arquivos .gz pré-comprimidos também serão bloqueados)",
        r"location ~* \.(bak|old|orig|save|swp|sql)$ { deny all; }",
        "nginx",
    ),
    Fix(
        "apache",
        "Apache (config ou .htaccess; para zip, tar e gz, restrinja à pasta afetada com <Directory>)",
        r'RedirectMatch 404 "(?i)\.(bak|old|orig|save|swp|sql)$"',
        "apache",
    ),
    Fix(
        "iis",
        "IIS (web.config, em <requestFiltering>)",
        '<fileExtensions><add fileExtension=".bak" allowed="false" /><add fileExtension=".sql" allowed="false" /><add fileExtension=".zip" allowed="false" /></fileExtensions>',
        "xml",
    ),
    Fix(
        "generico",
        "Localizar cópias esquecidas (Linux)",
        r"find /var/www -type f \( -name '*.bak' -o -name '*.sql' -o -name '*.zip' -o -name '*~' \) -ls",
        "bash",
    ),
)

kb.register(
    KBEntry(
        id="web.exposicao.repositorio",
        title="Repositório de código (.git/.svn) publicado no site",
        category=Category.WEB,
        severity=Severity.HIGH,
        summary="A pasta de controle de versão foi publicada junto com o site e pode ser baixada.",
        explanation=(
            "Quando o deploy é feito copiando a pasta do projeto (ou com git pull direto no "
            "servidor), a pasta .git (ou .svn, .hg, .bzr) vai junto. Ferramentas públicas "
            "reconstroem todo o código-fonte e o histórico a partir dela, inclusive arquivos "
            "apagados e senhas que um dia foram commitadas."
        ),
        risk=(
            "Vazamento do código-fonte completo, de credenciais antigas e atuais, e um mapa "
            "perfeito para encontrar outras falhas na aplicação."
        ),
        steps=(
            "Bloqueie imediatamente o acesso a pastas ocultas no servidor web (exemplos abaixo).",
            "Remova a pasta de controle de versão da raiz pública e passe a publicar só os "
            "arquivos do build (git archive, rsync com --exclude, pipeline de CI).",
            "Considere comprometidas as senhas e chaves que já passaram pelo repositório: troque-as.",
        ),
        examples=(
            *HIDDEN_FIXES,
            Fix("generico", "Remover do servidor (Linux)", "rm -rf /var/www/html/.git", "bash"),
        ),
        verify="curl -si https://seu-site/.git/HEAD deve responder 403 ou 404.",
        effort="baixo",
        fix_group="exposicao",
        references=(WSTG_BACKUP, "https://cwe.mitre.org/data/definitions/527.html"),
        cwe="CWE-527",
        owasp="A05:2021",
        cis=("3.3", "4.1"),
        lgpd=True,
        tags=("exposicao", "codigo-fonte"),
    ),
    KBEntry(
        id="web.exposicao.env",
        title="Arquivo .env publicado no site",
        category=Category.WEB,
        severity=Severity.HIGH,
        summary="O arquivo de variáveis de ambiente (.env) pode ser baixado por qualquer pessoa.",
        explanation=(
            "O .env guarda a configuração secreta da aplicação: senhas de banco, chaves de API, "
            "chave de criptografia (APP_KEY), credenciais de e-mail e de nuvem. Ele nunca deve "
            "ficar dentro da pasta pública do servidor web."
        ),
        risk=(
            "Acesso direto ao banco de dados, envio de e-mails em nome da empresa, uso das contas "
            "de nuvem e falsificação de sessões. Robôs procuram /.env o tempo todo."
        ),
        steps=(
            "Bloqueie o acesso a arquivos ocultos no servidor web (exemplos abaixo).",
            "Mova o .env para fora da raiz pública (ex.: aponte o servidor para a pasta public/).",
            "Troque TODAS as senhas e chaves que estavam no arquivo — considere-as vazadas.",
            "Procure nos logs de acesso quem baixou o arquivo.",
        ),
        examples=HIDDEN_FIXES,
        verify="curl -si https://seu-site/.env deve responder 403 ou 404.",
        effort="medio",
        fix_group="exposicao",
        references=(SECRETS_CHEATSHEET, "https://cwe.mitre.org/data/definitions/538.html"),
        cwe="CWE-538",
        owasp="A05:2021",
        cis=("3.3", "4.1"),
        lgpd=True,
        tags=("exposicao", "segredos"),
    ),
    KBEntry(
        id="web.exposicao.config",
        title="Arquivo de configuração ou código-fonte legível",
        category=Category.WEB,
        severity=Severity.HIGH,
        summary=(
            "Um arquivo de configuração ou uma cópia de código-fonte (wp-config.php.bak, "
            "web.config, WEB-INF/web.xml, database.yml, .htaccess...) pode ser lido no site."
        ),
        explanation=(
            "Arquivos .php são executados pelo servidor e não mostram o código. Já as cópias com "
            "outra extensão (.bak, .old, ~, .save, .swp) são entregues como texto: o visitante "
            "lê o código-fonte, inclusive usuário e senha do banco de dados. O mesmo vale para "
            "web.config, WEB-INF/web.xml, config/database.yml e .htaccess, que nunca deveriam ser "
            "entregues pelo servidor web."
        ),
        risk=(
            "Credenciais do banco e chaves secretas expostas: acesso total aos dados do site. "
            "Mesmo sem senhas, o arquivo revela caminhos, regras de acesso e a estrutura interna."
        ),
        steps=(
            "Apague as cópias da pasta pública do servidor.",
            "Bloqueie extensões de backup e arquivos de configuração no servidor web (exemplos abaixo).",
            "Troque as senhas e chaves que estavam no arquivo.",
            "Configure o editor para não criar cópias (~, .swp) na pasta do site.",
        ),
        examples=(
            *BACKUP_FIXES,
            Fix(
                "nginx",
                "nginx (arquivos de configuração, dentro de server {})",
                r"location ~* (^|/)(web\.config|\.htaccess|WEB-INF/|database\.yml) { deny all; }",
                "nginx",
            ),
        ),
        verify="curl -si https://seu-site/wp-config.php.bak deve responder 403 ou 404 (repita para o caminho apontado no achado).",
        effort="baixo",
        fix_group="exposicao",
        references=(WSTG_BACKUP, "https://cwe.mitre.org/data/definitions/530.html"),
        cwe="CWE-530",
        owasp="A05:2021",
        cis=("3.3", "4.1"),
        lgpd=True,
        tags=("exposicao", "segredos"),
    ),
    KBEntry(
        id="web.exposicao.htpasswd",
        title="Arquivo .htpasswd legível",
        category=Category.WEB,
        severity=Severity.HIGH,
        summary="O arquivo com usuários e hashes de senha da autenticação HTTP pode ser baixado.",
        explanation=(
            "O .htpasswd guarda usuários e senhas (em hash) de áreas protegidas por autenticação "
            "básica. Com o arquivo em mãos, o atacante quebra as senhas fracas offline, sem "
            "limite de tentativas."
        ),
        risk="Acesso às áreas protegidas e reaproveitamento das senhas em outros sistemas.",
        steps=(
            "Mova o .htpasswd para fora da raiz pública (ex.: /etc/apache2/.htpasswd).",
            "Bloqueie arquivos ocultos no servidor web.",
            "Troque as senhas dos usuários listados.",
        ),
        examples=HIDDEN_FIXES,
        verify="curl -si https://seu-site/.htpasswd deve responder 403 ou 404.",
        effort="baixo",
        fix_group="exposicao",
        references=(
            "https://httpd.apache.org/docs/2.4/howto/auth.html",
            "https://cwe.mitre.org/data/definitions/538.html",
        ),
        cwe="CWE-538",
        owasp="A05:2021",
        cis=("3.3", "4.1"),
        tags=("exposicao", "senhas"),
    ),
    KBEntry(
        id="web.exposicao.ds_store",
        title="Arquivo .DS_Store publicado",
        category=Category.WEB,
        severity=Severity.LOW,
        summary="Um arquivo de sistema do macOS revela os nomes dos arquivos da pasta.",
        explanation=(
            "O macOS cria .DS_Store em cada pasta aberta no Finder. Publicado no site, ele lista "
            "os arquivos e subpastas, inclusive os que não têm link (backups, rascunhos)."
        ),
        risk="Ajuda o atacante a achar arquivos esquecidos que não seriam adivinhados.",
        steps=(
            "Apague os .DS_Store da pasta publicada.",
            "Bloqueie arquivos ocultos no servidor web.",
        ),
        examples=(
            *HIDDEN_FIXES,
            Fix("generico", "Apagar (Linux)", "find /var/www -name .DS_Store -delete", "bash"),
        ),
        verify="curl -si https://seu-site/.DS_Store deve responder 403 ou 404.",
        effort="baixo",
        fix_group="exposicao",
        references=(WSTG_BACKUP, "https://cwe.mitre.org/data/definitions/538.html"),
        cwe="CWE-538",
        owasp="A05:2021",
        cis=("4.1",),
        tags=("exposicao",),
    ),
    KBEntry(
        id="web.exposicao.backup",
        title="Backup do site disponível para download",
        category=Category.WEB,
        severity=Severity.HIGH,
        summary="Um arquivo compactado de backup (zip, tar.gz, rar, 7z) está na pasta pública do site.",
        explanation=(
            "Backups do site guardam o código-fonte e os arquivos de configuração, com as senhas "
            "do banco e as chaves da aplicação. Deixados na raiz pública, são baixados por "
            "qualquer um que adivinhe o nome — e nomes como backup.zip são os primeiros que os "
            "robôs testam. O EIGAN confirma o formato só pelos primeiros bytes e não baixa o arquivo."
        ),
        risk=(
            "Vazamento do código e das senhas do sistema, sem deixar rastro de invasão. Se o "
            "backup incluir dados de clientes, é um incidente de LGPD."
        ),
        steps=(
            "Retire o arquivo da pasta pública agora e guarde backups em local privado e "
            "criptografado.",
            "Bloqueie extensões de backup no servidor web (exemplos abaixo).",
            "Verifique nos logs se o arquivo foi baixado; se houver dados pessoais, avalie a "
            "comunicação do incidente (LGPD).",
            "Troque as senhas e chaves contidas no backup.",
        ),
        examples=BACKUP_FIXES,
        verify="curl -sI https://seu-site/backup.zip deve responder 403 ou 404.",
        effort="baixo",
        fix_group="exposicao",
        references=(WSTG_BACKUP, "https://cwe.mitre.org/data/definitions/530.html"),
        cwe="CWE-530",
        owasp="A05:2021",
        cis=("3.3", "3.11"),
        lgpd=True,
        tags=("exposicao", "dados-pessoais"),
    ),
    KBEntry(
        id="web.exposicao.dump_sql",
        title="Despejo de banco de dados (SQL) disponível para download",
        category=Category.WEB,
        severity=Severity.CRITICAL,
        summary="Um arquivo .sql com a cópia do banco de dados pode ser baixado por qualquer pessoa.",
        explanation=(
            "Um despejo (dump) guarda o banco inteiro: usuários, e-mails, senhas em hash, pedidos "
            "e tudo o que a aplicação registra. Costuma ser criado para uma migração ou um "
            "backup rápido e esquecido na pasta do site. O EIGAN lê só o começo do arquivo para "
            "reconhecer o formato; não baixa os dados."
        ),
        risk=(
            "Vazamento em massa de dados pessoais (incidente de LGPD) e das senhas dos usuários, "
            "que o atacante quebra offline, sem nenhum limite de tentativas."
        ),
        steps=(
            "Retire o arquivo da pasta pública agora e guarde despejos em local privado e criptografado.",
            "Bloqueie a extensão .sql (e .sql.gz) no servidor web (exemplos abaixo).",
            "Verifique nos logs quem baixou o arquivo; havendo dados pessoais, avalie a "
            "comunicação do incidente à ANPD e aos titulares (LGPD art. 48).",
            "Force a troca das senhas dos usuários e das credenciais guardadas no banco.",
        ),
        examples=BACKUP_FIXES,
        verify="curl -sI https://seu-site/backup.sql deve responder 403 ou 404 (repita para o caminho apontado no achado).",
        effort="medio",
        fix_group="exposicao",
        references=(WSTG_BACKUP, "https://cwe.mitre.org/data/definitions/530.html"),
        cwe="CWE-530",
        owasp="A05:2021",
        cis=("3.3", "3.11"),
        lgpd=True,
        tags=("exposicao", "dados-pessoais"),
    ),
    KBEntry(
        id="web.exposicao.credenciais",
        title="Arquivo de credenciais ou chave privada publicado",
        category=Category.WEB,
        severity=Severity.CRITICAL,
        summary="Chave privada, credenciais de nuvem ou tokens podem ser baixados do site.",
        explanation=(
            "Arquivos como id_rsa, .aws/credentials, .npmrc com token, .git-credentials e "
            "configuração do Docker com 'auths' dão acesso direto a servidores, contas de nuvem, "
            "repositórios e registros de pacotes."
        ),
        risk=(
            "Comprometimento direto: login em servidores por SSH, uso das contas de nuvem (com "
            "custo para a empresa), publicação de pacotes maliciosos em nome da organização."
        ),
        steps=(
            "Revogue AGORA a chave ou token exposto no painel do serviço e gere um novo.",
            "Apague o arquivo da pasta pública e bloqueie arquivos ocultos no servidor web.",
            "Revise os logs do serviço (CloudTrail, GitHub, npm) em busca de uso indevido.",
            "Guarde segredos em cofre (variáveis de ambiente do servidor, Vault, Secrets Manager).",
        ),
        examples=(
            *HIDDEN_FIXES,
            Fix(
                "generico",
                "Desativar chave de acesso da AWS (CLI)",
                "aws iam update-access-key --access-key-id AKIA... --status Inactive",
                "bash",
            ),
        ),
        verify="curl -si https://seu-site/id_rsa (e os demais caminhos) deve responder 403 ou 404; a chave antiga deve constar como revogada.",
        effort="medio",
        fix_group="exposicao",
        references=(
            SECRETS_CHEATSHEET,
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
            "https://docs.npmjs.com/revoking-access-tokens",
        ),
        cwe="CWE-522",
        owasp="A05:2021",
        cis=("3.3", "4.1"),
        lgpd=True,
        tags=("exposicao", "segredos"),
    ),
    KBEntry(
        id="web.exposicao.logs",
        title="Arquivo de log publicado no site",
        category=Category.WEB,
        severity=Severity.MEDIUM,
        summary="Um arquivo de log da aplicação ou do servidor pode ser lido por qualquer pessoa.",
        explanation=(
            "Logs de erro e de depuração (laravel.log, debug.log, error_log) registram caminhos "
            "internos, consultas SQL, mensagens de exceção e, muitas vezes, e-mails, tokens e "
            "dados enviados nos formulários."
        ),
        risk="Vazamento de dados pessoais e de detalhes internos que facilitam outros ataques.",
        steps=(
            "Grave os logs fora da pasta pública (ex.: /var/log/aplicacao).",
            "Bloqueie a extensão .log no servidor web.",
            "Desligue o modo de depuração em produção (WP_DEBUG_LOG, APP_DEBUG).",
            "Apague o log exposto depois de guardar uma cópia para análise.",
        ),
        examples=(
            Fix(
                "nginx", "nginx (dentro de server {})", r"location ~* \.log$ { deny all; }", "nginx"
            ),
            Fix(
                "apache",
                "Apache (config ou .htaccess)",
                r'RedirectMatch 404 "(?i)\.log$"',
                "apache",
            ),
            Fix("wordpress", "WordPress (wp-config.php)", "define('WP_DEBUG_LOG', false);", "php"),
            Fix("laravel", "Laravel (.env)", "APP_DEBUG=false", "ini"),
        ),
        verify="curl -si https://seu-site/storage/logs/laravel.log deve responder 403 ou 404.",
        effort="baixo",
        fix_group="exposicao",
        references=(
            "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/532.html",
        ),
        cwe="CWE-532",
        owasp="A05:2021",
        cis=("3.3", "8.2"),
        lgpd=True,
        tags=("exposicao", "logs"),
    ),
    KBEntry(
        id="web.exposicao.manifesto",
        title="Manifesto de dependências publicado",
        category=Category.WEB,
        severity=Severity.LOW,
        summary="composer.json/lock, package.json/lock ou yarn.lock podem ser lidos no site.",
        explanation=(
            "Esses arquivos listam as bibliotecas e as versões exatas usadas pela aplicação. "
            "Não são secretos no repositório, mas publicados no site entregam o inventário "
            "completo para quem procura uma versão vulnerável."
        ),
        risk="Reconhecimento facilitado: o atacante sabe exatamente quais falhas conhecidas testar.",
        steps=(
            "Aponte a raiz do servidor web para a pasta pública (public/, dist/), não para a raiz do projeto.",
            "Bloqueie esses nomes de arquivo no servidor web.",
        ),
        examples=(
            Fix(
                "nginx",
                "nginx (dentro de server {})",
                r"location ~* (composer\.(json|lock)|package(-lock)?\.json|yarn\.lock)$ { deny all; }",
                "nginx",
            ),
            Fix(
                "apache",
                "Apache (config ou .htaccess)",
                r'RedirectMatch 404 "(composer\.(json|lock)|package(-lock)?\.json|yarn\.lock)$"',
                "apache",
            ),
        ),
        verify="curl -si https://seu-site/composer.json deve responder 403 ou 404.",
        effort="baixo",
        fix_group="exposicao",
        references=(WSTG_BACKUP,),
        cwe="CWE-200",
        owasp="A05:2021",
        cis=("4.1",),
        tags=("exposicao", "dependencias"),
    ),
    KBEntry(
        id="web.exposicao.docker",
        title="Arquivos do Docker publicados no site",
        category=Category.WEB,
        severity=Severity.MEDIUM,
        summary="Dockerfile ou docker-compose.yml podem ser lidos no site.",
        explanation=(
            "Esses arquivos descrevem como a aplicação é montada e executada: imagens, portas, "
            "volumes, serviços internos e, com frequência, senhas em variáveis de ambiente."
        ),
        risk="Mapa da infraestrutura interna e possíveis senhas de banco e serviços.",
        steps=(
            "Retire os arquivos da pasta pública e publique só o resultado do build.",
            "Se havia senhas no arquivo, troque-as e passe a usar secrets do Docker/orquestrador.",
        ),
        examples=(
            Fix(
                "nginx",
                "nginx (dentro de server {})",
                r"location ~* (Dockerfile|docker-compose\.ya?ml)$ { deny all; }",
                "nginx",
            ),
            Fix(
                "apache",
                "Apache (config ou .htaccess)",
                r'RedirectMatch 404 "(Dockerfile|docker-compose\.ya?ml)$"',
                "apache",
            ),
        ),
        verify="curl -si https://seu-site/docker-compose.yml deve responder 403 ou 404.",
        effort="baixo",
        fix_group="exposicao",
        references=(
            "https://docs.docker.com/compose/how-tos/use-secrets/",
            "https://cwe.mitre.org/data/definitions/538.html",
        ),
        cwe="CWE-538",
        owasp="A05:2021",
        cis=("4.1", "16.7"),
        tags=("exposicao", "infraestrutura"),
    ),
    KBEntry(
        id="web.exposicao.sourcemap",
        title="Mapa de código-fonte (source map) publicado",
        category=Category.WEB,
        severity=Severity.LOW,
        summary="Os arquivos .map dos scripts permitem reconstruir o código-fonte original do front-end.",
        explanation=(
            "Source maps ligam o JavaScript minificado ao código original, com nomes de arquivos, "
            "comentários e às vezes trechos de configuração. São úteis no desenvolvimento, mas "
            "em produção entregam o código do front-end legível."
        ),
        risk="Facilita achar rotas internas, chaves esquecidas e falhas de lógica no front-end.",
        steps=(
            "Desative a geração de source maps no build de produção ou não publique os .map.",
            "Se precisar deles para monitoramento de erros, envie-os direto à ferramenta (Sentry etc.).",
        ),
        examples=(
            Fix("generico", "webpack (produção)", "devtool: false,", "javascript"),
            Fix("generico", "Vite (vite.config.js)", "build: { sourcemap: false },", "javascript"),
            Fix(
                "nginx", "nginx (dentro de server {})", r"location ~* \.map$ { deny all; }", "nginx"
            ),
            Fix("apache", "Apache (config ou .htaccess)", r'RedirectMatch 404 "\.map$"', "apache"),
        ),
        verify="Abra https://seu-site/caminho/do/script.js.map: deve responder 403 ou 404.",
        effort="baixo",
        fix_group="exposicao",
        references=(
            "https://developer.mozilla.org/en-US/docs/Glossary/Source_map",
            "https://webpack.js.org/configuration/devtool/",
        ),
        cwe="CWE-540",
        owasp="A05:2021",
        cis=("16.1",),
        tags=("exposicao", "codigo-fonte"),
    ),
    KBEntry(
        id="web.exposicao.crossdomain",
        title="Política cross-domain liberada para qualquer site",
        category=Category.WEB,
        severity=Severity.LOW,
        summary="crossdomain.xml ou clientaccesspolicy.xml permitem acesso de qualquer domínio.",
        explanation=(
            "Esses arquivos controlavam o acesso de aplicações Flash e Silverlight entre domínios. "
            "As tecnologias foram descontinuadas, mas um arquivo com '*' ainda indica configuração "
            "esquecida e pode valer para clientes antigos."
        ),
        risk="Clientes legados conseguem ler conteúdo do site com a sessão do usuário.",
        steps=(
            "Apague o arquivo se não houver aplicação Flash/Silverlight.",
            "Se houver, liste só os domínios necessários.",
        ),
        examples=(
            Fix(
                "generico",
                "Remover (Linux)",
                "rm /var/www/html/crossdomain.xml /var/www/html/clientaccesspolicy.xml",
                "bash",
            ),
        ),
        verify='curl -si https://seu-site/crossdomain.xml deve responder 404 ou não conter domain="*".',
        effort="baixo",
        fix_group="exposicao",
        references=("https://cwe.mitre.org/data/definitions/942.html",),
        cwe="CWE-942",
        owasp="A05:2021",
        cis=("4.1",),
        tags=("exposicao",),
    ),
)
