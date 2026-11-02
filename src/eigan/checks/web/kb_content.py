"""Base de conhecimento do conteúdo das páginas (checagem ``web.content``).\n\nConteúdo misto, scripts de terceiros sem SRI, formulários (senha sem HTTPS, envio\npor HTTP, sem token anti-CSRF), segredos no HTML/JavaScript e páginas de erro e\nde depuração expostas.\n"""

from __future__ import annotations

from ...core import kb
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Severity

_MIXED = "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"
_UIR = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/upgrade-insecure-requests"
_SRI = "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"
_PASSWORDS = "https://developer.mozilla.org/en-US/docs/Web/Security/Insecure_passwords"
_WSTG_UNENCRYPTED = (
    "https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/09-Weak_Cryptography/"
    "03-Sensitive_Information_Sent_via_Unencrypted_Channels"
)
_CSRF = "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
_SECRETS = "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"
_ERRORS = "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html"
_WSTG_ERRORS = (
    "https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/08-Error_Handling/"
    "01-Improper_Error_Handling"
)

#: diretiva CSP que faz o navegador trocar http:// por https:// nos recursos da página
_UIR_FIXES = (
    Fix(
        "nginx",
        "nginx",
        'add_header Content-Security-Policy "upgrade-insecure-requests" always;',
        "nginx",
    ),
    Fix(
        "apache",
        "Apache (mod_headers)",
        'Header always add Content-Security-Policy "upgrade-insecure-requests"',
        "apache",
    ),
    Fix(
        "iis",
        "IIS (web.config, em <customHeaders>; se já houver CSP, acrescente a diretiva a ela)",
        '<add name="Content-Security-Policy" value="upgrade-insecure-requests" />',
        "xml",
    ),
    Fix(
        "express",
        "Node.js / Express",
        "app.use((req, res, next) => { res.append('Content-Security-Policy', 'upgrade-insecure-requests'); next(); });",
        "javascript",
    ),
    Fix(
        "wordpress",
        "WordPress (WP-CLI: troca os endereços gravados no banco)",
        "wp search-replace 'http://www.exemplo.com.br' 'https://www.exemplo.com.br' --skip-columns=guid",
        "bash",
    ),
    Fix(
        "cloudflare",
        "Cloudflare (painel)",
        "SSL/TLS > Edge Certificates > Automatic HTTPS Rewrites: On",
        "text",
    ),
    Fix(
        "generico",
        "HTML (no <head> da página)",
        '<meta http-equiv="Content-Security-Policy" content="upgrade-insecure-requests">',
        "html",
    ),
)

kb.register(
    KBEntry(
        id="web.conteudo.misto_ativo",
        title="Conteúdo misto ativo: scripts ou estilos carregados por HTTP em página HTTPS",
        category=Category.WEB,
        severity=Severity.MEDIUM,
        summary="A página HTTPS busca scripts, folhas de estilo, frames ou objetos por http://, sem criptografia.",
        explanation=(
            "Conteúdo misto ativo é quando uma página entregue por HTTPS carrega, por HTTP comum, "
            "recursos capazes de alterar a própria página: scripts, folhas de estilo, iframes, "
            "objetos e imagens declaradas em srcset. Os navegadores atuais bloqueiam esses "
            "recursos (a página quebra); navegadores antigos e componentes embutidos os carregam "
            "sem proteção."
        ),
        risk=(
            "Quem está no caminho da rede (Wi-Fi público, roteador ou provedor comprometido) troca "
            "o script baixado por HTTP por código malicioso, que roda com os privilégios do site: "
            "rouba sessões, senhas digitadas e dados dos formulários."
        ),
        steps=(
            "Troque http:// por https:// em cada recurso listado na evidência, depois de confirmar "
            "que ele responde em HTTPS.",
            "Se o recurso de terceiros não existe em HTTPS, hospede uma cópia no próprio site ou "
            "troque de fornecedor.",
            "Como proteção adicional, envie a diretiva upgrade-insecure-requests na "
            "Content-Security-Policy: o navegador converte sozinho os endereços http:// restantes.",
            "Em CMS, corrija também os endereços gravados no banco de dados e nos temas.",
        ),
        examples=_UIR_FIXES,
        verify=(
            "Abra a página com as ferramentas do desenvolvedor (F12 > Console): não deve haver "
            'avisos de "Mixed Content". Depois repita a auditoria.'
        ),
        effort="medio",
        fix_group="conteudo",
        references=(_MIXED, _UIR),
        cwe="CWE-319",
        owasp="A02:2021",
        cis=("3.10",),
        tags=("conteudo", "https"),
    ),
    KBEntry(
        id="web.conteudo.misto_passivo",
        title="Conteúdo misto passivo: imagens ou mídia carregadas por HTTP em página HTTPS",
        category=Category.WEB,
        severity=Severity.LOW,
        summary="A página HTTPS exibe imagens, áudio ou vídeo buscados por http://.",
        explanation=(
            "Recursos passivos (imagens, áudio, vídeo) não executam código. Por isso os "
            "navegadores ainda os toleram: alguns os exibem com o aviso de página parcialmente "
            "segura, outros tentam buscá-los por HTTPS e os descartam se não conseguirem. Em "
            "qualquer caso, o conteúdo viaja sem criptografia ou some da página."
        ),
        risk=(
            "Um atacante na rede pode trocar imagens (instruções, QR codes, dados bancários "
            "exibidos como imagem) e acompanhar quais páginas o usuário visita. Endereços http:// "
            "esquecidos também tendem a aparecer depois em scripts."
        ),
        steps=(
            "Troque http:// por https:// (ou por caminhos relativos) nas imagens e mídias listadas "
            "na evidência.",
            "Envie upgrade-insecure-requests na Content-Security-Policy como proteção adicional.",
            "Em CMS, corrija os endereços gravados no banco de dados e nos temas.",
        ),
        examples=_UIR_FIXES,
        verify='No F12 > Console não deve haver avisos de "Mixed Content"; repita a auditoria.',
        effort="baixo",
        fix_group="conteudo",
        references=(_MIXED, _UIR),
        cwe="CWE-319",
        owasp="A02:2021",
        cis=("3.10",),
        tags=("conteudo", "https"),
    ),
    KBEntry(
        id="web.conteudo.sri_ausente",
        title="Scripts de terceiros sem verificação de integridade (SRI)",
        category=Category.WEB,
        severity=Severity.LOW,
        summary="A página executa JavaScript de outros domínios sem o atributo integrity.",
        explanation=(
            "Subresource Integrity (SRI) é o atributo integrity da tag <script>: ele traz o hash "
            "criptográfico do arquivo esperado, e o navegador se recusa a executar o script se o "
            "conteúdo baixado for diferente. Sem ele, a página confia em qualquer código que a "
            "CDN ou o fornecedor entregar naquele endereço."
        ),
        risk=(
            "Se a CDN ou o fornecedor for invadido, ou o arquivo for trocado, o código malicioso "
            "roda em todas as páginas do site com acesso às sessões e aos formulários — o ataque "
            "de cadeia de suprimentos usado para roubar dados de cartão em lojas virtuais."
        ),
        steps=(
            "Para cada script listado, use uma versão fixa (com o número da versão no endereço) e "
            "calcule o hash SHA-384 do arquivo.",
            'Acrescente integrity="sha384-..." e crossorigin="anonymous" na tag <script>.',
            "Scripts que o fornecedor altera no mesmo endereço (análise de tráfego, chat, "
            "pagamento) quebrariam com SRI: avalie a confiança no fornecedor, restrinja os domínios "
            "na Content-Security-Policy e, quando possível, hospede uma cópia versionada no site.",
        ),
        examples=(
            Fix(
                "generico",
                "HTML",
                '<script src="https://cdn.exemplo.com/biblioteca@1.2.3/biblioteca.min.js" '
                'integrity="sha384-HASH_DO_ARQUIVO" crossorigin="anonymous"></script>',
                "html",
            ),
            Fix(
                "generico",
                "Calcular o hash (Linux/macOS, OpenSSL)",
                "cat biblioteca.min.js | openssl dgst -sha384 -binary | openssl base64 -A",
                "bash",
            ),
            Fix(
                "generico",
                "Calcular o hash (Windows PowerShell)",
                '$b = [IO.File]::ReadAllBytes((Resolve-Path .\\biblioteca.min.js)); "sha384-" + '
                "[Convert]::ToBase64String([Security.Cryptography.SHA384]::Create().ComputeHash($b))",
                "powershell",
            ),
        ),
        verify=(
            "Em ambiente de teste, altere um caractere do hash: o navegador deve recusar o script "
            "(erro no console). Com o hash correto ele carrega normalmente."
        ),
        effort="baixo",
        fix_group="conteudo",
        references=(_SRI, "https://www.w3.org/TR/SRI/"),
        cwe="CWE-353",
        owasp="A08:2021",
        cis=("16.4", "16.10"),
        tags=("conteudo", "javascript", "cadeia-de-suprimentos"),
    ),
    KBEntry(
        id="web.formulario.senha_http",
        title="Formulário de senha em página sem HTTPS",
        category=Category.WEB,
        severity=Severity.HIGH,
        summary="Uma página entregue por HTTP comum pede a senha do usuário.",
        explanation=(
            "A página com o campo de senha chega ao navegador sem criptografia. Mesmo que o "
            "formulário envie os dados para um endereço HTTPS, quem intercepta a página pode "
            "trocar o destino do formulário ou injetar um script que copia o que é digitado. Os "
            'navegadores marcam essas páginas como "Não seguro".'
        ),
        risk=(
            "Senhas capturadas em redes Wi-Fi públicas ou comprometidas, contas invadidas e "
            "reaproveitamento das mesmas senhas em outros serviços."
        ),
        steps=(
            "Publique o site em HTTPS (certificado gratuito do Let's Encrypt ou do provedor de "
            "hospedagem).",
            "Redirecione permanentemente (301) todo o tráfego HTTP para HTTPS, em especial as "
            "páginas de login, cadastro e recuperação de senha.",
            "Ative o HSTS para o navegador nunca mais abrir o site por HTTP.",
        ),
        examples=(
            Fix(
                "nginx",
                "nginx (no server da porta 80)",
                "return 301 https://$host$request_uri;",
                "nginx",
            ),
            Fix(
                "apache",
                "Apache (VirtualHost da porta 80)",
                "Redirect permanent / https://www.exemplo.com.br/",
                "apache",
            ),
            Fix(
                "iis",
                "IIS (URL Rewrite, em <rewrite><rules>)",
                '<rule name="HTTPS" stopProcessing="true"><match url="(.*)" /><conditions>'
                '<add input="{HTTPS}" pattern="off" /></conditions>'
                '<action type="Redirect" url="https://{HTTP_HOST}/{R:1}" redirectType="Permanent" /></rule>',
                "xml",
            ),
            Fix(
                "express",
                "Node.js / Express (com app.set('trust proxy', 1) atrás de proxy)",
                "app.use((req, res, next) => req.secure ? next() : res.redirect(301, 'https://' + req.headers.host + req.url));",
                "javascript",
            ),
            Fix(
                "wordpress", "WordPress (wp-config.php)", "define('FORCE_SSL_ADMIN', true);", "php"
            ),
            Fix(
                "cloudflare",
                "Cloudflare (painel)",
                "SSL/TLS > Edge Certificates > Always Use HTTPS: On",
                "text",
            ),
        ),
        verify=(
            "Abra a página de login por http:// e confirme que o navegador é redirecionado para "
            "https:// antes de mostrar o formulário."
        ),
        effort="medio",
        fix_group="https",
        references=(_PASSWORDS, _WSTG_UNENCRYPTED),
        cwe="CWE-319",
        owasp="A02:2021",
        cis=("3.10",),
        lgpd=True,
        tags=("formulario", "senha", "https"),
    ),
    KBEntry(
        id="web.formulario.envio_http",
        title="Formulário de página HTTPS envia os dados por HTTP",
        category=Category.WEB,
        severity=Severity.MEDIUM,
        summary="O destino (action) de um formulário da página HTTPS é um endereço http://.",
        explanation=(
            "A página chegou com criptografia, mas ao enviar o formulário o navegador manda o que "
            "foi digitado para um endereço sem HTTPS. Os navegadores atuais mostram um aviso de "
            "formulário não seguro antes do envio — e muitos usuários simplesmente confirmam."
        ),
        risk=(
            "Os dados enviados (senha, CPF, contato) trafegam em texto puro e podem ser lidos ou "
            "alterados por quem estiver na rede."
        ),
        steps=(
            'Troque o atributo action para https:// ou para um caminho relativo (ex.: action="/login").',
            "Garanta que o destino responde em HTTPS e redireciona o HTTP.",
            "Envie upgrade-insecure-requests na Content-Security-Policy como proteção adicional "
            "para os envios ao próprio site.",
        ),
        examples=(
            Fix("generico", "HTML", '<form method="post" action="/login">', "html"),
            Fix(
                "generico",
                "HTML (destino em outro domínio)",
                '<form method="post" action="https://servicos.exemplo.com.br/contato">',
                "html",
            ),
        ),
        verify=(
            "No código-fonte da página (Ctrl+U), nenhum <form> deve ter action começando com "
            "http://. Ao enviar, o F12 > Rede deve mostrar a requisição indo para https://."
        ),
        effort="baixo",
        fix_group="conteudo",
        references=(_PASSWORDS, _WSTG_UNENCRYPTED, _MIXED),
        cwe="CWE-319",
        owasp="A02:2021",
        cis=("3.10",),
        lgpd=True,
        tags=("formulario", "https"),
    ),
    KBEntry(
        id="web.formulario.sem_csrf",
        title="Formulário com senha sem token anti-CSRF aparente",
        category=Category.WEB,
        severity=Severity.LOW,
        summary="Um formulário POST com campo de senha não traz campo oculto com token anti-CSRF.",
        explanation=(
            "Cross-Site Request Forgery (CSRF) é quando um site malicioso faz o navegador da "
            "vítima enviar um formulário ao seu site usando a sessão dela. A defesa padrão é um "
            "token aleatório, ligado à sessão, em um campo oculto do formulário e conferido pelo "
            "servidor. Não encontramos campo oculto nem meta tag com cara de token "
            "anti-CSRF neste formulário. A proteção pode existir por outro meio (cookie duplicado, "
            "cabeçalho enviado por JavaScript, conferência do Origin), por isso o achado é indicativo e "
            "precisa ser confirmado no código."
        ),
        risk=(
            "Em formulários de troca de senha ou de e-mail, o atacante altera a conta da vítima "
            "só por ela abrir uma página maliciosa enquanto está logada. Em formulários de login, "
            'permite o "login CSRF": a vítima é conectada na conta do atacante e passa a '
            "registrar dados nela."
        ),
        steps=(
            "Ative a proteção anti-CSRF nativa do framework e inclua o token em todos os "
            "formulários POST.",
            "Valide o token no servidor e recuse requisições sem ele ou com valor inválido.",
            "Como defesa em profundidade, use cookies de sessão com SameSite=Lax ou Strict e "
            "confira os cabeçalhos Origin/Referer nas requisições que alteram dados.",
        ),
        examples=(
            Fix("django", "Django (template, dentro do <form>)", "{% csrf_token %}", "html"),
            Fix("laravel", "Laravel (Blade, dentro do <form>)", "@csrf", "php"),
            Fix(
                "aspnet",
                "ASP.NET MVC (Razor, com [ValidateAntiForgeryToken] na ação)",
                "@Html.AntiForgeryToken()",
                "html",
            ),
            Fix(
                "spring",
                "Spring Security (JSP, dentro do <form>)",
                '<input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>',
                "html",
            ),
            Fix(
                "flask",
                "Flask (Flask-WTF)",
                "from flask_wtf.csrf import CSRFProtect\nCSRFProtect(app)  # no template: {{ csrf_token() }}",
                "python",
            ),
            Fix(
                "wordpress",
                "WordPress (no formulário e no tratamento do envio)",
                "wp_nonce_field('minha_acao');\ncheck_admin_referer('minha_acao');",
                "php",
            ),
            Fix(
                "php",
                "PHP puro (token na sessão)",
                "$_SESSION['csrf_token'] ??= bin2hex(random_bytes(32));\n"
                "// no envio:\nif (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'] ?? '')) "
                "{ http_response_code(403); exit; }",
                "php",
            ),
        ),
        verify=(
            "Inspecione o formulário (F12 > Elementos): deve existir um campo oculto com o token. "
            "Em ambiente de teste, reenvie a requisição sem o token: o servidor deve recusá-la."
        ),
        effort="medio",
        fix_group="conteudo",
        references=(_CSRF, "https://owasp.org/www-community/attacks/csrf"),
        cwe="CWE-352",
        owasp="A01:2021",
        cis=("16.10",),
        tags=("formulario", "csrf"),
    ),
    KBEntry(
        id="web.conteudo.segredo",
        title="Segredo (chave de API, token ou chave privada) exposto no código da página",
        category=Category.WEB,
        severity=Severity.HIGH,
        summary="O HTML ou um JavaScript do site traz uma credencial que deveria ficar só no servidor.",
        explanation=(
            "Tudo o que vai para o navegador — HTML e JavaScript — pode ser lido por qualquer "
            "visitante. Encontramos um valor com o formato exato de uma credencial privada: chave "
            "de acesso da AWS, token do GitHub ou do Slack, chave secreta do Stripe, endereço de "
            "webhook do Slack ou bloco de chave privada. O valor aparece mascarado no relatório. "
            "O identificador de acesso da AWS (AKIA/ASIA) sozinho não dá acesso à conta: é "
            "reportado com gravidade média e confiança tentativa, e sobe quando a chave secreta "
            "aparece junto."
        ),
        risk=(
            "Quem copiar a credencial age em nome da empresa: acessa a nuvem (AWS), o código-fonte "
            "(GitHub), cobra ou estorna pagamentos (Stripe), lê ou envia mensagens internas "
            "(Slack). Robôs varrem sites e repositórios atrás desses formatos o tempo todo."
        ),
        steps=(
            "Revogue ou gere novamente a credencial IMEDIATAMENTE no painel do fornecedor; "
            "apagá-la do site não basta, porque ela já pode ter sido copiada.",
            "Verifique nos registros do fornecedor (CloudTrail, log de auditoria do GitHub, painel "
            "do Stripe ou do Slack) se houve uso indevido.",
            "Tire o segredo do código entregue ao navegador: chamadas que exigem a credencial "
            "devem passar por um endpoint do seu servidor, que guarda o segredo em variável de "
            "ambiente ou cofre de segredos.",
            "Procure o mesmo valor no repositório e no histórico do Git e adote uma varredura de "
            "segredos no processo de publicação.",
        ),
        examples=(
            Fix(
                "generico",
                "AWS CLI (desativar e depois apagar a chave exposta)",
                "aws iam update-access-key --access-key-id ID_DA_CHAVE --status Inactive --user-name USUARIO\n"
                "aws iam delete-access-key --access-key-id ID_DA_CHAVE --user-name USUARIO",
                "bash",
            ),
            Fix(
                "express",
                "Node.js / Express (a chave fica no servidor)",
                "app.get('/api/cotacao', async (req, res) => {\n"
                "  const r = await fetch('https://api.fornecedor.com/v1/cotacao', "
                "{ headers: { Authorization: `Bearer ${process.env.FORNECEDOR_TOKEN}` } });\n"
                "  res.status(r.status).json(await r.json());\n});",
                "javascript",
            ),
            Fix(
                "php",
                "PHP (a chave fica no servidor)",
                "$token = getenv('FORNECEDOR_TOKEN'); // definido no servidor, fora da pasta pública",
                "php",
            ),
        ),
        verify=(
            "Depois de publicar a correção, procure o início do valor mascarado no código-fonte "
            "da página e dos scripts (Ctrl+U e F12 > Fontes) e repita a auditoria. Confirme no "
            "painel do fornecedor que a credencial antiga foi revogada."
        ),
        effort="medio",
        fix_group="segredos",
        references=(
            _SECRETS,
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-prefixes",
            "https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/",
            "https://docs.stripe.com/keys",
            "https://docs.slack.dev/authentication/tokens",
        ),
        cwe="CWE-798",
        owasp="A07:2021",
        cis=("16.12",),
        lgpd=True,
        tags=("segredos", "conteudo"),
    ),
    KBEntry(
        id="web.conteudo.chave_google",
        title="Chave de API do Google no código da página (conferir restrições)",
        category=Category.WEB,
        severity=Severity.LOW,
        summary="O site publica uma chave de API do Google (AIza...). É normal para Maps e afins, desde que a chave seja restrita.",
        explanation=(
            "Chaves de API do Google usadas no navegador (Maps JavaScript, Places, YouTube) ficam "
            "necessariamente visíveis no código. O problema é a chave SEM restrição: sem limitar a "
            "quais sites (referenciadores HTTP) e a quais APIs ela serve, qualquer pessoa a usa em "
            "outro lugar e a cobrança cai na conta da empresa. De fora não dá para saber se a "
            "chave está restrita; por isso o achado é para conferência."
        ),
        risk=(
            "Uso da chave por terceiros, com custo na fatura do Google Cloud e cotas esgotadas "
            "(o mapa do site para de funcionar)."
        ),
        steps=(
            "No Google Cloud Console (APIs e serviços > Credenciais), abra a chave e defina a "
            'restrição de aplicativo "Referenciadores HTTP" com os domínios do site.',
            'Em "Restrições de API", libere só as APIs que o site usa.',
            "Configure alertas de orçamento. Se a chave já foi usada indevidamente, gere outra e "
            "apague a antiga.",
        ),
        examples=(
            Fix(
                "generico",
                "Google Cloud CLI",
                'gcloud services api-keys update ID_DA_CHAVE --allowed-referrers="https://www.exemplo.com.br/*" '
                "--api-target=service=SERVICO.googleapis.com",
                "bash",
            ),
        ),
        verify=(
            "No Console, a chave deve mostrar restrições de aplicativo e de API; uma chamada feita "
            "a partir de outro domínio deve ser recusada."
        ),
        effort="baixo",
        fix_group="conteudo",
        references=(
            "https://developers.google.com/maps/api-security-best-practices",
            "https://firebase.google.com/docs/projects/api-keys",
            "https://docs.cloud.google.com/sdk/gcloud/reference/services/api-keys/update",
        ),
        cwe="CWE-284",
        owasp="A05:2021",
        cis=("3.3",),
        tags=("segredos", "conteudo", "google"),
    ),
    KBEntry(
        id="web.conteudo.token_localstorage",
        title="Token de sessão guardado em localStorage ou sessionStorage",
        category=Category.WEB,
        severity=Severity.LOW,
        summary="O JavaScript do site grava um token de sessão onde qualquer script da página consegue lê-lo.",
        explanation=(
            "O localStorage e o sessionStorage são legíveis por todo JavaScript que roda na página: "
            "o do próprio site, bibliotecas de terceiros e qualquer script injetado por uma falha "
            "de XSS. Diferente do cookie com HttpOnly, não há como proibir essa leitura. A "
            "detecção olha o nome da chave (token, jwt, session, sessao, auth) e a variável "
            "gravada; por isso a confiança é tentativa: confirme se o valor guardado é mesmo o "
            "que autentica o usuário. Chaves de tema, idioma, carrinho e consentimento são "
            "ignoradas."
        ),
        risk=(
            "Uma única falha de XSS, ou um script de terceiros comprometido, copia o token e o "
            "envia a um servidor do atacante, que passa a agir como o usuário sem precisar da "
            "senha. O token continua valendo mesmo depois de a falha ser corrigida, até expirar."
        ),
        steps=(
            "Confirme no navegador (F12 > Aplicativo > Armazenamento local) o que a chave "
            "contém e se ela autentica chamadas ao servidor.",
            "Emita a sessão pelo servidor em um cookie com HttpOnly, Secure e SameSite, e deixe "
            "o navegador enviá-lo sozinho (fetch com credentials).",
            "Se o token precisar mesmo ficar no JavaScript, use validade curta, renovação por "
            "cookie HttpOnly e uma Content-Security-Policy restritiva para reduzir o alcance de "
            "um XSS.",
            "Revogue os tokens que já foram emitidos e guardados dessa forma.",
        ),
        examples=(
            Fix(
                "express",
                "Node.js / Express (sessão em cookie HttpOnly)",
                "res.cookie('sessao', token, {\n"
                "  httpOnly: true, secure: true, sameSite: 'strict', maxAge: 3600 * 1000,\n});",
                "javascript",
            ),
            Fix(
                "generico",
                "Navegador (o cookie vai junto, sem ler o token)",
                "fetch('/api/perfil', { credentials: 'include' });",
                "javascript",
            ),
            Fix(
                "generico",
                "Cabeçalho que o servidor deve enviar",
                "Set-Cookie: sessao=...; Path=/; Secure; HttpOnly; SameSite=Strict",
                "text",
            ),
        ),
        verify=(
            "Repita o login e confira em F12 > Aplicativo que nenhuma chave de token surge em "
            "Armazenamento local e Armazenamento de sessão; o cookie de sessão deve aparecer "
            "marcado com HttpOnly e Secure. Repita a auditoria."
        ),
        effort="medio",
        fix_group="conteudo",
        references=(
            "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage",
            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/922.html",
        ),
        cwe="CWE-922",
        owasp="A07:2021",
        cis=("16.10", "3.3"),
        tags=("sessao", "javascript", "conteudo"),
    ),
    KBEntry(
        id="web.conteudo.credencial_literal",
        title="Usuário e senha escritos no JavaScript do site",
        category=Category.WEB,
        severity=Severity.MEDIUM,
        summary="O código entregue ao navegador traz uma senha literal; quem abrir o código-fonte a lê.",
        explanation=(
            "Foi encontrada uma senha escrita entre aspas no JavaScript (por exemplo, "
            'senha: "...", ou um par usuário e senha no mesmo objeto). Um login conferido só no '
            "navegador não é barreira de segurança: o código, e portanto a senha, é entregue a "
            "todos os visitantes, e quem não quiser ler o código pode simplesmente pular a "
            "verificação. Rótulos de formulário, placeholders, traduções, mensagens de validação "
            "e nomes de campo são descartados; o valor encontrado aparece sempre mascarado. Por "
            "ser uma leitura heurística, a confiança é tentativa: confira o trecho antes de agir."
        ),
        risk=(
            "Qualquer pessoa entra com a credencial publicada. Se a mesma senha é usada em outro "
            "sistema, o vazamento se estende a ele. Em demonstrações, o risco real é o hábito: "
            "o mesmo desenho, levado à produção, deixa a área restrita aberta."
        ),
        steps=(
            "Confirme no trecho indicado se o valor é uma senha real ou apenas um dado de "
            "demonstração.",
            "Se for real, troque a senha em todo lugar onde ela é usada e trate-a como vazada.",
            "Mova a autenticação para o servidor: o navegador envia o que o usuário digitou e o "
            "servidor confere contra um hash (bcrypt, Argon2) guardado fora do código público.",
            "Para dados de teste, gere as credenciais na instalação e nunca as publique no "
            "código entregue ao navegador.",
        ),
        examples=(
            Fix(
                "express",
                "Node.js / Express (a conferência fica no servidor)",
                "app.post('/login', async (req, res) => {\n"
                "  const user = await usuarios.porEmail(req.body.email);\n"
                "  if (!user || !(await bcrypt.compare(req.body.senha, user.hash))) {\n"
                "    return res.status(401).json({ erro: 'Credenciais inválidas' });\n  }\n"
                "  req.session.userId = user.id;\n  res.sendStatus(204);\n});",
                "javascript",
            ),
            Fix(
                "flask",
                "Flask (hash no servidor)",
                "from werkzeug.security import check_password_hash\n"
                "if not user or not check_password_hash(user.hash, request.form['senha']):\n"
                "    abort(401)",
                "python",
            ),
        ),
        verify=(
            "Procure no código-fonte da página e dos scripts (Ctrl+U e F12 > Fontes) o início do "
            "valor mascarado: ele não pode mais aparecer. Teste o login com a senha antiga; "
            "deve falhar."
        ),
        effort="medio",
        fix_group="conteudo",
        references=(
            _SECRETS,
            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/798.html",
        ),
        cwe="CWE-798",
        owasp="A07:2021",
        cis=("5.2",),
        tags=("segredos", "autenticacao", "conteudo"),
    ),
    KBEntry(
        id="web.erro.detalhado",
        title="Página de erro mostra detalhes internos (rastreamento de pilha)",
        category=Category.WEB,
        severity=Severity.MEDIUM,
        summary="Uma página de erro exibe stack trace, caminhos de arquivos ou mensagens internas da aplicação.",
        explanation=(
            "Quando a aplicação falha, ela mostra ao visitante a mensagem técnica completa: o "
            "rastreamento de pilha (stack trace) com classes e funções, caminhos de arquivos no "
            "servidor, versões de componentes e às vezes trechos de código ou consultas SQL. Essas "
            "informações servem para quem desenvolve, não para o público."
        ),
        risk=(
            "O atacante descobre tecnologia, versões, estrutura de pastas e pontos frágeis da "
            "aplicação, o que encurta o caminho até uma falha explorável."
        ),
        steps=(
            "Desligue a exibição de erros detalhados em produção e mostre uma página genérica com "
            "um código de referência para o suporte.",
            "Registre o erro completo apenas no log do servidor.",
            "Corrija a causa do erro (a evidência mostra a página e o tipo de falha).",
        ),
        examples=(
            Fix("php", "PHP (php.ini)", "display_errors = Off\nlog_errors = On", "ini"),
            Fix("laravel", "Laravel (.env)", "APP_DEBUG=false", "ini"),
            Fix("django", "Django (settings.py)", "DEBUG = False", "python"),
            Fix("flask", "Flask (servidor de produção)", "gunicorn -w 4 'app:app'", "bash"),
            Fix(
                "aspnet",
                "ASP.NET (web.config, em <system.web>)",
                '<customErrors mode="RemoteOnly" defaultRedirect="~/Erro.aspx" />',
                "xml",
            ),
            Fix(
                "aspnet",
                "ASP.NET Core (Program.cs)",
                'app.UseExceptionHandler("/Error");',
                "csharp",
            ),
            Fix(
                "express", "Node.js / Express (variável de ambiente)", "NODE_ENV=production", "bash"
            ),
            Fix(
                "spring",
                "Spring Boot (application.properties)",
                "server.error.include-stacktrace=never",
                "ini",
            ),
            Fix(
                "tomcat",
                "Tomcat (server.xml, dentro de <Host>)",
                '<Valve className="org.apache.catalina.valves.ErrorReportValve" showReport="false" showServerInfo="false" />',
                "xml",
            ),
        ),
        verify=(
            "Provoque um erro (por exemplo, acesse um endereço inexistente) e confirme que a "
            "resposta não mostra stack trace nem caminhos de arquivos."
        ),
        effort="baixo",
        fix_group="debug",
        references=(
            _ERRORS,
            _WSTG_ERRORS,
            "https://www.php.net/manual/en/errorfunc.configuration.php",
            "https://learn.microsoft.com/en-us/aspnet/core/fundamentals/error-handling",
            "https://expressjs.com/en/guide/error-handling.html",
        ),
        cwe="CWE-209",
        owasp="A05:2021",
        cis=("4.1", "16.7"),
        tags=("debug", "erros"),
    ),
    KBEntry(
        id="web.debug.modo_debug",
        title="Aplicação em modo de depuração (DEBUG) em produção",
        category=Category.WEB,
        severity=Severity.HIGH,
        summary="A página de erro é a página de depuração do framework (Django com DEBUG = True, Laravel com APP_DEBUG ativo).",
        explanation=(
            "No modo de depuração o framework mostra a qualquer visitante páginas de erro "
            "completas: rastreamento de pilha com trechos do código-fonte, variáveis, "
            "configurações e, no Django, a lista de rotas da aplicação. A documentação do Django "
            "proíbe publicar com DEBUG ligado, e a do Laravel avisa que APP_DEBUG ativo em "
            "produção expõe valores sensíveis de configuração aos usuários."
        ),
        risk=(
            "O atacante obtém o mapa da aplicação e, com frequência, credenciais (senha do banco, "
            "chaves de API) exibidas em configurações ou variáveis de ambiente — às vezes o "
            "suficiente para invadir sem explorar falha nenhuma."
        ),
        steps=(
            "Desligue o modo de depuração na configuração de produção (DEBUG = False no Django; "
            "APP_DEBUG=false no Laravel) e reinicie a aplicação.",
            "Troque as senhas e chaves que podem ter aparecido nas páginas de erro (banco de "
            "dados, SECRET_KEY/APP_KEY, chaves de API).",
            "Separe a configuração de produção da de desenvolvimento (variáveis de ambiente) para "
            "o modo de depuração não voltar por engano.",
        ),
        examples=(
            Fix("django", "Django (settings.py)", "DEBUG = False", "python"),
            Fix(
                "laravel",
                "Laravel (.env e depois recriar o cache de configuração)",
                "APP_DEBUG=false\n# depois: php artisan config:cache",
                "ini",
            ),
        ),
        verify=(
            "Acesse um endereço inexistente: a resposta deve ser a página 404 comum do site, sem "
            "a mensagem de depuração do framework."
        ),
        effort="baixo",
        fix_group="debug",
        references=(
            "https://docs.djangoproject.com/en/stable/ref/settings/#debug",
            "https://laravel.com/docs/configuration#debug-mode",
            _ERRORS,
        ),
        cwe="CWE-489",
        owasp="A05:2021",
        cis=("4.1", "16.7"),
        tags=("debug",),
    ),
    KBEntry(
        id="web.debug.werkzeug",
        title="Console de depuração do Werkzeug/Flask exposto",
        category=Category.WEB,
        severity=Severity.CRITICAL,
        summary="O depurador interativo do Werkzeug (usado pelo Flask em modo debug) responde neste site.",
        explanation=(
            "O depurador do Werkzeug permite executar código Python no servidor pelo navegador; a "
            "própria documentação avisa que ele é um risco de segurança e nunca deve ser usado em "
            "produção. Ele aparece quando a aplicação roda no servidor de desenvolvimento em modo "
            "debug (flask run --debug, app.run(debug=True)). O console costuma pedir um PIN, mas o "
            "PIN pode estar desativado — a evidência informa o que foi observado. Sem PIN a "
            "gravidade é crítica; com PIN o console continua exposto, mas exige descobrir o PIN."
        ),
        risk=(
            "Execução remota de código: quem passar pelo PIN (ou encontrá-lo desativado) controla "
            "o servidor, lê o banco de dados e as chaves da aplicação."
        ),
        steps=(
            "Desligue o modo debug imediatamente (remova debug=True, --debug ou FLASK_DEBUG=1) e "
            "reinicie a aplicação.",
            "Publique com um servidor WSGI de produção (gunicorn, waitress, uWSGI) atrás de um "
            "proxy reverso, nunca com o servidor de desenvolvimento.",
            "Se o console estava acessível sem PIN, trate o servidor como comprometido: revise os "
            "logs, troque senhas e chaves e procure arquivos ou processos estranhos.",
        ),
        examples=(
            Fix("flask", "Flask em Linux (gunicorn)", "gunicorn -w 4 'app:app'", "bash"),
            Fix(
                "flask", "Flask em Windows (waitress)", "waitress-serve --port=8080 app:app", "bash"
            ),
        ),
        verify='Acesse /console e provoque um erro: nenhuma página "Werkzeug Debugger" deve aparecer.',
        effort="baixo",
        fix_group="debug",
        references=(
            "https://werkzeug.palletsprojects.com/en/stable/debug/",
            "https://flask.palletsprojects.com/en/stable/deploying/",
        ),
        cwe="CWE-489",
        owasp="A05:2021",
        cis=("4.1", "4.8", "16.7"),
        tags=("debug", "flask"),
    ),
)
