"""Base de conhecimento dos cabeçalhos de segurança HTTP (checagem ``web.headers``).

Os exemplos de correção são de UMA linha por tecnologia: o plano de correção junta
as linhas da mesma tecnologia (todos os cabeçalhos do nginx viram um só bloco).
"""

from __future__ import annotations

from ...core import kb
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Severity

CSP_VALUE = "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'"
PERMISSIONS_VALUE = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
HEADERS_CHEATSHEET = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
SECURE_HEADERS = "https://owasp.org/www-project-secure-headers/"


def header_fixes(
    name: str,
    value: str,
    *,
    express: str,
    django: str | None = None,
    spring: str | None = None,
) -> tuple[Fix, ...]:
    """Exemplos de uma linha que definem ``name: value`` em cada tecnologia."""
    fixes = [
        Fix("nginx", "nginx", f'add_header {name} "{value}" always;', "nginx"),
        Fix("apache", "Apache", f'Header always set {name} "{value}"', "apache"),
        Fix("litespeed", "LiteSpeed (.htaccess)", f'Header always set {name} "{value}"', "apache"),
        Fix(
            "iis",
            "IIS (web.config, em <customHeaders>)",
            f'<add name="{name}" value="{value}" />',
            "xml",
        ),
        Fix("express", "Node.js / Express", express, "javascript"),
        Fix("php", "PHP (antes de qualquer saída)", f'header("{name}: {value}");', "php"),
        Fix(
            "aspnet",
            "ASP.NET Core (Program.cs)",
            "app.Use(async (ctx, next) => { "
            f'ctx.Response.Headers["{name}"] = "{value}"; await next(); }});',
            "csharp",
        ),
    ]
    if django:
        fixes.append(Fix("django", "Django (settings.py)", django, "python"))
    if spring:
        fixes.append(Fix("spring", "Spring Security", spring, "java"))
    fixes.append(
        Fix(
            "cloudflare",
            "Cloudflare",
            "Rules > Overview > Create rule > Response Header Transform Rule: "
            f'Set static "{name}" = "{value}"',
            "text",
        )
    )
    return tuple(fixes)


kb.register(
    KBEntry(
        id="web.csp.ausente",
        title="Content-Security-Policy ausente",
        category=Category.WEB,
        severity=Severity.MEDIUM,
        summary="As páginas não definem uma política de segurança de conteúdo (CSP).",
        explanation=(
            "A CSP diz ao navegador de onde a página pode carregar scripts, estilos, imagens e "
            "quadros. Sem ela, qualquer script que um atacante consiga injetar (por um campo "
            "de comentário, parâmetro da URL ou biblioteca comprometida) roda com todos os "
            "poderes do site."
        ),
        risk=(
            "Uma falha de XSS vira roubo de sessão, captura de senhas digitadas, alteração do "
            "conteúdo exibido e envio de dados para servidores do atacante. A CSP é a principal "
            "barreira que limita o estrago quando o XSS acontece."
        ),
        steps=(
            "Liste de onde o site carrega scripts, estilos, fontes e imagens (ferramentas do "
            "desenvolvedor do navegador, aba Rede).",
            "Publique primeiro em modo de teste com Content-Security-Policy-Report-Only e "
            "acompanhe as violações por alguns dias.",
            "Ajuste a política para liberar só as origens necessárias; troque scripts embutidos "
            "por arquivos ou use nonce.",
            "Publique o cabeçalho Content-Security-Policy definitivo em todas as páginas HTML.",
        ),
        examples=header_fixes(
            "Content-Security-Policy",
            CSP_VALUE,
            express=(
                "app.use(require('helmet').contentSecurityPolicy({ directives: { "
                "defaultSrc: [\"'self'\"], objectSrc: [\"'none'\"], baseUri: [\"'self'\"], "
                "frameAncestors: [\"'self'\"] } }));"
            ),
            django=(
                'SECURE_CSP = {"default-src": ["\'self\'"], "object-src": ["\'none\'"], '
                '"base-uri": ["\'self\'"], "frame-ancestors": ["\'self\'"]}  '
                "# Django 6+, com ContentSecurityPolicyMiddleware"
            ),
            spring=(
                "http.headers(h -> h.contentSecurityPolicy(csp -> csp.policyDirectives("
                f'"{CSP_VALUE}")));'
            ),
        ),
        verify=(
            "curl -sI https://seu-site | grep -i content-security-policy — e navegue pelo site "
            "com o console aberto: não deve haver bloqueios inesperados."
        ),
        effort="medio",
        fix_group="cabecalhos",
        references=(
            "https://developer.mozilla.org/pt-BR/docs/Web/HTTP/CSP",
            "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
            SECURE_HEADERS,
        ),
        cwe="CWE-693",
        owasp="A05:2021",
        cis=("16.7",),
        tags=("cabecalhos", "xss"),
    ),
    KBEntry(
        id="web.csp.fraca",
        title="Content-Security-Policy com brechas",
        category=Category.WEB,
        severity=Severity.LOW,
        summary="A CSP existe, mas tem diretivas que permitem contorná-la.",
        explanation=(
            "Algumas diretivas anulam boa parte da proteção: 'unsafe-inline' sem nonce/hash "
            "deixa rodar scripts injetados no HTML; 'unsafe-eval' libera eval(); curingas como "
            "* ou https: em script-src aceitam scripts de qualquer site; sem object-src plugins "
            "podem executar código; e, sem base-uri, uma tag <base> injetada muda o destino de "
            "links e formulários relativos — em políticas com nonce, também dos scripts."
        ),
        risk=(
            "Com essas brechas, um XSS continua explorável apesar da CSP: o atacante injeta o "
            "script direto na página ou o hospeda em outro domínio aceito pelo curinga."
        ),
        steps=(
            "Remova 'unsafe-inline' de script-src: mova scripts embutidos para arquivos .js ou "
            "use nonces gerados a cada resposta (com 'strict-dynamic').",
            "Remova 'unsafe-eval' e reescreva o código que usa eval/new Function.",
            "Troque *, http:, https: e data: em script-src pelos domínios exatos necessários.",
            "Inclua object-src 'none' e base-uri 'self' (ou 'none').",
            "Valide a política no CSP Evaluator antes de publicar.",
        ),
        examples=header_fixes(
            "Content-Security-Policy",
            CSP_VALUE,
            express=(
                "app.use(require('helmet').contentSecurityPolicy({ directives: { "
                "defaultSrc: [\"'self'\"], objectSrc: [\"'none'\"], baseUri: [\"'self'\"], "
                "frameAncestors: [\"'self'\"] } }));"
            ),
            django=(
                'SECURE_CSP = {"default-src": ["\'self\'"], "object-src": ["\'none\'"], '
                '"base-uri": ["\'self\'"], "frame-ancestors": ["\'self\'"]}  '
                "# Django 6+, com ContentSecurityPolicyMiddleware"
            ),
            spring=(
                "http.headers(h -> h.contentSecurityPolicy(csp -> csp.policyDirectives("
                f'"{CSP_VALUE}")));'
            ),
        ),
        verify="Cole a política em https://csp-evaluator.withgoogle.com/ — não deve haver alertas altos.",
        effort="medio",
        fix_group="cabecalhos",
        references=(
            "https://csp-evaluator.withgoogle.com/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
            "https://web.dev/articles/strict-csp",
        ),
        cwe="CWE-693",
        owasp="A05:2021",
        cis=("16.7",),
        tags=("cabecalhos", "xss"),
    ),
    KBEntry(
        id="web.clickjacking.ausente",
        title="Proteção contra clickjacking ausente",
        category=Category.WEB,
        severity=Severity.LOW,
        summary="O site pode ser exibido dentro de quadros (iframes) de outros sites.",
        # severidade: BAIXA numa página estática; sobe para MÉDIA quando a página tem login ou
        # formulário que altera dados (há o que sequestrar com cliques)
        explanation=(
            "Sem X-Frame-Options nem a diretiva frame-ancestors da CSP, qualquer site pode "
            "carregar as suas páginas em um iframe invisível e enganar o usuário para clicar em "
            "botões reais (confirmar, transferir, excluir) achando que clica em outra coisa."
        ),
        risk=(
            "Ações indesejadas executadas com a sessão da vítima: mudar e-mail ou senha, "
            "autorizar pagamentos, dar permissões ou curtir/compartilhar conteúdo."
        ),
        steps=(
            "Envie X-Frame-Options: SAMEORIGIN (ou DENY se o site nunca usa iframes de si mesmo).",
            "Se usar CSP, inclua frame-ancestors 'self' — é o substituto moderno do "
            "X-Frame-Options (só vale no cabeçalho, não em <meta>).",
            "Se precisa ser incorporado por parceiros, liste os domínios em frame-ancestors.",
        ),
        examples=header_fixes(
            "X-Frame-Options",
            "SAMEORIGIN",
            express="app.use(require('helmet').frameguard({ action: 'sameorigin' }));",
            django='X_FRAME_OPTIONS = "SAMEORIGIN"  # com XFrameOptionsMiddleware',
            spring="http.headers(h -> h.frameOptions(f -> f.sameOrigin()));",
        ),
        verify="curl -sI https://seu-site | grep -iE 'x-frame-options|frame-ancestors'",
        effort="baixo",
        fix_group="cabecalhos",
        references=(
            "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
            "https://developer.mozilla.org/pt-BR/docs/Web/HTTP/Headers/X-Frame-Options",
        ),
        cwe="CWE-1021",
        owasp="A05:2021",
        cis=("16.7",),
        tags=("cabecalhos", "clickjacking"),
    ),
    KBEntry(
        id="web.nosniff.ausente",
        title="Cabeçalho X-Content-Type-Options ausente",
        category=Category.WEB,
        severity=Severity.LOW,
        summary="O navegador pode 'adivinhar' o tipo dos arquivos (MIME sniffing).",
        explanation=(
            "Sem X-Content-Type-Options: nosniff, o navegador pode interpretar um arquivo de "
            "texto ou imagem enviado por usuários como script ou HTML se o conteúdo parecer um."
        ),
        risk=(
            "Arquivos enviados ao site (avatares, anexos) podem ser executados como script, "
            "abrindo caminho para XSS armazenado."
        ),
        steps=(
            "Envie X-Content-Type-Options: nosniff em todas as respostas.",
            "Garanta que o servidor mande o Content-Type correto para cada arquivo.",
        ),
        examples=header_fixes(
            "X-Content-Type-Options",
            "nosniff",
            express="app.use(require('helmet').noSniff());",
            django="SECURE_CONTENT_TYPE_NOSNIFF = True",
            spring="http.headers(h -> h.contentTypeOptions(Customizer.withDefaults()));",
        ),
        verify="curl -sI https://seu-site | grep -i x-content-type-options",
        effort="baixo",
        fix_group="cabecalhos",
        references=(
            "https://developer.mozilla.org/pt-BR/docs/Web/HTTP/Headers/X-Content-Type-Options",
            HEADERS_CHEATSHEET,
        ),
        cwe="CWE-693",
        owasp="A05:2021",
        cis=("16.7",),
        tags=("cabecalhos",),
    ),
    KBEntry(
        id="web.referrer.ausente",
        title="Cabeçalho Referrer-Policy ausente",
        category=Category.WEB,
        severity=Severity.INFO,
        summary="O site não define quanto da URL é enviado a outros sites (Referer).",
        explanation=(
            "Quando o usuário clica em um link ou a página carrega recursos externos, o navegador "
            "envia o endereço de origem. Sem política explícita (no cabeçalho ou em "
            '<meta name="referrer">), os navegadores atuais usam '
            "strict-origin-when-cross-origin e mandam só o domínio para outros sites; navegadores "
            "antigos ainda enviam a URL completa, com parâmetros. Definir a política deixa o "
            "comportamento previsível em qualquer navegador."
        ),
        risk=(
            "Em navegadores antigos, tokens, identificadores e dados pessoais presentes em URLs "
            "(links de redefinição de senha, buscas, números de pedido) vazam para terceiros e "
            "ficam nos logs deles."
        ),
        steps=(
            "Envie Referrer-Policy: strict-origin-when-cross-origin (ou no-referrer, se possível).",
            "Evite colocar tokens e dados pessoais em URLs.",
        ),
        examples=header_fixes(
            "Referrer-Policy",
            "strict-origin-when-cross-origin",
            express=(
                "app.use(require('helmet').referrerPolicy({ policy: "
                "'strict-origin-when-cross-origin' }));"
            ),
            django='SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"',
        ),
        verify="curl -sI https://seu-site | grep -i referrer-policy",
        effort="baixo",
        fix_group="cabecalhos",
        references=(
            "https://developer.mozilla.org/pt-BR/docs/Web/HTTP/Headers/Referrer-Policy",
            HEADERS_CHEATSHEET,
        ),
        cwe="CWE-200",
        owasp="A05:2021",
        cis=("16.7",),
        lgpd=True,
        tags=("cabecalhos", "privacidade"),
    ),
    KBEntry(
        id="web.referrer.inseguro",
        title="Referrer-Policy envia a URL completa a outros sites",
        category=Category.WEB,
        severity=Severity.LOW,
        summary="A política configurada manda o endereço completo (com parâmetros) para terceiros.",
        explanation=(
            "Os valores unsafe-url e no-referrer-when-downgrade fazem o navegador enviar a URL "
            "inteira — caminho e parâmetros — para qualquer site de destino, inclusive anúncios "
            "e ferramentas de análise."
        ),
        risk=(
            "Tokens e dados pessoais presentes nas URLs vazam para terceiros e ficam gravados nos "
            "logs deles."
        ),
        steps=(
            "Troque o valor por strict-origin-when-cross-origin (ou no-referrer).",
            "Confirme que nenhum outro ponto (meta referrer, atributo referrerpolicy) reativa o "
            "envio completo.",
        ),
        examples=header_fixes(
            "Referrer-Policy",
            "strict-origin-when-cross-origin",
            express=(
                "app.use(require('helmet').referrerPolicy({ policy: "
                "'strict-origin-when-cross-origin' }));"
            ),
            django='SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"',
        ),
        verify="curl -sI https://seu-site | grep -i referrer-policy",
        effort="baixo",
        fix_group="cabecalhos",
        references=("https://developer.mozilla.org/pt-BR/docs/Web/HTTP/Headers/Referrer-Policy",),
        cwe="CWE-200",
        owasp="A05:2021",
        cis=("16.7",),
        lgpd=True,
        tags=("cabecalhos", "privacidade"),
    ),
    KBEntry(
        id="web.permissions_policy.ausente",
        title="Cabeçalho Permissions-Policy ausente",
        category=Category.WEB,
        severity=Severity.INFO,
        summary="O site não restringe o uso de câmera, microfone, localização e outros recursos.",
        explanation=(
            "A Permissions-Policy desliga recursos poderosos do navegador que o site não usa. "
            "Assim, mesmo um script de terceiros comprometido ou um iframe não consegue pedir "
            "acesso à câmera, ao microfone ou à localização do visitante."
        ),
        risk="Defesa em profundidade: limita o que um script malicioso ou um iframe pode pedir.",
        steps=(
            "Liste os recursos que o site realmente usa.",
            "Envie Permissions-Policy desligando o resto, por exemplo camera=(), microphone=(), "
            "geolocation=().",
        ),
        examples=header_fixes(
            "Permissions-Policy",
            PERMISSIONS_VALUE,
            express=(
                "app.use((req, res, next) => { res.setHeader('Permissions-Policy', "
                f"'{PERMISSIONS_VALUE}'); next(); }});"
            ),
        ),
        verify="curl -sI https://seu-site | grep -i permissions-policy",
        effort="baixo",
        fix_group="cabecalhos",
        references=(
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
            SECURE_HEADERS,
        ),
        cwe="CWE-693",
        owasp="A05:2021",
        cis=("16.7",),
        tags=("cabecalhos",),
    ),
    KBEntry(
        id="web.coop.ausente",
        title="Cabeçalho Cross-Origin-Opener-Policy ausente",
        category=Category.WEB,
        severity=Severity.INFO,
        summary="Janelas abertas por outros sites podem manter referência à página do site.",
        explanation=(
            "O Cross-Origin-Opener-Policy isola a janela do site das janelas de outras origens "
            "(pop-ups e abas abertas por links). Sem ele, uma página maliciosa que abriu o site "
            "mantém uma referência à janela e pode navegar com ela ou medir o seu comportamento."
        ),
        risk=(
            "Defesa em profundidade contra ataques de vazamento entre sites (XS-Leaks) e trocas "
            "de página para phishing (tabnabbing)."
        ),
        steps=(
            "Envie Cross-Origin-Opener-Policy: same-origin.",
            "Se o site depende de pop-ups de outros domínios (login social, pagamentos), use "
            "same-origin-allow-popups e teste esses fluxos.",
        ),
        examples=header_fixes(
            "Cross-Origin-Opener-Policy",
            "same-origin",
            express="app.use(require('helmet').crossOriginOpenerPolicy());",
            django='SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"',
        ),
        verify="curl -sI https://seu-site | grep -i cross-origin-opener-policy",
        effort="baixo",
        fix_group="cabecalhos",
        references=(
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
            HEADERS_CHEATSHEET,
        ),
        cwe="CWE-693",
        owasp="A05:2021",
        cis=("16.7",),
        tags=("cabecalhos",),
    ),
    KBEntry(
        id="web.xss_protection.ativo",
        title="X-XSS-Protection ativado (cabeçalho obsoleto)",
        category=Category.WEB,
        severity=Severity.INFO,
        summary="O site liga o antigo filtro de XSS do navegador, que já foi removido e causava falhas.",
        explanation=(
            "O X-XSS-Protection controlava o 'XSS Auditor' de navegadores antigos. Os navegadores "
            "modernos removeram esse filtro e, nos que ainda o têm, ele já foi usado para vazar "
            "informações entre sites. A recomendação atual é desligá-lo (valor 0) ou não enviar o "
            "cabeçalho, e proteger o site com CSP."
        ),
        risk="Em navegadores antigos, o filtro pode ser abusado para vazar dados ou bloquear scripts legítimos.",
        steps=(
            "Envie X-XSS-Protection: 0 ou remova o cabeçalho.",
            "Use uma Content-Security-Policy para a proteção real contra XSS.",
        ),
        examples=header_fixes(
            "X-XSS-Protection",
            "0",
            express="app.use(require('helmet').xXssProtection());",
            spring=(
                "http.headers(h -> h.xssProtection(x -> "
                "x.headerValue(XXssProtectionHeaderWriter.HeaderValue.DISABLED)));"
            ),
        ),
        verify="curl -sI https://seu-site | grep -i x-xss-protection — deve mostrar 0 ou nada.",
        effort="baixo",
        fix_group="cabecalhos",
        references=(
            "https://developer.mozilla.org/pt-BR/docs/Web/HTTP/Headers/X-XSS-Protection",
            HEADERS_CHEATSHEET,
        ),
        cwe="CWE-693",
        owasp="A05:2021",
        cis=("16.7",),
        tags=("cabecalhos",),
    ),
)
