"""Base de conhecimento dos atributos de cookies (checagem ``web.cookies``)."""

from __future__ import annotations

from ...core import kb
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Severity

_SESSION_CHEATSHEET = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"
)
_SET_COOKIE = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie"
_EXPRESS_SESSION = (
    "app.use(session({ secret: process.env.SESSION_SECRET, cookie: "
    "{ secure: true, httpOnly: true, sameSite: 'lax' } }));"
)

kb.register(
    KBEntry(
        id="web.cookie.sem_secure",
        title="Cookie sem o atributo Secure",
        category=Category.WEB,
        severity=Severity.MEDIUM,
        summary="Um cookie do site HTTPS pode ser enviado também por HTTP, sem criptografia.",
        explanation=(
            "O atributo Secure faz o navegador enviar o cookie só em conexões HTTPS. Sem ele, "
            "basta a vítima acessar um único endereço http:// do domínio (um link antigo, uma "
            "imagem) para o cookie viajar em texto puro. O HSTS reduz o risco (depois da primeira "
            "visita o navegador deixa de usar HTTP no domínio), mas não substitui o Secure: a "
            "primeira visita e subdomínios sem HSTS continuam expostos."
        ),
        risk=(
            "Em Wi-Fi público ou rede comprometida, o atacante captura o cookie de sessão e entra "
            "na conta da vítima sem precisar da senha."
        ),
        steps=(
            "Marque como Secure todos os cookies emitidos pelo site HTTPS, em especial os de "
            "sessão e autenticação.",
            "Ative o HSTS para que o navegador nunca mais use HTTP no domínio.",
        ),
        examples=(
            Fix("php", "PHP (php.ini)", "session.cookie_secure = 1", "ini"),
            Fix("laravel", "Laravel (.env)", "SESSION_SECURE_COOKIE=true", "ini"),
            Fix("django", "Django (settings.py)", "SESSION_COOKIE_SECURE = True", "python"),
            Fix("django", "Django (settings.py)", "CSRF_COOKIE_SECURE = True", "python"),
            Fix("flask", "Flask", "app.config.update(SESSION_COOKIE_SECURE=True)", "python"),
            Fix("express", "Node.js / express-session", _EXPRESS_SESSION, "javascript"),
            Fix(
                "aspnet",
                "ASP.NET (web.config, em <system.web>)",
                '<httpCookies requireSSL="true" />',
                "xml",
            ),
            Fix("iis", "IIS / ASP.NET (web.config)", '<httpCookies requireSSL="true" />', "xml"),
            Fix(
                "spring",
                "Spring Boot (application.properties)",
                "server.servlet.session.cookie.secure=true",
                "ini",
            ),
            Fix(
                "tomcat",
                "Tomcat (web.xml)",
                "<session-config><cookie-config><secure>true</secure></cookie-config></session-config>",
                "xml",
            ),
            Fix(
                "wordpress", "WordPress (wp-config.php)", "define('FORCE_SSL_ADMIN', true);", "php"
            ),
            Fix("nginx", "nginx 1.19.3+ (proxy reverso)", "proxy_cookie_flags ~ secure;", "nginx"),
            Fix(
                "apache",
                "Apache (mod_headers)",
                'Header always edit Set-Cookie ^(.*)$ "$1; Secure"',
                "apache",
            ),
        ),
        verify="No navegador (F12 > Application > Cookies) a coluna Secure deve estar marcada.",
        effort="baixo",
        fix_group="cookies",
        references=(_SET_COOKIE, _SESSION_CHEATSHEET),
        cwe="CWE-614",
        owasp="A05:2021",
        cis=("3.10",),
        lgpd=True,
        tags=("cookies", "sessao"),
    ),
    KBEntry(
        id="web.cookie.sem_httponly",
        title="Cookie de sessão sem o atributo HttpOnly",
        category=Category.WEB,
        severity=Severity.MEDIUM,
        summary="Scripts da página conseguem ler o cookie de sessão.",
        explanation=(
            "O atributo HttpOnly esconde o cookie do JavaScript (document.cookie). Cookies de "
            "sessão e autenticação não precisam ser lidos por scripts; sem HttpOnly, qualquer "
            "XSS consegue copiá-los."
        ),
        risk="Uma falha de XSS vira sequestro imediato de sessão: o script envia o cookie ao atacante.",
        steps=(
            "Marque como HttpOnly os cookies de sessão e de autenticação.",
            "Se algum script precisa de um valor, entregue-o por outro meio (por exemplo, um "
            "cookie separado só com o token anti-CSRF).",
        ),
        examples=(
            Fix("php", "PHP (php.ini)", "session.cookie_httponly = 1", "ini"),
            Fix("laravel", "Laravel (config/session.php)", "'http_only' => true,", "php"),
            Fix("django", "Django (settings.py)", "SESSION_COOKIE_HTTPONLY = True", "python"),
            Fix("flask", "Flask", "app.config.update(SESSION_COOKIE_HTTPONLY=True)", "python"),
            Fix("express", "Node.js / express-session", _EXPRESS_SESSION, "javascript"),
            Fix(
                "aspnet",
                "ASP.NET (web.config, em <system.web>)",
                '<httpCookies httpOnlyCookies="true" />',
                "xml",
            ),
            Fix(
                "iis", "IIS / ASP.NET (web.config)", '<httpCookies httpOnlyCookies="true" />', "xml"
            ),
            Fix(
                "spring",
                "Spring Boot (application.properties)",
                "server.servlet.session.cookie.http-only=true",
                "ini",
            ),
            Fix(
                "tomcat",
                "Tomcat (web.xml)",
                "<session-config><cookie-config><http-only>true</http-only></cookie-config></session-config>",
                "xml",
            ),
            Fix(
                "nginx", "nginx 1.19.3+ (proxy reverso)", "proxy_cookie_flags ~ httponly;", "nginx"
            ),
            Fix(
                "apache",
                "Apache (mod_headers)",
                'Header always edit Set-Cookie ^(.*)$ "$1; HttpOnly"',
                "apache",
            ),
        ),
        verify="No console do navegador, document.cookie não deve mostrar o cookie de sessão.",
        effort="baixo",
        fix_group="cookies",
        references=("https://owasp.org/www-community/HttpOnly", _SESSION_CHEATSHEET),
        cwe="CWE-1004",
        owasp="A05:2021",
        cis=("16.10",),
        lgpd=True,
        tags=("cookies", "sessao", "xss"),
    ),
    KBEntry(
        id="web.cookie.sem_samesite",
        title="Cookie de sessão sem o atributo SameSite",
        category=Category.WEB,
        severity=Severity.LOW,
        summary="O cookie de sessão não diz se pode ser enviado em requisições vindas de outros sites.",
        explanation=(
            "SameSite=Lax (ou Strict) impede que o navegador anexe o cookie a requisições "
            "disparadas por outros sites, a base dos ataques de CSRF. Sem o atributo, o "
            "comportamento varia: alguns navegadores assumem Lax, outros enviam sempre. Um valor "
            "diferente de Strict, Lax ou None é ignorado pelo navegador e conta como ausente."
        ),
        risk="Facilita CSRF: um site malicioso faz o navegador da vítima executar ações com a sessão dela.",
        steps=(
            "Defina SameSite=Lax nos cookies de sessão (Strict se o site não depende de links "
            "externos chegando já logados).",
            "Mantenha a proteção anti-CSRF da aplicação: SameSite é uma camada a mais.",
        ),
        examples=(
            Fix("php", "PHP 7.3+ (php.ini)", 'session.cookie_samesite = "Lax"', "ini"),
            Fix("laravel", "Laravel (config/session.php)", "'same_site' => 'lax',", "php"),
            Fix("django", "Django (settings.py)", 'SESSION_COOKIE_SAMESITE = "Lax"', "python"),
            Fix("flask", "Flask", 'app.config.update(SESSION_COOKIE_SAMESITE="Lax")', "python"),
            Fix("express", "Node.js / express-session", _EXPRESS_SESSION, "javascript"),
            Fix(
                "aspnet",
                "ASP.NET 4.7.2+ (web.config, em <system.web>)",
                '<sessionState cookieSameSite="Lax" />',
                "xml",
            ),
            Fix(
                "spring",
                "Spring Boot (application.properties)",
                "server.servlet.session.cookie.same-site=lax",
                "ini",
            ),
            Fix(
                "nginx",
                "nginx 1.19.3+ (proxy reverso)",
                "proxy_cookie_flags ~ samesite=lax;",
                "nginx",
            ),
            Fix(
                "apache",
                "Apache (mod_headers)",
                'Header always edit Set-Cookie ^(.*)$ "$1; SameSite=Lax"',
                "apache",
            ),
        ),
        verify="No navegador (F12 > Application > Cookies) a coluna SameSite deve mostrar Lax ou Strict.",
        effort="baixo",
        fix_group="cookies",
        references=(
            "https://owasp.org/www-community/SameSite",
            "https://web.dev/articles/samesite-cookies-explained",
        ),
        cwe="CWE-1275",
        owasp="A01:2021",
        cis=("16.10",),
        tags=("cookies", "csrf"),
    ),
    KBEntry(
        id="web.cookie.samesite_none_sem_secure",
        title="Cookie com SameSite=None sem Secure",
        category=Category.WEB,
        severity=Severity.LOW,
        summary="O cookie pede para ser enviado entre sites, mas sem exigir HTTPS.",
        explanation=(
            "SameSite=None libera o cookie em requisições de outros sites e, por isso, os "
            "navegadores exigem que ele também seja Secure. Sem Secure, navegadores modernos "
            "recusam o cookie (a funcionalidade quebra) e os antigos o enviam por HTTP."
        ),
        risk=(
            "Funcionalidades que dependem do cookie (login embutido, pagamentos, widgets) "
            "falham; em navegadores antigos o cookie trafega sem criptografia."
        ),
        steps=(
            "Acrescente Secure a todo cookie com SameSite=None.",
            "Reavalie se o cookie precisa mesmo ser enviado entre sites; se não, use Lax.",
        ),
        examples=(
            Fix(
                "generico",
                "Set-Cookie correto",
                "Set-Cookie: nome=valor; Path=/; Secure; HttpOnly; SameSite=None",
                "http",
            ),
            Fix(
                "express",
                "Node.js / Express",
                "res.cookie('nome', valor, { sameSite: 'none', secure: true });",
                "javascript",
            ),
            Fix(
                "php",
                "PHP 7.3+",
                "setcookie('nome', $valor, ['samesite' => 'None', 'secure' => true]);",
                "php",
            ),
            Fix("django", "Django (settings.py)", "SESSION_COOKIE_SECURE = True", "python"),
        ),
        verify="O cabeçalho Set-Cookie deve trazer SameSite=None junto com Secure.",
        effort="baixo",
        fix_group="cookies",
        references=(_SET_COOKIE, "https://web.dev/articles/samesite-cookies-explained"),
        cwe="CWE-614",
        owasp="A05:2021",
        cis=("3.10",),
        tags=("cookies",),
    ),
    KBEntry(
        id="web.cookie.prefixo_invalido",
        title="Cookie com prefixo __Host-/__Secure- mal configurado",
        category=Category.WEB,
        severity=Severity.LOW,
        summary="O cookie usa um prefixo de segurança, mas sem os atributos que ele exige.",
        explanation=(
            "Cookies que começam com __Secure- precisam ser Secure; os que começam com __Host- "
            "precisam ser Secure, ter Path=/ e NÃO ter Domain. Quando a regra não é cumprida, o "
            "navegador descarta o cookie — a proteção pretendida não existe."
        ),
        risk="Sessão ou proteção que não funciona como planejado (o cookie é rejeitado pelo navegador).",
        steps=(
            "Para __Host-: use Secure, Path=/ e remova o atributo Domain.",
            "Para __Secure-: use Secure.",
        ),
        examples=(
            Fix(
                "generico",
                "Set-Cookie correto",
                "Set-Cookie: __Host-sessao=valor; Path=/; Secure; HttpOnly; SameSite=Lax",
                "http",
            ),
            Fix(
                "express",
                "Node.js / Express",
                "res.cookie('__Host-sessao', valor, { path: '/', secure: true, httpOnly: true, sameSite: 'lax' });",
                "javascript",
            ),
        ),
        verify="O cookie aparece no navegador (F12 > Application > Cookies) depois do login.",
        effort="baixo",
        fix_group="cookies",
        references=(_SET_COOKIE,),
        cwe="CWE-614",
        owasp="A05:2021",
        cis=("16.10",),
        tags=("cookies",),
    ),
)
