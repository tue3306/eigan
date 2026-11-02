"""HTTPS e HSTS: o site usa criptografia, redireciona HTTP e manda o navegador lembrar disso.

Módulo de referência do padrão de checagem do EIGAN:

1. registrar na base (``kb.register``) cada achado que o módulo pode emitir;
2. declarar a checagem com ``@check`` (o que consome, o que pode produzir);
3. reportar com ``ctx.report``, registrar controles aprovados com ``ctx.passed`` e
   ensinar fatos novos ao motor com ``ctx.add_*``.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from ...core import facts, kb
from ...core.context import CheckContext
from ...core.facts import base_url
from ...core.http import Response
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Confidence, Fact, Severity
from ...core.registry import check
from ...core.target import is_ip

HSTS_MIN_AGE = 15_552_000  # 180 dias

kb.register(
    KBEntry(
        id="web.https.ausente",
        title="Site sem HTTPS",
        category=Category.WEB,
        severity=Severity.HIGH,
        summary="O site só funciona em HTTP: tudo trafega sem criptografia.",
        explanation=(
            "Sem HTTPS, senhas, cookies de sessão e dados de formulários passam pela rede em "
            "texto puro. Qualquer pessoa no caminho (Wi-Fi público, provedor, rede da empresa) "
            "pode ler e alterar o conteúdo."
        ),
        risk=(
            "Roubo de credenciais e de sessões, injeção de conteúdo malicioso nas páginas e "
            "vazamento de dados pessoais (LGPD). Navegadores também marcam o site como "
            "'Não seguro', o que afasta usuários."
        ),
        steps=(
            "Emita um certificado gratuito com Let's Encrypt (certbot) ou use o do seu provedor/CDN.",
            "Configure o servidor para responder na porta 443 com o certificado.",
            "Redirecione todo o tráfego HTTP (porta 80) para HTTPS com código 301.",
            "Depois de estável, ative o HSTS para o navegador nunca mais usar HTTP.",
        ),
        examples=(
            Fix(
                "nginx",
                "nginx",
                "server {\n    listen 80;\n    server_name exemplo.com.br;\n"
                "    return 301 https://$host$request_uri;\n}\n\nserver {\n"
                "    listen 443 ssl http2;\n    server_name exemplo.com.br;\n"
                "    ssl_certificate     /etc/letsencrypt/live/exemplo.com.br/fullchain.pem;\n"
                "    ssl_certificate_key /etc/letsencrypt/live/exemplo.com.br/privkey.pem;\n}",
                "nginx",
            ),
            Fix(
                "apache",
                "Apache",
                "<VirtualHost *:80>\n    ServerName exemplo.com.br\n"
                "    Redirect permanent / https://exemplo.com.br/\n</VirtualHost>",
                "apache",
            ),
            Fix("linux", "Certbot (Linux)", "sudo certbot --nginx -d exemplo.com.br", "bash"),
        ),
        verify="Abra http://seu-site e confirme que vai para https:// com cadeado válido.",
        effort="medio",
        fix_group="https",
        references=(
            "https://letsencrypt.org/pt-br/getting-started/",
            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
        ),
        cwe="CWE-319",
        owasp="A02:2021",
        cis=("3.10",),
        lgpd=True,
        tags=("https", "criptografia"),
    ),
    KBEntry(
        id="web.https.sem_redirecionamento",
        title="HTTP não redireciona para HTTPS",
        category=Category.WEB,
        severity=Severity.MEDIUM,
        summary="O site tem HTTPS, mas a versão HTTP continua servindo páginas.",
        explanation=(
            "Quem digita o endereço sem 'https://' ou segue um link antigo cai na versão sem "
            "criptografia. O HTTPS existe, mas não é obrigatório."
        ),
        risk=(
            "Um atacante na mesma rede pode interceptar a primeira requisição HTTP e manter a "
            "vítima em HTTP (ataque de 'SSL stripping'), lendo senhas e cookies."
        ),
        steps=(
            "Faça a porta 80 responder apenas com um redirecionamento 301 para a mesma URL em HTTPS.",
            "Atualize links internos, sitemap e canonical para https://.",
            "Ative o HSTS para que o navegador pule o HTTP nas próximas visitas.",
        ),
        examples=(
            Fix(
                "nginx",
                "nginx",
                "server {\n    listen 80;\n    server_name _;\n"
                "    return 301 https://$host$request_uri;\n}",
                "nginx",
            ),
            Fix(
                "apache",
                "Apache (.htaccess)",
                "RewriteEngine On\nRewriteCond %{HTTPS} off\n"
                "RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]",
                "apache",
            ),
            Fix(
                "iis",
                "IIS (web.config, URL Rewrite)",
                '<rule name="Forcar HTTPS" stopProcessing="true">\n'
                '  <match url="(.*)" />\n  <conditions>\n'
                '    <add input="{HTTPS}" pattern="off" />\n  </conditions>\n'
                '  <action type="Redirect" url="https://{HTTP_HOST}/{R:1}" '
                'redirectType="Permanent" />\n</rule>',
                "xml",
            ),
            Fix(
                "express",
                "Node.js / Express",
                "app.use((req, res, next) => {\n"
                "  if (req.secure || req.get('x-forwarded-proto') === 'https') return next();\n"
                "  res.redirect(301, 'https://' + req.get('host') + req.originalUrl);\n});",
                "javascript",
            ),
        ),
        verify="curl -I http://seu-site deve responder 301 com Location: https://...",
        effort="baixo",
        fix_group="https",
        references=(
            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
        ),
        cwe="CWE-319",
        owasp="A02:2021",
        cis=("3.10",),
        lgpd=True,
        tags=("https",),
    ),
    KBEntry(
        id="web.hsts.ausente",
        title="Cabeçalho HSTS ausente",
        category=Category.WEB,
        severity=Severity.MEDIUM,
        summary="O navegador não é instruído a usar sempre HTTPS (Strict-Transport-Security).",
        explanation=(
            "Sem o cabeçalho Strict-Transport-Security, cada nova visita pode começar em HTTP. "
            "O HSTS faz o navegador converter qualquer acesso ao domínio em HTTPS por um "
            "período definido, inclusive quando o usuário digita só o domínio."
        ),
        risk=(
            "Abre espaço para ataques de rebaixamento (SSL stripping) e interceptação de "
            "cookies na primeira requisição, especialmente em redes Wi-Fi públicas."
        ),
        steps=(
            "Confirme que todo o site (e subdomínios, se usar includeSubDomains) funciona em HTTPS.",
            "Adicione Strict-Transport-Security nas respostas HTTPS com max-age de pelo menos 1 ano.",
            "Opcional: depois de estável, inclua 'preload' e cadastre em hstspreload.org.",
        ),
        examples=(
            Fix(
                "nginx",
                "nginx",
                'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
                "nginx",
            ),
            Fix(
                "apache",
                "Apache",
                'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"',
                "apache",
            ),
            Fix(
                "iis",
                "IIS (web.config)",
                '<add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains" />',
                "xml",
            ),
            Fix(
                "express",
                "Node.js / Express (helmet)",
                "app.use(require('helmet').hsts({ maxAge: 31536000, includeSubDomains: true }));",
                "javascript",
            ),
        ),
        verify="curl -sI https://seu-site | grep -i strict-transport-security",
        effort="baixo",
        fix_group="cabecalhos",
        references=(
            "https://developer.mozilla.org/pt-BR/docs/Web/HTTP/Headers/Strict-Transport-Security",
            "https://owasp.org/www-project-secure-headers/",
        ),
        cwe="CWE-523",
        owasp="A05:2021",
        cis=("3.10",),
        tags=("cabecalhos", "https"),
    ),
    KBEntry(
        id="web.hsts.fraco",
        title="HSTS com validade curta",
        category=Category.WEB,
        severity=Severity.LOW,
        summary="O HSTS existe, mas o max-age é menor que 180 dias.",
        explanation=(
            "Um max-age curto faz o navegador 'esquecer' a regra de usar HTTPS rapidamente, "
            "reabrindo a janela para ataques de rebaixamento entre visitas espaçadas."
        ),
        risk="Proteção parcial contra SSL stripping para quem volta ao site depois do prazo.",
        steps=(
            "Aumente o max-age para 31536000 (1 ano) depois de confirmar que o HTTPS está estável.",
            "Considere includeSubDomains se todos os subdomínios usam HTTPS.",
        ),
        examples=(
            Fix(
                "nginx",
                "nginx",
                'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
                "nginx",
            ),
            Fix(
                "apache",
                "Apache",
                'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"',
                "apache",
            ),
        ),
        verify="O cabeçalho deve mostrar max-age=31536000 ou maior.",
        effort="baixo",
        fix_group="cabecalhos",
        references=("https://hstspreload.org/",),
        cwe="CWE-523",
        owasp="A05:2021",
        tags=("cabecalhos", "https"),
    ),
)

_MAX_AGE = re.compile(r"max-age\s*=\s*\"?(\d{1,12})", re.I)
_REDIRECTS = (301, 302, 303, 307, 308)


def _location(resp: Response) -> str | None:
    """Destino do redirecionamento; ``Location`` malformado vale como ausente."""
    try:
        return resp.location
    except ValueError:  # ex.: "http://[::1" ou porta não numérica
        return None


def _same_host_https(location: str | None, host: str) -> bool:
    if not location:
        return False
    parts = urlsplit(location)
    return parts.scheme == "https" and (parts.hostname or "").lower() == host.lower()


@check(
    id="web.transport",
    name="HTTPS e HSTS",
    category=Category.WEB,
    consumes=facts.HTTP_SERVICE,
    description="Verifica se o site usa HTTPS, se redireciona HTTP para HTTPS e se envia HSTS.",
    findings=(
        "web.https.ausente",
        "web.https.sem_redirecionamento",
        "web.hsts.ausente",
        "web.hsts.fraco",
    ),
    facts=(facts.HTTP_SERVICE, facts.TLS_SERVICE),
    order=10,
)
def check_transport(ctx: CheckContext, fact: Fact) -> None:
    url = str(fact.data["url"])
    host = str(fact.data.get("host") or urlsplit(url).hostname or "")
    scheme = urlsplit(url).scheme
    if scheme == "http":
        _audit_plain_http(ctx, url, host)
    else:
        _audit_https(ctx, url, host)


def _audit_plain_http(ctx: CheckContext, url: str, host: str) -> None:
    plain = ctx.http.get(url)
    if plain is None:
        ctx.log(f"{url} não respondeu.")
        return
    https_url = base_url("https", host, 443)
    secure = ctx.http.get(https_url)
    if secure is None:
        ctx.report(
            "web.https.ausente",
            asset=base_url("http", host, urlsplit(url).port),
            evidence=f"{url} respondeu HTTP {plain.status}; {https_url} não respondeu.",
            confidence=Confidence.CONFIRMED,
        )
        return
    ctx.add_http_service(https_url, reason=f"{host} também responde em HTTPS")
    _check_redirect(ctx, plain.status, _location(plain), url, host)


def _audit_https(ctx: CheckContext, url: str, host: str) -> None:
    resp = ctx.http.get(url)
    if resp is None:
        ctx.log(f"{url} não respondeu.")
        return
    hsts = resp.header("strict-transport-security")
    if hsts is None and resp.status in _REDIRECTS and _location(resp):
        hsts = _hsts_after_redirects(ctx, url, host)
    origin = base_url("https", host, urlsplit(url).port)
    # RFC 6797, 8.1.1: o navegador nunca anota um IP como host HSTS; num alvo por IP a falta do
    # cabeçalho não tem efeito real (vale só como recomendação para quando houver um nome)
    by_ip = is_ip(host)
    sev = Severity.LOW if by_ip else None
    conf = Confidence.TENTATIVE if by_ip else Confidence.CONFIRMED
    if hsts is None:
        ctx.report(
            "web.hsts.ausente",
            asset=origin,
            evidence=f"Resposta HTTP {resp.status} de {url} sem Strict-Transport-Security.",
            severity=sev,
            confidence=conf,
        )
    else:
        match = _MAX_AGE.search(hsts)
        age = int(match.group(1)) if match else 0
        if age < HSTS_MIN_AGE:
            ctx.report(
                "web.hsts.fraco",
                asset=origin,
                evidence=f"Strict-Transport-Security: {hsts}",
                details={"max_age": age},
                severity=sev,
                confidence=conf,
            )
        else:
            extra = " com includeSubDomains" if "includesubdomains" in hsts.lower() else ""
            ctx.passed("web.hsts", f"HSTS ativo por {age // 86400} dias{extra}", origin)

    if urlsplit(url).port in (None, 443):
        plain_url = base_url("http", host, 80)
        plain = ctx.http.get(plain_url)
        if plain is None:
            ctx.passed("web.https.forcado", "Porta 80 fechada: não há versão HTTP do site", origin)
        else:
            _check_redirect(ctx, plain.status, _location(plain), plain_url, host)


def _hsts_after_redirects(ctx: CheckContext, url: str, host: str) -> str | None:
    """HSTS da resposta final, quando os redirecionamentos ficam no mesmo host."""
    current = url
    for _ in range(5):
        resp = ctx.http.get(current)
        if resp is None:
            return None
        if resp.header("strict-transport-security") is not None or resp.status not in _REDIRECTS:
            return resp.header("strict-transport-security")
        nxt = _location(resp)
        # nunca sai do host auditado: seguir para terceiros seria fora do escopo
        if not nxt or (urlsplit(nxt).hostname or "").lower() != host.lower():
            return None
        current = nxt
    return None


def _check_redirect(
    ctx: CheckContext, status: int, location: str | None, plain_url: str, host: str
) -> None:
    if status in _REDIRECTS and _same_host_https(location, host):
        ctx.passed("web.https.forcado", "HTTP redireciona para HTTPS", plain_url)
        return
    if status in _REDIRECTS and location and location.startswith("https://"):
        ctx.passed("web.https.forcado", f"HTTP redireciona para {location}", plain_url)
        return
    port = urlsplit(plain_url).port
    ctx.report(
        "web.https.sem_redirecionamento",
        asset=base_url("http", host, port),
        evidence=f"GET {plain_url} respondeu HTTP {status}"
        + (f" com Location: {location}" if location else " sem redirecionar para HTTPS"),
        # portas HTTP não padrão (8080, 8000...) costumam ser consoles internos de propósito
        confidence=Confidence.CONFIRMED if port in (None, 80) else Confidence.TENTATIVE,
    )
