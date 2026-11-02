"""Base de conhecimento dos achados de certificado TLS."""

from __future__ import annotations

from ...core import kb
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Severity
from .kb_exemplos import (
    APACHE_SSL,
    CABF_BR,
    CERT_APACHE,
    CERT_CERTBOT,
    CERT_IIS,
    CERT_NGINX,
    LETSENCRYPT_GUIDE,
    LETSENCRYPT_START,
    NGINX_SSL,
    OWASP_TLS,
)

EXPIRED = "tls.certificado.expirado"
EXPIRING = "tls.certificado.expira_em_breve"
NOT_YET_VALID = "tls.certificado.ainda_nao_valido"
SELF_SIGNED = "tls.certificado.autoassinado"
UNTRUSTED = "tls.certificado.nao_confiavel"
INCOMPLETE_CHAIN = "tls.certificado.cadeia_incompleta"
NAME_MISMATCH = "tls.certificado.nome_divergente"
WEAK_KEY = "tls.certificado.chave_fraca"
WEAK_SIGNATURE = "tls.certificado.assinatura_fraca"

FINDINGS = (
    EXPIRED,
    EXPIRING,
    NOT_YET_VALID,
    SELF_SIGNED,
    UNTRUSTED,
    INCOMPLETE_CHAIN,
    NAME_MISMATCH,
    WEAK_KEY,
    WEAK_SIGNATURE,
)

_RFC5280 = "https://www.rfc-editor.org/rfc/rfc5280.html"
_RFC9525 = "https://www.rfc-editor.org/rfc/rfc9525.html"
_RFC6151 = "https://www.rfc-editor.org/rfc/rfc6151.html"
_NIST_HASHES = "https://csrc.nist.gov/projects/hash-functions/nist-policy-on-hash-functions"
_NIST_KEYS = "https://csrc.nist.gov/pubs/sp/800/131/a/r2/final"
_MS_IMPORT = "https://learn.microsoft.com/en-us/powershell/module/pki/import-certificate"

_RENEW_FIXES: tuple[Fix, ...] = (CERT_CERTBOT, CERT_NGINX, CERT_APACHE, CERT_IIS)
_NEW_KEY_OPENSSL = Fix(
    "linux",
    "OpenSSL: nova chave e pedido com SAN",
    "openssl req -new -newkey rsa:2048 -nodes -sha256 \\\n"
    "  -keyout novo.key -out novo.csr \\\n"
    '  -subj "/CN=exemplo.com.br" \\\n'
    '  -addext "subjectAltName=DNS:exemplo.com.br,DNS:www.exemplo.com.br"\n'
    "# Envie novo.csr à autoridade certificadora e instale o certificado devolvido",
    "bash",
)
_NEW_KEY_WINDOWS = Fix(
    "windows",
    "Windows (certreq, a partir de um arquivo pedido.inf)",
    '; pedido.inf\n[NewRequest]\nSubject = "CN=exemplo.com.br"\nKeyLength = 2048\nKeySpec = 1\n'
    "MachineKeySet = TRUE\nRequestType = PKCS10\n\n"
    "; no prompt, como administrador:\n"
    "; certreq -new pedido.inf pedido.req\n"
    "; certreq -submit pedido.req certificado.cer\n"
    "; certreq -accept certificado.cer",
    "ini",
)

kb.register(
    KBEntry(
        id=EXPIRED,
        title="Certificado TLS vencido",
        category=Category.TLS,
        severity=Severity.HIGH,
        summary="A data de validade do certificado já passou.",
        explanation=(
            "Todo certificado tem data de vencimento. Depois dela, navegadores e aplicativos "
            "mostram um erro de segurança ou recusam a conexão, e os visitantes passam a ser "
            "treinados a ignorar esse tipo de aviso."
        ),
        risk=(
            "O site ou serviço fica fora do ar para muita gente. Quem clica em 'continuar assim "
            "mesmo' não tem como notar um ataque de interceptação, já que o aviso seria igual."
        ),
        steps=(
            "Renove o certificado com a sua autoridade certificadora (com Let's Encrypt: certbot renew).",
            "Instale o novo certificado no servidor, junto com a cadeia de intermediários.",
            "Recarregue o serviço para ele passar a usar o arquivo novo.",
            "Automatize a renovação e monitore o vencimento para não repetir o problema.",
        ),
        examples=_RENEW_FIXES,
        verify=(
            "openssl s_client -connect seu-site:443 -servername seu-site </dev/null 2>/dev/null "
            "| openssl x509 -noout -dates"
        ),
        effort="baixo",
        fix_group="certificado",
        references=(LETSENCRYPT_GUIDE, OWASP_TLS, _RFC5280),
        cwe="CWE-324",
        owasp="A02:2021",
        cis=("3.10",),
        lgpd=True,
        tags=("certificado", "validade"),
    ),
    KBEntry(
        id=EXPIRING,
        title="Certificado TLS perto de vencer",
        category=Category.TLS,
        severity=Severity.MEDIUM,
        summary="O certificado vence em poucos dias e ainda não foi renovado.",
        explanation=(
            "Quem renova automaticamente troca o certificado bem antes do vencimento: o Let's "
            "Encrypt recomenda renovar quando resta um terço da validade. Chegar perto da data "
            "final costuma indicar que a renovação falhou ou que ela é manual e foi esquecida."
        ),
        risk=(
            "Se nada for feito, o certificado vence e o serviço passa a exibir erro de segurança "
            "ou fica fora do ar para os clientes, muitas vezes de madrugada ou em um feriado."
        ),
        steps=(
            "Renove o certificado agora, sem esperar o vencimento.",
            "Se a renovação é automática, descubra por que ela falhou (certbot renew --dry-run e "
            "os logs em /var/log/letsencrypt).",
            "Configure um alerta de vencimento com pelo menos 30 dias de antecedência.",
        ),
        examples=_RENEW_FIXES,
        verify=(
            "openssl s_client -connect seu-site:443 -servername seu-site </dev/null 2>/dev/null "
            "| openssl x509 -noout -enddate"
        ),
        effort="baixo",
        fix_group="certificado",
        references=(LETSENCRYPT_GUIDE, CABF_BR),
        cwe="CWE-324",
        owasp="A02:2021",
        cis=("3.10",),
        tags=("certificado", "validade"),
    ),
    KBEntry(
        id=NOT_YET_VALID,
        title="Certificado TLS ainda não é válido",
        category=Category.TLS,
        severity=Severity.HIGH,
        summary="A data de início de validade do certificado ainda não chegou.",
        explanation=(
            "O certificado tem uma data 'válido a partir de' no futuro. Isso acontece quando ele "
            "foi instalado antes da hora ou quando o relógio do servidor que o gerou está errado. "
            "Confira também o relógio desta máquina: se ele estiver atrasado, o aviso é dela."
        ),
        risk=(
            "Navegadores e aplicativos recusam a conexão até a data chegar, deixando o serviço "
            "indisponível ou ensinando os usuários a ignorar o aviso de segurança."
        ),
        steps=(
            "Confira se o relógio desta máquina e o do servidor estão corretos (NTP).",
            "Se o certificado foi gerado com a data errada, emita um novo.",
            "Instale o certificado novo e recarregue o serviço.",
        ),
        examples=_RENEW_FIXES,
        verify=(
            "openssl s_client -connect seu-site:443 -servername seu-site </dev/null 2>/dev/null "
            "| openssl x509 -noout -startdate"
        ),
        effort="baixo",
        fix_group="certificado",
        references=(_RFC5280, OWASP_TLS),
        cwe="CWE-295",
        owasp="A02:2021",
        cis=("3.10",),
        tags=("certificado", "validade"),
    ),
    KBEntry(
        id=SELF_SIGNED,
        title="Certificado TLS autoassinado",
        category=Category.TLS,
        severity=Severity.HIGH,
        summary="O certificado foi assinado por ele mesmo: nenhuma autoridade confiável o garante.",
        explanation=(
            "Um certificado autoassinado criptografa o tráfego, mas não prova quem é o servidor: "
            "qualquer pessoa pode gerar um igual, com o mesmo nome. Por isso os navegadores "
            "mostram um aviso de 'conexão não particular'."
        ),
        risk=(
            "Um atacante no caminho apresenta o próprio certificado autoassinado e o usuário, "
            "acostumado com o aviso, aceita. A partir daí, senhas e dados passam por ele."
        ),
        steps=(
            "Para serviços públicos, emita um certificado gratuito com Let's Encrypt ou use o do "
            "seu provedor/CDN.",
            "Para serviços internos, use uma autoridade certificadora interna e distribua a raiz "
            "às máquinas da empresa.",
            "Instale o novo certificado com a cadeia de intermediários e recarregue o serviço.",
        ),
        examples=(
            CERT_CERTBOT,
            CERT_NGINX,
            CERT_APACHE,
            CERT_IIS,
            _NEW_KEY_WINDOWS,
        ),
        verify=(
            "curl -sSI https://seu-site deve responder sem erro de certificado; em um serviço "
            "interno, rode o comando em uma máquina que já tenha a raiz da empresa."
        ),
        effort="medio",
        fix_group="certificado",
        references=(LETSENCRYPT_START, OWASP_TLS),
        cwe="CWE-295",
        owasp="A02:2021",
        cis=("3.10",),
        lgpd=True,
        tags=("certificado", "confianca"),
    ),
    KBEntry(
        id=UNTRUSTED,
        title="Certificado TLS não confiável",
        category=Category.TLS,
        severity=Severity.HIGH,
        summary="A cadeia do certificado não chega a uma autoridade confiável nesta máquina.",
        explanation=(
            "O sistema operacional guarda uma lista de autoridades certificadoras de confiança. "
            "Este certificado foi emitido por alguém fora dessa lista (uma autoridade interna, "
            "por exemplo) ou tem um problema na cadeia. A causa exata aparece na evidência."
        ),
        risk=(
            "Clientes sem a raiz instalada recebem erro de segurança. Se o costume for ignorar "
            "o aviso, ninguém nota quando um atacante troca o certificado por um dele."
        ),
        steps=(
            "Confirme quem emitiu o certificado: openssl x509 -noout -issuer -subject.",
            "Em serviços públicos, troque por um certificado de uma autoridade pública.",
            "Em serviços internos, instale a raiz da empresa em todas as máquinas clientes "
            "(por GPO no Windows, update-ca-certificates no Linux).",
            "Se esta auditoria rodou fora da rede da empresa, repita em uma máquina que tenha a "
            "raiz antes de concluir que há um problema.",
        ),
        examples=(
            CERT_CERTBOT,
            Fix(
                "windows",
                "Windows: instalar a raiz interna (PowerShell como administrador)",
                "Import-Certificate -FilePath .\\raiz-da-empresa.cer "
                "-CertStoreLocation Cert:\\LocalMachine\\Root",
                "powershell",
            ),
            Fix(
                "linux",
                "Debian/Ubuntu: instalar a raiz interna",
                "sudo cp raiz-da-empresa.crt /usr/local/share/ca-certificates/\n"
                "sudo update-ca-certificates",
                "bash",
            ),
        ),
        verify="openssl s_client -connect seu-site:443 -servername seu-site -verify_return_error </dev/null",
        effort="medio",
        fix_group="certificado",
        references=(OWASP_TLS, _MS_IMPORT),
        cwe="CWE-295",
        owasp="A02:2021",
        cis=("3.10",),
        lgpd=True,
        tags=("certificado", "confianca"),
    ),
    KBEntry(
        id=INCOMPLETE_CHAIN,
        title="Cadeia do certificado incompleta",
        category=Category.TLS,
        severity=Severity.MEDIUM,
        summary="O servidor entrega só o certificado final, sem os intermediários.",
        explanation=(
            "Entre o seu certificado e a raiz confiável existe um certificado intermediário, e "
            "cabe ao servidor enviá-lo. Alguns navegadores contornam a falta baixando o "
            "intermediário por conta própria, então o site parece funcionar. Mas celulares, "
            "APIs, scripts e sistemas integrados falham com erro de certificado."
        ),
        risk=(
            "Parte dos clientes não consegue conectar, de forma intermitente e difícil de "
            "diagnosticar, e pode acabar desligando a validação para contornar o erro."
        ),
        steps=(
            "Baixe a cadeia completa fornecida pela autoridade certificadora ('fullchain').",
            "Aponte o servidor para o arquivo com o certificado primeiro e os intermediários depois.",
            "Recarregue o serviço e teste com um cliente que não busca intermediários, como o curl.",
        ),
        examples=(
            Fix(
                "nginx",
                "nginx (certificado e intermediários no mesmo arquivo)",
                "ssl_certificate     /etc/letsencrypt/live/exemplo.com.br/fullchain.pem;\n"
                "ssl_certificate_key /etc/letsencrypt/live/exemplo.com.br/privkey.pem;",
                "nginx",
            ),
            CERT_APACHE,
            Fix(
                "iis",
                "IIS / Windows: instalar o intermediário (PowerShell como administrador)",
                "Import-Certificate -FilePath .\\intermediario.cer "
                "-CertStoreLocation Cert:\\LocalMachine\\CA\n"
                "iisreset",
                "powershell",
            ),
            Fix(
                "tomcat",
                "Tomcat (server.xml)",
                '<Certificate certificateFile="conf/cert.pem"\n'
                '             certificateKeyFile="conf/key.pem"\n'
                '             certificateChainFile="conf/chain.pem" />',
                "xml",
            ),
            Fix(
                "express",
                "Node.js (https)",
                "https.createServer({\n"
                "  key: fs.readFileSync('privkey.pem'),\n"
                "  cert: fs.readFileSync('fullchain.pem'), // certificado + intermediários\n"
                "}, app).listen(443);",
                "javascript",
            ),
        ),
        verify=(
            "openssl s_client -connect seu-site:443 -servername seu-site -showcerts </dev/null "
            "deve listar mais de um certificado e terminar com 'Verify return code: 0 (ok)'."
        ),
        effort="baixo",
        fix_group="certificado",
        references=(NGINX_SSL, APACHE_SSL, _RFC5280),
        cwe="CWE-295",
        owasp="A02:2021",
        cis=("3.10",),
        tags=("certificado", "confianca"),
    ),
    KBEntry(
        id=NAME_MISMATCH,
        title="Certificado TLS emitido para outro nome",
        category=Category.TLS,
        severity=Severity.HIGH,
        summary="O nome acessado não aparece na lista de nomes (SAN) do certificado.",
        explanation=(
            "O certificado precisa listar, no campo 'nomes alternativos' (SAN), o endereço que o "
            "cliente acessou. Clientes modernos consideram só esse campo e ignoram o CN. Se o "
            "nome não está lá, o navegador recusa a conexão com um erro de nome inválido."
        ),
        risk=(
            "Os usuários veem um aviso de segurança e, ao ignorá-lo, ficam sem nenhuma garantia "
            "de que falam com o servidor certo: é a mesma tela que apareceria em um ataque."
        ),
        steps=(
            "Liste todos os nomes usados para acessar o serviço (com e sem www, subdomínios).",
            "Emita um certificado que traga todos esses nomes no campo SAN.",
            "Se o servidor hospeda vários sites, confira se o nome certo está na configuração "
            "de SNI (server_name no nginx, ServerName no Apache, binding no IIS).",
        ),
        examples=(
            CERT_CERTBOT,
            _NEW_KEY_OPENSSL,
            Fix(
                "nginx",
                "nginx",
                "server {\n    listen 443 ssl;\n    server_name exemplo.com.br www.exemplo.com.br;\n"
                "    ssl_certificate     /etc/letsencrypt/live/exemplo.com.br/fullchain.pem;\n"
                "    ssl_certificate_key /etc/letsencrypt/live/exemplo.com.br/privkey.pem;\n}",
                "nginx",
            ),
        ),
        verify=(
            "openssl s_client -connect seu-site:443 -servername seu-site </dev/null 2>/dev/null "
            "| openssl x509 -noout -ext subjectAltName"
        ),
        effort="baixo",
        fix_group="certificado",
        references=(_RFC9525, OWASP_TLS),
        cwe="CWE-297",
        owasp="A02:2021",
        cis=("3.10",),
        lgpd=True,
        tags=("certificado", "nome"),
    ),
    KBEntry(
        id=WEAK_KEY,
        title="Chave do certificado fraca demais",
        category=Category.TLS,
        severity=Severity.HIGH,
        summary="A chave pública é curta demais: RSA abaixo de 2048 bits ou curva abaixo de 256 bits.",
        explanation=(
            "A segurança do certificado depende do tamanho da chave. As autoridades públicas só "
            "emitem RSA com pelo menos 2048 bits, e as diretrizes da Mozilla pedem curvas de "
            "pelo menos 256 bits. Chaves menores estão ao alcance de atacantes com recursos."
        ),
        risk=(
            "Quem quebrar a chave consegue se passar pelo servidor e, nas conexões sem sigilo "
            "futuro, decifrar também o tráfego gravado. Clientes modernos já recusam essas chaves."
        ),
        steps=(
            "Gere uma chave nova: RSA de 2048 bits ou mais, ou ECDSA P-256.",
            "Peça um certificado novo usando essa chave (não reaproveite a antiga).",
            "Instale o certificado, recarregue o serviço e apague a chave antiga.",
        ),
        examples=(
            _NEW_KEY_OPENSSL,
            _NEW_KEY_WINDOWS,
            Fix(
                "generico",
                "Let's Encrypt (certbot) com ECDSA",
                "sudo certbot --nginx -d exemplo.com.br --key-type ecdsa --elliptic-curve secp256r1",
                "bash",
            ),
        ),
        verify=(
            "openssl s_client -connect seu-site:443 -servername seu-site </dev/null 2>/dev/null "
            "| openssl x509 -noout -text | grep 'Public-Key'"
        ),
        effort="medio",
        fix_group="certificado",
        references=(CABF_BR, OWASP_TLS, _NIST_KEYS),
        cwe="CWE-326",
        owasp="A02:2021",
        cis=("3.10",),
        lgpd=True,
        tags=("certificado", "chave"),
    ),
    KBEntry(
        id=WEAK_SIGNATURE,
        title="Certificado assinado com hash fraco",
        category=Category.TLS,
        severity=Severity.HIGH,
        summary="A assinatura do certificado usa SHA-1 ou MD5, que têm colisões conhecidas.",
        explanation=(
            "A assinatura é o que prova que a autoridade emitiu aquele certificado. MD5 e SHA-1 "
            "permitem criar dois documentos diferentes com o mesmo resumo, abrindo caminho para "
            "certificados falsos. Por isso as autoridades públicas abandonaram esses algoritmos."
        ),
        risk=(
            "Um atacante com recursos pode forjar um certificado com assinatura válida e se "
            "passar pelo servidor. Navegadores e sistemas atuais recusam esses certificados."
        ),
        steps=(
            "Peça à autoridade certificadora um novo certificado assinado com SHA-256 ou superior.",
            "Se a autoridade é interna, configure-a para assinar com SHA-256 antes de reemitir.",
            "Instale o novo certificado e recarregue o serviço.",
        ),
        examples=(
            _NEW_KEY_OPENSSL,
            Fix(
                "windows",
                "Autoridade certificadora interna do Windows (AD CS)",
                "certutil -setreg ca\\csp\\CNGHashAlgorithm SHA256\n"
                "net stop certsvc\n"
                "net start certsvc",
                "powershell",
            ),
        ),
        verify=(
            "openssl s_client -connect seu-site:443 -servername seu-site </dev/null 2>/dev/null "
            "| openssl x509 -noout -text | grep 'Signature Algorithm'"
        ),
        effort="medio",
        fix_group="certificado",
        references=(_RFC6151, _NIST_HASHES, OWASP_TLS),
        cwe="CWE-328",
        owasp="A02:2021",
        cis=("3.10",),
        tags=("certificado", "assinatura"),
    ),
)
