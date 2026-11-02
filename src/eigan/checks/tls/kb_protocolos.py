"""Base de conhecimento dos achados de versões do protocolo TLS."""

from __future__ import annotations

from ...core import kb
from ...core.kb import KBEntry
from ...core.models import Category, Severity
from .kb_exemplos import MODERN_TLS, MOZILLA_GUIDELINES, MS_SCHANNEL, OWASP_TLS, SSL_LABS_GUIDE
from .suites import SSL2, SSL3, TLS10, TLS11

SSLV2 = "tls.protocolo.sslv2"
SSLV3 = "tls.protocolo.sslv3"
TLS1_0 = "tls.protocolo.tls10"
TLS1_1 = "tls.protocolo.tls11"
NO_TLS12 = "tls.versao.sem_tls12"
NO_TLS13 = "tls.versao.sem_tls13"

#: versão obsoleta -> achado
LEGACY_FINDINGS = {SSL2: SSLV2, SSL3: SSLV3, TLS10: TLS1_0, TLS11: TLS1_1}
FINDINGS = (SSLV2, SSLV3, TLS1_0, TLS1_1, NO_TLS12, NO_TLS13)

_RFC6176 = "https://www.rfc-editor.org/rfc/rfc6176.html"
_RFC7568 = "https://www.rfc-editor.org/rfc/rfc7568.html"
_RFC8996 = "https://www.rfc-editor.org/rfc/rfc8996.html"
_RFC8446 = "https://www.rfc-editor.org/rfc/rfc8446.html"
_DROWN = "https://nvd.nist.gov/vuln/detail/CVE-2016-0800"
_POODLE = "https://nvd.nist.gov/vuln/detail/CVE-2014-3566"
_MS_SERVER_2022 = (
    "https://learn.microsoft.com/en-us/windows-server/get-started/whats-new-in-windows-server-2022"
)

_DISABLE_STEPS = (
    "Confira se todos os clientes que precisam acessar o serviço já usam TLS 1.2 ou superior.",
    "Deixe só TLS 1.2 e TLS 1.3 na configuração do servidor, do balanceador ou da CDN.",
    "Recarregue o serviço e repita o teste: a versão antiga precisa ser recusada.",
)

kb.register(
    KBEntry(
        id=SSLV2,
        title="Servidor aceita SSLv2",
        category=Category.TLS,
        severity=Severity.CRITICAL,
        summary="O servidor ainda fala SSL 2.0, versão quebrada e proibida desde 2011.",
        explanation=(
            "O SSL 2.0 é de 1995 e tem falhas de projeto que não têm conserto. A RFC 6176 proíbe "
            "seu uso. Mesmo que nenhum cliente o utilize, deixá-lo ligado expõe o servidor a "
            "ataques como o DROWN, que usa o SSLv2 para atacar conexões em versões modernas."
        ),
        risk=(
            "Um atacante pode decifrar conexões TLS modernas que compartilhem a mesma chave RSA "
            "(DROWN, CVE-2016-0800), expondo senhas e dados pessoais trafegados."
        ),
        steps=(
            "Desligue o SSLv2 no servidor, no balanceador e em qualquer serviço que use a mesma chave.",
            "Atualize a biblioteca TLS: versões atuais nem incluem mais o SSLv2.",
            "Se a chave privada era compartilhada com outro serviço que aceitava SSLv2, troque-a.",
        ),
        examples=MODERN_TLS,
        verify="nmap --script ssl-enum-ciphers -p 443 seu-site não deve listar SSLv2.",
        effort="baixo",
        fix_group="tls",
        references=(_RFC6176, _DROWN, OWASP_TLS, MS_SCHANNEL),
        cwe="CWE-327",
        owasp="A02:2021",
        cis=("3.10", "4.1"),
        lgpd=True,
        tags=("protocolo", "legado"),
    ),
    KBEntry(
        id=SSLV3,
        title="Servidor aceita SSLv3",
        category=Category.TLS,
        severity=Severity.HIGH,
        summary="O servidor ainda fala SSL 3.0, versão quebrada e proibida desde 2015.",
        explanation=(
            "O SSL 3.0 tem uma falha no modo CBC que permite descobrir o conteúdo cifrado, "
            "conhecida como POODLE, e não há como corrigi-la mantendo o protocolo. "
            "A RFC 7568 determina que ele não deve mais ser usado."
        ),
        risk=(
            "Um atacante na rede força a conexão a cair para SSLv3 e recupera, aos poucos, "
            "cookies de sessão e outros dados secretos (POODLE, CVE-2014-3566)."
        ),
        steps=_DISABLE_STEPS,
        examples=MODERN_TLS,
        verify=(
            "nmap --script ssl-enum-ciphers -p 443 seu-site não deve listar SSLv3 "
            "(muitas versões novas do openssl nem conseguem mais testar essa versão)."
        ),
        effort="baixo",
        fix_group="tls",
        references=(_RFC7568, _POODLE, OWASP_TLS, MS_SCHANNEL),
        cwe="CWE-327",
        owasp="A02:2021",
        cis=("3.10", "4.1"),
        lgpd=True,
        tags=("protocolo", "legado"),
    ),
    KBEntry(
        id=TLS1_0,
        title="Servidor aceita TLS 1.0",
        category=Category.TLS,
        severity=Severity.MEDIUM,
        summary="O servidor ainda aceita TLS 1.0, oficialmente obsoleto desde 2021.",
        explanation=(
            "O TLS 1.0 é de 1999 e depende de algoritmos antigos. A RFC 8996 o tornou obsoleto "
            "e os principais navegadores já não o aceitam. As diretrizes da Mozilla e da OWASP "
            "pedem que ele seja desligado."
        ),
        risk=(
            "Enfraquece a proteção da conexão para quem ainda usa esses clientes e costuma ser "
            "apontado como não conformidade em auditorias de segurança."
        ),
        steps=_DISABLE_STEPS,
        examples=MODERN_TLS,
        verify=(
            "openssl s_client -connect seu-site:443 -servername seu-site -tls1 "
            "-cipher 'DEFAULT@SECLEVEL=0' </dev/null precisa falhar."
        ),
        effort="baixo",
        fix_group="tls",
        references=(_RFC8996, OWASP_TLS, MOZILLA_GUIDELINES, MS_SCHANNEL),
        cwe="CWE-327",
        owasp="A02:2021",
        cis=("3.10", "4.1"),
        lgpd=True,
        tags=("protocolo", "legado"),
    ),
    KBEntry(
        id=TLS1_1,
        title="Servidor aceita TLS 1.1",
        category=Category.TLS,
        severity=Severity.MEDIUM,
        summary="O servidor ainda aceita TLS 1.1, oficialmente obsoleto desde 2021.",
        explanation=(
            "O TLS 1.1 é de 2006 e não tem as cifras modernas do TLS 1.2. A RFC 8996 o tornou "
            "obsoleto junto com o TLS 1.0, e os principais navegadores já não o aceitam."
        ),
        risk=(
            "Enfraquece a proteção da conexão para quem ainda usa esses clientes e costuma ser "
            "apontado como não conformidade em auditorias de segurança."
        ),
        steps=_DISABLE_STEPS,
        examples=MODERN_TLS,
        verify=(
            "openssl s_client -connect seu-site:443 -servername seu-site -tls1_1 "
            "-cipher 'DEFAULT@SECLEVEL=0' </dev/null precisa falhar."
        ),
        effort="baixo",
        fix_group="tls",
        references=(_RFC8996, OWASP_TLS, MOZILLA_GUIDELINES, MS_SCHANNEL),
        cwe="CWE-327",
        owasp="A02:2021",
        cis=("3.10", "4.1"),
        lgpd=True,
        tags=("protocolo", "legado"),
    ),
    KBEntry(
        id=NO_TLS12,
        title="Servidor não aceita TLS 1.2 nem TLS 1.3",
        category=Category.TLS,
        severity=Severity.HIGH,
        summary="O servidor só fala versões obsoletas do protocolo.",
        explanation=(
            "TLS 1.2 e TLS 1.3 são as únicas versões consideradas seguras hoje. Um servidor que "
            "não aceita nenhuma delas usa software muito antigo e deixa os visitantes presos a "
            "versões que os navegadores atuais recusam."
        ),
        risk=(
            "Navegadores e aplicativos modernos não conseguem conectar, e os clientes antigos "
            "que conectam usam uma criptografia obsoleta, que pode ser enfraquecida por um atacante."
        ),
        steps=(
            "Atualize o software do servidor e a biblioteca TLS (OpenSSL 1.1.1 ou mais novo, ou o "
            "firmware atual do equipamento).",
            "Se o equipamento não recebe mais atualização, coloque um proxy reverso moderno na "
            "frente dele ou substitua-o.",
            "Ative TLS 1.2 e TLS 1.3 e desligue as versões antigas.",
        ),
        examples=MODERN_TLS,
        verify=(
            "openssl s_client -connect seu-site:443 -servername seu-site -tls1_2 </dev/null "
            "deve concluir o handshake."
        ),
        effort="alto",
        fix_group="tls",
        references=(_RFC8996, OWASP_TLS, SSL_LABS_GUIDE),
        cwe="CWE-327",
        owasp="A02:2021",
        cis=("3.10", "4.1"),
        lgpd=True,
        tags=("protocolo", "legado"),
    ),
    KBEntry(
        id=NO_TLS13,
        title="Servidor não aceita TLS 1.3",
        category=Category.TLS,
        severity=Severity.INFO,
        summary="O serviço funciona, mas ainda não oferece a versão mais recente do protocolo.",
        explanation=(
            "O TLS 1.3 é mais rápido, cifra uma parte maior do handshake e só permite algoritmos "
            "modernos, todos com sigilo futuro. A OWASP recomenda usá-lo como padrão. "
            "Não é um problema urgente: o TLS 1.2 bem configurado continua seguro."
        ),
        risk=(
            "Sem risco imediato. O serviço apenas deixa de ter as proteções extras do TLS 1.3 e, "
            "na classificação do SSL Labs, fica limitado à nota A-."
        ),
        steps=(
            "Confira se a biblioteca TLS suporta a versão (OpenSSL 1.1.1 ou mais novo).",
            "Acrescente TLSv1.3 à lista de versões do servidor ou do balanceador.",
            "No Windows, o TLS 1.3 vem ativado por padrão a partir do Windows Server 2022: planeje "
            "a atualização se o servidor for mais antigo.",
        ),
        examples=MODERN_TLS[:2],
        verify=(
            "openssl s_client -connect seu-site:443 -servername seu-site -tls1_3 </dev/null "
            "deve concluir o handshake."
        ),
        effort="baixo",
        fix_group="tls",
        references=(_RFC8446, OWASP_TLS, SSL_LABS_GUIDE, _MS_SERVER_2022),
        cwe="CWE-327",
        owasp="A02:2021",
        cis=("3.10",),
        tags=("protocolo", "moderno"),
    ),
)
