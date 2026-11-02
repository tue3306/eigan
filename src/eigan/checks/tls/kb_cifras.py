"""Base de conhecimento dos achados de suítes de cifra."""

from __future__ import annotations

from ...core import kb
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Severity
from .kb_exemplos import (
    MODERN_APACHE,
    MODERN_NGINX,
    MODERN_NODE,
    MODERN_TOMCAT,
    MOZILLA_GUIDELINES,
    MS_DISABLE_SUITE,
    OWASP_TLS,
    STRONG_CIPHERS,
)

INSECURE = "tls.cifra.insegura"
BROKEN = "tls.cifra.quebrada"
TRIPLE_DES = "tls.cifra.3des"
NO_FORWARD_SECRECY = "tls.cifra.sem_sigilo_futuro"

FINDINGS = (INSECURE, BROKEN, TRIPLE_DES, NO_FORWARD_SECRECY)

_RFC7465 = "https://www.rfc-editor.org/rfc/rfc7465.html"
_LOGJAM = "https://nvd.nist.gov/vuln/detail/CVE-2015-4000"
_RC4_BIASES = "https://nvd.nist.gov/vuln/detail/CVE-2013-2566"
_BAR_MITZVAH = "https://nvd.nist.gov/vuln/detail/CVE-2015-2808"
_SWEET32 = "https://nvd.nist.gov/vuln/detail/CVE-2016-2183"

_VERIFY_NMAP = "nmap --script ssl-enum-ciphers -p 443 seu-site"

kb.register(
    KBEntry(
        id=INSECURE,
        title="Servidor aceita cifra sem proteção real (NULL, anônima ou EXPORT)",
        category=Category.TLS,
        severity=Severity.CRITICAL,
        summary="O servidor aceita suítes sem criptografia, sem autenticação ou com chave de exportação.",
        explanation=(
            "Algumas suítes antigas anulam o TLS: as NULL não cifram nada, as anônimas não "
            "provam quem é o servidor e as EXPORT usam chaves curtas de propósito, herança de "
            "regras dos anos 1990. Nenhum cliente legítimo precisa delas hoje."
        ),
        risk=(
            "Um atacante na rede pode ler o tráfego, se passar pelo servidor ou forçar uma chave "
            "tão curta que pode ser quebrada (nas suítes DHE_EXPORT, o ataque Logjam, CVE-2015-4000)."
        ),
        steps=(
            "Troque a lista de cifras do servidor pela lista recomendada abaixo.",
            "Remova listas com ALL ou DEFAULT sem filtros, que costumam trazer essas suítes de volta.",
            "Recarregue o serviço e repita o teste: nenhuma dessas suítes pode ser aceita.",
        ),
        examples=STRONG_CIPHERS,
        verify=f"{_VERIFY_NMAP} não deve listar NULL, anon nem EXPORT.",
        effort="baixo",
        fix_group="tls",
        references=(OWASP_TLS, _LOGJAM, MOZILLA_GUIDELINES, MS_DISABLE_SUITE),
        cwe="CWE-327",
        owasp="A02:2021",
        cis=("3.10", "4.1"),
        lgpd=True,
        tags=("cifra",),
    ),
    KBEntry(
        id=BROKEN,
        title="Servidor aceita cifra quebrada (RC4, DES, RC2 ou IDEA)",
        category=Category.TLS,
        severity=Severity.HIGH,
        summary="O servidor aceita suítes com algoritmos de cifra considerados quebrados.",
        explanation=(
            "O RC4 tem desvios estatísticos que permitem recuperar o conteúdo cifrado, e a "
            "RFC 7465 proíbe servidores de escolhê-lo. DES e RC2 têm chaves curtas ou blocos "
            "pequenos demais, e o IDEA foi removido dos perfis atuais."
        ),
        risk=(
            "Um atacante que capture tráfego suficiente pode recuperar cookies de sessão e senhas "
            "(RC4: CVE-2013-2566 e CVE-2015-2808). Com DES, a chave pode ser descoberta por tentativa."
        ),
        steps=(
            "Troque a lista de cifras do servidor pela lista recomendada abaixo.",
            "Confira se balanceadores, CDN e proxies não têm uma lista própria mais permissiva.",
            "Recarregue o serviço e repita o teste: nenhuma dessas suítes pode ser aceita.",
        ),
        examples=STRONG_CIPHERS,
        verify=f"{_VERIFY_NMAP} não deve listar RC4, DES, RC2 nem IDEA.",
        effort="baixo",
        fix_group="tls",
        references=(_RFC7465, _RC4_BIASES, _BAR_MITZVAH, OWASP_TLS, MS_DISABLE_SUITE),
        cwe="CWE-327",
        owasp="A02:2021",
        cis=("3.10", "4.1"),
        lgpd=True,
        tags=("cifra",),
    ),
    KBEntry(
        id=TRIPLE_DES,
        title="Servidor aceita 3DES (SWEET32)",
        category=Category.TLS,
        severity=Severity.MEDIUM,
        summary="O servidor aceita suítes 3DES, que usam blocos de só 64 bits.",
        explanation=(
            "O 3DES cifra em blocos de 64 bits. Em conexões longas, com muito tráfego, os blocos "
            "começam a se repetir (limite do aniversário) e isso revela parte do conteúdo. "
            "É o ataque SWEET32. As diretrizes atuais não incluem mais o 3DES."
        ),
        risk=(
            "Um atacante que capture uma sessão longa pode recuperar dados como cookies "
            "(SWEET32, CVE-2016-2183). A exploração exige muito tráfego, por isso a severidade é média."
        ),
        steps=(
            "Troque a lista de cifras do servidor pela lista recomendada abaixo.",
            "Se um cliente muito antigo depende de 3DES, planeje a atualização dele.",
            "Recarregue o serviço e repita o teste: as suítes 3DES não podem ser aceitas.",
        ),
        examples=STRONG_CIPHERS,
        verify=f"{_VERIFY_NMAP} não deve listar 3DES.",
        effort="baixo",
        fix_group="tls",
        references=(_SWEET32, MOZILLA_GUIDELINES, MS_DISABLE_SUITE),
        cwe="CWE-327",
        owasp="A02:2021",
        cis=("3.10", "4.1"),
        lgpd=True,
        tags=("cifra",),
    ),
    KBEntry(
        id=NO_FORWARD_SECRECY,
        title="Servidor sem sigilo futuro (só troca de chaves RSA)",
        category=Category.TLS,
        severity=Severity.LOW,
        summary="Na versão testada, o servidor só aceita troca de chaves RSA, sem ECDHE nem DHE.",
        explanation=(
            "Na troca de chaves RSA, a mesma chave privada do certificado protege todas as "
            "sessões. Com ECDHE ou DHE, cada conexão usa uma chave descartável: é o chamado "
            "sigilo futuro (forward secrecy). A OWASP recomenda evitar a troca de chaves RSA."
        ),
        risk=(
            "Quem gravar o tráfego hoje e obtiver a chave privada amanhã (por invasão, descarte "
            "de disco ou ordem judicial) consegue decifrar todas as conversas antigas."
        ),
        steps=(
            "Coloque suítes ECDHE no início da lista de cifras do servidor.",
            "Depois de confirmar que os clientes funcionam, remova as suítes TLS_RSA_WITH_*.",
            "Recarregue o serviço e repita o teste.",
        ),
        examples=(
            MODERN_NGINX,
            MODERN_APACHE,
            Fix(
                "iis",
                "IIS / Windows (PowerShell como administrador)",
                "Enable-TlsCipherSuite -Name 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256' -Position 0\n"
                "Enable-TlsCipherSuite -Name 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384' -Position 1\n"
                "Get-TlsCipherSuite | Where-Object { $_.Name -like 'TLS_RSA_*' } |\n"
                "    ForEach-Object { Disable-TlsCipherSuite -Name $_.Name }",
                "powershell",
            ),
            MODERN_TOMCAT,
            MODERN_NODE,
        ),
        verify=f"{_VERIFY_NMAP} deve listar suítes TLS_ECDHE_ ou TLS_DHE_ em TLS 1.2.",
        effort="baixo",
        fix_group="tls",
        references=(OWASP_TLS, MOZILLA_GUIDELINES, MS_DISABLE_SUITE),
        cwe="CWE-326",
        owasp="A02:2021",
        cis=("3.10",),
        tags=("cifra",),
    ),
)
