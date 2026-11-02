"""Base de conhecimento dos achados de zona DNS: CAA, DNSSEC, AXFR e sequestro de subdomínio."""

from __future__ import annotations

from ...core import kb
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Severity

RFC_CAA = "https://www.rfc-editor.org/rfc/rfc8659"
RFC_DNSSEC = "https://www.rfc-editor.org/rfc/rfc4033"
RFC_DNSSEC_VALIDACAO = "https://www.rfc-editor.org/rfc/rfc4035"
RFC_AXFR = "https://www.rfc-editor.org/rfc/rfc5936"
CISA_AXFR = "https://www.cisa.gov/news-events/alerts/2015/04/13/dns-zone-transfer-axfr-requests-may-leak-domain-information"
OWASP_TAKEOVER = (
    "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/"
    "02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover"
)
MS_TAKEOVER = "https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover"
CAN_I_TAKE_OVER = "https://github.com/EdOverflow/can-i-take-over-xyz"

_REMOVER_CNAME = (
    Fix(
        "generico",
        "Zona DNS",
        "; apague o registro que aponta para o recurso que não existe mais\n"
        "; loja.exemplo.com.br.  IN CNAME  loja-antiga.azurewebsites.net.   <- remover",
        "text",
    ),
    Fix(
        "windows",
        "Servidor DNS do Windows",
        'Remove-DnsServerResourceRecord -ZoneName "exemplo.com.br" -Name "loja" -RRType CNAME -Force',
        "powershell",
    ),
    Fix(
        "azure",
        "Azure DNS",
        "az network dns record-set cname delete -g meu-grupo -z exemplo.com.br -n loja --yes",
        "bash",
    ),
)

kb.register(
    KBEntry(
        id="dns.caa.ausente",
        title="Domínio sem registro CAA",
        category=Category.DNS,
        severity=Severity.LOW,
        summary="Nenhum registro CAA limita quais autoridades certificadoras podem emitir certificados para o domínio.",
        explanation=(
            "O registro CAA (RFC 8659) diz quais autoridades certificadoras (CAs) podem emitir "
            "certificados para o domínio. As CAs são obrigadas a consultá-lo antes de emitir; sem "
            "ele, qualquer CA pública pode emitir. Só a propriedade 'issue' limita os certificados "
            "comuns: um CAA apenas com 'iodef' ou 'issuewild' não restringe esses certificados."
        ),
        risk=(
            "Se um atacante conseguir enganar a validação de alguma CA (ex.: sequestrando um "
            "subdomínio ou a rota), obtém um certificado válido para o seu domínio. O CAA reduz "
            "esse risco às CAs que você realmente usa."
        ),
        steps=(
            "Descubra quais CAs emitem os seus certificados (veja o emissor no cadeado do navegador).",
            "Publique um CAA 'issue' para cada uma delas na raiz do domínio.",
            "Opcional: publique 'iodef' com um e-mail para receber avisos de tentativas recusadas.",
        ),
        examples=(
            Fix(
                "generico",
                "Zona DNS",
                'exemplo.com.br.  IN CAA  0 issue "letsencrypt.org"\n'
                'exemplo.com.br.  IN CAA  0 iodef "mailto:seguranca@exemplo.com.br"',
                "text",
            ),
            Fix(
                "azure",
                "Azure DNS",
                "az network dns record-set caa add-record -g meu-grupo -z exemplo.com.br -n @ "
                "--flags 0 --tag issue --value letsencrypt.org",
                "bash",
            ),
        ),
        verify="Consulte o CAA do domínio (nslookup -type=caa exemplo.com.br ou dig CAA exemplo.com.br).",
        effort="baixo",
        fix_group="dns",
        references=(RFC_CAA, "https://letsencrypt.org/docs/caa/"),
        cwe="CWE-284",
        owasp="A05:2021",
        cis=("4.1",),
        tags=("dns", "caa", "certificado"),
    ),
    KBEntry(
        id="dns.dnssec.ausente",
        title="Domínio sem DNSSEC",
        category=Category.DNS,
        severity=Severity.LOW,
        summary="As respostas DNS do domínio não são assinadas (sem DS no registro.br/registrador e sem DNSKEY).",
        explanation=(
            "O DNSSEC assina digitalmente os registros DNS. Resolvedores que validam DNSSEC "
            "descartam respostas falsificadas, protegendo quem acessa o site ou envia e-mail ao domínio."
        ),
        risk=(
            "Sem DNSSEC, um atacante que consiga envenenar o cache de um resolvedor pode desviar "
            "visitantes e e-mails para servidores dele."
        ),
        steps=(
            "Ative a assinatura DNSSEC no seu provedor de DNS (muitos fazem com um clique).",
            "Publique o registro DS gerado pelo provedor no registrador do domínio (para .br, no registro.br).",
            "Acompanhe a renovação de chaves, se o provedor não fizer isso automaticamente.",
        ),
        examples=(
            Fix(
                "windows",
                "Servidor DNS do Windows",
                'Invoke-DnsServerZoneSign -ZoneName "exemplo.com.br" -SignWithDefault -PassThru',
                "powershell",
            ),
            Fix(
                "linux",
                "BIND 9.16+ (named.conf)",
                'zone "exemplo.com.br" {\n    type primary;\n    file "exemplo.com.br.db";\n    dnssec-policy default;\n    inline-signing yes;\n};',
                "text",
            ),
        ),
        verify="Consulte o DS do domínio (dig DS exemplo.com.br) e teste a validação em um resolvedor que valida DNSSEC.",
        effort="medio",
        fix_group="dns",
        references=(RFC_DNSSEC, "https://developers.cloudflare.com/dns/dnssec/"),
        cwe="CWE-345",
        owasp="A05:2021",
        cis=("4.1",),
        tags=("dns", "dnssec"),
    ),
    KBEntry(
        id="dns.dnssec.quebrado",
        title="Cadeia DNSSEC quebrada (DS sem chave correspondente)",
        category=Category.DNS,
        severity=Severity.HIGH,
        summary="O domínio pai anuncia DNSSEC (DS), mas a zona não publica a chave correspondente.",
        explanation=(
            "O registro DS no domínio pai avisa que a zona é assinada e diz qual chave (DNSKEY) "
            "esperar. Sem essa chave a validação falha: é o que costuma acontecer depois de trocar "
            "de provedor de DNS ou de chave sem atualizar o DS no registrador."
        ),
        risk=(
            "Resolvedores que validam DNSSEC (como os grandes resolvedores públicos) tratam as "
            "respostas como falsas e devolvem erro: para os usuários deles, o site e o e-mail do "
            "domínio ficam fora do ar."
        ),
        steps=(
            "Se a zona deveria estar assinada, reative a assinatura no provedor de DNS e confira a chave.",
            "Atualize o DS no registrador (para .br, no registro.br) com o valor mostrado pelo provedor.",
            "Se o domínio não vai usar DNSSEC, apague o DS no registrador.",
        ),
        examples=(
            Fix(
                "generico",
                "Conferir a chave e o DS",
                "dig DS exemplo.com.br +short\ndig DNSKEY exemplo.com.br +cd +short",
                "bash",
            ),
        ),
        verify="Consulte o domínio num resolvedor que valida (dig A exemplo.com.br @8.8.8.8): não pode responder SERVFAIL.",
        effort="medio",
        fix_group="dns",
        references=(RFC_DNSSEC, RFC_DNSSEC_VALIDACAO),
        cwe="CWE-345",
        owasp="A05:2021",
        cis=("4.1",),
        tags=("dns", "dnssec"),
    ),
    KBEntry(
        id="dns.dnssec.incompleto",
        title="DNSSEC assinado, mas sem DS no registrador",
        category=Category.DNS,
        severity=Severity.LOW,
        summary="A zona publica chaves DNSSEC (DNSKEY), mas o registro DS não foi publicado no domínio pai.",
        explanation=(
            "A cadeia de confiança do DNSSEC passa pelo registro DS publicado no domínio pai "
            "(registrador). Sem o DS, os resolvedores não validam as assinaturas e a zona se "
            "comporta como se não tivesse DNSSEC."
        ),
        risk="As respostas do domínio continuam falsificáveis, apesar do trabalho de assinar a zona.",
        steps=(
            "Copie o registro DS (ou a chave KSK) mostrado pelo seu provedor de DNS.",
            "Cadastre o DS no registrador do domínio (para .br, no painel do registro.br).",
        ),
        examples=(
            Fix(
                "generico",
                "Registro DS (exemplo)",
                "exemplo.com.br.  IN DS  12345 13 2 <hash SHA-256 da KSK fornecido pelo provedor>",
                "text",
            ),
        ),
        verify="Consulte o DS do domínio (dig DS exemplo.com.br) e confirme que ele aparece.",
        effort="baixo",
        fix_group="dns",
        references=(RFC_DNSSEC, "https://developers.cloudflare.com/dns/dnssec/"),
        cwe="CWE-345",
        owasp="A05:2021",
        cis=("4.1",),
        tags=("dns", "dnssec"),
    ),
    KBEntry(
        id="dns.axfr.permitido",
        title="Transferência de zona (AXFR) liberada para qualquer um",
        category=Category.DNS,
        severity=Severity.HIGH,
        summary="Um servidor DNS do domínio entrega a zona inteira para qualquer pessoa que pedir.",
        explanation=(
            "A transferência de zona (AXFR) existe para sincronizar servidores DNS secundários. "
            "Quando não é restrita, qualquer pessoa baixa a lista completa de nomes do domínio — "
            "inclusive sistemas internos, ambientes de teste e servidores esquecidos."
        ),
        risk=(
            "O atacante ganha o mapa completo da sua infraestrutura sem esforço, encontrando "
            "alvos fracos (homologação, painéis, VPN) que não apareceriam de outra forma."
        ),
        steps=(
            "Restrinja a transferência aos IPs dos servidores secundários (ou desative se não houver secundários).",
            "Se possível, autentique as transferências com TSIG.",
            "Repita a verificação em todos os servidores NS do domínio.",
        ),
        examples=(
            Fix(
                "linux",
                "BIND (named.conf)",
                'zone "exemplo.com.br" {\n    type primary;\n    file "exemplo.com.br.db";\n    allow-transfer { 192.0.2.53; };  // só o secundário\n};',
                "text",
            ),
            Fix(
                "windows",
                "Servidor DNS do Windows",
                'Set-DnsServerPrimaryZone -Name "exemplo.com.br" -SecureSecondaries NoTransfer',
                "powershell",
            ),
        ),
        verify="De uma máquina externa, rode 'dig AXFR exemplo.com.br @ns1.exemplo.com.br': a resposta deve ser 'Transfer failed'.",
        effort="baixo",
        fix_group="dns",
        references=(RFC_AXFR, CISA_AXFR),
        cwe="CWE-200",
        owasp="A05:2021",
        cis=("4.1",),
        tags=("dns", "axfr", "exposicao"),
    ),
    KBEntry(
        id="dns.takeover.possivel",
        title="Subdomínio sequestrável (aponta para serviço desativado)",
        category=Category.DNS,
        severity=Severity.HIGH,
        summary="Um registro CNAME aponta para um recurso de nuvem que não existe mais e pode ser criado por outra pessoa.",
        explanation=(
            "Quando um serviço (site no Azure, bucket S3, blog hospedado...) é apagado mas o CNAME "
            "continua no DNS, o nome fica 'pendurado'. Em vários provedores, qualquer cliente pode "
            "criar um recurso com o mesmo nome e passar a responder pelo seu subdomínio. A lista de "
            "serviços vulneráveis segue o projeto can-i-take-over-xyz e a documentação do Azure. A "
            "prova é o destino não existir no DNS ou a página do provedor dizer que o recurso não "
            "existe; o EIGAN não tenta criar nada, então confira também no painel do provedor."
        ),
        risk=(
            "Um atacante publica conteúdo no seu subdomínio: phishing com o seu endereço legítimo, "
            "roubo de cookies do domínio principal, contorno de CORS/CSP e emissão de certificados válidos."
        ),
        steps=(
            "Apague imediatamente o CNAME apontado na evidência (ou recrie o recurso na sua conta, se ainda for usado).",
            "Revise todos os registros DNS que apontam para serviços externos e remova os que não são mais usados.",
            "Inclua a remoção do DNS no processo de desativação de qualquer serviço.",
            "No Azure App Service, use também o registro TXT asuid para amarrar o domínio à sua assinatura.",
        ),
        examples=_REMOVER_CNAME,
        verify="Consulte o subdomínio (nslookup) e confirme que o CNAME foi removido ou aponta para um recurso seu.",
        effort="baixo",
        fix_group="takeover",
        references=(OWASP_TAKEOVER, MS_TAKEOVER, CAN_I_TAKE_OVER),
        cwe="CWE-672",
        owasp="A05:2021",
        cis=("4.1",),
        tags=("dns", "takeover", "subdominio"),
    ),
    KBEntry(
        id="dns.takeover.dominio_livre",
        title="Subdomínio aponta para domínio que não existe (pode ser registrado)",
        category=Category.DNS,
        severity=Severity.HIGH,
        summary="O CNAME aponta para um nome cujo domínio não está registrado: quem registrar passa a controlar o seu subdomínio.",
        explanation=(
            "O destino do CNAME pertence a um domínio que não existe no DNS (NXDOMAIN na raiz do "
            "domínio). Normalmente é um domínio de fornecedor que expirou ou foi digitado errado."
        ),
        risk=(
            "Qualquer pessoa pode registrar esse domínio e responder pelo seu subdomínio, com os "
            "mesmos impactos de um sequestro de subdomínio (phishing, cookies, certificados)."
        ),
        steps=(
            "Apague o CNAME indicado ou corrija o destino.",
            "Confirme no WHOIS/RDAP (registro.br, ICANN Lookup) a situação do domínio de destino.",
        ),
        examples=_REMOVER_CNAME,
        verify="Consulte o subdomínio e confirme que não aponta mais para o domínio inexistente.",
        effort="baixo",
        fix_group="takeover",
        references=(OWASP_TAKEOVER, MS_TAKEOVER),
        cwe="CWE-672",
        owasp="A05:2021",
        cis=("4.1",),
        tags=("dns", "takeover", "subdominio"),
    ),
    KBEntry(
        id="dns.cname.orfao",
        title="Registro CNAME órfão (aponta para nome inexistente)",
        category=Category.DNS,
        severity=Severity.LOW,
        summary="Um CNAME aponta para um nome que não existe mais; o subdomínio não funciona e deve ser limpo.",
        explanation=(
            "O destino do CNAME responde NXDOMAIN. Não há indício de que outra pessoa consiga recriar "
            "o recurso (a evidência diz o motivo quando ele é conhecido), mas registros órfãos são "
            "exatamente o que permite sequestros de subdomínio quando o provedor muda de comportamento."
        ),
        risk="Hoje, só um subdomínio quebrado; amanhã, um possível sequestro de subdomínio.",
        steps=(
            "Apague o CNAME se o serviço foi desativado; se ainda é usado, corrija o destino.",
            "Mantenha um inventário dos registros DNS que apontam para terceiros.",
        ),
        examples=_REMOVER_CNAME,
        verify="Consulte o subdomínio e confirme que não há mais CNAME para nome inexistente.",
        effort="baixo",
        fix_group="takeover",
        references=(OWASP_TAKEOVER, MS_TAKEOVER),
        cwe="CWE-672",
        owasp="A05:2021",
        cis=("4.1",),
        tags=("dns", "takeover", "higiene"),
    ),
)
