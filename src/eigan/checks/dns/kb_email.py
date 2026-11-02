"""Base de conhecimento dos achados de e-mail do domínio (SPF, DMARC, DKIM, MTA-STS, TLS-RPT)."""

from __future__ import annotations

from ...core import kb
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Severity

RFC_SPF = "https://www.rfc-editor.org/rfc/rfc7208"
RFC_DMARC = "https://www.rfc-editor.org/rfc/rfc7489"
RFC_DKIM = "https://www.rfc-editor.org/rfc/rfc6376"
RFC_MTA_STS = "https://www.rfc-editor.org/rfc/rfc8461"
RFC_TLS_RPT = "https://www.rfc-editor.org/rfc/rfc8460"
RFC_NULL_MX = "https://www.rfc-editor.org/rfc/rfc7505"
M3AAWG_2015 = "https://www.m3aawg.org/sites/default/files/m3aawg_parked_domains_bp-2015-12.pdf"
M3AAWG_2022 = "https://m3aawg.org/M3AAWG-Protecting-Parked-Domains-BCP-update-2022-06"
MS_DKIM = (
    "https://learn.microsoft.com/en-us/defender-office-365/email-authentication-dkim-configure"
)
GOOGLE_DKIM = "https://knowledge.workspace.google.com/admin/security/set-up-dkim"
PROTON_DKIM = "https://proton.me/support/anti-spoofing-custom-domain"

_SPF_OK = (
    Fix(
        "generico",
        "Registro TXT (zona DNS)",
        "; só os serviços que realmente enviam e-mail em nome do domínio\n"
        'exemplo.com.br.  IN TXT  "v=spf1 include:_spf.google.com -all"\n'
        '; Microsoft 365: "v=spf1 include:spf.protection.outlook.com -all"',
        "text",
    ),
    Fix(
        "windows",
        "Servidor DNS do Windows",
        'Add-DnsServerResourceRecord -ZoneName "exemplo.com.br" -Name "@" -Txt '
        '-DescriptiveText "v=spf1 include:_spf.google.com -all"',
        "powershell",
    ),
)
_DMARC_OK = (
    Fix(
        "generico",
        "Registro TXT (zona DNS)",
        '_dmarc.exemplo.com.br.  IN TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@exemplo.com.br"\n'
        "; depois de algumas semanas lendo os relatórios, endureça para p=reject",
        "text",
    ),
    Fix(
        "windows",
        "Servidor DNS do Windows",
        'Add-DnsServerResourceRecord -ZoneName "exemplo.com.br" -Name "_dmarc" -Txt '
        '-DescriptiveText "v=DMARC1; p=quarantine; rua=mailto:dmarc@exemplo.com.br"',
        "powershell",
    ),
)


def _email(
    id: str,
    title: str,
    severity: Severity,
    summary: str,
    explanation: str,
    risk: str,
    steps: tuple[str, ...],
    verify: str,
    examples: tuple[Fix, ...],
    references: tuple[str, ...],
    *,
    effort: str = "baixo",
    cwe: str = "CWE-290",
    owasp: str = "A05:2021",
    cis: tuple[str, ...] = ("9.5",),
    tags: tuple[str, ...] = ("email",),
) -> KBEntry:
    return KBEntry(
        id=id,
        title=title,
        category=Category.DNS,
        severity=severity,
        summary=summary,
        explanation=explanation,
        risk=risk,
        steps=steps,
        verify=verify,
        examples=examples,
        effort=effort,
        fix_group="email",
        references=references,
        cwe=cwe,
        owasp=owasp,
        cis=cis,
        tags=tags,
    )


kb.register(
    _email(
        "dns.email.spf_ausente",
        "Domínio sem SPF",
        Severity.MEDIUM,
        "O domínio não publica SPF: ninguém sabe quais servidores podem enviar e-mail por ele.",
        "O SPF (Sender Policy Framework) é um registro TXT que lista os servidores autorizados a "
        "enviar e-mail com o seu domínio no remetente. Sem ele, quem recebe a mensagem não tem como "
        "separar o e-mail legítimo do falsificado.",
        "Golpistas enviam e-mails em nome da empresa (boletos e notas fiscais falsas, pedidos de "
        "pagamento, phishing) com mais chance de chegar à caixa de entrada. Os e-mails legítimos "
        "também passam a cair mais no spam.",
        (
            "Liste todos os serviços que enviam e-mail com o seu domínio (provedor de e-mail, "
            "sistema de nota fiscal, CRM, marketing).",
            "Publique UM registro TXT na raiz do domínio começando com v=spf1, incluindo só esses serviços.",
            "Termine com -all (recusar o resto) quando a lista estiver completa; use ~all só durante a transição.",
            "Configure também o DMARC para que a política seja aplicada.",
        ),
        "Consulte o TXT do domínio (nslookup -type=txt exemplo.com.br) e envie um e-mail de teste "
        "para uma conta externa: o cabeçalho Authentication-Results deve mostrar spf=pass.",
        _SPF_OK,
        (RFC_SPF, M3AAWG_2015),
        tags=("email", "spf"),
    ),
    _email(
        "dns.email.spf_multiplo",
        "Mais de um registro SPF no domínio",
        Severity.MEDIUM,
        "Há dois ou mais registros SPF: pela norma, o SPF inteiro vira erro e é ignorado.",
        "A RFC 7208 exige um único registro TXT começando com v=spf1 por domínio. Com dois ou mais, "
        "o resultado da verificação é 'permerror' — na prática, é como não ter SPF.",
        "A proteção contra e-mails falsos deixa de funcionar e o DMARC não consegue validar pelo SPF; "
        "mensagens legítimas podem ser rejeitadas por provedores mais rígidos.",
        (
            "Junte todos os mecanismos (include, ip4, ip6...) em um único registro v=spf1.",
            "Apague os registros SPF duplicados.",
        ),
        "Consulte o TXT do domínio e confirme que só existe uma linha começando com v=spf1.",
        _SPF_OK,
        (RFC_SPF,),
        tags=("email", "spf"),
    ),
    _email(
        "dns.email.spf_permissivo",
        "SPF autoriza qualquer servidor (+all)",
        Severity.HIGH,
        "O SPF aprova qualquer servidor do mundo (ou quase): qualquer um pode enviar e-mail pelo domínio.",
        "O mecanismo 'all' diz o que fazer com servidores não listados. Com +all (ou 'all' sem "
        "qualificador), todos são aprovados — o SPF passa a confirmar e-mails falsificados. O efeito "
        "é o mesmo quando o registro aprova uma faixa gigantesca (ex.: ip4:0.0.0.0/0) ou inclui "
        "outro registro que termina em +all, mesmo que o seu termine em -all.",
        "Pior do que não ter SPF: o e-mail falso chega com 'spf=pass', ganhando credibilidade em "
        "golpes de phishing e fraude de pagamento.",
        (
            "Troque +all por -all (recusar) depois de listar todos os serviços legítimos.",
            "Remova as faixas gigantescas e os includes indicados na evidência, deixando só os IPs "
            "e serviços que realmente enviam e-mail.",
            "Se ainda não tem certeza da lista, use ~all temporariamente e acompanhe os relatórios DMARC.",
        ),
        "Consulte o TXT do domínio: ele deve terminar em -all ou ~all e listar só remetentes legítimos.",
        _SPF_OK,
        (RFC_SPF,),
        tags=("email", "spf"),
    ),
    _email(
        "dns.email.spf_neutro",
        "SPF neutro (?all ou sem 'all')",
        Severity.MEDIUM,
        "O SPF não diz o que fazer com servidores não autorizados, então não protege.",
        "Com ?all — ou sem nenhum mecanismo 'all' e sem 'redirect' — o resultado para servidores fora "
        "da lista é 'neutral', que a RFC 7208 manda tratar como se não houvesse SPF.",
        "E-mails falsificados com o seu domínio não são barrados pelo SPF.",
        (
            "Termine o registro com -all depois de incluir todos os serviços legítimos.",
            "Durante a transição, ~all é aceitável desde que o DMARC esteja em quarantine ou reject.",
        ),
        "Consulte o TXT do domínio e confirme o final -all (ou ~all com DMARC aplicado).",
        _SPF_OK,
        (RFC_SPF,),
        tags=("email", "spf"),
    ),
    _email(
        "dns.email.spf_softfail",
        "SPF em modo brando (~all)",
        Severity.INFO,
        "O SPF termina em ~all: servidores não autorizados recebem só uma marcação de suspeita.",
        "~all (softfail) é o padrão recomendado durante a implantação. A proteção real vem do "
        "DMARC: com p=quarantine ou p=reject, o ~all já basta. Quando todos os remetentes legítimos "
        "estiverem no SPF, trocar para -all deixa a política explícita.",
        "Sem DMARC aplicado, provedores podem entregar e-mails falsos marcados apenas como suspeitos.",
        (
            "Confirme que o DMARC está em p=quarantine ou p=reject.",
            "Quando a lista de remetentes estiver completa, considere trocar ~all por -all.",
        ),
        "Consulte o TXT do domínio e o registro _dmarc correspondente.",
        _SPF_OK,
        (RFC_SPF, RFC_DMARC),
        tags=("email", "spf"),
    ),
    _email(
        "dns.email.spf_consultas",
        "SPF com mais de 10 consultas DNS",
        Severity.MEDIUM,
        "O SPF exige mais de 10 consultas DNS para ser avaliado, o limite da norma.",
        "Cada include, a, mx, ptr, exists e redirect custa uma consulta DNS, somando também as dos "
        "includes de terceiros. Acima de 10, a RFC 7208 manda devolver 'permerror' e o SPF é ignorado.",
        "O SPF para de funcionar para parte dos destinatários: e-mails legítimos podem ser recusados "
        "e os falsificados deixam de ser barrados.",
        (
            "Remova includes de serviços que não são mais usados.",
            "Troque includes por faixas ip4/ip6 quando o fornecedor publicar IPs fixos.",
            "Evite o mecanismo ptr (lento e desaconselhado pela norma) e mx/a desnecessários.",
            "Se precisar de muitos serviços, use subdomínios de envio (ex.: news.exemplo.com.br) com SPF próprio.",
        ),
        "Recalcule as consultas após a mudança (o EIGAN mostra a contagem na evidência).",
        _SPF_OK,
        (RFC_SPF,),
        effort="medio",
        tags=("email", "spf"),
    ),
    _email(
        "dns.email.spf_invalido",
        "SPF com erro de sintaxe ou include quebrado",
        Severity.MEDIUM,
        "O SPF tem um termo inválido ou inclui um domínio sem SPF — o resultado vira 'permerror'.",
        "Mecanismos desconhecidos, erros de digitação (ex.: 'inlcude:') e includes que apontam para "
        "domínios sem registro SPF fazem a avaliação falhar com 'permerror'.",
        "O SPF deixa de proteger o domínio e o DMARC perde uma das formas de validar os e-mails.",
        (
            "Corrija o termo indicado na evidência (só valem all, include, a, mx, ptr, ip4, ip6, exists e os modificadores redirect/exp).",
            "Remova includes de domínios que não publicam mais SPF.",
        ),
        "Consulte o TXT do domínio novamente e valide a sintaxe termo a termo.",
        _SPF_OK,
        (RFC_SPF,),
        tags=("email", "spf"),
    ),
    _email(
        "dns.email.dmarc_ausente",
        "Domínio sem DMARC",
        Severity.MEDIUM,
        "Não há política DMARC: os provedores não sabem o que fazer com e-mails falsos do domínio.",
        "O DMARC (registro TXT em _dmarc.seudominio) junta SPF e DKIM, exige que o domínio visível no "
        "'De:' seja o autenticado e diz ao destinatário se deve entregar, pôr em quarentena ou "
        "rejeitar o que falhar. Também envia relatórios de quem está usando o seu domínio.",
        "Sem DMARC, golpistas conseguem usar exatamente o seu endereço no remetente. Grandes "
        "provedores (Gmail, Yahoo, Microsoft) exigem DMARC de quem envia em volume.",
        (
            "Publique _dmarc.seudominio com p=none e um endereço rua= para receber relatórios.",
            "Acompanhe os relatórios por algumas semanas e corrija SPF/DKIM dos serviços legítimos.",
            "Endureça para p=quarantine e depois p=reject.",
        ),
        "Consulte o TXT de _dmarc.seudominio (nslookup -type=txt _dmarc.exemplo.com.br).",
        _DMARC_OK,
        (RFC_DMARC, "https://www.cisecurity.org/controls/v8"),
        effort="medio",
        tags=("email", "dmarc"),
    ),
    _email(
        "dns.email.dmarc_invalido",
        "Registro DMARC inválido ou duplicado",
        Severity.MEDIUM,
        "O DMARC publicado não é válido (duplicado ou sem os campos obrigatórios) e é ignorado.",
        "A RFC 7489 manda ignorar o DMARC quando há mais de um registro em _dmarc ou quando o "
        "registro não começa com v=DMARC1.",
        "O domínio fica, na prática, sem política DMARC e sem relatórios.",
        (
            "Mantenha um único registro TXT em _dmarc.seudominio.",
            "Comece com v=DMARC1; e inclua p=none|quarantine|reject.",
        ),
        "Consulte o TXT de _dmarc.seudominio e confirme uma única linha válida.",
        _DMARC_OK,
        (RFC_DMARC,),
        tags=("email", "dmarc"),
    ),
    _email(
        "dns.email.dmarc_monitoramento",
        "DMARC só em monitoramento (p=none)",
        Severity.LOW,
        "A política DMARC é 'none': os e-mails falsos são só relatados, não bloqueados.",
        "p=none é a fase inicial do DMARC, útil para descobrir quem envia em nome do domínio. "
        "Enquanto ela durar, o destinatário entrega normalmente o e-mail que falha na autenticação. "
        "O mesmo vale para sp=none, que afrouxa a regra dos subdomínios.",
        "Phishing com o seu domínio continua chegando à caixa de entrada das vítimas.",
        (
            "Revise os relatórios rua e corrija SPF/DKIM dos serviços legítimos.",
            "Mude para p=quarantine e, depois de estável, para p=reject (e sp igual ou ausente).",
        ),
        "Consulte o TXT de _dmarc.seudominio e confirme p=quarantine ou p=reject.",
        _DMARC_OK,
        (RFC_DMARC,),
        effort="medio",
        tags=("email", "dmarc"),
    ),
    _email(
        "dns.email.dmarc_parcial",
        "DMARC aplicado só a parte dos e-mails (pct < 100)",
        Severity.LOW,
        "O campo pct faz a política DMARC valer só para uma fração das mensagens.",
        "pct=50, por exemplo, manda aplicar quarantine/reject a metade dos e-mails que falham; o "
        "resto é tratado como p=none. É útil numa transição curta, não como estado final.",
        "Parte dos e-mails falsificados continua sendo entregue.",
        ("Depois de validar os relatórios, remova o pct ou use pct=100.",),
        "Consulte o TXT de _dmarc.seudominio e confirme que não há pct menor que 100.",
        _DMARC_OK,
        (RFC_DMARC,),
        tags=("email", "dmarc"),
    ),
    _email(
        "dns.email.dmarc_sem_relatorio",
        "DMARC sem endereço de relatórios (rua)",
        Severity.INFO,
        "O DMARC não pede relatórios agregados: você não vê quem envia e-mail em nome do domínio.",
        "O campo rua=mailto:... recebe relatórios diários dos provedores com os servidores que "
        "usaram o seu domínio e o resultado de SPF/DKIM. Sem ele, a política funciona, mas às cegas.",
        "Fica difícil perceber campanhas de falsificação ou serviços legítimos falhando.",
        (
            "Acrescente rua=mailto:dmarc@seudominio (ou o endereço de uma ferramenta de análise DMARC).",
            "Se o endereço for de outro domínio, esse domínio precisa autorizar o recebimento (RFC 7489, seção 7.1).",
        ),
        "Consulte o TXT de _dmarc.seudominio e confirme o campo rua.",
        _DMARC_OK,
        (RFC_DMARC,),
        cwe="CWE-778",
        owasp="A09:2021",
        tags=("email", "dmarc"),
    ),
    _email(
        "dns.email.dkim_nao_encontrado",
        "DKIM não encontrado nos seletores comuns",
        Severity.INFO,
        "Não achamos chave DKIM nos seletores mais usados — isso NÃO prova que o domínio não usa DKIM.",
        "O DKIM assina cada e-mail com uma chave publicada em <seletor>._domainkey.seudominio. O "
        "nome do seletor é escolhido pelo provedor (ex.: selector1/selector2 no Microsoft 365, "
        "google no Google Workspace, protonmail no Proton) e não pode ser listado pelo DNS, por "
        "isso a ausência nos seletores testados é só um indício.",
        "Sem DKIM, o DMARC depende só do SPF, que quebra em encaminhamentos; as mensagens legítimas "
        "têm mais chance de cair no spam.",
        (
            "Confira no painel do seu provedor de e-mail se a assinatura DKIM está ativa.",
            "Publique os registros (TXT ou CNAME) indicados pelo provedor e ative a assinatura.",
            "Faça o mesmo em cada serviço que envia e-mail em seu nome (marketing, nota fiscal, CRM).",
        ),
        "Envie um e-mail para uma conta externa e procure dkim=pass no cabeçalho Authentication-Results.",
        (
            Fix(
                "generico",
                "Registro DKIM (exemplo Microsoft 365)",
                "selector1._domainkey.exemplo.com.br.  IN CNAME  (valor exibido no portal do Microsoft Defender)",
                "text",
            ),
        ),
        (RFC_DKIM, MS_DKIM, GOOGLE_DKIM, PROTON_DKIM),
        tags=("email", "dkim"),
    ),
    _email(
        "dns.email.mta_sts_ausente",
        "Domínio sem MTA-STS",
        Severity.LOW,
        "Sem MTA-STS, quem envia e-mail ao domínio aceita entregar sem criptografia se for enganado.",
        "Por padrão, a criptografia entre servidores de e-mail (STARTTLS) é oportunista: um atacante "
        "no caminho pode removê-la. O MTA-STS (RFC 8461) publica uma política dizendo que os seus "
        "servidores MX exigem TLS com certificado válido.",
        "E-mails recebidos podem ser lidos ou desviados por quem controla a rede entre os servidores "
        "(ataque de rebaixamento de STARTTLS).",
        (
            "Garanta que todos os MX aceitem STARTTLS com certificado válido para o nome do MX.",
            "Publique a política em https://mta-sts.seudominio/.well-known/mta-sts.txt (mode: testing no início).",
            "Publique o TXT _mta-sts.seudominio com v=STSv1; id=<identificador> (troque o id a cada mudança).",
            "Acompanhe os relatórios TLS-RPT e passe para mode: enforce.",
        ),
        "Abra https://mta-sts.seudominio/.well-known/mta-sts.txt e consulte o TXT _mta-sts.seudominio.",
        (
            Fix(
                "generico",
                "TXT + arquivo de política",
                '_mta-sts.exemplo.com.br.  IN TXT  "v=STSv1; id=20261101T000000"\n\n'
                "# https://mta-sts.exemplo.com.br/.well-known/mta-sts.txt\n"
                "version: STSv1\nmode: testing\nmx: mx1.exemplo.com.br\nmax_age: 604800",
                "text",
            ),
        ),
        (RFC_MTA_STS, RFC_TLS_RPT),
        effort="medio",
        cwe="CWE-319",
        owasp="A02:2021",
        cis=("3.10",),
        tags=("email", "mta-sts", "tls"),
    ),
    _email(
        "dns.email.mta_sts_invalido",
        "Política MTA-STS quebrada",
        Severity.MEDIUM,
        "O domínio anuncia MTA-STS, mas a política não pode ser usada ou não cobre os servidores MX.",
        "A política precisa estar em https://mta-sts.seudominio/.well-known/mta-sts.txt, com "
        "certificado válido, resposta 200 sem redirecionamento, campos version/mode/mx/max_age e "
        "linhas mx que cubram todos os servidores MX do domínio.",
        "Remetentes que respeitam MTA-STS podem deixar de entregar e-mails (se mode: enforce e o MX "
        "não estiver coberto) ou ignorar a proteção quando a política não pode ser lida.",
        (
            "Corrija o problema descrito na evidência (certificado, endereço, conteúdo ou lista mx).",
            "Depois de corrigir, troque o id do TXT _mta-sts para os remetentes buscarem a política nova.",
        ),
        "Abra a URL da política num navegador (cadeado válido) e confira as linhas mx contra os MX do domínio.",
        (
            Fix(
                "generico",
                "Arquivo de política",
                "version: STSv1\nmode: enforce\nmx: mx1.exemplo.com.br\nmx: *.mail.exemplo.com.br\nmax_age: 604800",
                "text",
            ),
        ),
        (RFC_MTA_STS,),
        cwe="CWE-319",
        owasp="A02:2021",
        cis=("3.10",),
        tags=("email", "mta-sts", "tls"),
    ),
    _email(
        "dns.email.mta_sts_nao_aplicado",
        "MTA-STS em modo de teste ou desligado",
        Severity.LOW,
        "A política MTA-STS existe, mas está em 'testing' ou 'none' e não bloqueia o rebaixamento.",
        "Em mode: testing os remetentes só relatam falhas (via TLS-RPT) e entregam mesmo assim; "
        "mode: none sinaliza que a política está sendo retirada.",
        "A criptografia na entrega dos e-mails continua podendo ser removida por um atacante no caminho.",
        (
            "Analise os relatórios TLS-RPT; se não houver falhas, mude para mode: enforce.",
            "Troque o id no TXT _mta-sts depois da mudança.",
        ),
        "Abra a política e confirme mode: enforce.",
        (
            Fix(
                "generico",
                "Arquivo de política",
                "version: STSv1\nmode: enforce\nmx: mx1.exemplo.com.br\nmax_age: 604800",
                "text",
            ),
        ),
        (RFC_MTA_STS,),
        cwe="CWE-319",
        owasp="A02:2021",
        cis=("3.10",),
        tags=("email", "mta-sts", "tls"),
    ),
    _email(
        "dns.email.tls_rpt_ausente",
        "Domínio sem relatórios TLS-RPT",
        Severity.INFO,
        "Sem TLS-RPT, você não fica sabendo quando a entrega criptografada de e-mails falha.",
        "O TLS-RPT (RFC 8460) é um TXT em _smtp._tls.seudominio que pede aos remetentes relatórios "
        "diários de falhas de TLS na entrega para os seus MX. Complementa o MTA-STS e o DANE.",
        "Problemas de certificado ou tentativas de rebaixamento passam despercebidos.",
        ("Publique _smtp._tls.seudominio com v=TLSRPTv1; rua=mailto:<endereço>.",),
        "Consulte o TXT de _smtp._tls.seudominio.",
        (
            Fix(
                "generico",
                "Registro TXT (zona DNS)",
                '_smtp._tls.exemplo.com.br.  IN TXT  "v=TLSRPTv1; rua=mailto:tlsrpt@exemplo.com.br"',
                "text",
            ),
        ),
        (RFC_TLS_RPT,),
        cwe="CWE-778",
        owasp="A09:2021",
        cis=("3.10",),
        tags=("email", "tls-rpt"),
    ),
    _email(
        "dns.email.estacionado",
        "Domínio que não usa e-mail sem proteção contra falsificação",
        Severity.MEDIUM,
        "O domínio não recebe e-mail (sem MX), mas não declara que também não envia — fica fácil falsificá-lo.",
        "Domínios estacionados ou que não usam e-mail são alvos preferidos de golpistas, porque ninguém "
        "acompanha. A recomendação da M3AAWG é publicar um SPF que não autoriza ninguém "
        "(v=spf1 -all) e um DMARC p=reject; o MX nulo (RFC 7505) deixa claro que o domínio não recebe e-mail.",
        "E-mails falsos em nome do domínio (phishing, fraude de boletos) são entregues sem nenhuma "
        "verificação capaz de barrá-los.",
        (
            "Publique o TXT v=spf1 -all na raiz do domínio.",
            "Publique _dmarc com p=reject (e sp=reject para os subdomínios).",
            "Opcional: publique o MX nulo '0 .' para indicar que o domínio não recebe e-mail.",
        ),
        "Consulte TXT, _dmarc e MX do domínio.",
        (
            Fix(
                "generico",
                "Registros para domínio sem e-mail",
                'exemplo.com.br.         IN TXT  "v=spf1 -all"\n'
                '_dmarc.exemplo.com.br.  IN TXT  "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s"\n'
                "exemplo.com.br.         IN MX   0 .",
                "text",
            ),
        ),
        (M3AAWG_2015, M3AAWG_2022, RFC_NULL_MX, RFC_SPF, RFC_DMARC),
        tags=("email", "spf", "dmarc"),
    ),
)
