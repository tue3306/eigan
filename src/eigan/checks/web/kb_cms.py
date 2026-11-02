"""Conhecimento sobre os CMS (checagem ``web.cms``): textos dos achados e versões oficiais.

As versões, as datas de fim de suporte e as faixas de CVE ficam em ``data/web_cms.json``
(com a fonte oficial de cada dado); as funções abaixo só consultam esse arquivo.
"""

from __future__ import annotations

import re
from datetime import UTC, date, datetime
from typing import Any

from ...core import kb
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Severity
from ...core.versions import compare, in_range, lt
from ...data import load_json

DATA_FILE = "web_cms.json"


def _data() -> dict[str, Any]:
    try:
        data = load_json(DATA_FILE)
    except (OSError, ValueError):  # sem os dados, a checagem só não avalia as versões
        return {}
    return data if isinstance(data, dict) else {}


def today() -> date:
    return datetime.now(UTC).date()


def data_date() -> str:
    """Quando os dados embarcados foram conferidos pela última vez."""
    return str(_data().get("atualizado", ""))


def end_of_life(product: str, version: str, day: date) -> dict[str, str] | None:
    """A linha de fim de suporte que vale para a versão, se a data já passou."""
    for row in _data().get(product, {}).get("fim_de_suporte", []):
        if compare(version, row["antes_de"]) < 0:
            return row if date.fromisoformat(row["data"]) <= day else None
    return None


def _in_band(version: str, band: dict[str, str]) -> bool:
    return in_range(
        version,
        introduced=band.get("de"),
        fixed=band.get("antes_de"),
        last_affected=band.get("ate"),
    )


def known_cves(product: str, version: str) -> list[dict[str, Any]]:
    """CVEs do núcleo cuja faixa publicada contém esta versão."""
    return [
        cve
        for cve in _data().get("cves", [])
        if cve["produto"] == product and any(_in_band(version, band) for band in cve["faixas"])
    ]


def outdated(product: str, version: str) -> tuple[str, bool] | None:
    """(versão de referência, atrasada dentro da própria série?) ou ``None`` se estiver em dia."""
    info = _data().get(product, {})
    numbers = re.findall(r"\d+", version)[:2]
    if not numbers or "ramos" not in info:
        return None
    newest = info["ramos"].get(".".join(numbers)) or info["ramos"].get(numbers[0])
    if newest is None:
        return None  # série mais nova que os dados embarcados, ou já sem suporte
    if lt(version, newest):
        return newest, True
    if info.get("so_ultima_serie") and lt(version, info["ultima"]):
        return info["ultima"], False
    return None


def has_reference(product: str, version: str) -> bool:
    """Há uma versão de referência igual ou mais nova que esta nos dados embarcados?"""
    info = _data().get(product, {})
    numbers = re.findall(r"\d+", version)[:2]
    if not numbers or "ramos" not in info:
        return False
    newest = info["ramos"].get(".".join(numbers)) or info["ramos"].get(numbers[0])
    return newest is not None and not lt(newest, version)


WP_POLICY = "https://wordpress.org/documentation/article/supported-versions/"
WP_UPDATE = "https://wordpress.org/documentation/article/updating-wordpress/"
WP_HARDENING = "https://developer.wordpress.org/advanced-administration/security/hardening/"
WP_BRUTE_FORCE = "https://developer.wordpress.org/advanced-administration/security/brute-force/"
DRUPAL_CYCLE = "https://www.drupal.org/about/core/policies/core-release-cycles/schedule"
DRUPAL_UPDATE = "https://www.drupal.org/docs/updating-drupal"
JOOMLA_ROADMAP = "https://developer.joomla.org/roadmap.html"
JOOMLA_SECURITY = "https://developer.joomla.org/security-centre.html"
KEV = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

#: atualizar o núcleo do CMS, por produto
UPDATE_FIXES = (
    Fix(
        "wordpress",
        "WordPress (WP-CLI, faça backup antes)",
        "wp db export backup.sql\nwp core update\nwp core update-db\nwp core version",
        "bash",
    ),
    Fix(
        "wordpress",
        "WordPress (wp-config.php: atualizações automáticas do núcleo)",
        "define('WP_AUTO_UPDATE_CORE', true);",
        "php",
    ),
    Fix(
        "drupal",
        "Drupal 8+ (Composer e Drush, faça backup antes)",
        'composer update "drupal/core-*" --with-all-dependencies\nvendor/bin/drush updatedb\nvendor/bin/drush cache:rebuild',
        "bash",
    ),
    Fix(
        "joomla",
        "Joomla (painel administrativo, faça backup antes)",
        "Sistema > Atualizar > Joomla > Instalar a atualização",
        "text",
    ),
)

kb.register(
    KBEntry(
        id="web.cms.versao_vulneravel",
        title="CMS em versão com falha sabidamente explorada",
        category=Category.WEB,
        severity=Severity.HIGH,
        summary=(
            "A versão do WordPress, Joomla ou Drupal informada pelo site está na faixa afetada "
            "por uma falha pública do núcleo do CMS."
        ),
        explanation=(
            "O EIGAN compara a versão que o próprio site divulga com as faixas publicadas no NVD "
            "para as falhas do núcleo dos CMS que constam no catálogo CISA KEV, a lista de "
            "vulnerabilidades com ataques reais em andamento. Nenhuma falha é testada contra o "
            "site. Se a sua hospedagem aplica correções sem mudar o número da versão, ou o HTML "
            "está em cache, confirme a versão instalada no painel do CMS."
        ),
        risk=(
            "Robôs procuram essas versões o tempo todo. Dependendo da falha, o atacante lê ou "
            "altera o banco de dados ou executa código no servidor: roubo de dados de clientes, "
            "páginas adulteradas e uso do site para espalhar malware."
        ),
        steps=(
            "Confira a versão instalada no painel administrativo do CMS.",
            "Faça backup dos arquivos e do banco de dados.",
            "Atualize o núcleo do CMS para a versão mais recente da série (exemplos abaixo).",
            "Procure sinais de invasão: administradores desconhecidos, arquivos .php novos nas "
            "pastas de upload e alterações recentes em temas e plugins.",
            "Ative as atualizações automáticas de segurança, se o CMS oferecer.",
        ),
        examples=UPDATE_FIXES,
        verify=(
            "Depois de atualizar, confira a versão no painel do CMS e repita a auditoria: o achado "
            "não deve voltar."
        ),
        effort="medio",
        fix_group="cms",
        references=(KEV, WP_UPDATE, DRUPAL_UPDATE, JOOMLA_SECURITY),
        cwe="CWE-1395",
        owasp="A06:2021",
        cis=("7.4", "2.2"),
        lgpd=True,
        tags=("cms", "cve"),
    ),
    KBEntry(
        id="web.cms.fim_de_suporte",
        title="CMS em versão sem suporte de segurança",
        category=Category.WEB,
        severity=Severity.HIGH,
        summary="A série do WordPress, Joomla ou Drupal usada pelo site não recebe mais correções de segurança.",
        explanation=(
            "Cada série de um CMS tem data para deixar de receber correções, publicada pelo "
            "próprio projeto. Depois dela, qualquer falha nova fica aberta para sempre: não há "
            "atualização que resolva sem mudar de série. Plugins e temas também abandonam essas "
            "versões aos poucos."
        ),
        risk=(
            "Falhas descobertas depois do fim do suporte nunca são corrigidas e costumam ser "
            "exploradas em massa. Uma invasão expõe dados de clientes e o próprio servidor."
        ),
        steps=(
            "Planeje a migração para uma série com suporte e teste em uma cópia do site.",
            "Faça backup dos arquivos e do banco de dados.",
            "Atualize plugins, temas e extensões para versões compatíveis com a nova série.",
            "Se a migração for demorar, restrinja o painel administrativo por IP e use um WAF, "
            "sabendo que isso só reduz o risco.",
        ),
        examples=UPDATE_FIXES,
        verify="Confira a versão no painel do CMS e repita a auditoria: o achado não deve voltar.",
        effort="alto",
        fix_group="cms",
        references=(
            DRUPAL_CYCLE,
            JOOMLA_ROADMAP,
            "https://wordpress.org/news/2025/06/dropping-security-updates-for-wordpress-versions-4-1-through-4-6/",
            "https://wordpress.org/news/2022/09/dropping-security-updates-for-wordpress-versions-3-7-through-4-0/",
        ),
        cwe="CWE-1104",
        owasp="A06:2021",
        cis=("2.2", "7.4"),
        lgpd=True,
        tags=("cms", "fim-de-suporte"),
    ),
    KBEntry(
        id="web.cms.desatualizado",
        title="CMS desatualizado",
        category=Category.WEB,
        severity=Severity.MEDIUM,
        summary="O site usa uma versão do CMS mais antiga que a última publicada pelo projeto.",
        explanation=(
            "As atualizações menores de um CMS trazem correções de segurança. O WordPress declara "
            "oficialmente que só a série mais recente é mantida; as anteriores recebem correções "
            "apenas como cortesia, sem garantia. A comparação usa as versões oficiais embarcadas "
            "no EIGAN, então uma versão indicada aqui com certeza já foi superada."
        ),
        risk=(
            "Falhas já corrigidas nas versões novas continuam abertas neste site, e as correções "
            "publicadas mostram aos atacantes exatamente o que explorar."
        ),
        steps=(
            "Faça backup dos arquivos e do banco de dados.",
            "Atualize o núcleo do CMS para a versão mais recente (exemplos abaixo).",
            "Atualize também plugins, temas e extensões.",
            "Ative as atualizações automáticas de segurança, se o CMS oferecer.",
        ),
        examples=UPDATE_FIXES,
        verify="Confira a versão no painel do CMS e repita a auditoria: o achado não deve voltar.",
        effort="baixo",
        fix_group="cms",
        references=(WP_POLICY, WP_UPDATE, "https://downloads.joomla.org/api/v1/latest/cms"),
        cwe="CWE-1104",
        owasp="A06:2021",
        cis=("7.4",),
        tags=("cms", "atualizacao"),
    ),
    KBEntry(
        id="web.cms.xmlrpc",
        title="xmlrpc.php do WordPress ativo",
        category=Category.WEB,
        severity=Severity.LOW,
        summary="A interface antiga de publicação remota do WordPress (xmlrpc.php) responde no site.",
        explanation=(
            "O xmlrpc.php permite publicar e administrar o site por programas externos. Hoje a API "
            "REST faz o mesmo papel, mas ele continua ligado por padrão. Ele aceita muitas "
            "tentativas de senha em uma só requisição, o que escapa de limites feitos para a tela "
            "de login, e o recurso de pingback pode ser usado contra outros sites. O EIGAN só "
            "confirma que o arquivo responde; não envia nenhum comando a ele."
        ),
        risk=(
            "Tentativas de adivinhar senhas em grande volume, mais difíceis de bloquear, e uso do "
            "site como ponte em ataques a terceiros."
        ),
        steps=(
            "Confirme se algo ainda usa o XML-RPC (app móvel antigo, Jetpack, publicação remota).",
            "Se nada usa, bloqueie o arquivo no servidor web (exemplos abaixo).",
            "Se for preciso manter, libere só os IPs dos serviços que usam.",
        ),
        examples=(
            Fix(
                "apache",
                "Apache (.htaccess)",
                "<Files xmlrpc.php>\n    Require all denied\n</Files>",
                "apache",
            ),
            Fix(
                "litespeed",
                "LiteSpeed (.htaccess)",
                "<Files xmlrpc.php>\n    Require all denied\n</Files>",
                "apache",
            ),
            Fix(
                "nginx",
                "nginx (dentro de server {})",
                "location = /xmlrpc.php { deny all; }",
                "nginx",
            ),
            Fix(
                "wordpress",
                "WordPress (plugin ou functions.php: desliga os métodos autenticados)",
                "add_filter('xmlrpc_enabled', '__return_false');",
                "php",
            ),
        ),
        verify="curl -si https://seu-site/xmlrpc.php deve responder 403 ou 404.",
        effort="baixo",
        fix_group="cms",
        references=(
            WP_BRUTE_FORCE,
            WP_HARDENING,
            "https://cwe.mitre.org/data/definitions/307.html",
        ),
        cwe="CWE-307",
        owasp="A07:2021",
        cis=("4.8",),
        tags=("cms", "wordpress"),
    ),
    KBEntry(
        id="web.cms.usuarios",
        title="WordPress revela os nomes de usuário",
        category=Category.WEB,
        severity=Severity.LOW,
        summary="A API REST ou o endereço /?author=1 mostram os nomes de login dos usuários do site.",
        explanation=(
            "O WordPress publica em /wp-json/wp/v2/users os autores do site e redireciona /?author=1 "
            "para uma página com o nome de login. O projeto não considera esses nomes secretos, "
            "mas eles entregam metade do que é preciso para entrar: quem conhece o usuário só "
            "precisa adivinhar a senha."
        ),
        risk=(
            "Facilita tentativas de senha direcionadas contra wp-login.php e xmlrpc.php, e o "
            "phishing contra quem administra o site."
        ),
        steps=(
            "Use senhas longas e únicas e ative a autenticação em dois fatores para administradores.",
            "Limite as tentativas de login (plugin de segurança ou WAF).",
            "Se a lista de usuários não for necessária, retire a rota da API REST e bloqueie o "
            "/?author= (exemplos abaixo).",
        ),
        examples=(
            Fix(
                "wordpress",
                "WordPress (plugin ou functions.php: tira a rota de usuários da API para visitantes)",
                "add_filter('rest_endpoints', function ($endpoints) {\n"
                "    if (!is_user_logged_in()) {\n"
                "        unset($endpoints['/wp/v2/users'], $endpoints['/wp/v2/users/(?P<id>[\\d]+)']);\n"
                "    }\n"
                "    return $endpoints;\n"
                "});",
                "php",
            ),
            Fix(
                "apache",
                "Apache (.htaccess: bloqueia /?author=N)",
                "RewriteEngine On\nRewriteCond %{QUERY_STRING} ^author=\\d+ [NC]\nRewriteRule ^ - [F]",
                "apache",
            ),
            Fix(
                "nginx",
                "nginx (dentro de server {}: bloqueia /?author=N)",
                'if ($args ~* "^author=\\d+") { return 403; }',
                "nginx",
            ),
        ),
        verify=(
            "curl -s https://seu-site/wp-json/wp/v2/users não deve listar usuários e "
            "curl -sI 'https://seu-site/?author=1' não deve redirecionar para /author/."
        ),
        effort="baixo",
        fix_group="cms",
        references=(
            "https://developer.wordpress.org/rest-api/reference/users/",
            "https://make.wordpress.org/core/handbook/testing/reporting-security-vulnerabilities/",
            WP_BRUTE_FORCE,
        ),
        cwe="CWE-200",
        owasp="A07:2021",
        cis=("4.1", "6.3"),
        tags=("cms", "wordpress", "enumeracao"),
    ),
    KBEntry(
        id="web.cms.arquivos_padrao",
        title="Arquivos de instalação do CMS legíveis",
        category=Category.WEB,
        severity=Severity.LOW,
        summary="Arquivos que acompanham o CMS (readme.html, CHANGELOG.txt, joomla.xml) revelam o produto e, às vezes, a versão exata.",
        explanation=(
            "Esses arquivos vêm no pacote de instalação e não são necessários para o site "
            "funcionar. O CHANGELOG.txt do Drupal 7 e o joomla.xml dizem a versão exata instalada, "
            "o que permite a um atacante escolher a falha certa sem nenhuma tentativa."
        ),
        risk="Reconhecimento facilitado: quem procura sites vulneráveis filtra pela versão exibida.",
        steps=(
            "Bloqueie esses arquivos no servidor web (exemplos abaixo): atualizações podem recriá-los.",
            "Manter o CMS atualizado continua sendo a proteção de verdade.",
        ),
        examples=(
            Fix(
                "apache",
                "Apache (.htaccess)",
                '<FilesMatch "^(readme\\.html|license\\.txt|CHANGELOG\\.txt|joomla\\.xml)$">\n    Require all denied\n</FilesMatch>',
                "apache",
            ),
            Fix(
                "litespeed",
                "LiteSpeed (.htaccess)",
                '<FilesMatch "^(readme\\.html|license\\.txt|CHANGELOG\\.txt|joomla\\.xml)$">\n    Require all denied\n</FilesMatch>',
                "apache",
            ),
            Fix(
                "nginx",
                "nginx (dentro de server {})",
                r"location ~* /(readme\.html|license\.txt|CHANGELOG\.txt|joomla\.xml)$ { deny all; }",
                "nginx",
            ),
        ),
        verify="curl -si https://seu-site/readme.html (e o caminho apontado no achado) deve responder 403 ou 404.",
        effort="baixo",
        fix_group="cms",
        references=(WP_HARDENING, "https://cwe.mitre.org/data/definitions/200.html"),
        cwe="CWE-200",
        owasp="A05:2021",
        cis=("4.1",),
        tags=("cms", "divulgacao"),
    ),
    KBEntry(
        id="web.cms.uploads_listagem",
        title="Pasta de uploads do WordPress com listagem aberta",
        category=Category.WEB,
        severity=Severity.MEDIUM,
        summary="Qualquer pessoa pode navegar por /wp-content/uploads/ e ver tudo o que foi enviado ao site.",
        explanation=(
            "Com a listagem ligada, a pasta de mídia vira um catálogo: currículos, planilhas, "
            "comprovantes e cópias geradas por plugins aparecem mesmo sem nenhum link no site. "
            "Muita gente envia documentos internos achando que ficam escondidos."
        ),
        risk="Vazamento de documentos e dados pessoais enviados ao site, sem necessidade de login.",
        steps=(
            "Desligue a listagem de diretórios no servidor web (exemplos abaixo).",
            "Revise a pasta e retire o que não deveria ser público.",
            "Se havia dados pessoais, avalie a comunicação do incidente (LGPD).",
        ),
        examples=(
            Fix("apache", "Apache (.htaccess em wp-content/uploads)", "Options -Indexes", "apache"),
            Fix(
                "litespeed",
                "LiteSpeed (.htaccess em wp-content/uploads)",
                "Options -Indexes",
                "apache",
            ),
            Fix("nginx", "nginx (http, server ou location)", "autoindex off;", "nginx"),
            Fix(
                "iis",
                "IIS (web.config, em <system.webServer>)",
                '<directoryBrowse enabled="false" />',
                "xml",
            ),
        ),
        verify="Abra https://seu-site/wp-content/uploads/ no navegador: deve responder 403 ou 404.",
        effort="baixo",
        fix_group="cms",
        references=(WP_HARDENING, "https://cwe.mitre.org/data/definitions/548.html"),
        cwe="CWE-548",
        owasp="A05:2021",
        cis=("3.3", "4.1"),
        lgpd=True,
        tags=("cms", "wordpress", "exposicao"),
    ),
    KBEntry(
        id="web.cms.login",
        title="Tela de login do CMS aberta para a Internet",
        category=Category.WEB,
        severity=Severity.LOW,
        summary="A área administrativa do WordPress, Joomla ou Drupal pode ser acessada de qualquer lugar.",
        explanation=(
            "A tela de login do CMS fica no mesmo endereço em todos os sites, então robôs tentam "
            "senhas nela o dia inteiro. Isso é o padrão do produto; o problema é não haver nenhuma "
            "barreira além da senha. O EIGAN só lê a página: nunca tenta entrar."
        ),
        risk="Quem acerta a senha de um administrador controla o site inteiro e o conteúdo publicado.",
        steps=(
            "Restrinja a área administrativa por IP ou VPN, se a equipe tiver endereços fixos.",
            "Ative a autenticação em dois fatores para todos os administradores.",
            "Limite as tentativas de login (plugin de segurança, módulo ou WAF).",
        ),
        examples=(
            Fix(
                "apache",
                "Apache (restringir por IP, troque pela faixa da empresa)",
                "<Files wp-login.php>\n    Require ip 203.0.113.0/24\n</Files>",
                "apache",
            ),
            Fix(
                "nginx",
                "nginx (restringir por IP, troque pela faixa da empresa)",
                "location = /wp-login.php { allow 203.0.113.0/24; deny all; }",
                "nginx",
            ),
            Fix(
                "joomla",
                "Joomla (.htaccess dentro de administrator/)",
                "Require ip 203.0.113.0/24",
                "apache",
            ),
            Fix(
                "cloudflare",
                "Cloudflare Zero Trust (Access)",
                "Crie uma aplicação do Access para o caminho do login e exija autenticação + MFA.",
                "text",
            ),
        ),
        verify="De uma rede fora da lista liberada, a tela de login deve responder 403 ou pedir a autenticação extra.",
        effort="medio",
        fix_group="admin",
        references=(
            WP_BRUTE_FORCE,
            WP_HARDENING,
            "https://www.drupal.org/docs/administering-a-drupal-site/security-in-drupal",
        ),
        cwe="CWE-307",
        owasp="A07:2021",
        cis=("6.5", "6.3"),
        tags=("cms", "admin"),
    ),
)
