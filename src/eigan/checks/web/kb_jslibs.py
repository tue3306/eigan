"""Base de conhecimento das bibliotecas JavaScript vulneráveis (checagem ``web.jslibs``).

A explicação é uma só, para qualquer biblioteca: quem diz qual biblioteca, qual
versão e quais CVEs é a evidência do achado, montada a partir da base embarcada do
retire.js (``eigan/data/web_retire.json``).
"""

from __future__ import annotations

from ...core import kb
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Severity

kb.register(
    KBEntry(
        id="web.biblioteca.vulneravel",
        title="Biblioteca JavaScript com vulnerabilidades conhecidas",
        category=Category.WEB,
        severity=Severity.MEDIUM,
        summary="O site entrega ao navegador uma versão de biblioteca JavaScript com falhas públicas.",
        explanation=(
            "O site usa uma biblioteca de terceiros (jQuery, Bootstrap, AngularJS...) em uma versão "
            "para a qual existem vulnerabilidades publicadas. A versão foi identificada pelo "
            "endereço do script ou pelo conteúdo do arquivo e comparada com a base do retire.js, "
            "que vai embarcada no EIGAN. A evidência mostra a biblioteca, a versão, os CVEs e a "
            "versão mínima que corrige o que foi encontrado. A falha só é explorável se a aplicação "
            "usar a função afetada; mesmo assim, a correção mais segura é atualizar."
        ),
        risk=(
            "Essas falhas são públicas e muitas têm exploração documentada. A mais comum é o XSS: "
            "um atacante executa JavaScript no navegador de quem visita o site, rouba sessões, "
            "altera a página ou captura o que é digitado. Quando o CVE está no catálogo CISA KEV, "
            "já existe ataque real acontecendo com ele."
        ),
        steps=(
            "Localize onde a biblioteca é carregada: a evidência mostra o endereço do script.",
            "Atualize para a versão indicada na evidência ou mais recente e teste as páginas que "
            "usam a biblioteca, porque versões novas podem mudar o comportamento.",
            "Se a biblioteca veio de um plugin, tema ou CMS, atualize esse componente em vez de "
            "trocar o arquivo à mão.",
            "Se a evidência disser que não há versão corrigida (projeto encerrado), planeje a troca "
            "por uma alternativa mantida.",
            "Inclua a verificação de dependências no processo de publicação para a versão antiga "
            "não voltar.",
        ),
        examples=(
            Fix(
                "generico",
                "npm (projeto com package.json)",
                "npm install biblioteca@VERSAO_CORRIGIDA\nnpm audit",
                "bash",
            ),
            Fix(
                "generico",
                "HTML (script carregado de CDN, com versão fixa e SRI)",
                '<script src="https://cdn.exemplo.com/biblioteca@VERSAO_CORRIGIDA/biblioteca.min.js" '
                'integrity="sha384-HASH_DO_ARQUIVO" crossorigin="anonymous"></script>',
                "html",
            ),
            Fix(
                "generico",
                "retire.js (conferir os arquivos publicados)",
                "npx retire --path ./pasta-publica",
                "bash",
            ),
            Fix(
                "wordpress",
                "WordPress (WP-CLI: atualiza o núcleo, os plugins e os temas que trazem a biblioteca)",
                "wp core update\nwp plugin update --all\nwp theme update --all",
                "bash",
            ),
        ),
        verify=(
            "Abra o endereço do script e confira a versão no cabeçalho do arquivo ou, no console do "
            "navegador (F12), em jQuery.fn.jquery ou no objeto equivalente. Depois repita a "
            "auditoria: o achado deve sumir."
        ),
        effort="medio",
        fix_group="bibliotecas",
        references=(
            "https://top10.owasp.org/2021/A06_2021-Vulnerable_and_Outdated_Components",
            "https://retirejs.github.io/retire.js/",
            "https://github.com/RetireJS/retire.js",
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        ),
        cwe="CWE-1395",
        owasp="A06:2021",
        cis=("7.4", "16.4"),
        tags=("javascript", "dependencias", "cve"),
    ),
)
