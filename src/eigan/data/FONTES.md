# Fontes dos dados embarcados

O EIGAN não consulta a Internet durante uma auditoria. Os arquivos desta pasta vão dentro do
pacote e do executável, e cada um registra no próprio JSON a fonte, a licença e a data em que
foi obtido. Esta tabela reúne tudo em um só lugar e guarda os avisos que as licenças exigem.

Para baixar os dados de novo, somente quando você pedir: `eigan atualizar`.

| Arquivo | Conteúdo | Fonte | Licença | Obtido em |
|---|---|---|---|---|
| `kev.json` | Vulnerabilidades com exploração confirmada | [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | CC0 1.0 | ver campo `versao` |
| `code_advisories.json` | Avisos de dependências de código, com títulos e resumos traduzidos ou adaptados | [GitHub Advisory Database](https://github.com/github/advisory-database), via [OSV.dev](https://osv.dev) | CC BY 4.0 | 2026-11-01 |
| `dns_sufixos.json` | Sufixos públicos de domínio, convertidos para JSON | [Public Suffix List](https://publicsuffix.org/list/public_suffix_list.dat), Mozilla Foundation e colaboradores | MPL-2.0 | 2026-11-01 |
| `dns_takeover.json` | Serviços sujeitos a sequestro de subdomínio; só os marcados como vulneráveis e com CNAME conhecido | [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz), EdOverflow e colaboradores, e documentação do Microsoft Azure | CC BY 4.0 | 2026-11-02 |
| `logs_scanners.json` | User-Agents de ferramentas de varredura | [OWASP Core Rule Set](https://github.com/coreruleset/coreruleset/blob/main/rules/scanners-user-agents.data) | Apache-2.0 | 2026-11-01 |
| `logs_webshells.json` | Nomes de arquivo comuns de webshells | [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content) | MIT | 2026-11-01 |
| `tls_suites.json` | Catálogo de suítes TLS | [Registro da IANA](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4) | CC0 1.0 | 2026-11-01 |
| `web_retire.json` | Bibliotecas JavaScript com versões vulneráveis | [retire.js](https://github.com/RetireJS/retire.js) | Apache-2.0 | 2026-11-01 |
| `host_eol.json` | Datas de fim de suporte de sistemas operacionais | Curadoria do EIGAN a partir das páginas oficiais dos fabricantes, listadas em `_fontes` | Apache-2.0 | 2026-11-01 |
| `net_ports.json` | Portas relevantes para segurança | Curadoria do EIGAN com nomes do [registro da IANA](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml); não deriva do nmap-services | Apache-2.0 | 2026-11-01 |
| `net_vulns.json` | Faixas de versão vulneráveis de serviços de rede | Curadoria do EIGAN a partir dos avisos dos fabricantes e do [registro CVE](https://www.cve.org/), com os links em cada regra | Apache-2.0 | 2026-11-02 |
| `web_cms.json` | Versões, suporte e CVEs de WordPress, Joomla e Drupal | Curadoria do EIGAN a partir do [NVD](https://nvd.nist.gov/) e das páginas oficiais de cada projeto, listadas em cada item | Apache-2.0 | 2026-11-02 |

Nas linhas de curadoria, o EIGAN compila fatos públicos e escreve os próprios textos; nenhum texto
de terceiros foi copiado.

## Avisos exigidos pelas licenças

### CISA KEV Catalog

Distribuído sob a licença Creative Commons 0 1.0. O uso destes dados não implica aprovação da CISA
ou do DHS, nem autoriza o uso dos logotipos dessas instituições.

### GitHub Advisory Database (CC BY 4.0)

Dados da [GitHub Advisory Database](https://github.com/github/advisory-database), licenciados sob
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Alterações feitas pelo EIGAN: seleção de
campos, conversão de formato e títulos e resumos traduzidos ou adaptados para o português.

### can-i-take-over-xyz (CC BY 4.0)

Adaptado de [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz), de EdOverflow e
colaboradores, licenciado sob [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Alterações
feitas pelo EIGAN: seleção dos serviços marcados como vulneráveis e com CNAME conhecido, campos
renomeados e restrições de formato acrescentadas a partir da documentação dos provedores.

### Public Suffix List (MPL-2.0)

`dns_sufixos.json` é uma modificação da Public Suffix List (convertida para JSON, regras IDN em
A-label) e continua sob a [Mozilla Public License 2.0](https://mozilla.org/MPL/2.0/). A forma original
está em <https://publicsuffix.org/list/public_suffix_list.dat>. O restante do EIGAN não fica sujeito
à MPL por causa deste arquivo.

### retire.js (Apache-2.0)

Copyright 2018 Erlend Oftedal. Licensed under the Apache License, Version 2.0. As alterações feitas
pelo EIGAN estão descritas no campo `alteracoes` de `web_retire.json`.

### OWASP Core Rule Set (Apache-2.0)

`logs_scanners.json` deriva de `rules/scanners-user-agents.data`, do OWASP Core Rule Set, sob a
Apache License, Version 2.0. Alteração feita pelo EIGAN: lista convertida para JSON.

### SecLists (MIT)

`logs_webshells.json` deriva das listas `CommonBackdoors` do SecLists.

```text
MIT License

Copyright (c) 2018 Daniel Miessler

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
