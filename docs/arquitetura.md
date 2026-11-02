# Arquitetura do EIGAN

O EIGAN é um auditor de segurança defensivo (blue team). Ele observa um alvo,
encontra problemas de configuração e vulnerabilidades conhecidas e explica, em
português, como corrigir cada um. Não usa IA nem chaves de API: as decisões vêm de
um motor de regras e de uma base de conhecimento escrita à mão, e tudo funciona
offline.

## Fluxo de uma auditoria

```
alvo digitado
  └─ core/target.py      identifica o tipo (site, servidor, esta máquina, pasta, logs)
      └─ fatos iniciais
          └─ core/engine.py   motor de regras (encadeamento para frente)
              ├─ checagens consomem fatos e reportam achados e pontos fortes
              └─ checagens aprendem fatos novos, que disparam outras checagens
                  └─ ScanResult (achados, pontos fortes, fatos, linha do tempo)
                      └─ intel/  exposição, triagem, cenários, prioridade, nota,
                                 plano de correção, narrativa, conformidade
                          └─ storage/db.py  histórico em SQLite
                              └─ painel, linha de comando e relatórios
```

### Motor de regras (`core/engine.py`)

Cada checagem declara o tipo de fato que consome (`consumes`). O alvo vira um ou
mais fatos iniciais; o motor põe na fila as checagens interessadas em cada fato
novo. Uma checagem pode:

- reportar achados (`ctx.report`), sempre ligados a uma entrada da base de
  conhecimento;
- registrar pontos fortes (`ctx.passed`), controles verificados e aprovados;
- ensinar fatos novos (`ctx.add_fact`, `ctx.add_http_service`, `ctx.add_tech`...),
  por exemplo "a porta 8443 fala HTTPS" ou "este site usa WordPress".

Cada decisão do motor entra na linha do tempo com o motivo, então dá para ver por
que cada verificação rodou. O motor roda checagens em paralelo (com limite por
host), respeita o perfil escolhido (rápida, padrão, completa), aplica tetos de
fatos para alvos grandes e pode ser cancelado a qualquer momento mantendo o
resultado parcial.

### Checagens (`checks/`)

| Pasta  | O que avalia |
|--------|--------------|
| `web`  | cabeçalhos de segurança, cookies, CORS, arquivos expostos, painéis, versões divulgadas, conteúdo misto |
| `net`  | portas e serviços expostos, TLS (protocolos, cifras, certificado), SSH, RDP, SMB, bancos de dados abertos |
| `dns`  | SPF, DMARC, DKIM, DNSSEC, CAA, transferência de zona, subdomínios órfãos |
| `host` | a própria máquina: atualizações, firewall, antivírus, contas, serviços, configurações de Windows e Linux |
| `code` | pastas de projeto: segredos no código, dependências com vulnerabilidade conhecida, configurações inseguras |
| `logs` | arquivos de log: força bruta, varreduras, ataques web e outros sinais de invasão |

Todas seguem as regras de [escrevendo-checagens.md](escrevendo-checagens.md):
não intrusivas, offline, nada inventado, textos em português e segredos sempre
mascarados.

### Base de conhecimento (`core/kb.py`)

Cada tipo de achado tem uma entrada com título, explicação simples, risco para o
negócio, passos de correção, exemplos prontos de configuração (nginx, Apache,
IIS, Windows, Linux...), como verificar a correção, esforço, referências e
mapeamentos (CWE, OWASP Top 10, CIS, LGPD). O teste
`tests/checks/test_registry.py` garante que nenhuma checagem reporte um achado
sem entrada na base.

### Dados embarcados (`data/`)

Catálogos usados offline: CISA KEV (vulnerabilidades exploradas), faixas de
versão vulneráveis, datas de fim de suporte, assinaturas de serviços e de
subdomínios órfãos. A origem e a licença de cada arquivo estão em
`src/eigan/data/FONTES.md`.

## Inteligência sem IA (`intel/`)

| Módulo | Função |
|--------|--------|
| `exposure.py` | classifica onde o ativo está: internet, rede interna, máquina local, código, logs |
| `scoring.py` | prioridade de 0 a 100 por achado (severidade, confiança, exposição, KEV) e a nota de postura de A+ a F |
| `correlation.py` | cenários de ataque: combinações de achados que juntos viram um risco maior |
| `remediation.py` | plano de correção agrupado por ação, com exemplos mesclados por tecnologia e ganhos rápidos |
| `narrative.py` | resumo executivo em linguagem simples |
| `compliance.py` | visão por OWASP Top 10, CIS, CWE e LGPD |
| `inventory.py` | inventário do que foi descoberto (serviços, tecnologias, certificados...) |
| `diff.py` | comparação com a auditoria anterior do mesmo alvo: novos, corrigidos, persistentes |

### Prioridade e nota

- Prioridade = peso da severidade × confiança × exposição. CVE no catálogo KEV
  recebe piso alto; achado que participa de um cenário de ataque ganha bônus.
  Faixas: P1 (75 ou mais, corrigir em 72 horas), P2 (50, em 7 dias), P3 (25, em
  30 dias), P4 (planejar na próxima janela).
- Nota de postura = 100 menos penalidades por achado aberto, com retorno
  decrescente para repetições do mesmo problema. Tetos: KEV limita a F, crítico a
  D, alto a C. A+ só sem achados abertos. Achados marcados como risco aceito,
  falso positivo ou corrigido não contam.
- O plano de correção mostra quanto a nota sobe ao concluir as três primeiras
  ações.

## Persistência (`storage/db.py`)

SQLite com WAL, uma conexão por operação. Guarda cada auditoria (JSON completo e
resumo), a triagem por alvo e impressão digital do achado, e a data em que cada
achado apareceu pela primeira vez. A triagem sobrevive entre auditorias: um
achado marcado como corrigido que reaparece volta a ficar aberto, com aviso.

Local dos dados: `%LOCALAPPDATA%\EIGAN` no Windows, `~/.local/share/eigan` no
Linux, ou a pasta definida em `EIGAN_HOME`.

## Painel (`panel/`)

Servidor HTTP da biblioteca padrão, somente em `127.0.0.1`.

- Token aleatório por execução, exigido em toda chamada da API (cabeçalho
  `X-EIGAN-Token`).
- Cabeçalho `Host` conferido (bloqueia DNS rebinding) e `Origin` conferido em
  métodos que alteram estado.
- CSP restritiva (`default-src 'self'`), sem scripts de terceiros nem fontes
  externas; a interface funciona sem internet.
- Arquivos estáticos servidos de uma lista fixa.
- Auditorias rodam em threads (até 2 ao mesmo tempo) e transmitem o progresso por
  Server-Sent Events.

A interface é JavaScript puro (módulos ES), sem framework e sem `innerHTML` para
dados vindos do alvo.

## Relatórios (`reports/`)

HTML (arquivo único, sem JavaScript), PDF executivo (A4), JSON completo, SARIF
2.1.0 (para GitHub Code Scanning e afins) e CSV dos achados. Gravação atômica.

## Linha de comando (`cli/`)

`eigan` sem argumentos abre o painel. Comandos: `auditar`, `checagens`,
`explicar`, `historico`, `relatorio`, `comparar`, `painel`, `versao`. Códigos de
saída: 0 sucesso, 1 achado acima do limite de `--falhar-em`, 2 erro, 130
cancelado.

## Executáveis (`packaging/`)

PyInstaller em arquivo único, com o painel, a base e os dados embutidos.
`python packaging/build.py` gera e testa o executável do sistema atual. O
workflow `executaveis.yml` faz o mesmo no GitHub Actions para Windows e Linux.
