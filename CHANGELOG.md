# Changelog

Mudanças relevantes do EIGAN. O formato segue o
[Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/) e o projeto usa
[Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [Não lançado]

## [0.0.0] - 2026-11-01 (pré-lançamento)

Reescrita completa. O EIGAN deixa de ser um agente de IA de red/blue/purple team e
passa a ser um auditor de segurança **somente blue team**: encontra
vulnerabilidades e falhas de configuração e explica como corrigir cada uma. A
versão continua `0.0.0` enquanto o produto é construído; o histórico da linha
anterior está no git.

### Adicionado

- Motor de regras determinístico (encadeamento para frente): fatos disparam
  checagens, checagens aprendem fatos novos, e cada decisão fica na linha do tempo
  com o motivo. Sem IA e sem chaves de API.
- Base de conhecimento em português para cada achado: explicação simples, risco,
  passos de correção, exemplos prontos (nginx, Apache, IIS, Windows, Linux e
  outros), como verificar, esforço e referências (CWE, OWASP Top 10, CIS, LGPD).
- Checagens para cinco tipos de alvo: site ou aplicação web, servidor ou rede,
  esta máquina (Windows e Linux), pasta de projeto e arquivos de log.
- Dados embarcados para funcionar offline: catálogo CISA KEV, faixas de versões
  vulneráveis, datas de fim de suporte e assinaturas de serviços.
- Inteligência sem IA: prioridade de 0 a 100 com prazos (P1 a P4), nota de
  postura de A+ a F, cenários de ataque que combinam achados, plano de correção
  agrupado por ação com ganhos rápidos e simulação da nota após as primeiras
  correções, resumo executivo, visão de conformidade e inventário.
- Histórico em SQLite com triagem por achado (aceito, falso positivo, corrigido),
  data da primeira ocorrência e comparação com a auditoria anterior.
- Painel web novo, local (`127.0.0.1`), com token por execução, progresso ao vivo,
  plano de correção, achados com filtros, cenários, pontos fortes, conformidade,
  inventário, linha do tempo, histórico com tendência e comparação.
- Relatórios em HTML, PDF executivo, JSON, SARIF 2.1.0 e CSV.
- Linha de comando em português: `auditar`, `checagens`, `explicar`,
  `historico`, `relatorio`, `comparar`, `painel`, com `--falhar-em` para
  pipelines de CI.
- Executáveis de arquivo único para Windows e Linux (PyInstaller), com ícone,
  teste de fumaça e workflow de build no GitHub Actions.
- CI em Windows e Linux (formatação, lint, tipos e testes) e imagem Docker para
  pipelines.

### Removido

- Toda a integração com provedores de IA, chaves de API e configurações
  relacionadas.
- Módulos ofensivos (red team, exploração, força bruta) e o orquestrador de
  ferramentas externas.
- API remota exposta na rede, plugins antigos, avaliações do agente e
  documentação da arquitetura anterior.
- Publicação automática no PyPI.
