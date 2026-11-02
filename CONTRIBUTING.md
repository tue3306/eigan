# Contribuindo com o EIGAN

Obrigado pelo interesse. O EIGAN é um auditor de segurança defensivo: encontra
problemas e explica como corrigir. Este guia mostra como preparar o ambiente,
rodar o portão de qualidade e escrever uma checagem nova.

Leia também o [Código de Conduta](CODE_OF_CONDUCT.md). Contribuições que
incentivem uso não autorizado ou técnicas ofensivas serão recusadas.

## Ambiente

Requer Python 3.11 ou mais novo.

```bash
git clone https://github.com/tue3306/eigan.git
cd eigan
python -m venv .venv
```

Ative o ambiente (`source .venv/bin/activate` no Linux, `.venv\Scripts\activate`
no Windows) e instale em modo de desenvolvimento:

```bash
pip install -e ".[dev]"
```

## Portão de qualidade

Um PR só está pronto quando os quatro passos passam:

```bash
ruff format --check src tests packaging
ruff check src tests packaging
mypy src
pytest -q
```

`ruff check` não confere formatação; rode os dois. Os testes são offline: sobem
servidores locais e nunca acessam alvos de terceiros.

## Escrevendo uma checagem

O guia completo está em [docs/escrevendo-checagens.md](docs/escrevendo-checagens.md).
Em resumo:

1. Crie a entrada na base de conhecimento (`KBEntry`) com explicação, risco,
   passos, exemplos de correção, como verificar e referências reais.
2. Escreva a função com `@check`, declarando o fato que ela consome e todos os
   achados que pode reportar.
3. Adicione testes com um servidor ou arquivo local que reproduza o caso
   vulnerável e o caso corrigido.

Regras que não se negociam:

- **Só observar.** Nada de explorar, forçar senha, causar indisponibilidade ou
  alterar dados do alvo.
- **Nada inventado.** CVE, faixa de versão, data de fim de suporte e chave de
  registro precisam de referência verificável.
- **Offline e sem IA.** Dados de apoio ficam em `src/eigan/data/` com origem e
  licença em `FONTES.md`.
- **Segredos mascarados** em telas, relatórios e logs.
- **Windows e Linux.** `pathlib`, nunca `shell=True`, comandos externos com lista
  de argumentos e tempo limite.

## Gerar o executável

```bash
pip install -e ".[build]"
python packaging/build.py
```

O executável e o arquivo `.sha256` ficam em `dist/`. O script também roda um
teste de fumaça (versão, auditoria de pasta com os cinco relatórios e o painel).

## Fluxo de PR

1. Crie um branch a partir de `main`.
2. Rode o portão de qualidade e atualize o `CHANGELOG.md` (seção "Não lançado").
3. Abra o PR pelo template, explicando o porquê da mudança.

## Bugs e vulnerabilidades

- Erro de funcionamento: abra uma issue pelo template.
- Vulnerabilidade no próprio EIGAN: não abra issue pública, siga o
  [SECURITY.md](SECURITY.md).
