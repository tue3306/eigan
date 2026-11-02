<!-- Obrigado por contribuir! PRs pequenos e focados são revisados mais rápido. -->

## O que muda e por quê

<!-- Descreva o porquê, não só o quê. Issue relacionada: Closes #___ -->

## Checklist

- [ ] `ruff format --check src tests packaging` e `ruff check src tests packaging` limpos
- [ ] `mypy src` sem erros
- [ ] `pytest -q` verde, com teste novo cobrindo a mudança
- [ ] `CHANGELOG.md` atualizado (seção "Não lançado")

## Regras do projeto (confirmo que o PR respeita)

- [ ] Checagens só observam: nada de explorar, forçar senha ou alterar o alvo
- [ ] Todo achado novo tem explicação, passos de correção e referência na base de conhecimento
- [ ] Nenhum CVE, versão ou referência inventada
- [ ] Segredos sempre mascarados em telas, relatórios e logs
- [ ] Sem `shell=True`, sem chave de API e sem dependência de serviço externo para funcionar
- [ ] Testes rodam offline (servidores locais, nada de alvos de terceiros)

## Como testar

```bash
```
