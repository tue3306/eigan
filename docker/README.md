# docker/

Imagem do EIGAN para rodar auditorias em pipelines (CI/CD) e servidores sem
interface gráfica. Para uso no dia a dia, prefira o executável da página de
releases: ele abre o painel no navegador.

## Gerar a imagem

```bash
docker build -f docker/Dockerfile -t eigan .
```

## Exemplos

Auditar o código de um projeto (somente leitura):

```bash
docker run --rm -v "$PWD:/alvo:ro" eigan auditar /alvo --tipo projeto
```

Auditar um site de homologação que você administra e falhar o pipeline se houver
achado de risco alto ou crítico:

```bash
docker run --rm -v "$PWD/relatorios:/dados" eigan auditar https://staging.seu-dominio.com.br --sim --falhar-em alta
```

Os relatórios (HTML, PDF e JSON) ficam em `/dados/relatorios` dentro do
container; monte um volume em `/dados` para guardá-los.

## Observações

- O painel web escuta só em `127.0.0.1` por segurança, por isso a imagem é
  pensada para a linha de comando.
- A auditoria de "esta máquina" dentro de um container avalia o próprio
  container, não o servidor hospedeiro.
- Audite apenas sistemas que você administra ou tem autorização por escrito
  para avaliar.
