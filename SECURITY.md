# Política de Segurança

O EIGAN é uma ferramenta de segurança, então a segurança do próprio EIGAN vem
antes de qualquer recurso novo.

## Versões suportadas

O projeto está em pré-lançamento (`0.0.0`). Correções de segurança entram no
branch `main`, a única linha suportada até a primeira versão estável.

| Versão | Suportada |
|--------|-----------|
| `0.0.0` (pré-lançamento, `main`) | sim |

## Como reportar uma vulnerabilidade

Não abra issue pública.

1. Preferencial: [reporte privado de vulnerabilidade do GitHub][ghsa]
   (aba Security, "Report a vulnerability").
2. Alternativa: e-mail para **hoffmann3701@gmail.com** com o assunto
   `[EIGAN Security]`.

Inclua, se possível: descrição, versão, passos para reproduzir e impacto. Pedimos
que não divulgue publicamente até a correção.

### O que esperar

- Confirmação de recebimento em até 72 horas.
- Avaliação inicial em até 7 dias.
- Correção e divulgação coordenada conforme a gravidade, com crédito a quem
  reportou (salvo pedido de anonimato).

## Escopo

Em escopo, por exemplo:

- o painel aceitar requisições de outra origem, de outro host ou sem o token;
- leitura de arquivos fora das pastas permitidas pelo painel;
- execução de comandos a partir de dados do alvo (cabeçalhos, banners, arquivos
  de log, conteúdo de projetos);
- relatórios que executem script ao serem abertos (XSS no HTML);
- segredos encontrados aparecendo sem máscara em telas, relatórios ou logs;
- uma checagem que altere o alvo ou cause indisponibilidade.

Fora de escopo: problemas em sistemas que você auditou com o EIGAN (reporte ao
responsável por eles) e o uso do EIGAN contra alvos sem autorização.

## Modelo de segurança do painel

- Escuta somente em `127.0.0.1`.
- Token aleatório por execução, exigido em toda chamada da API.
- Cabeçalho `Host` conferido (contra DNS rebinding) e `Origin` conferido em
  métodos que alteram estado.
- Política de conteúdo restritiva (`default-src 'self'`) e nenhum recurso
  externo.

## Uso responsável

Use o EIGAN apenas em sistemas que você administra ou tem autorização por
escrito para avaliar. As checagens só observam, mas mesmo uma varredura de portas
sem autorização pode ser ilegal.

[ghsa]: https://docs.github.com/pt/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability
