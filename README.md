<p align="center">
  <img src="packaging/eigan.png" alt="EIGAN" width="96" height="96">
</p>

<h1 align="center">EIGAN</h1>

<p align="center">
  <strong>Auditor de segurança blue team.</strong><br>
  Encontra vulnerabilidades e falhas de configuração em sites, servidores, na sua máquina,
  em código e em logs, e explica em português como corrigir cada uma.<br>
  Sem IA, sem chaves de API e sem depender de serviços externos durante a auditoria.
</p>

<p align="center">
  <img alt="Versão" src="https://img.shields.io/badge/vers%C3%A3o-0.0.0-1f4fd1">
  <img alt="Status" src="https://img.shields.io/badge/status-pr%C3%A9--lan%C3%A7amento-orange">
  <a href="LICENSE"><img alt="Licença" src="https://img.shields.io/badge/licen%C3%A7a-Apache--2.0-blue"></a>
  <img alt="Python" src="https://img.shields.io/badge/python-3.11%2B-3776ab">
  <img alt="Windows e Linux" src="https://img.shields.io/badge/Windows%20%7C%20Linux-suportados-2b8a3e">
  <a href="https://github.com/tue3306/eigan/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/tue3306/eigan/actions/workflows/ci.yml/badge.svg"></a>
</p>

> **Uso autorizado.** Audite apenas sistemas que você administra ou tem autorização por
> escrito para avaliar. As checagens só observam (nada de exploração, força bruta ou
> alteração de dados), mas até uma varredura de portas sem autorização pode ser ilegal.

> **Pré-lançamento (`0.0.0`).** O EIGAN está sendo construído; a numeração só sobe na
> primeira versão estável.

## O que o EIGAN faz

Você informa o alvo, o EIGAN descobre o que existe ali, verifica cada ponto e entrega:

- **os achados priorizados** (P1 a P4, com prazo sugerido) e uma **nota de postura** de A+ a F;
- **como corrigir cada um**: explicação simples, risco para o negócio, passo a passo,
  exemplo pronto de configuração (nginx, Apache, IIS, Windows, Linux...) e como confirmar
  que a correção funcionou;
- um **plano de correção** que agrupa achados na mesma ação, destaca os ganhos rápidos e
  mostra quanto a nota sobe depois das primeiras correções;
- **cenários de ataque**: combinações de achados que juntos viram um risco maior (por
  exemplo, versão vulnerável divulgada e serviço exposto na internet);
- **pontos fortes** (controles verificados e aprovados), conformidade com OWASP Top 10,
  CIS Controls, CWE e LGPD, inventário do que foi encontrado e comparação com a auditoria
  anterior.

### Tipos de alvo

| Alvo | Exemplos de verificação |
|------|-------------------------|
| **Site ou aplicação web** (`https://site.com.br`) | HTTPS e HSTS, cabeçalhos de segurança, CSP, cookies, CORS, arquivos sensíveis publicados (`.git`, `.env`, backups), painéis administrativos, versões divulgadas, bibliotecas JavaScript vulneráveis, certificado e TLS |
| **Servidor ou rede** (`servidor.local`, `10.0.0.5`, `10.0.0.0/24`) | portas e serviços expostos, bancos de dados sem senha, RDP sem NLA, SMBv1, SSH fraco, protocolos legados, versões com vulnerabilidade conhecida (CISA KEV) |
| **Domínio** (parte da auditoria de site) | SPF, DMARC, DKIM, DNSSEC, CAA, transferência de zona, subdomínios órfãos |
| **Esta máquina** (`local`) | atualizações, firewall, antivírus, criptografia de disco, contas, serviços, configurações de endurecimento do Windows e do Linux |
| **Pasta de projeto** | segredos no código, dependências com vulnerabilidade conhecida, Dockerfile e configurações inseguras |
| **Logs** (arquivo ou pasta) | força bruta, varreduras, ataques web, criação de contas e outros sinais de invasão |

### Como ele decide sem IA

Um motor de regras faz o trabalho de raciocínio: o alvo vira fatos ("o host responde na
porta 443", "o site usa WordPress"), cada fato dispara as checagens que se aplicam a ele, e
cada checagem pode descobrir fatos novos que disparam outras. Toda decisão aparece na linha
do tempo com o motivo. A explicação e a correção de cada achado vêm de uma base de
conhecimento escrita e revisada, com referências verificáveis. Detalhes em
[docs/arquitetura.md](docs/arquitetura.md).

## Começando

### Executável (recomendado)

> Os executáveis desta reescrita entram na release `v0.0.0` quando a construção terminar. A
> release publicada hoje ainda é a da versão antiga; até a troca, use o código-fonte.

Baixe o arquivo do seu sistema na [página de releases](https://github.com/tue3306/eigan/releases):

| Sistema | Arquivo |
|---------|---------|
| Windows 10/11 (64 bits) | `eigan-0.0.0-windows-x64.exe` |
| Linux (64 bits, glibc 2.17 ou mais novo) | `eigan-0.0.0-linux-x64` |

**Windows:** dê dois cliques. O painel abre no navegador. Como o executável ainda não tem
assinatura digital, o SmartScreen pode avisar: clique em "Mais informações" e "Executar
assim mesmo". Confira o arquivo pelo `.sha256` publicado junto.

**Linux:**

```bash
chmod +x eigan-0.0.0-linux-x64
./eigan-0.0.0-linux-x64
```

Para auditar "esta máquina" com todos os detalhes, rode como administrador (Windows) ou com
`sudo` (Linux); sem privilégios, as verificações que dependem deles aparecem como não
avaliadas, sem falso alarme.

### Pelo código-fonte

Requer Python 3.11 ou mais novo.

```bash
git clone https://github.com/tue3306/eigan.git
cd eigan
python -m venv .venv
```

Ative o ambiente (`source .venv/bin/activate` no Linux, `.venv\Scripts\activate` no
Windows) e instale:

```bash
pip install .
eigan
```

## Linha de comando

`eigan` sem argumentos abre o painel. Para uso no terminal:

```bash
eigan auditar https://staging.minhaempresa.com.br
eigan auditar 10.0.0.0/24 --perfil rapido
eigan auditar local
eigan auditar ./meu-projeto --tipo projeto
eigan auditar /var/log/nginx --tipo logs
eigan explicar web.hsts.ausente
eigan checagens --categoria web
eigan historico
eigan comparar <id-anterior> <id-atual>
eigan relatorio <id> --formatos pdf,html
```

Perfis: `rapido` (o essencial em minutos), `padrao` (recomendado) e `completo` (cobertura
máxima). Antes de auditar um site ou servidor, o EIGAN pede a confirmação de que você tem
autorização; em scripts, use `--sim`.

### Em pipelines de CI

`--falhar-em` faz o comando sair com código 1 quando houver achado aberto com a severidade
indicada ou maior. O relatório SARIF pode ir para o GitHub Code Scanning:

```yaml
- name: Auditoria de segurança
  run: eigan auditar . --tipo projeto --formatos sarif,html --saida relatorios --falhar-em alta
- uses: github/codeql-action/upload-sarif@v4
  if: always()
  with:
    sarif_file: relatorios/eigan-resultado.sarif
```

Códigos de saída: `0` sucesso, `1` achado acima do limite, `2` erro, `130` cancelado.

## Relatórios

| Formato | Para quê |
|---------|----------|
| HTML | relatório completo em um único arquivo, sem scripts, para abrir em qualquer navegador |
| PDF | relatório executivo (A4) para gestão e auditoria |
| JSON | resultado completo, para integrar com outras ferramentas |
| SARIF 2.1.0 | GitHub Code Scanning, Azure DevOps e outras plataformas |
| CSV | planilha de achados para acompanhamento |

## Privacidade e dados

- Nada é enviado para fora: sem telemetria, sem IA, sem consultas a APIs durante a auditoria.
- Segredos encontrados aparecem sempre mascarados em telas, relatórios e logs.
- Histórico, triagem, relatórios e logs ficam em `%LOCALAPPDATA%\EIGAN` (Windows) ou
  `~/.local/share/eigan` (Linux). Para outro local, defina `EIGAN_HOME`. Para um modo
  portátil, crie uma pasta `EIGAN-dados` ao lado do executável.
- O painel escuta só em `127.0.0.1`, com token por execução e proteção contra requisições
  de outros sites.

## Desenvolvimento

- [Arquitetura](docs/arquitetura.md)
- [Escrevendo checagens](docs/escrevendo-checagens.md)
- [Como contribuir](CONTRIBUTING.md)
- [Política de segurança](SECURITY.md)
- [Changelog](CHANGELOG.md)

## Licença

[Apache-2.0](LICENSE). Dados de terceiros embarcados e suas licenças estão em
[src/eigan/data/FONTES.md](src/eigan/data/FONTES.md).
