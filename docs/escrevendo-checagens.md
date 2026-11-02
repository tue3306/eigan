# Escrevendo checagens

Uma checagem do EIGAN é uma função Python registrada com `@check`. Ela consome um
**fato** (ex.: "este endereço fala HTTP"), faz a verificação e pode:

- **reportar achados** (`ctx.report`) — cada achado aponta para uma entrada da base de
  conhecimento, que explica o problema e ensina a corrigir;
- **registrar pontos fortes** (`ctx.passed`) — controles verificados e aprovados;
- **ensinar fatos novos** ao motor (`ctx.add_fact`, `ctx.add_http_service`,
  `ctx.add_tls_service`, `ctx.add_tech`) — que disparam outras checagens.

O motor de regras (`core/engine.py`) faz o encadeamento: cada fato novo dispara as
checagens que o consomem. É assim que o EIGAN "decide" o que fazer sem IA — e cada
decisão aparece na linha do tempo com o motivo.

O módulo de referência é [`src/eigan/checks/web/transport.py`](../src/eigan/checks/web/transport.py).

## Regras do projeto

1. **Defensivo e não intrusivo.** Só leitura e requisições que um navegador, um cliente
   comum ou um handshake fariam. Nada de exploração, força bruta, adivinhação de senha,
   DoS ou payload que altere dados. Exceção aceita: verificações anônimas padrão de
   auditoria (ex.: FTP anônimo, Redis sem senha respondendo `PING`), sempre só leitura.
2. **Offline e sem IA.** Nenhuma chamada a APIs durante a auditoria. Dados de apoio
   (catálogos, assinaturas, faixas de versão) ficam embarcados em `src/eigan/data/`
   com a origem e a licença registradas em `src/eigan/data/FONTES.md`.
3. **Nada inventado.** CVE, faixa de versão, data de fim de suporte, caminho de registro:
   tudo com referência verificável no campo `references` da base.
4. **Português do Brasil** em todo texto visível (títulos, explicações, passos).
   Identificadores técnicos (cabeçalhos, chaves de registro, comandos) ficam como são.
5. **Funciona em Windows e Linux.** Use `pathlib`, nunca `shell=True`; comandos externos
   só com lista de argumentos, tempo limite e tratamento de ausência.
6. **Falso positivo é defeito.** Confirme pelo conteúdo (assinatura), não só pelo código
   HTTP. Páginas "soft 404" (respondem 200 para tudo) precisam ser descartadas.
7. **Segredos nunca aparecem inteiros.** O contexto mascara a evidência
   automaticamente (`core/redact.py`); use `redact.mask()` em textos montados à mão.

## Anatomia

```python
from ...core import facts, kb
from ...core.context import CheckContext
from ...core.kb import Fix, KBEntry
from ...core.models import Category, Confidence, Fact, Severity
from ...core.registry import check

kb.register(
    KBEntry(
        id="web.exemplo.problema",          # familia.assunto.problema (snake_case, sem acento)
        title="Título curto do achado",
        category=Category.WEB,
        severity=Severity.MEDIUM,          # severidade padrão (ctx.report pode ajustar)
        summary="Uma frase: o que está errado.",
        explanation="O que é e por que é um problema, em linguagem simples.",
        risk="O que um atacante consegue fazer e o impacto no negócio.",
        steps=("Passo 1.", "Passo 2."),
        examples=(Fix("nginx", "nginx", "server_tokens off;", "nginx"),),
        verify="Como confirmar que a correção funcionou.",
        effort="baixo",                     # baixo | medio | alto
        fix_group="divulgacao",            # ver FIX_GROUPS em core/kb.py
        references=("https://...",),
        cwe="CWE-200", owasp="A05:2021", cis=("4.1",), lgpd=False,
    ),
)

@check(
    id="web.exemplo",
    name="Nome curto exibido no painel",
    category=Category.WEB,
    consumes=facts.HTTP_SERVICE,
    description="O que esta checagem verifica.",
    findings=("web.exemplo.problema",),     # TODOS os ids que ela pode reportar
    facts=(facts.TECH,),                   # tipos de fato que ela pode produzir
)
def check_exemplo(ctx: CheckContext, fact: Fact) -> None:
    resp = ctx.http.get(fact.data["url"])
    if resp is None:
        return
    if "problema" in resp.text:
        ctx.report("web.exemplo.problema", asset=fact.data["url"], evidence="...",
                   confidence=Confidence.CONFIRMED)
    else:
        ctx.passed("web.exemplo", "Sem o problema", fact.data["url"])
```

Depois, importe o módulo no `__init__.py` do subpacote da família.

## Contexto da checagem (`CheckContext`)

| Membro | Uso |
|---|---|
| `ctx.http` | `get/head/options/post(url, headers=, body=, timeout=, max_bytes=, follow_redirects=)` → `Response` ou `None`. `Response`: `status`, `headers`, `header(n)`, `headers_all(n)`, `text`, `body`, `content_type`, `location`, `is_html`, `url`, `redirects`. |
| `ctx.report(id, asset=, title=, severity=, evidence=, details=, confidence=, cves=, kev=, discriminator=, tech=)` | Reporta um achado. `discriminator` separa achados do mesmo tipo no mesmo ativo (ex.: nome do cookie). `tech` escolhe o exemplo de correção (`nginx`, `iis`...). |
| `ctx.passed(control, texto, asset)` | Ponto forte verificado. |
| `ctx.add_fact(tipo, chave, motivo, **dados)` | Ensina um fato (ver `core/facts.py`). |
| `ctx.add_http_service(url, motivo)` / `ctx.add_tls_service(host, porta, motivo)` / `ctx.add_tech(host, nome, version=, kind=, evidence=)` | Atalhos padronizados. |
| `ctx.facts(tipo)` / `ctx.techs(host)` | Lê o que já se sabe. |
| `ctx.memo(chave, fábrica)` | Calcula algo uma vez por auditoria (ex.: linha de base de soft 404). |
| `ctx.settings` | Perfil (`quick`, `deep`), tempos limite, portas, limites de arquivos. |
| `ctx.check_cancel()` | Chame dentro de laços longos (respeita o botão Cancelar). |
| `ctx.log(texto)` | Linha no registro de atividade. |

Apoios do núcleo: `core.netutil` (resolução, `tcp_connect`, `exchange`, exposição de IP),
`core.versions` (`compare`, `in_range`, `extract_version`), `core.vulndb` (`is_kev`,
`kev_entry`), `eigan.data.load_json`.

## Convenções

- **Ids de achado:** `web.*`, `tls.*`, `dns.*`, `net.*`, `host.win.*`, `host.linux.*`,
  `code.*`, `logs.*`.
- **Ativo (`asset`):** origem `https://host/` para problemas do site todo, URL completa para
  um recurso, `host:porta` para TLS, `host:porta/tcp` para serviços, domínio para DNS,
  `caminho/relativo:linha` para código, caminho do arquivo para logs.
- **Tecnologias (`tech`, `Fix.tech`):** minúsculas — `nginx`, `apache`, `iis`, `litespeed`,
  `tomcat`, `express`, `php`, `aspnet`, `django`, `flask`, `laravel`, `spring`, `wordpress`,
  `joomla`, `drupal`, `cloudflare`, `openssh`, `windows`, `linux`, `generico`.
- **Severidade:** crítica = comprometimento direto e fácil (banco sem senha na Internet,
  versão no CISA KEV, chave privada exposta); alta = fraqueza séria (SMBv1, `.env` exposto,
  certificado vencido); média = falta de proteção importante (HSTS, CSP, TLS 1.0);
  baixa = defesa em profundidade (versão do servidor divulgada); informativo = inventário.

## Testes

Cada checagem tem testes em `tests/checks/` sem Internet: use a fixture `serve` (servidor
HTTP/HTTPS local programável) e `helpers.run_check(id_da_checagem, fato)`. Para checagens
de sistema, isole o acesso ao SO (registro, arquivos, comandos) em funções pequenas e
substitua-as com `monkeypatch` — os testes precisam passar em Windows e Linux.
