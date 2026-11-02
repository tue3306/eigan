"""Atualização dos catálogos de dados, somente a pedido (``eigan atualizar`` ou o painel).

A auditoria nunca baixa nada: ela lê os catálogos embarcados ou, se existir e valer
mais, a cópia baixada por este módulo em ``<dados do EIGAN>/dados/``. Cada fonte é
convertida para o formato exato do arquivo embarcado, validada (estrutura, tamanho e
contagem mínima) e só então gravada, de forma atômica. Uma fonte com falha mantém os
dados anteriores e não impede as outras.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import unicodedata
import urllib.error
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from .. import data
from ..data import formato
from . import baixar

log = logging.getLogger(__name__)

#: dias sem atualizar a partir dos quais o EIGAN avisa que o catálogo está velho
LIMITE_IDADE_DIAS = 30
TIMEOUT = 60.0

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
RETIRE_URL = (
    "https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v5.json"
)
SUFIXOS_URL = "https://publicsuffix.org/list/public_suffix_list.dat"

_KEV_CAMPOS = ["fornecedor", "produto", "nome", "adicionado", "ransomware"]
_TEXTO_MAX = 600
#: campos do retire.js que o EIGAN não usa (ver o campo ``alteracoes`` do arquivo embarcado)
_RETIRE_BIBLIOTECA_DESCARTADA = ("licenses", "bowername", "basePurl")
_RETIRE_EXTRATOR_DESCARTADO = ("func", "ast")
_VERSAO_MAX = 80
#: segundos para baixar uma fonte inteira (o TIMEOUT vale para cada leitura)
TEMPO_TOTAL = 120.0

#: curadoria manual: não há fonte pública estável, então só mudam com uma nova versão do EIGAN
MANUAIS: dict[str, str] = {
    "host_eol.json": "Fim de suporte de sistemas operacionais",
    "net_vulns.json": "Faixas de versão vulneráveis de serviços de rede",
    "net_ports.json": "Portas relevantes para segurança",
    "web_cms.json": "Versões e CVEs de WordPress, Joomla e Drupal",
    "dns_takeover.json": "Serviços sujeitos a sequestro de subdomínio",
    "tls_suites.json": "Suítes TLS (registro da IANA)",
}
_TITULOS = {
    "kev.json": "CISA KEV (vulnerabilidades exploradas)",
    "web_retire.json": "retire.js (bibliotecas JavaScript vulneráveis)",
    "dns_sufixos.json": "Lista de sufixos públicos",
}


class FalhaAtualizacao(ValueError):
    """Dados baixados rejeitados (estrutura, tamanho ou quantidade fora do esperado)."""


# -- conversores ----------------------------------------------------------------------------


def _limpo(valor: Any, limite: int) -> str:
    """Texto de fora sem caracteres de controle e formatação (ESC, BEL...) e com tamanho limitado.

    O que vem da rede é gravado nos catálogos e impresso no terminal; uma sequência de
    escape ali poderia apagar a tela ou trocar o título da janela.
    """
    texto = " ".join(str(valor or "").split())
    return "".join(c for c in texto if unicodedata.category(c) not in ("Cc", "Cf"))[:limite]


def _texto(valor: Any) -> str:
    return _limpo(valor, _TEXTO_MAX)


def _json(bruto: bytes) -> Any:
    try:
        return json.loads(bruto.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise FalhaAtualizacao("o arquivo baixado não é um JSON válido") from exc


def converter_kev(bruto: bytes, _hoje: date) -> dict[str, Any]:
    """Catálogo da CISA -> formato de ``kev.json``."""
    feed = _json(bruto)
    lista = feed.get("vulnerabilities") if isinstance(feed, dict) else None
    if not isinstance(lista, list):
        raise FalhaAtualizacao("o catálogo da CISA não traz a lista 'vulnerabilities'")
    linhas: list[tuple[str, list[Any]]] = []
    for item in lista:
        if not isinstance(item, dict):
            continue
        cve = str(item.get("cveID") or "").strip().upper()
        if not cve.startswith("CVE-"):
            continue
        ransomware = 1 if str(item.get("knownRansomwareCampaignUse")) == "Known" else 0
        linhas.append(
            (
                cve,
                [
                    _texto(item.get("vendorProject")),
                    _texto(item.get("product")),
                    _texto(item.get("vulnerabilityName")),
                    _limpo(item.get("dateAdded"), 10),
                    ransomware,
                ],
            )
        )
    linhas.sort(key=lambda par: par[1][3], reverse=True)  # mais recentes primeiro (estável)
    return {
        "fonte": "CISA Known Exploited Vulnerabilities Catalog",
        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "licenca": "CC0 1.0 (https://github.com/cisagov/kev-data/blob/develop/LICENSE)",
        "versao": _limpo(feed.get("catalogVersion"), _VERSAO_MAX),
        "publicado": _limpo(feed.get("dateReleased"), 32),
        "campos": _KEV_CAMPOS,
        "itens": dict(linhas),
    }


def converter_retire(bruto: bytes, hoje: date) -> dict[str, Any]:
    """Repositório do retire.js v5 -> formato de ``web_retire.json``."""
    repo = _json(bruto)
    if not isinstance(repo, dict):
        raise FalhaAtualizacao("o repositório do retire.js não é um objeto JSON")
    bibliotecas: dict[str, Any] = {}
    for nome, bruta in repo.items():
        if nome == "retire-example" or not isinstance(bruta, dict):
            continue
        biblioteca = {k: v for k, v in bruta.items() if k not in _RETIRE_BIBLIOTECA_DESCARTADA}
        extratores = biblioteca.get("extractors")
        if isinstance(extratores, dict):
            biblioteca["extractors"] = {
                k: v for k, v in extratores.items() if k not in _RETIRE_EXTRATOR_DESCARTADO
            }
        bibliotecas[nome] = biblioteca
    return {
        "fonte": "retire.js: repositório de bibliotecas JavaScript vulneráveis (projeto RetireJS/retire.js)",
        "url": RETIRE_URL,
        "projeto": "https://github.com/RetireJS/retire.js",
        "licenca": "Apache-2.0",
        "licenca_url": "https://www.apache.org/licenses/LICENSE-2.0",
        "aviso": "Copyright 2018 Erlend Oftedal. Licensed under the Apache License, Version 2.0.",
        "atualizado": hoje.isoformat(),
        "alteracoes": (
            "Arquivo minificado pelo EIGAN. Removidos a entrada de exemplo retire-example e os "
            "campos func, ast, licenses, bowername e basePurl, que o EIGAN não usa. Padrões e "
            "faixas de versão sem alteração. Limitação: sem os extratores func e ast, bibliotecas "
            "reconhecidas só por eles (por exemplo axios, nextjs, DOMPurify e tinyMCE minificados) "
            "só são achadas pelo endereço ou por padrões de conteúdo; o EIGAN acrescenta no código "
            "um extrator para o lodash minificado e o padrão /npm/pacote@versao/ das CDNs."
        ),
        "bibliotecas": bibliotecas,
    }


def _a_label(regra: str) -> str | None:
    """Regra da lista em A-label (punycode); ``None`` se o codec IDNA 2003 não converte."""
    prefixo = ""
    for marca in ("!", "*."):
        if regra.startswith(marca):
            prefixo, regra = marca, regra[len(marca) :]
            break
    rotulos: list[str] = []
    for rotulo in regra.split("."):
        if not rotulo.isascii():
            try:
                rotulo = rotulo.encode("idna").decode("ascii")
            except UnicodeError:
                return None
        rotulos.append(rotulo.lower())
    return prefixo + ".".join(rotulos)


def converter_sufixos(bruto: bytes, hoje: date) -> dict[str, Any]:
    """``public_suffix_list.dat`` -> formato de ``dns_sufixos.json``."""
    try:
        texto = bruto.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise FalhaAtualizacao("a lista de sufixos não está em UTF-8") from exc
    secoes: dict[str, set[str]] = {"icann": set(), "privado": set()}
    atual: str | None = None
    versao = commit = ""
    ignoradas: list[str] = []
    for linha in texto.splitlines():
        linha = linha.strip()
        if not linha:
            continue
        if linha.startswith("//"):
            if "===BEGIN ICANN DOMAINS===" in linha:
                atual = "icann"
            elif "===BEGIN PRIVATE DOMAINS===" in linha:
                atual = "privado"
            elif "===END " in linha:
                atual = None
            elif linha.startswith("// VERSION:"):
                versao = _limpo(linha.split(":", 1)[1], _VERSAO_MAX)
            elif linha.startswith("// COMMIT:"):
                commit = _limpo(linha.split(":", 1)[1], 40)
            continue
        if atual is None:
            continue
        regra = unicodedata.normalize("NFC", linha.split()[0])
        convertida = _a_label(regra)
        if convertida is None:
            ignoradas.append(regra)
        else:
            secoes[atual].add(convertida)
    omitidas = ", ".join(sorted(ignoradas)[:20]) if ignoradas else "nenhuma"
    return {
        "fonte": "Public Suffix List — Mozilla Foundation e colaboradores",
        "url": SUFIXOS_URL,
        "licenca": (
            "MPL-2.0 (https://mozilla.org/MPL/2.0/). Este arquivo é uma Modificação da lista "
            "(convertida para JSON, regras IDN em A-label/punycode) e continua sob a MPL-2.0."
        ),
        "versao": f"{versao} (commit {commit})" if commit else versao,
        "atualizado": hoje.isoformat(),
        "obs": (
            "Regras da seção ICANN ('icann') e da seção de domínios privados ('privado'), no "
            "formato da lista: '*.' = curinga, '!' = exceção. Usadas para achar o domínio "
            "organizacional (www.exemplo.com.br -> exemplo.com.br) e para reconhecer nomes sob "
            "plataformas compartilhadas (ex.: github.io). Regras IDN que o codec IDNA 2003 do "
            f"Python não converte ficaram de fora: {omitidas}."
        ),
        "icann": sorted(secoes["icann"]),
        "privado": sorted(secoes["privado"]),
    }


# -- serialização (idêntica à dos arquivos embarcados) --------------------------------------


def _compacto(dados: dict[str, Any]) -> str:
    return json.dumps(dados, ensure_ascii=False, separators=(",", ":"))


def _serializar_sufixos(dados: dict[str, Any], largura: int = 95) -> str:
    partes = []
    for chave, valor in dados.items():
        if isinstance(valor, list):
            linhas: list[str] = []
            atual = ""
            for i, item in enumerate(valor):
                token = json.dumps(item, ensure_ascii=False) + ("," if i < len(valor) - 1 else "")
                if atual and len(atual) + 1 + len(token) > largura:
                    linhas.append(atual)
                    atual = token
                else:
                    atual = f"{atual} {token}" if atual else token
            linhas.append(atual)
            corpo = "[\n" + "\n".join("    " + linha for linha in linhas) + "\n  ]"
        else:
            corpo = json.dumps(valor, ensure_ascii=False)
        partes.append(f"  {json.dumps(chave)}: {corpo}")
    return "{\n" + ",\n".join(partes) + "\n}\n"


# -- validação -------------------------------------------------------------------------------


def _validar_kev(dados: dict[str, Any]) -> None:
    itens = dados.get("itens")
    if not isinstance(itens, dict) or len(itens) < 1000:
        raise FalhaAtualizacao("o catálogo KEV tem menos de 1000 itens")
    if not data.data_do_catalogo("kev.json", dados):
        raise FalhaAtualizacao("o catálogo KEV não informa a data de publicação")
    problema = formato.problema("kev.json", dados)
    if problema:
        raise FalhaAtualizacao(f"catálogo KEV: {problema}")


def _validar_retire(dados: dict[str, Any]) -> None:
    bibliotecas = dados.get("bibliotecas")
    if not isinstance(bibliotecas, dict) or len(bibliotecas) < 40:
        raise FalhaAtualizacao("o repositório do retire.js tem menos de 40 bibliotecas")
    if "jquery" not in bibliotecas:
        raise FalhaAtualizacao("o repositório do retire.js não traz o jquery")
    problema = formato.problema("web_retire.json", dados)
    if problema:
        raise FalhaAtualizacao(f"retire.js: {problema}")
    from ..checks.web import jslibs

    # Os padrões rodam sobre páginas hostis e o Python não interrompe uma busca no meio.
    for nome, biblioteca in bibliotecas.items():
        suspeito = jslibs.padrao_suspeito(biblioteca["extractors"])
        if suspeito:
            raise FalhaAtualizacao(
                "padrão recusado no retire.js (inválido, longo demais ou com risco de "
                f"travar a busca): {nome[:40]}: {suspeito[:60]}"
            )


def _validar_sufixos(dados: dict[str, Any]) -> None:
    icann, privado = dados.get("icann"), dados.get("privado")
    if not isinstance(icann, list) or len(icann) < 3000:
        raise FalhaAtualizacao("a seção ICANN da lista de sufixos tem menos de 3000 regras")
    if not isinstance(privado, list) or len(privado) < 1000:
        raise FalhaAtualizacao("a seção de domínios privados tem menos de 1000 regras")
    if not {"com", "br", "org"} <= set(icann):
        raise FalhaAtualizacao("a lista de sufixos não traz com, br e org")
    if formato.problema("dns_sufixos.json", dados):
        raise FalhaAtualizacao("regra inesperada na lista de sufixos")


def _contar_kev(dados: Any) -> int:
    return len(dados.get("itens", {})) if isinstance(dados, dict) else 0


def _contar_retire(dados: Any) -> int:
    return len(dados.get("bibliotecas", {})) if isinstance(dados, dict) else 0


def _contar_sufixos(dados: Any) -> int:
    if not isinstance(dados, dict):
        return 0
    return len(dados.get("icann", [])) + len(dados.get("privado", []))


# -- tabela de fontes ------------------------------------------------------------------------


@dataclass(frozen=True)
class Fonte:
    nome: str
    arquivo: str
    url: str
    max_bytes: int
    converter: Callable[[bytes, date], dict[str, Any]]
    validar: Callable[[dict[str, Any]], None]
    contar: Callable[[Any], int]
    serializar: Callable[[dict[str, Any]], str]


FONTES: dict[str, Fonte] = {
    f.nome: f
    for f in (
        Fonte(
            "kev",
            "kev.json",
            KEV_URL,
            20_000_000,
            converter_kev,
            _validar_kev,
            _contar_kev,
            _compacto,
        ),
        Fonte(
            "retire",
            "web_retire.json",
            RETIRE_URL,
            25_000_000,
            converter_retire,
            _validar_retire,
            _contar_retire,
            lambda d: _compacto(d) + "\n",
        ),
        Fonte(
            "sufixos",
            "dns_sufixos.json",
            SUFIXOS_URL,
            5_000_000,
            converter_sufixos,
            _validar_sufixos,
            _contar_sufixos,
            _serializar_sufixos,
        ),
    )
}
PADRAO = tuple(FONTES)
_lock = threading.Lock()


def ocupado() -> bool:
    return _lock.locked()


# -- gravação --------------------------------------------------------------------------------


def _gravar(destino: Path, texto: str) -> None:
    """Grava em arquivo temporário e troca de uma vez; nunca deixa o arquivo pela metade."""
    destino.parent.mkdir(parents=True, exist_ok=True)
    temporario = destino.with_name(destino.name + ".tmp")
    try:
        with temporario.open("w", encoding="utf-8", newline="\n") as saida:
            saida.write(texto)
            saida.flush()
            os.fsync(saida.fileno())
        os.replace(temporario, destino)
    finally:
        temporario.unlink(missing_ok=True)


def _descrever_erro(exc: BaseException) -> str:
    return _limpo(_causa(exc), 300)


def _causa(exc: BaseException) -> str:
    if isinstance(exc, urllib.error.HTTPError):
        return f"o servidor respondeu HTTP {exc.code}"
    if isinstance(exc, urllib.error.URLError):
        return f"falha de conexão: {exc.reason}"
    if isinstance(exc, TimeoutError):
        return "tempo esgotado"
    if isinstance(exc, ValueError):
        return str(exc)
    return f"{type(exc).__name__}: {exc}"


def _limpar_derivados() -> None:
    """Esvazia os caches de quem já compilou os catálogos (sem importar o que não foi usado)."""
    data.limpar_cache()
    alvos = (
        ("eigan.core.vulndb", "_catalog"),
        ("eigan.checks.web.jslibs", "repository"),
        ("eigan.checks.dns.nomes", "_regras"),
    )
    for modulo, funcao in alvos:
        carregado = sys.modules.get(modulo)
        limpar = getattr(getattr(carregado, funcao, None), "cache_clear", None)
        if callable(limpar):
            limpar()


def _atualizar_uma(
    fonte: Fonte, fetch: baixar.Opener, timeout: float, saida: Path | None, hoje: date
) -> dict[str, Any]:
    bruto = baixar.fetch_bytes(fonte.url, timeout, fetch, fonte.max_bytes, total=TEMPO_TOTAL)
    novo = fonte.converter(bruto, hoje)
    fonte.validar(novo)
    publicada = data.data_do_catalogo(fonte.arquivo, novo)
    if data.data_futura(publicada, hoje):
        raise FalhaAtualizacao(
            f"a data da fonte ({publicada}) está no futuro: confira o relógio do computador"
        )
    atual = data.load_json(fonte.arquivo)
    antes, depois = fonte.contar(atual), fonte.contar(novo)
    if depois * 2 < antes:
        raise FalhaAtualizacao(
            f"o arquivo baixado tem {depois} itens e o atual tem {antes}: recusado por parecer incompleto"
        )
    resultado: dict[str, Any] = {
        "nome": fonte.nome,
        "ok": True,
        "itens": depois,
        "bytes": len(bruto),
        "versao": novo.get("versao") or novo.get("atualizado"),
        "data": data.data_do_catalogo(fonte.arquivo, novo),
        "gravado": False,
    }
    if saida is None:
        data_atual = data.data_do_catalogo(fonte.arquivo, atual)
        if data_atual and resultado["data"] < data_atual:
            resultado["motivo"] = f"os dados em uso (de {data_atual}) já são mais recentes"
            return resultado
        destino = data.overlay_dir() / fonte.arquivo
    else:
        destino = saida / fonte.arquivo
    _gravar(destino, fonte.serializar(novo))
    resultado.update(gravado=True, arquivo=str(destino))
    return resultado


def atualizar(
    nomes: list[str] | None = None,
    *,
    saida: Path | None = None,
    opener: baixar.Opener | None = None,
    timeout: float = TIMEOUT,
    hoje: date | None = None,
) -> list[dict[str, Any]]:
    """Baixa e grava as fontes pedidas (padrão: kev, retire e sufixos).

    Com ``saida``, grava no formato embarcado nessa pasta (uso de quem mantém o EIGAN)
    e não altera os dados em uso. Devolve um resultado por fonte, ``ok`` verdadeiro ou
    ``erro`` com a causa; uma fonte com falha não impede as demais.
    """
    escolhidas = list(nomes or PADRAO)
    desconhecidas = [n for n in escolhidas if n not in FONTES]
    if desconhecidas:
        raise ValueError(
            f"Fonte desconhecida: {', '.join(desconhecidas)}. Use {', '.join(FONTES)}."
        )
    if not _lock.acquire(blocking=False):
        raise RuntimeError("Já há uma atualização em andamento.")
    try:
        fetch = opener or baixar.https_opener()
        dia = hoje or data.hoje()
        resultados: list[dict[str, Any]] = []
        for nome in escolhidas:
            try:
                resultados.append(_atualizar_uma(FONTES[nome], fetch, timeout, saida, dia))
            except Exception as exc:  # noqa: BLE001 — uma fonte com falha não impede as outras
                log.warning("Atualização de %s falhou: %s", nome, exc)
                resultados.append({"nome": nome, "ok": False, "erro": _descrever_erro(exc)})
        _limpar_derivados()
        return resultados
    finally:
        _lock.release()


def atualizar_osv(
    ecossistemas: list[str], *, opener: baixar.Opener | None = None, timeout: float = 120.0
) -> list[dict[str, Any]]:
    """Baixa a base do OSV.dev dos ecossistemas pedidos (grande; só quando o usuário nomeia)."""
    from ..checks.code import osv

    brutos = osv.download_osv(ecossistemas, opener=opener, timeout=timeout)
    resultados: list[dict[str, Any]] = []
    for ecossistema, info in brutos.items():
        resultado: dict[str, Any] = {"nome": f"osv:{ecossistema}", "ok": bool(info.get("ok"))}
        if info.get("ok"):
            resultado.update(
                itens=info.get("registros"),
                pacotes=info.get("pacotes"),
                bytes=info.get("bytes"),
                arquivo=info.get("arquivo"),
                gravado=True,
            )
        else:
            resultado["erro"] = str(info.get("erro", "falha desconhecida"))
        resultados.append(resultado)
    return resultados


# -- estado e idade dos dados ------------------------------------------------------------------


def _data_do(arquivo: str, dados: Any) -> str:
    if arquivo in data.ATUALIZAVEIS:
        return data.data_do_catalogo(arquivo, dados)
    if not isinstance(dados, dict):
        return ""
    for campo in ("atualizado", "_verificado_em"):
        texto = str(dados.get(campo) or "")[:10]
        if len(texto) == 10 and texto[4] == "-":
            return texto
    return ""


def _itens(arquivo: str, dados: Any) -> int | None:
    fonte = next((f for f in FONTES.values() if f.arquivo == arquivo), None)
    return fonte.contar(dados) if fonte else None


def estado(hoje: date | None = None) -> list[dict[str, Any]]:
    """Nome, versão, data, idade em dias e origem de cada catálogo (nada de rede)."""
    dia = hoje or data.hoje()
    linhas: list[dict[str, Any]] = []
    itens = [(f.arquivo, f.nome, _TITULOS[f.arquivo], True) for f in FONTES.values()]
    itens += [
        (arquivo, arquivo.removesuffix(".json"), titulo, False)
        for arquivo, titulo in MANUAIS.items()
    ]
    for arquivo, nome, titulo, atualizavel in itens:
        try:
            dados = data.load_json(arquivo)
        except (OSError, ValueError):
            dados = {}
        quando = _data_do(arquivo, dados)
        try:
            idade: int | None = (dia - date.fromisoformat(quando)).days
        except ValueError:
            idade = None
        versao = str(dados.get("versao") or "") if isinstance(dados, dict) else ""
        linhas.append(
            {
                "nome": nome,
                "arquivo": arquivo,
                "titulo": titulo,
                "versao": versao or quando or None,
                "data": quando or None,
                "idade_dias": idade,
                "origem": data.origem(arquivo) if atualizavel else "embarcado",
                "atualizavel": atualizavel,
                "itens": _itens(arquivo, dados),
            }
        )
    return linhas


def avisos(linhas: list[dict[str, Any]], limite: int = LIMITE_IDADE_DIAS) -> list[str]:
    """Avisos em português para os catálogos atualizáveis com mais de ``limite`` dias."""
    textos = []
    for linha in linhas:
        idade, quando = linha.get("idade_dias"), linha.get("data")
        if not linha.get("atualizavel") or idade is None or idade <= limite:
            continue
        ano, mes, dia = str(quando).split("-")
        textos.append(
            f"{linha['titulo']}: dados de {dia}/{mes}/{ano}, há {idade} dias. "
            "Para atualizar, rode 'eigan atualizar' ou use o botão em Sobre no painel."
        )
    return textos


def resumo() -> dict[str, Any]:
    """Estado + avisos, no formato guardado no resultado da auditoria e nos relatórios."""
    linhas = estado()
    return {"limite_dias": LIMITE_IDADE_DIAS, "catalogos": linhas, "avisos": avisos(linhas)}
