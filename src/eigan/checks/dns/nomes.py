"""Nomes de domínio: normalização e domínio organizacional pela Public Suffix List.

A lista vai embarcada em ``data/dns_sufixos.json`` (seções ICANN e de domínios
privados, regras IDN em punycode). O algoritmo é o da própria lista
(https://publicsuffix.org/list/): vale a regra de exceção (``!``); senão, a regra
com mais rótulos (``*`` casa um rótulo qualquer); sem regra, o último rótulo.

Três perguntas diferentes usam a lista:

* :func:`dominio_organizacional` — onde ficam SPF, DMARC, CAA e DNSSEC
  (``www.exemplo.com.br`` -> ``exemplo.com.br``), com as duas seções, como
  pede a RFC 7489 (DMARC);
* :func:`dominio_registravel` — o que se compra num registrador (só a seção
  ICANN): ``app.herokuapp.com`` -> ``herokuapp.com``;
* :func:`plataforma` — o nome está sob uma plataforma compartilhada
  (``meusite.github.io``) cujo DNS pertence ao provedor, não ao cliente.

Limitação: a lista muda com o tempo; um sufixo criado depois da versão embarcada
cai na regra padrão (o último rótulo).
"""

from __future__ import annotations

from functools import lru_cache

from ...data import load_json


def normalizar(nome: str) -> str:
    """Minúsculas, sem o ponto final e em punycode (A-label) quando possível."""
    limpo = nome.strip().lower().rstrip(".")
    if limpo.isascii():
        return limpo
    try:
        return limpo.encode("idna").decode("ascii")
    except UnicodeError:
        return limpo


def dentro_de(nome: str, dominio: str) -> bool:
    """``nome`` é ``dominio`` ou um subdomínio dele."""
    a, b = normalizar(nome), normalizar(dominio)
    return a == b or a.endswith("." + b)


@lru_cache(maxsize=1)
def _regras() -> tuple[frozenset[str], frozenset[str]]:
    dados = load_json("dns_sufixos.json")
    return frozenset(dados.get("icann", [])), frozenset(dados.get("privado", []))


def _tamanho_sufixo(rotulos: list[str], regras: frozenset[str]) -> int:
    """Quantos rótulos (da direita) formam o sufixo público de ``rotulos``."""
    maior = 1  # regra padrão "*": o último rótulo
    for tamanho in range(1, len(rotulos) + 1):
        candidato = ".".join(rotulos[-tamanho:])
        if "!" + candidato in regras:
            return tamanho - 1  # exceção: a regra sem o rótulo mais à esquerda
        curinga = "*." + ".".join(rotulos[-tamanho + 1 :]) if tamanho > 1 else ""
        if candidato in regras or (curinga and curinga in regras):
            maior = tamanho
    return maior


def sufixo_publico(nome: str, *, privados: bool = True) -> str:
    """Sufixo público de ``nome`` (``com.br``, ``github.io``...)."""
    rotulos = normalizar(nome).split(".")
    icann, privado = _regras()
    regras = icann | privado if privados else icann
    return ".".join(rotulos[-_tamanho_sufixo(rotulos, regras) :])


def _mais_um_rotulo(nome: str, sufixo: str) -> str | None:
    rotulos = normalizar(nome).split(".")
    tamanho = len(sufixo.split(".")) + 1
    if len(rotulos) < tamanho:
        return None
    return ".".join(rotulos[-tamanho:])


def dominio_organizacional(nome: str) -> str:
    """``www.exemplo.com.br`` -> ``exemplo.com.br``. Um sufixo público fica como está."""
    limpo = normalizar(nome)
    return _mais_um_rotulo(limpo, sufixo_publico(limpo)) or limpo


def dominio_registravel(nome: str) -> str | None:
    """Domínio que se registra num registrador (só a seção ICANN); None para um sufixo."""
    limpo = normalizar(nome)
    return _mais_um_rotulo(limpo, sufixo_publico(limpo, privados=False))


def tld_existe(nome: str) -> bool:
    """O último rótulo é um TLD da lista (``.local``, ``.corp``, ``.lan`` não são)."""
    tld = normalizar(nome).rsplit(".", 1)[-1]
    icann, _ = _regras()
    return tld in icann or f"*.{tld}" in icann


def plataforma(nome: str) -> str | None:
    """Sufixo de plataforma compartilhada sob o qual ``nome`` está (ex.: ``github.io``).

    Só vale para nomes ABAIXO do sufixo privado: o domínio do próprio provedor
    (``github.io``) é auditado normalmente.
    """
    limpo = normalizar(nome)
    completo = sufixo_publico(limpo)
    icann = sufixo_publico(limpo, privados=False)
    if completo == limpo or completo.count(".") <= icann.count("."):
        return None
    return completo
