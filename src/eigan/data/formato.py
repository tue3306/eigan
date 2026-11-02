"""Conferência do formato interno dos catálogos atualizáveis.

Vale para a cópia baixada, que pode ter sido truncada, editada à mão ou gravada por
outra versão do EIGAN: se qualquer item fugir do formato do arquivo embarcado, a
cópia inteira é descartada em vez de estourar dentro das checagens. Só olha o tipo
dos campos; as contagens mínimas e a data ficam com quem baixa (``core.atualizacao``).
"""

from __future__ import annotations

from typing import Any

#: tamanho máximo de um padrão de extração do retire.js (o maior embarcado tem bem menos)
PADRAO_MAX = 1000


def _lista_de_textos(valor: Any) -> bool:
    return isinstance(valor, list) and all(isinstance(x, str) for x in valor)


def _kev(dados: dict[str, Any]) -> str | None:
    itens = dados.get("itens")
    if not isinstance(itens, dict):
        return "itens não é um objeto"
    for cve, linha in itens.items():
        ok = (
            isinstance(cve, str)
            and len(cve) <= 30
            and isinstance(linha, list)
            and len(linha) == 5
            and all(isinstance(x, str) for x in linha[:4])
            and linha[4] in (0, 1)
        )
        if not ok:
            return f"item inesperado: {str(cve)[:40]}"
    return None


def _vulnerabilidade_valida(vuln: Any) -> bool:
    if not isinstance(vuln, dict):
        return False
    for campo in ("below", "atOrAbove"):
        if campo in vuln and not isinstance(vuln[campo], str):
            return False
    for campo in ("excludes", "cwe", "info"):
        if campo in vuln and not _lista_de_textos(vuln[campo]):
            return False
    identificadores = vuln.get("identifiers", {})
    if not isinstance(identificadores, dict):
        return False
    if "CVE" in identificadores and not _lista_de_textos(identificadores["CVE"]):
        return False
    return all(isinstance(identificadores.get(c, ""), str) for c in ("summary", "githubID"))


def _extratores_validos(extratores: Any) -> bool:
    if not isinstance(extratores, dict):
        return False
    for campo in ("uri", "filename", "filecontent", "filecontentreplace"):
        valor = extratores.get(campo, [])
        if not _lista_de_textos(valor) or any(len(p) > PADRAO_MAX for p in valor):
            return False
    hashes = extratores.get("hashes", {})
    return isinstance(hashes, dict) and all(
        isinstance(k, str) and isinstance(v, str) for k, v in hashes.items()
    )


def _retire(dados: dict[str, Any]) -> str | None:
    bibliotecas = dados.get("bibliotecas")
    if not isinstance(bibliotecas, dict):
        return "bibliotecas não é um objeto"
    for nome, biblioteca in bibliotecas.items():
        ok = (
            isinstance(biblioteca, dict)
            and _extratores_validos(biblioteca.get("extractors"))
            and isinstance(biblioteca.get("vulnerabilities"), list)
            and all(_vulnerabilidade_valida(v) for v in biblioteca["vulnerabilities"])
            and isinstance(biblioteca.get("npmname", ""), str)
        )
        if not ok:
            return f"biblioteca com formato inesperado: {str(nome)[:40]}"
    return None


def _sufixos(dados: dict[str, Any]) -> str | None:
    for secao in ("icann", "privado"):
        regras = dados.get(secao)
        if not isinstance(regras, list):
            return f"{secao} não é uma lista"
        if not all(isinstance(r, str) and r.isascii() and 0 < len(r) < 256 for r in regras):
            return f"regra inesperada em {secao}"
    return None


_CONFERENCIAS = {"kev.json": _kev, "web_retire.json": _retire, "dns_sufixos.json": _sufixos}


def problema(name: str, dados: Any) -> str | None:
    """Por que ``dados`` não tem o formato de ``name``; ``None`` se está tudo certo."""
    conferir = _CONFERENCIAS.get(name)
    if conferir is None or not isinstance(dados, dict):
        return "catálogo desconhecido ou fora do formato"
    try:
        return conferir(dados)
    except (TypeError, AttributeError, KeyError, RecursionError) as exc:
        return f"formato inesperado ({type(exc).__name__})"
