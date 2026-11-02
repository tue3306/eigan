"""Fontes falsas para testar a atualização dos catálogos, sem rede."""

from __future__ import annotations

import io
import json
import urllib.error
from collections.abc import Callable
from typing import Any

from eigan.core import atualizacao

#: data de publicação do KEV falso, depois da do arquivo embarcado
KEV_PUBLICADO = "2027-01-15T10:00:00.123Z"
KEV_DATA = "2027-01-15"


class FakeResponse:
    def __init__(self, body: bytes, url: str, headers: dict[str, str] | None = None) -> None:
        self._body = io.BytesIO(body)
        self._url = url
        self.headers = headers or {}

    def geturl(self) -> str:
        return self._url

    def read(self, size: int = -1) -> bytes:
        return self._body.read(size)

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


def kev_feed(count: int = 1200, *, released: str = KEV_PUBLICADO, extra: str = "") -> bytes:
    vulns = [
        {
            "cveID": f"CVE-2027-{1000 + i}",
            "vendorProject": f"Fornecedor {i}",
            "product": "Produto",
            "vulnerabilityName": f"  Falha   número {i} ",
            "dateAdded": f"2027-01-{1 + i % 15:02d}",
            "knownRansomwareCampaignUse": "Known" if i % 100 == 0 else "Unknown",
        }
        for i in range(count)
    ]
    if extra:
        vulns.append(
            {
                "cveID": extra,
                "vendorProject": "X",
                "product": "Y",
                "vulnerabilityName": "Z",
                "dateAdded": "2027-01-16",
                "knownRansomwareCampaignUse": "Unknown",
            }
        )
    feed = {
        "catalogVersion": "2027.01.15",
        "dateReleased": released,
        "count": len(vulns),
        "vulnerabilities": vulns,
    }
    return json.dumps(feed).encode()


def retire_repo(count: int = 45) -> bytes:
    def library(i: int) -> dict[str, Any]:
        return {
            "bowername": [f"lib{i}"],
            "basePurl": f"pkg:npm/lib{i}",
            "licenses": ["MIT"],
            "npmname": f"lib{i}",
            "extractors": {
                "func": ["lib.version"],
                "ast": ["//x"],
                "uri": ["/(§§version§§)/lib.js"],
                "filecontent": ["lib v(§§version§§)"],
            },
            "vulnerabilities": [
                {
                    "below": "2.0.0",
                    "severity": "high",
                    "cwe": ["CWE-79"],
                    "identifiers": {"CVE": ["CVE-2020-1"]},
                    "info": ["https://exemplo.invalid"],
                }
            ],
        }

    repo: dict[str, Any] = {"retire-example": library(0)}
    repo["jquery"] = library(1)
    for i in range(2, count):
        repo[f"lib{i}"] = library(i)
    return json.dumps(repo).encode()


def psl_text(icann: int = 4500, private: int = 1500, *, extra_icann: tuple[str, ...] = ()) -> bytes:
    linhas = [
        "// VERSION: 2027-01-14_10-00-00_UTC",
        "// COMMIT: abcdef0123456789",
        "// ===BEGIN ICANN DOMAINS===",
        "com",
        "br",
        "org",
        "*.ck",
        "!www.ck",
        "公司.cn",
    ]
    linhas += list(extra_icann)
    linhas += [f"tld{i}.example   // comentário" for i in range(icann)]
    linhas += ["// ===END ICANN DOMAINS===", "// ===BEGIN PRIVATE DOMAINS===", "github.io"]
    linhas += [f"priv{i}.exemplo.net" for i in range(private)]
    linhas += ["// ===END PRIVATE DOMAINS==="]
    return "\n".join(linhas).encode()


def ok_routes() -> dict[str, bytes | Exception]:
    return {
        atualizacao.KEV_URL: kev_feed(),
        atualizacao.RETIRE_URL: retire_repo(),
        atualizacao.SUFIXOS_URL: psl_text(),
    }


def opener_for(
    routes: dict[str, bytes | Exception], calls: list[str] | None = None
) -> Callable[..., Any]:
    def fetch(url: str, timeout: float = 0.0) -> FakeResponse:
        if calls is not None:
            calls.append(url)
        body = routes.get(url)
        if body is None:
            raise urllib.error.HTTPError(url, 404, "Not Found", None, None)  # type: ignore[arg-type]
        if isinstance(body, Exception):
            raise body
        return FakeResponse(body, url)

    return fetch
