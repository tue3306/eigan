"""Base offline completa do OSV.dev (opcional) para casar dependências.

Quando o usuário baixa a base (``download_osv``, comando de atualização — nunca
durante a auditoria), cada ecossistema fica em ``<cache>/osv/<ECOSSISTEMA>/all.zip``;
arquivos ``*.json`` extraídos na mesma pasta também servem. Na auditoria **nada é
baixado**: um índice ``pacote -> registros`` (``eigan-index.json``) evita abrir o
zip inteiro, e só os registros dos pacotes do projeto são lidos.

Formato e semântica: https://ossf.github.io/osv-schema/. Licenças por fonte em
https://google.github.io/osv.dev/data/ — só os ecossistemas de linguagem (dados
CC-BY-4.0, CC0, MIT ou Apache-2.0) são aceitos; fontes com licença não comercial
(Chainguard/Wolfi, CC-BY-NC-ND-4.0) são recusadas no download e ignoradas no índice.
"""

from __future__ import annotations

import json
import os
import threading
import zipfile
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any
from urllib.parse import quote

from ...core import baixar, paths
from ...core.models import Severity, now_iso
from .advisories import Advisory, package_key
from .cvss import severity_from_vector
from .versioning import VersionRange

OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
DATA_PAGE = "https://google.github.io/osv.dev/data/"
ECOSYSTEMS = ("npm", "PyPI", "Maven", "Packagist", "RubyGems", "NuGet", "Go", "crates.io")
#: ecossistemas do OSV com licença não comercial — nunca baixados
NONCOMMERCIAL = {"Chainguard": "CC-BY-NC-ND-4.0", "Wolfi": "CC-BY-NC-ND-4.0"}
#: prefixos de registros dessas fontes (ignorados se aparecerem em outro ecossistema)
_NONCOMMERCIAL_PREFIXES = ("CGA-",)
LICENSES = (
    "Cada registro mantém a licença da fonte: GitHub Advisory Database (CC-BY-4.0), "
    "PyPA (CC-BY-4.0), Go Vulnerability Database (CC-BY-4.0), RustSec (CC0-1.0), "
    "OpenSSF Malicious Packages (Apache-2.0), Drupal (MIT) — " + DATA_PAGE
)
INDEX_FILE = "eigan-index.json"
SOURCE_FILE = "eigan-fonte.json"
INDEX_VERSION = 2
MAX_DOWNLOAD_BYTES = 800_000_000
MAX_UNCOMPRESSED_BYTES = 20_000_000_000
MAX_RECORD_BYTES = 5_000_000
MAX_RECORDS = 2_000_000

_GHSA_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "LOW": "low"}

Opener = baixar.Opener


def osv_root() -> Path:
    """Pasta da base offline do OSV dentro do cache do EIGAN."""
    return paths.cache_dir() / "osv"


class OsvDatabase:
    """Registros do OSV de um ecossistema, lidos sob demanda pelo índice."""

    def __init__(self, ecosystem: str, folder: Path, index: dict[str, list[str]]) -> None:
        self.ecosystem = ecosystem
        self.folder = folder
        self.index = index
        self._archive = folder / "all.zip"
        self._lock = threading.Lock()
        self._cache: dict[str, list[Advisory]] = {}

    @property
    def packages(self) -> int:
        return len(self.index)

    def prefetch(self, names: Iterable[str]) -> None:
        """Lê de uma vez (abrindo o zip uma só vez) os registros dos pacotes informados."""
        keys = {package_key(self.ecosystem, n) for n in names}
        with self._lock:
            pending = [k for k in keys if k not in self._cache and k in self.index]
            for key in keys - set(pending):
                self._cache.setdefault(key, [])
            if not pending:
                return
            archive = self._open_archive()
            try:
                for key in pending:
                    found: list[Advisory] = []
                    for member in self.index.get(key, []):
                        record = self._read(archive, member)
                        if record is not None:
                            found.extend(advisories_from_record(record, self.ecosystem, key))
                    self._cache[key] = found
            finally:
                if archive is not None:
                    archive.close()

    def advisories(self, name: str) -> list[Advisory]:
        """Avisos (não retirados) que citam o pacote."""
        key = package_key(self.ecosystem, name)
        if key not in self._cache:
            self.prefetch([name])
        return list(self._cache.get(key, []))

    def _open_archive(self) -> zipfile.ZipFile | None:
        if not self._archive.is_file():
            return None
        try:
            return zipfile.ZipFile(self._archive)
        except (OSError, zipfile.BadZipFile):
            return None

    def _read(self, archive: zipfile.ZipFile | None, member: str) -> dict[str, Any] | None:
        try:
            if archive is not None:
                info = archive.getinfo(member)
                if info.file_size > MAX_RECORD_BYTES:
                    return None
                raw = archive.read(info)
            else:
                path = self.folder / Path(member).name
                if path.stat().st_size > MAX_RECORD_BYTES:
                    return None
                raw = path.read_bytes()
            data = json.loads(raw.decode("utf-8", errors="replace"))
        except (OSError, KeyError, ValueError, RecursionError, zipfile.BadZipFile):
            return None
        return data if isinstance(data, dict) else None


def load_database(ecosystem: str, root: Path | None = None) -> OsvDatabase | None:
    """Abre a base de um ecossistema, se ela existir no cache (sem rede)."""
    if ecosystem not in ECOSYSTEMS:
        return None
    folder = (root or osv_root()) / ecosystem
    if not folder.is_dir():
        return None
    signature = _source_signature(folder)
    if signature is None:
        return None
    index = _load_index(folder, signature)
    if index is None:
        if _source_bytes(folder) > MAX_SCAN_INDEX_BYTES:
            return None  # base grande sem índice: quem indexa é a atualização, não a auditoria
        index = build_index(ecosystem, folder)
        _save_index(folder, signature, index)
    return OsvDatabase(ecosystem, folder, index)


#: acima disto, a auditoria não monta o índice sozinha (rode a atualização da base OSV)
MAX_SCAN_INDEX_BYTES = 32 * 1024 * 1024


def _source_bytes(folder: Path) -> int:
    total = 0
    for path in [folder / "all.zip", *_json_records(folder)]:
        try:
            total += path.stat().st_size
        except OSError:
            continue
    return total


def database_info(ecosystem: str, root: Path | None = None) -> dict[str, Any] | None:
    """Origem e data da base baixada (``eigan-fonte.json``), se houver."""
    try:
        data = json.loads(((root or osv_root()) / ecosystem / SOURCE_FILE).read_text("utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _json_records(folder: Path) -> list[Path]:
    return sorted(p for p in folder.glob("*.json") if p.name not in (INDEX_FILE, SOURCE_FILE))


def _source_signature(folder: Path) -> dict[str, Any] | None:
    """Identifica a versão dos dados no disco (o índice é refeito quando ela muda)."""
    archive = folder / "all.zip"
    try:
        if archive.is_file():
            stat = archive.stat()
            return {"tipo": "zip", "tamanho": stat.st_size, "mtime": int(stat.st_mtime)}
        records = _json_records(folder)
        if not records:
            return None
        newest = max(int(p.stat().st_mtime) for p in records)
    except OSError:
        return None
    return {"tipo": "json", "arquivos": len(records), "ultimo": records[-1].name, "mtime": newest}


def _load_index(folder: Path, signature: dict[str, Any]) -> dict[str, list[str]] | None:
    try:
        data = json.loads((folder / INDEX_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("versao") != INDEX_VERSION:
        return None
    if data.get("origem") != signature:
        return None
    packages = data.get("pacotes")
    return packages if isinstance(packages, dict) else None


def _atomic_write(target: Path, text: str) -> None:
    """Grava em arquivo temporário e troca de uma vez (nunca deixa arquivo pela metade)."""
    temp = target.with_name(target.name + ".tmp")
    try:
        temp.write_text(text, encoding="utf-8")
        os.replace(temp, target)
    except OSError:
        temp.unlink(missing_ok=True)


def _save_index(folder: Path, signature: dict[str, Any], index: dict[str, list[str]]) -> None:
    payload = {"versao": INDEX_VERSION, "origem": signature, "pacotes": index}
    _atomic_write(folder / INDEX_FILE, json.dumps(payload, separators=(",", ":")))


def _iter_zip(archive_path: Path) -> Iterator[tuple[str, bytes]]:
    with zipfile.ZipFile(archive_path) as archive:
        members = [i for i in archive.infolist() if not i.is_dir() and i.filename.endswith(".json")]
        if sum(i.file_size for i in members) > MAX_UNCOMPRESSED_BYTES:
            raise ValueError("o zip descompactado passa do limite (arquivo suspeito)")
        for info in members[:MAX_RECORDS]:
            if info.file_size <= MAX_RECORD_BYTES:
                yield info.filename, archive.read(info)


def _iter_records(folder: Path) -> Iterator[tuple[str, bytes]]:
    archive_path = folder / "all.zip"
    if archive_path.is_file():
        yield from _iter_zip(archive_path)
        return
    for path in _json_records(folder)[:MAX_RECORDS]:
        try:
            if path.stat().st_size <= MAX_RECORD_BYTES:
                yield path.name, path.read_bytes()
        except OSError:
            continue


def _index_records(ecosystem: str, records: Iterator[tuple[str, bytes]]) -> dict[str, list[str]]:
    index: dict[str, list[str]] = {}
    for member, raw in records:
        try:
            record = json.loads(raw.decode("utf-8", errors="replace"))
        except (ValueError, RecursionError):
            continue
        if not isinstance(record, dict) or not _usable(record):
            continue
        for name in _record_packages(record, ecosystem):
            bucket = index.setdefault(name, [])
            if member not in bucket:
                bucket.append(member)
    return index


def build_index(ecosystem: str, folder: Path) -> dict[str, list[str]]:
    """Monta o índice ``pacote -> registros`` lendo cada registro uma vez."""
    try:
        return _index_records(ecosystem, _iter_records(folder))
    except (OSError, ValueError, zipfile.BadZipFile):
        return {}


def _usable(record: dict[str, Any]) -> bool:
    """Registro vigente e de fonte com licença aceita."""
    rec_id = str(record.get("id", ""))
    return not record.get("withdrawn") and not rec_id.startswith(_NONCOMMERCIAL_PREFIXES)


def _same_ecosystem(value: str, ecosystem: str) -> bool:
    return value.split(":", 1)[0] == ecosystem


def _record_packages(record: dict[str, Any], ecosystem: str) -> set[str]:
    names: set[str] = set()
    for affected in record.get("affected") or []:
        package = (affected or {}).get("package") or {}
        if _same_ecosystem(str(package.get("ecosystem", "")), ecosystem) and package.get("name"):
            names.add(package_key(ecosystem, str(package["name"])))
    return names


def advisories_from_record(record: dict[str, Any], ecosystem: str, key: str) -> list[Advisory]:
    """Converte um registro OSV nos avisos aplicáveis ao pacote ``key``."""
    if not _usable(record):
        return []
    rec_id = str(record.get("id", ""))
    aliases = tuple(str(a) for a in record.get("aliases") or [])
    cves = tuple(sorted({a for a in (rec_id, *aliases) if a.startswith("CVE-")}))
    title = str(record.get("summary") or "").strip() or _first_line(str(record.get("details", "")))
    found: list[Advisory] = []
    for affected in record.get("affected") or []:
        package = (affected or {}).get("package") or {}
        if not _same_ecosystem(str(package.get("ecosystem", "")), ecosystem):
            continue
        if package_key(ecosystem, str(package.get("name", ""))) != key:
            continue
        ranges = tuple(
            VersionRange(tuple(_events(rng.get("events") or [])))
            for rng in affected.get("ranges") or []
            if isinstance(rng, dict) and rng.get("type") in ("SEMVER", "ECOSYSTEM")
        )
        explicit = frozenset(str(v) for v in affected.get("versions") or [])
        if not ranges and not explicit:
            continue
        severity, known = _severity(record, affected, rec_id)
        found.append(
            Advisory(
                id=rec_id,
                ecosystem=ecosystem,
                package=str(package.get("name", "")),
                severity=severity,
                title=title[:200] or rec_id,
                summary=title[:400],
                reference=f"https://osv.dev/vulnerability/{quote(rec_id)}",
                cves=cves,
                aliases=aliases,
                ranges=ranges,
                versions=explicit,
                malicious=rec_id.startswith("MAL-"),
                source="osv",
                severity_known=known,
            )
        )
    return found


def _events(raw: list[Any]) -> list[tuple[str, str]]:
    events: list[tuple[str, str]] = []
    for event in raw:
        if not isinstance(event, dict):
            continue
        for kind in ("introduced", "fixed", "last_affected", "limit"):
            if kind in event:
                events.append((kind, str(event[kind])))
    return events


def _first_line(text: str) -> str:
    for line in text.splitlines():
        if line.strip():
            return line.strip().lstrip("#").strip()
    return ""


def _severity(
    record: dict[str, Any], affected: dict[str, Any], rec_id: str
) -> tuple[Severity, bool]:
    """Severidade do registro: rótulo do GHSA, nota CVSS v3 ou média (estimada)."""
    if rec_id.startswith("MAL-"):
        return Severity.CRITICAL, True
    for source in (affected.get("database_specific") or {}, record.get("database_specific") or {}):
        label = str(source.get("severity", "")).upper() if isinstance(source, dict) else ""
        if label in _GHSA_SEVERITY:
            return Severity(_GHSA_SEVERITY[label]), True
    for entry in list(affected.get("severity") or []) + list(record.get("severity") or []):
        if isinstance(entry, dict) and str(entry.get("type", "")).upper() == "CVSS_V3":
            computed = severity_from_vector(str(entry.get("score", "")))
            if computed is not None:
                return computed, True
    return Severity.MEDIUM, False


# -- download (comando de atualização, nunca durante a auditoria) ---------------------


_HttpsOnlyRedirect = baixar.HttpsOnlyRedirect
_https_opener = baixar.https_opener


def download_osv(
    ecosystems: list[str],
    *,
    root: Path | None = None,
    timeout: float = 120.0,
    opener: Opener | None = None,
    max_bytes: int = MAX_DOWNLOAD_BYTES,
) -> dict[str, dict[str, Any]]:
    """Baixa ``all.zip`` de cada ecossistema para o cache e monta o índice.

    Uso fora da auditoria (comando de atualização). Devolve, por ecossistema,
    ``{"ok": True, "arquivo", "bytes", "pacotes", "registros"}`` ou ``{"ok": False,
    "erro": mensagem}``. O arquivo novo só substitui o anterior depois de validado
    (zip íntegro e registros legíveis); falhas não apagam a base que já existia.
    """
    base = root or osv_root()
    fetch = opener or _https_opener()
    results: dict[str, dict[str, Any]] = {}
    for ecosystem in ecosystems:
        if ecosystem in NONCOMMERCIAL:
            results[ecosystem] = {
                "ok": False,
                "erro": f"licença não comercial ({NONCOMMERCIAL[ecosystem]}): não é baixado",
            }
            continue
        if ecosystem not in ECOSYSTEMS:
            results[ecosystem] = {"ok": False, "erro": "ecossistema não suportado"}
            continue
        try:
            results[ecosystem] = _download_one(ecosystem, base, timeout, fetch, max_bytes)
        except Exception as exc:  # noqa: BLE001 — um ecossistema com falha não impede os outros
            results[ecosystem] = {"ok": False, "erro": f"{type(exc).__name__}: {exc}"}
    return results


_fetch_to = baixar.fetch_to


def _download_one(
    ecosystem: str, base: Path, timeout: float, fetch: Opener, max_bytes: int
) -> dict[str, Any]:
    folder = base / ecosystem
    folder.mkdir(parents=True, exist_ok=True)
    url = OSV_URL.format(ecosystem=quote(ecosystem, safe="."))
    partial = folder / "all.zip.part"
    try:
        total = _fetch_to(url, partial, timeout, fetch, max_bytes)
        if not zipfile.is_zipfile(partial):
            raise ValueError("o arquivo baixado não é um zip válido")
        index = _index_records(ecosystem, _iter_zip(partial))  # lê tudo: valida o CRC
        if not index:
            raise ValueError("o zip não tem registros do ecossistema")
        target = folder / "all.zip"
        os.replace(partial, target)
    finally:
        partial.unlink(missing_ok=True)
    signature = _source_signature(folder)
    if signature is not None:
        _save_index(folder, signature, index)
    records = len({member for members in index.values() for member in members})
    source = {
        "fonte": "OSV.dev — https://osv.dev",
        "url": url,
        "ecossistema": ecosystem,
        "baixado_em": now_iso(),
        "bytes": total,
        "registros": records,
        "licencas": LICENSES,
    }
    _atomic_write(folder / SOURCE_FILE, json.dumps(source, ensure_ascii=False, indent=2))
    return {
        "ok": True,
        "arquivo": str(target),
        "bytes": total,
        "pacotes": len(index),
        "registros": records,
    }
