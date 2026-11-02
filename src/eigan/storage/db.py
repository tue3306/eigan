"""Histórico local em SQLite: auditorias, triagem de achados e primeira aparição.

Tudo fica no diretório de dados do EIGAN (``core.paths.db_path()``); nada sai da
máquina. Cada operação abre a própria conexão, então o armazenamento é seguro para
uso simultâneo pelo painel (várias threads) e pela linha de comando.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from ..core import paths
from ..core.models import ScanResult, TriageStatus, now_iso

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scans (
    id          TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    target_key  TEXT NOT NULL,
    kind        TEXT NOT NULL,
    profile     TEXT NOT NULL,
    status      TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    finished_at TEXT NOT NULL DEFAULT '',
    score       INTEGER,
    grade       TEXT NOT NULL DEFAULT '',
    critical    INTEGER NOT NULL DEFAULT 0,
    high        INTEGER NOT NULL DEFAULT 0,
    medium      INTEGER NOT NULL DEFAULT 0,
    low         INTEGER NOT NULL DEFAULT 0,
    info        INTEGER NOT NULL DEFAULT 0,
    app_version TEXT NOT NULL DEFAULT '',
    data        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS scans_by_target ON scans (target_key, started_at);
CREATE INDEX IF NOT EXISTS scans_by_date ON scans (started_at);
CREATE TABLE IF NOT EXISTS triage (
    target_key  TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    status      TEXT NOT NULL,
    note        TEXT NOT NULL DEFAULT '',
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (target_key, fingerprint)
);
CREATE TABLE IF NOT EXISTS seen (
    target_key  TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    PRIMARY KEY (target_key, fingerprint)
);
"""

_SUMMARY_COLUMNS = (
    "id, target, target_key, kind, profile, status, started_at, finished_at, score, grade, "
    "critical, high, medium, low, info, app_version"
)


def target_key(kind: str, target: str) -> str:
    """Chave estável para agrupar auditorias do mesmo alvo."""
    return f"{kind}:{target.strip().rstrip('/').lower()}"


class Store:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or paths.db_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_lock = threading.Lock()
        self._ready = False

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            self._ensure_schema(conn)
            with conn:
                yield conn
        finally:
            conn.close()

    def _ensure_schema(self, conn: sqlite3.Connection) -> None:
        if self._ready:
            return
        with self._init_lock:
            if self._ready:
                return
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_SCHEMA)
            conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('schema', ?)",
                (str(SCHEMA_VERSION),),
            )
            conn.commit()
            self._ready = True

    # -- auditorias ---------------------------------------------------------------
    def save(self, result: ScanResult) -> None:
        counts = result.analysis.get("counts", {})
        posture = result.analysis.get("posture", {})
        row = {
            "id": result.id,
            "target": result.target,
            "target_key": target_key(result.kind.value, result.target),
            "kind": result.kind.value,
            "profile": result.profile,
            "status": result.status,
            "started_at": result.started_at,
            "finished_at": result.finished_at,
            "score": posture.get("score") if result.analysis.get("evaluated") else None,
            "grade": posture.get("grade", ""),
            "critical": counts.get("critical", 0),
            "high": counts.get("high", 0),
            "medium": counts.get("medium", 0),
            "low": counts.get("low", 0),
            "info": counts.get("info", 0),
            "app_version": result.app_version,
            "data": json.dumps(result.to_dict(), ensure_ascii=False),
        }
        columns = ", ".join(row)
        marks = ", ".join(f":{name}" for name in row)
        with self._connect() as conn:
            conn.execute(f"INSERT OR REPLACE INTO scans ({columns}) VALUES ({marks})", row)

    def get(self, scan_id: str) -> ScanResult | None:
        with self._connect() as conn:
            row = conn.execute("SELECT data FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            return None
        return ScanResult.from_dict(json.loads(row["data"]))

    def scans(self, *, target: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        # Só a constante de colunas é interpolada; valores sempre por parâmetro.
        sql = f"SELECT {_SUMMARY_COLUMNS} FROM scans"  # nosec B608
        params: list[Any] = []
        if target:
            sql += " WHERE target_key = ?"
            params.append(target)
        sql += " ORDER BY started_at DESC LIMIT ?"
        params.append(max(1, min(int(limit), 5000)))
        with self._connect() as conn:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]

    def targets(self) -> list[dict[str, Any]]:
        """Um item por alvo com a auditoria mais recente e a quantidade de auditorias."""
        # Só a constante de colunas é interpolada.
        sql = (
            f"SELECT {_SUMMARY_COLUMNS}, total FROM ("  # nosec B608
            " SELECT *, COUNT(*) OVER (PARTITION BY target_key) AS total,"
            " ROW_NUMBER() OVER (PARTITION BY target_key ORDER BY started_at DESC) AS n"
            " FROM scans"
            ") WHERE n = 1 ORDER BY started_at DESC"
        )
        with self._connect() as conn:
            return [dict(r) for r in conn.execute(sql).fetchall()]

    def delete(self, scan_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            return cur.rowcount > 0

    def previous(self, result: ScanResult) -> ScanResult | None:
        """Última auditoria concluída do mesmo alvo, anterior a ``result``."""
        key = target_key(result.kind.value, result.target)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT data FROM scans WHERE target_key = ? AND id != ? AND started_at < ? "
                "AND status IN ('concluida', 'cancelada') ORDER BY started_at DESC LIMIT 1",
                (key, result.id, result.started_at),
            ).fetchone()
        if row is None:
            return None
        return ScanResult.from_dict(json.loads(row["data"]))

    # -- primeira aparição e triagem ---------------------------------------------
    def mark_first_seen(self, result: ScanResult) -> None:
        key = target_key(result.kind.value, result.target)
        with self._connect() as conn:
            for finding in result.findings:
                conn.execute(
                    "INSERT OR IGNORE INTO seen (target_key, fingerprint, first_seen) "
                    "VALUES (?, ?, ?)",
                    (key, finding.fingerprint, result.started_at or now_iso()),
                )
            rows = conn.execute(
                "SELECT fingerprint, first_seen FROM seen WHERE target_key = ?", (key,)
            ).fetchall()
        first = {r["fingerprint"]: r["first_seen"] for r in rows}
        for finding in result.findings:
            finding.first_seen = first.get(finding.fingerprint, finding.first_seen)

    def triage_for(self, kind: str, target: str) -> dict[str, dict[str, str]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT fingerprint, status, note, updated_at FROM triage WHERE target_key = ?",
                (target_key(kind, target),),
            ).fetchall()
        return {r["fingerprint"]: dict(r) for r in rows}

    def apply_triage(self, result: ScanResult) -> None:
        """Aplica a triagem salva. "Corrigido" que reaparece volta a "aberto"."""
        saved = self.triage_for(result.kind.value, result.target)
        reopened: list[str] = []
        for finding in result.findings:
            item = saved.get(finding.fingerprint)
            if item is None:
                continue
            status = TriageStatus(item["status"])
            if status is TriageStatus.FIXED:
                finding.status = TriageStatus.OPEN
                finding.status_note = "Foi marcado como corrigido, mas reapareceu nesta auditoria."
                reopened.append(finding.fingerprint)
                continue
            finding.status = status
            finding.status_note = item.get("note", "")
        if reopened:
            key = target_key(result.kind.value, result.target)
            with self._connect() as conn:
                conn.executemany(
                    "DELETE FROM triage WHERE target_key = ? AND fingerprint = ?",
                    [(key, fp) for fp in reopened],
                )

    def set_triage(
        self, kind: str, target: str, fingerprint: str, status: TriageStatus, note: str = ""
    ) -> None:
        key = target_key(kind, target)
        with self._connect() as conn:
            if status is TriageStatus.OPEN:
                conn.execute(
                    "DELETE FROM triage WHERE target_key = ? AND fingerprint = ?",
                    (key, fingerprint),
                )
                return
            conn.execute(
                "INSERT OR REPLACE INTO triage (target_key, fingerprint, status, note, updated_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (key, fingerprint, status.value, note[:1000], now_iso()),
            )
