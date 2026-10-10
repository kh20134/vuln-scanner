"""로컬 SQLite 저장소. 전체 DB 파일은 저장소에 넣지 않는다."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cve (
  cve_id TEXT PRIMARY KEY,
  description TEXT NOT NULL DEFAULT '',
  published TEXT,
  last_modified TEXT,
  vuln_status TEXT,
  cvss_v3_version TEXT,
  cvss_v3_score REAL,
  cvss_v3_vector TEXT,
  cvss_v3_severity TEXT,
  cvss_v4_score REAL,
  cvss_v4_vector TEXT,
  cvss_v4_severity TEXT,
  kev INTEGER NOT NULL DEFAULT 0,
  epss_score REAL,
  epss_percentile REAL
);

CREATE TABLE IF NOT EXISTS cve_cwe (
  cve_id TEXT NOT NULL,
  cwe_id TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT '',
  cwe_type TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (cve_id, cwe_id, source, cwe_type)
);

CREATE TABLE IF NOT EXISTS cwe (
  cwe_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  abstraction TEXT,
  status TEXT
);

CREATE TABLE IF NOT EXISTS cpe_match (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cve_id TEXT NOT NULL,
  part TEXT,
  vendor TEXT,
  product TEXT,
  version TEXT,
  update_ver TEXT,
  criteria TEXT NOT NULL,
  vulnerable INTEGER NOT NULL,
  version_start_including TEXT,
  version_start_excluding TEXT,
  version_end_including TEXT,
  version_end_excluding TEXT
);

CREATE INDEX IF NOT EXISTS idx_cpe_lookup ON cpe_match(part, vendor, product);
CREATE INDEX IF NOT EXISTS idx_cpe_cve ON cpe_match(cve_id);

CREATE TABLE IF NOT EXISTS kev (
  cve_id TEXT PRIMARY KEY,
  vendor_project TEXT,
  product TEXT,
  vulnerability_name TEXT,
  date_added TEXT,
  short_description TEXT,
  required_action TEXT,
  due_date TEXT,
  known_ransomware TEXT
);

CREATE TABLE IF NOT EXISTS epss (
  cve_id TEXT PRIMARY KEY,
  score REAL,
  percentile REAL,
  score_date TEXT
);

CREATE TABLE IF NOT EXISTS scan (
  scan_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  started_at TEXT NOT NULL,
  scope TEXT,
  sample INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS inventory (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  asset TEXT NOT NULL,
  asset_kind TEXT NOT NULL,
  component TEXT NOT NULL,
  version TEXT,
  source TEXT,
  mapped INTEGER NOT NULL DEFAULT 0,
  evidence TEXT
);

CREATE TABLE IF NOT EXISTS finding (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  asset TEXT NOT NULL,
  asset_kind TEXT NOT NULL,
  component TEXT NOT NULL,
  installed_version TEXT,
  cve_id TEXT,
  cwe_ids TEXT NOT NULL DEFAULT '[]',
  cwe_names TEXT NOT NULL DEFAULT '[]',
  title TEXT NOT NULL,
  cvss_score REAL,
  cvss_vector TEXT,
  cvss_severity TEXT,
  cvss_version TEXT,
  cvss_v4_score REAL,
  kev INTEGER NOT NULL DEFAULT 0,
  epss_score REAL,
  epss_percentile REAL,
  remediation TEXT,
  evidence TEXT,
  risk_score REAL NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_finding_scan ON finding(scan_id);
"""


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if self.path.parent and not self.path.parent.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> Database:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def meta_get(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return None if row is None else str(row["value"])

    def meta_set(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        self.conn.commit()

    def upsert_cve(self, record: dict[str, Any], cwes: list[dict[str, str]], cpes: list[dict[str, Any]]) -> None:
        cve_id = record["cve_id"]
        enrichment = self._enrichment(cve_id)
        record = {**record, **enrichment}
        self.conn.execute(
            """
            INSERT INTO cve (
              cve_id, description, published, last_modified, vuln_status,
              cvss_v3_version, cvss_v3_score, cvss_v3_vector, cvss_v3_severity,
              cvss_v4_score, cvss_v4_vector, cvss_v4_severity,
              kev, epss_score, epss_percentile
            ) VALUES (
              :cve_id, :description, :published, :last_modified, :vuln_status,
              :cvss_v3_version, :cvss_v3_score, :cvss_v3_vector, :cvss_v3_severity,
              :cvss_v4_score, :cvss_v4_vector, :cvss_v4_severity,
              :kev, :epss_score, :epss_percentile
            )
            ON CONFLICT(cve_id) DO UPDATE SET
              description = excluded.description,
              published = excluded.published,
              last_modified = excluded.last_modified,
              vuln_status = excluded.vuln_status,
              cvss_v3_version = excluded.cvss_v3_version,
              cvss_v3_score = excluded.cvss_v3_score,
              cvss_v3_vector = excluded.cvss_v3_vector,
              cvss_v3_severity = excluded.cvss_v3_severity,
              cvss_v4_score = excluded.cvss_v4_score,
              cvss_v4_vector = excluded.cvss_v4_vector,
              cvss_v4_severity = excluded.cvss_v4_severity,
              kev = excluded.kev,
              epss_score = excluded.epss_score,
              epss_percentile = excluded.epss_percentile
            """,
            record,
        )
        self.conn.execute("DELETE FROM cve_cwe WHERE cve_id = ?", (cve_id,))
        self.conn.executemany(
            "INSERT OR REPLACE INTO cve_cwe(cve_id, cwe_id, source, cwe_type) VALUES(?, ?, ?, ?)",
            [(cve_id, item["cwe_id"], item.get("source", ""), item.get("cwe_type", "")) for item in cwes],
        )
        self.conn.execute("DELETE FROM cpe_match WHERE cve_id = ?", (cve_id,))
        self.conn.executemany(
            """
            INSERT INTO cpe_match (
              cve_id, part, vendor, product, version, update_ver, criteria, vulnerable,
              version_start_including, version_start_excluding,
              version_end_including, version_end_excluding
            ) VALUES (
              :cve_id, :part, :vendor, :product, :version, :update_ver, :criteria, :vulnerable,
              :version_start_including, :version_start_excluding,
              :version_end_including, :version_end_excluding
            )
            """,
            cpes,
        )

    def commit(self) -> None:
        self.conn.commit()

    def upsert_cwes(self, rows: list[dict[str, str]]) -> int:
        self.conn.executemany(
            """
            INSERT INTO cwe(cwe_id, name, description, abstraction, status)
            VALUES(:cwe_id, :name, :description, :abstraction, :status)
            ON CONFLICT(cwe_id) DO UPDATE SET
              name = excluded.name,
              description = excluded.description,
              abstraction = excluded.abstraction,
              status = excluded.status
            """,
            rows,
        )
        self.conn.commit()
        return len(rows)

    def replace_kev(self, rows: list[dict[str, str]]) -> int:
        """KEV 피드는 전체 스냅샷으로 보고 기존 표를 교체한다."""
        self.conn.execute("DELETE FROM kev")
        self.conn.executemany(
            """
            INSERT INTO kev (
              cve_id, vendor_project, product, vulnerability_name, date_added,
              short_description, required_action, due_date, known_ransomware
            ) VALUES (
              :cve_id, :vendor_project, :product, :vulnerability_name, :date_added,
              :short_description, :required_action, :due_date, :known_ransomware
            )
            """,
            rows,
        )
        self.conn.execute("UPDATE cve SET kev = 0")
        self.conn.execute("UPDATE cve SET kev = 1 WHERE cve_id IN (SELECT cve_id FROM kev)")
        self.conn.commit()
        return len(rows)

    def upsert_epss(self, rows: list[dict[str, Any]], *, replace: bool = False) -> int:
        if replace:
            self.conn.execute("DELETE FROM epss")
        self.conn.executemany(
            """
            INSERT INTO epss(cve_id, score, percentile, score_date)
            VALUES(:cve_id, :score, :percentile, :score_date)
            ON CONFLICT(cve_id) DO UPDATE SET
              score = excluded.score,
              percentile = excluded.percentile,
              score_date = excluded.score_date
            """,
            rows,
        )
        self.conn.execute(
            """
            UPDATE cve SET
              epss_score = (SELECT score FROM epss WHERE epss.cve_id = cve.cve_id),
              epss_percentile = (SELECT percentile FROM epss WHERE epss.cve_id = cve.cve_id)
            WHERE cve_id IN (SELECT cve_id FROM epss)
            """
        )
        self.conn.commit()
        return len(rows)

    def _enrichment(self, cve_id: str) -> dict[str, Any]:
        kev = self.conn.execute("SELECT 1 FROM kev WHERE cve_id = ?", (cve_id,)).fetchone()
        epss = self.conn.execute("SELECT score, percentile FROM epss WHERE cve_id = ?", (cve_id,)).fetchone()
        return {
            "kev": 1 if kev else 0,
            "epss_score": None if epss is None else epss["score"],
            "epss_percentile": None if epss is None else epss["percentile"],
        }

    def cve_count(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) AS n FROM cve").fetchone()
        return int(row["n"])

    def cwe_count(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) AS n FROM cwe").fetchone()
        return int(row["n"])

    def cve_ids(self) -> list[str]:
        return [str(row["cve_id"]) for row in self.conn.execute("SELECT cve_id FROM cve ORDER BY cve_id")]

    def get_cve(self, cve_id: str) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM cve WHERE cve_id = ?", (cve_id,)).fetchone()

    def cwes_for(self, cve_id: str) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                "SELECT * FROM cve_cwe WHERE cve_id = ? ORDER BY cwe_type DESC, cwe_id",
                (cve_id,),
            )
        )

    def cwe_name(self, cwe_id: str) -> str | None:
        numeric = cwe_id[4:] if cwe_id.upper().startswith("CWE-") else cwe_id
        row = self.conn.execute("SELECT name FROM cwe WHERE cwe_id = ?", (numeric,)).fetchone()
        return None if row is None else str(row["name"])

    def kev_action(self, cve_id: str) -> str | None:
        row = self.conn.execute("SELECT required_action FROM kev WHERE cve_id = ?", (cve_id,)).fetchone()
        if row is None or not row["required_action"]:
            return None
        return str(row["required_action"])

    def cpe_rows(self, part: str, vendor: str, product: str) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                """
                SELECT * FROM cpe_match
                WHERE vulnerable = 1 AND part = ? AND vendor = ? AND product = ?
                """,
                (part, vendor, product),
            )
        )

    def product_rows(self, part: str, vendor: str, product: str) -> list[sqlite3.Row]:
        """취약 여부와 관계없이 같은 제품의 CPE. 수정 버전 힌트에 쓴다."""
        return list(
            self.conn.execute(
                """
                SELECT * FROM cpe_match
                WHERE part = ? AND vendor = ? AND product = ?
                """,
                (part, vendor, product),
            )
        )

    def add_scan(self, scan_id: str, kind: str, started_at: str, scope: str, sample: bool) -> None:
        self.conn.execute(
            "INSERT INTO scan(scan_id, kind, started_at, scope, sample) VALUES(?, ?, ?, ?, ?)",
            (scan_id, kind, started_at, scope, 1 if sample else 0),
        )

    def add_inventory(self, rows: list[dict[str, Any]]) -> None:
        self.conn.executemany(
            """
            INSERT INTO inventory(
              scan_id, asset, asset_kind, component, version, source, mapped, evidence
            ) VALUES (
              :scan_id, :asset, :asset_kind, :component, :version, :source, :mapped, :evidence
            )
            """,
            rows,
        )

    def add_findings(self, rows: list[dict[str, Any]]) -> None:
        payload = []
        for row in rows:
            item = dict(row)
            item["cwe_ids"] = json.dumps(item.get("cwe_ids") or [], ensure_ascii=False)
            item["cwe_names"] = json.dumps(item.get("cwe_names") or [], ensure_ascii=False)
            payload.append(item)
        self.conn.executemany(
            """
            INSERT INTO finding (
              scan_id, asset, asset_kind, component, installed_version, cve_id,
              cwe_ids, cwe_names, title, cvss_score, cvss_vector, cvss_severity,
              cvss_version, cvss_v4_score, kev, epss_score, epss_percentile,
              remediation, evidence, risk_score
            ) VALUES (
              :scan_id, :asset, :asset_kind, :component, :installed_version, :cve_id,
              :cwe_ids, :cwe_names, :title, :cvss_score, :cvss_vector, :cvss_severity,
              :cvss_version, :cvss_v4_score, :kev, :epss_score, :epss_percentile,
              :remediation, :evidence, :risk_score
            )
            """,
            payload,
        )

    def finish_scan(self) -> None:
        self.conn.commit()

    def latest_scan_id(self) -> str | None:
        row = self.conn.execute("SELECT scan_id FROM scan ORDER BY started_at DESC, scan_id DESC LIMIT 1").fetchone()
        return None if row is None else str(row["scan_id"])

    def scan_row(self, scan_id: str) -> sqlite3.Row | None:
        return self.conn.execute("SELECT * FROM scan WHERE scan_id = ?", (scan_id,)).fetchone()

    def scans(self) -> list[sqlite3.Row]:
        return list(self.conn.execute("SELECT * FROM scan ORDER BY started_at, scan_id"))

    def findings(self, scan_id: str | None) -> list[sqlite3.Row]:
        if scan_id is None or scan_id == "all":
            query = "SELECT * FROM finding ORDER BY risk_score DESC, cvss_score DESC, cve_id"
            rows = list(self.conn.execute(query))
        else:
            rows = list(
                self.conn.execute(
                    """
                    SELECT * FROM finding WHERE scan_id = ?
                    ORDER BY risk_score DESC, cvss_score DESC, cve_id
                    """,
                    (scan_id,),
                )
            )
        return rows

    def inventory_count(self, scan_id: str | None) -> int:
        if scan_id is None or scan_id == "all":
            row = self.conn.execute("SELECT COUNT(*) AS n FROM inventory").fetchone()
        else:
            row = self.conn.execute("SELECT COUNT(*) AS n FROM inventory WHERE scan_id = ?", (scan_id,)).fetchone()
        return int(row["n"])

    def export_cves(self) -> list[dict[str, Any]]:
        rows = []
        for cve in self.conn.execute("SELECT * FROM cve ORDER BY cve_id"):
            cwes = [str(item["cwe_id"]) for item in self.cwes_for(str(cve["cve_id"]))]
            rows.append({**dict(cve), "cwe_ids": cwes})
        return rows

    def export_cwes(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self.conn.execute("SELECT * FROM cwe ORDER BY CAST(cwe_id AS INTEGER)")]
