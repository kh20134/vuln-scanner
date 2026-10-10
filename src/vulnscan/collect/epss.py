"""FIRST EPSS. 소량 CVE는 API, 대량은 일일 CSV 피드를 쓴다."""

from __future__ import annotations

import csv
import gzip
import io
import json
from typing import Any

from vulnscan.db import Database
from vulnscan.errors import DataError

EPSS_API = "https://api.first.org/data/v1/epss"
EPSS_FEED = "https://epss.cyentia.com/epss_scores-current.csv.gz"
API_BATCH = 100


def parse_epss_api(document: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for item in document.get("data") or []:
        cve_id = item.get("cve")
        if not cve_id:
            continue
        rows.append(
            {
                "cve_id": str(cve_id),
                "score": float(item["epss"]) if item.get("epss") not in {None, ""} else None,
                "percentile": float(item["percentile"]) if item.get("percentile") not in {None, ""} else None,
                "score_date": str(item.get("date") or ""),
            }
        )
    return rows


def parse_epss_csv(text: str) -> list[dict[str, Any]]:
    lines = [line for line in text.splitlines() if line and not line.startswith("#")]
    if not lines:
        raise DataError("EPSS CSV가 비어 있습니다.")
    score_date = ""
    for line in text.splitlines():
        if line.startswith("#") and "score_date:" in line:
            score_date = line.split("score_date:", 1)[1].split(",")[0].strip()
            break
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    rows = []
    for item in reader:
        cve_id = item.get("cve")
        if not cve_id:
            continue
        rows.append(
            {
                "cve_id": cve_id.strip(),
                "score": float(item["epss"]) if item.get("epss") else None,
                "percentile": float(item["percentile"]) if item.get("percentile") else None,
                "score_date": score_date,
            }
        )
    if not rows:
        raise DataError("EPSS CSV에서 CVE를 찾지 못했습니다.")
    return rows


def maybe_decompress(payload: bytes) -> bytes:
    if payload[:2] == b"\x1f\x8b":
        return gzip.decompress(payload)
    return payload


def load_epss_bytes(db: Database, payload: bytes, *, replace: bool) -> int:
    raw = maybe_decompress(payload)
    text = raw.decode("utf-8")
    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            document = json.loads(text)
        except json.JSONDecodeError as exc:
            raise DataError("EPSS JSON을 해석하지 못했습니다.") from exc
        if not isinstance(document, dict):
            raise DataError("EPSS JSON 형식이 객체가 아닙니다.")
        rows = parse_epss_api(document)
    else:
        rows = parse_epss_csv(text)
        replace = True
    if not rows:
        raise DataError("EPSS 점수가 없습니다.")
    return db.upsert_epss(rows, replace=replace)


def epss_api_url(cve_ids: list[str]) -> str:
    return f"{EPSS_API}?cve={','.join(cve_ids)}"
