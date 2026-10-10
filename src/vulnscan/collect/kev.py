"""CISA Known Exploited Vulnerabilities JSON 피드."""

from __future__ import annotations

import json
from typing import Any

from vulnscan.db import Database
from vulnscan.errors import DataError

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def parse_kev(document: dict[str, Any]) -> list[dict[str, str]]:
    rows = []
    for item in document.get("vulnerabilities") or []:
        cve_id = item.get("cveID") or item.get("cveId")
        if not cve_id:
            continue
        rows.append(
            {
                "cve_id": str(cve_id),
                "vendor_project": str(item.get("vendorProject") or ""),
                "product": str(item.get("product") or ""),
                "vulnerability_name": str(item.get("vulnerabilityName") or ""),
                "date_added": str(item.get("dateAdded") or ""),
                "short_description": str(item.get("shortDescription") or ""),
                "required_action": str(item.get("requiredAction") or ""),
                "due_date": str(item.get("dueDate") or ""),
                "known_ransomware": str(item.get("knownRansomwareCampaignUse") or ""),
            }
        )
    if not rows:
        raise DataError("KEV 목록이 비어 있습니다.")
    return rows


def load_kev_document(db: Database, document: dict[str, Any]) -> int:
    return db.replace_kev(parse_kev(document))


def load_kev_bytes(db: Database, payload: bytes) -> int:
    try:
        document = json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise DataError("KEV JSON을 해석하지 못했습니다.") from exc
    if not isinstance(document, dict):
        raise DataError("KEV 응답이 객체가 아닙니다.")
    return load_kev_document(db, document)
