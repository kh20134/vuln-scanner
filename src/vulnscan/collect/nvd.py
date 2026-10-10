"""NVD CVE API 2.0 수집.

공개 한도는 30초당 5회, API 키가 있으면 30초당 50회다.
날짜 범위는 한 요청에 120일을 넘기지 않는다. 키는 환경 변수 ``NVD_API_KEY``만 읽는다.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode

from vulnscan import __version__
from vulnscan.db import Database
from vulnscan.errors import DataError
from vulnscan.http_client import HttpClient
from vulnscan.match.cpe import parse_cpe23

NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# NVD는 120일 초과 범위를 거절한다. 하루를 빼 경계 오류를 피한다.
MAX_WINDOW = timedelta(days=119)
PAGE_SIZE = 2000
PUBLIC_INTERVAL = 6.0
KEY_INTERVAL = 0.6

Sleep = Callable[[float], None]


def user_agent() -> str:
    return f"vulnscan/{__version__} (defensive local assessment)"


def parse_user_datetime(value: str) -> datetime:
    text = value.strip()
    if len(text) == 10:
        parsed = datetime.strptime(text, "%Y-%m-%d")
        return parsed.replace(tzinfo=UTC)
    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def nvd_stamp(moment: datetime) -> str:
    utc = moment.astimezone(UTC).replace(tzinfo=None)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]


def iter_windows(start: datetime, end: datetime) -> Iterator[tuple[datetime, datetime]]:
    if end <= start:
        return
    cursor = start
    while cursor < end:
        nxt = min(cursor + MAX_WINDOW, end)
        yield cursor, nxt
        cursor = nxt


def _pick_metric(metrics: dict[str, Any], key: str) -> dict[str, Any] | None:
    scored = []
    for item in metrics.get(key) or []:
        data = item.get("cvssData") or {}
        if data.get("baseScore") is None:
            continue
        scored.append(item)
    if not scored:
        return None

    def rank(item: dict[str, Any]) -> tuple[int, int]:
        primary = 0 if item.get("type") == "Primary" else 1
        source = str(item.get("source") or "")
        nvd = 0 if "nvd.nist.gov" in source else 1
        return primary, nvd

    scored.sort(key=rank)
    return scored[0]


def parse_cve_item(item: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, str]], list[dict[str, Any]]]:
    """API의 vulnerabilities[] 원소 하나를 저장 행으로 바꾼다."""
    cve = item.get("cve") or item
    cve_id = cve.get("id")
    if not cve_id:
        raise DataError("NVD 항목에 CVE ID가 없습니다.")
    description = ""
    for entry in cve.get("descriptions") or []:
        if entry.get("lang") == "en" and entry.get("value"):
            description = str(entry["value"])
            break
    if not description and cve.get("descriptions"):
        description = str(cve["descriptions"][0].get("value") or "")
    metrics = cve.get("metrics") or {}
    v3 = _pick_metric(metrics, "cvssMetricV31") or _pick_metric(metrics, "cvssMetricV30")
    v4 = _pick_metric(metrics, "cvssMetricV40")
    v3_data = (v3 or {}).get("cvssData") or {}
    v4_data = (v4 or {}).get("cvssData") or {}
    record = {
        "cve_id": cve_id,
        "description": description,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "vuln_status": cve.get("vulnStatus"),
        "cvss_v3_version": v3_data.get("version"),
        "cvss_v3_score": v3_data.get("baseScore"),
        "cvss_v3_vector": v3_data.get("vectorString"),
        "cvss_v3_severity": v3_data.get("baseSeverity"),
        "cvss_v4_score": v4_data.get("baseScore"),
        "cvss_v4_vector": v4_data.get("vectorString"),
        "cvss_v4_severity": v4_data.get("baseSeverity"),
    }
    cwes: list[dict[str, str]] = []
    for weakness in cve.get("weaknesses") or []:
        source = str(weakness.get("source") or "")
        kind = str(weakness.get("type") or "")
        for desc in weakness.get("description") or []:
            value = str(desc.get("value") or "").strip()
            if value:
                cwes.append({"cwe_id": value, "source": source, "cwe_type": kind})
    cpes: list[dict[str, Any]] = []
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                criteria = str(match.get("criteria") or "")
                parsed = parse_cpe23(criteria)
                if parsed is None:
                    continue
                cpes.append(
                    {
                        "cve_id": cve_id,
                        "part": parsed["part"],
                        "vendor": parsed["vendor"],
                        "product": parsed["product"],
                        "version": parsed["version"],
                        "update_ver": parsed["update"],
                        "criteria": parsed["criteria"],
                        "vulnerable": 1 if match.get("vulnerable") else 0,
                        "version_start_including": match.get("versionStartIncluding"),
                        "version_start_excluding": match.get("versionStartExcluding"),
                        "version_end_including": match.get("versionEndIncluding"),
                        "version_end_excluding": match.get("versionEndExcluding"),
                    }
                )
    return record, cwes, cpes


def load_nvd_document(db: Database, document: dict[str, Any]) -> int:
    if document.get("format") not in {None, "NVD_CVE"}:
        raise DataError(f"지원하지 않는 NVD format: {document.get('format')}")
    if document.get("version") not in {None, "2.0"}:
        raise DataError(f"지원하지 않는 NVD version: {document.get('version')}")
    count = 0
    for item in document.get("vulnerabilities") or []:
        record, cwes, cpes = parse_cve_item(item)
        db.upsert_cve(record, cwes, cpes)
        count += 1
    db.commit()
    return count


class Pace:
    """요청 사이 최소 간격. 첫 요청 전에는 기다리지 않는다."""

    def __init__(self, interval: float, sleep: Sleep = time.sleep) -> None:
        self.interval = interval
        self.sleep = sleep
        self._next = 0.0

    def wait(self) -> None:
        now = time.monotonic()
        if self._next > now:
            self.sleep(self._next - now)
        self._next = time.monotonic() + self.interval


def _headers(api_key: str | None) -> dict[str, str]:
    headers = {"User-Agent": user_agent(), "Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key
    return headers


def fetch_nvd_page(
    client: HttpClient,
    params: dict[str, str],
    api_key: str | None,
    *,
    attempts: int = 4,
    sleep: Sleep = time.sleep,
) -> dict[str, Any]:
    url = f"{NVD_CVE_URL}?{urlencode(params)}"
    last_error = "NVD 응답 없음"
    for attempt in range(attempts):
        response = client.get(url, headers=_headers(api_key))
        if response.status == 200:
            try:
                payload = json.loads(response.body.decode("utf-8"))
            except json.JSONDecodeError as exc:
                raise DataError("NVD 응답이 JSON이 아닙니다.") from exc
            if not isinstance(payload, dict):
                raise DataError("NVD 응답 형식이 객체가 아닙니다.")
            return payload
        last_error = f"HTTP {response.status}: {response.body[:200]!r}"
        if response.status in {403, 429, 503}:
            sleep(PUBLIC_INTERVAL * (attempt + 1))
            continue
        break
    raise DataError(f"NVD 조회 실패 ({params.get('cveId') or params.get('lastModStartDate')}): {last_error}")


def _store_pages(
    db: Database,
    client: HttpClient,
    params: dict[str, str],
    api_key: str | None,
    pace: Pace,
) -> int:
    start_index = 0
    stored = 0
    while True:
        pace.wait()
        page_params = {**params, "startIndex": str(start_index), "resultsPerPage": str(PAGE_SIZE)}
        document = fetch_nvd_page(client, page_params, api_key, sleep=pace.sleep)
        vulns = document.get("vulnerabilities") or []
        total = int(document.get("totalResults") or 0)
        if not vulns:
            break
        stored += load_nvd_document(db, document)
        start_index = int(document.get("startIndex") or 0) + len(vulns)
        if start_index >= total:
            break
    return stored


def update_nvd(
    db: Database,
    client: HttpClient,
    *,
    api_key: str | None,
    since: datetime | None,
    until: datetime | None,
    cve_ids: list[str] | None = None,
    sleep: Sleep = time.sleep,
    advance_cursor: bool = True,
) -> int:
    """증분 또는 CVE ID 단위로 NVD를 받아 업서트한다."""
    interval = KEY_INTERVAL if api_key else PUBLIC_INTERVAL
    pace = Pace(interval, sleep=sleep)
    stored = 0
    if cve_ids:
        for cve_id in cve_ids:
            stored += _store_pages(db, client, {"cveId": cve_id}, api_key, pace)
        return stored
    end = until or datetime.now(UTC)
    if since is None:
        previous = db.meta_get("nvd_last_mod_end")
        if previous:
            since = parse_user_datetime(previous)
        else:
            since = end - timedelta(days=7)
    if end <= since:
        return 0
    for window_start, window_end in iter_windows(since, end):
        stored += _store_pages(
            db,
            client,
            {
                "lastModStartDate": nvd_stamp(window_start),
                "lastModEndDate": nvd_stamp(window_end),
            },
            api_key,
            pace,
        )
    if advance_cursor:
        db.meta_set("nvd_last_mod_end", nvd_stamp(end))
    return stored
