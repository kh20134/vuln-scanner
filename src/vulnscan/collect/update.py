"""수집 작업 조합. ``--sample``은 네트워크를 쓰지 않는다."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from importlib.resources import files
from pathlib import Path

from vulnscan.collect.cwe import CWE_XML_URL, load_cwe_bytes
from vulnscan.collect.epss import EPSS_FEED, epss_api_url, load_epss_bytes
from vulnscan.collect.kev import KEV_URL, load_kev_bytes
from vulnscan.collect.nvd import load_nvd_document, parse_user_datetime, update_nvd
from vulnscan.db import Database
from vulnscan.errors import DataError
from vulnscan.http_client import HttpClient

Sleep = Callable[[float], None]
# 이보다 많으면 CVE마다 API를 치지 않고 일일 CSV를 받는다.
EPSS_API_LIMIT = 2000


def sample_bytes(name: str) -> bytes:
    """패키지 데이터 또는 소스 트리의 표본 파일을 읽는다."""
    resource = files("vulnscan").joinpath("data/sample").joinpath(name)
    try:
        data = resource.read_bytes()
    except (FileNotFoundError, OSError, TypeError):
        data = b""
    if data:
        return data
    fallback = Path(__file__).resolve().parents[1] / "data" / "sample" / name
    if not fallback.is_file():
        raise DataError(f"표본 파일이 없습니다: {name}")
    return fallback.read_bytes()


def load_sample(db: Database) -> dict[str, int]:
    nvd = json.loads(sample_bytes("nvd-sample.json").decode("utf-8"))
    kev = json.loads(sample_bytes("kev-sample.json").decode("utf-8"))
    counts = {
        "nvd": load_nvd_document(db, nvd),
        "cwe": load_cwe_bytes(db, sample_bytes("cwec-sample.xml")),
        "kev": load_kev_bytes(db, json.dumps(kev).encode("utf-8")),
        "epss": load_epss_bytes(db, sample_bytes("epss-sample.json"), replace=False),
    }
    db.meta_set("data_source", "sample")
    return counts


def _read_local(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


def run_update(
    db: Database,
    *,
    source: str,
    since: str | None,
    until: str | None,
    days: int | None,
    cve_ids: list[str] | None,
    sample: bool,
    nvd_file: str | None,
    cwe_file: str | None,
    kev_file: str | None,
    epss_file: str | None,
    epss_feed: bool,
    api_key: str | None,
    client: HttpClient | None = None,
    sleep: Sleep | None = None,
) -> dict[str, int]:
    if sample:
        return load_sample(db)
    http = client or HttpClient()
    sleeper: Sleep = sleep or (lambda seconds: __import__("time").sleep(seconds))
    counts: dict[str, int] = {}
    want_nvd = source in {"all", "nvd"}
    want_cwe = source in {"all", "cwe"}
    want_kev = source in {"all", "kev"}
    want_epss = source in {"all", "epss"}

    if want_nvd:
        if nvd_file:
            document = json.loads(_read_local(nvd_file).decode("utf-8"))
            if not isinstance(document, dict):
                raise DataError("NVD 파일이 객체가 아닙니다.")
            counts["nvd"] = load_nvd_document(db, document)
        else:
            start = parse_user_datetime(since) if since else None
            end = parse_user_datetime(until) if until else None
            if days is not None and since is None:
                end = end or datetime.now(UTC)
                start = end - timedelta(days=days)
            counts["nvd"] = update_nvd(
                db,
                http,
                api_key=api_key,
                since=start,
                until=end,
                cve_ids=cve_ids or None,
                sleep=sleeper,
                advance_cursor=not cve_ids,
            )
    if want_cwe:
        if cwe_file:
            payload = _read_local(cwe_file)
        else:
            payload = _fetch_ok(http, CWE_XML_URL)
        counts["cwe"] = load_cwe_bytes(db, payload)
    if want_kev:
        counts["kev"] = load_kev_bytes(db, _read_local(kev_file) if kev_file else _fetch_ok(http, KEV_URL))
    if want_epss:
        if epss_file:
            counts["epss"] = load_epss_bytes(db, _read_local(epss_file), replace=False)
        elif epss_feed or db.cve_count() > EPSS_API_LIMIT:
            counts["epss"] = load_epss_bytes(db, _fetch_ok(http, EPSS_FEED), replace=True)
        else:
            ids = db.cve_ids()
            stored = 0
            for index, offset in enumerate(range(0, len(ids), 100)):
                batch = ids[offset : offset + 100]
                if not batch:
                    continue
                if index:
                    sleeper(0.2)
                payload = _fetch_ok(http, epss_api_url(batch))
                stored += load_epss_bytes(db, payload, replace=False)
            counts["epss"] = stored
    if not counts:
        raise DataError("선택한 수집 소스가 없습니다.")
    db.meta_set("data_source", "live-or-file")
    return counts


def _fetch_ok(client: HttpClient, url: str) -> bytes:
    response = client.get(url, headers={"User-Agent": "vulnscan (defensive local assessment)"})
    if response.status != 200:
        raise DataError(f"다운로드 실패 HTTP {response.status}: {url}")
    return response.body
