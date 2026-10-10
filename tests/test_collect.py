import json
from datetime import UTC, datetime

from vulnscan.collect.cwe import parse_cwe_xml
from vulnscan.collect.epss import parse_epss_api, parse_epss_csv
from vulnscan.collect.kev import parse_kev
from vulnscan.collect.nvd import (
    iter_windows,
    load_nvd_document,
    nvd_stamp,
    parse_cve_item,
    update_nvd,
)
from vulnscan.collect.update import load_sample
from vulnscan.db import Database
from vulnscan.http_client import HttpClient


class _Response:
    def __init__(self, body: bytes, status: int = 200):
        self.status = status
        self.headers = {}
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _document(cve_id: str, start: int, total: int) -> dict:
    return {
        "format": "NVD_CVE",
        "version": "2.0",
        "startIndex": start,
        "totalResults": total,
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "published": "2024-01-01T00:00:00.000",
                    "lastModified": "2024-01-02T00:00:00.000",
                    "vulnStatus": "Analyzed",
                    "descriptions": [{"lang": "en", "value": "Example."}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "type": "Primary",
                                "source": "nvd@nist.gov",
                                "cvssData": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL",
                                },
                            }
                        ],
                        "cvssMetricV40": [
                            {
                                "type": "Primary",
                                "source": "nvd@nist.gov",
                                "cvssData": {
                                    "version": "4.0",
                                    "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                                    "baseScore": 9.3,
                                    "baseSeverity": "CRITICAL",
                                },
                            }
                        ],
                    },
                    "weaknesses": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "description": [{"lang": "en", "value": "CWE-79"}],
                        }
                    ],
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "operator": "OR",
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*",
                                        }
                                    ],
                                }
                            ]
                        }
                    ],
                }
            }
        ],
    }


def test_parse_keeps_v3_and_v4():
    record, cwes, cpes = parse_cve_item(_document("CVE-2024-0001", 0, 1)["vulnerabilities"][0])
    assert record["cvss_v3_score"] == 9.8
    assert record["cvss_v4_score"] == 9.3
    assert cwes[0]["cwe_id"] == "CWE-79"
    assert cpes[0]["product"] == "widget"


def test_windows_stay_inside_119_days():
    start = datetime(2024, 1, 1, tzinfo=UTC)
    end = datetime(2024, 9, 1, tzinfo=UTC)
    windows = list(iter_windows(start, end))
    assert len(windows) >= 2
    for left, right in windows:
        assert (right - left).days <= 119
    assert windows[0][0] == start
    assert windows[-1][1] == end
    assert nvd_stamp(start) == "2024-01-01T00:00:00.000"


def test_pagination_and_pace_without_live_network(tmp_path):
    pages = {
        0: _document("CVE-2024-0001", 0, 2),
        1: _document("CVE-2024-0002", 1, 2),
    }
    calls = []
    sleeps = []

    def opener(request, timeout=60):
        url = request.full_url
        calls.append(url)
        start = 0
        if "startIndex=1" in url:
            start = 1
        body = json.dumps(pages[start]).encode()
        return _Response(body)

    def fake_sleep(seconds):
        sleeps.append(seconds)

    with Database(tmp_path / "t.db") as db:
        stored = update_nvd(
            db,
            HttpClient(opener=opener),
            api_key=None,
            since=datetime(2024, 1, 1, tzinfo=UTC),
            until=datetime(2024, 1, 8, tzinfo=UTC),
            sleep=fake_sleep,
        )
        assert stored == 2
        assert db.cve_count() == 2
        assert db.get_cve("CVE-2024-0002")["cvss_v4_score"] == 9.3
    assert len(calls) == 2
    assert len(sleeps) == 1
    assert 5.5 <= sleeps[0] <= 6.0
    assert "apiKey" not in calls[0]


def test_sample_dataset_roundtrip(tmp_path):
    with Database(tmp_path / "sample.db") as db:
        counts = load_sample(db)
        assert counts["nvd"] == 10
        assert counts["cwe"] >= 30
        assert counts["kev"] == 5
        assert db.get_cve("CVE-2024-6387")["cvss_v3_score"] == 8.1
        assert db.get_cve("CVE-2021-44228")["kev"] == 1
        assert db.get_cve("CVE-2024-6387")["epss_score"] is not None
        assert db.cwe_name("CWE-362")
        assert "Race Condition" in db.cwe_name("CWE-362")


def test_cwe_xml_and_epss_parsers():
    xml = b"""<?xml version="1.0"?>
    <Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7">
      <Weaknesses>
        <Weakness ID="79" Name="XSS" Abstraction="Base" Status="Stable">
          <Description>cross site</Description>
        </Weakness>
      </Weaknesses>
    </Weakness_Catalog>
    """
    rows = parse_cwe_xml(xml)
    assert rows[0]["cwe_id"] == "79"
    assert rows[0]["description"] == "cross site"
    api = parse_epss_api({"data": [{"cve": "CVE-1", "epss": "0.5", "percentile": "0.9", "date": "2026-01-01"}]})
    assert api[0]["score"] == 0.5
    csv_rows = parse_epss_csv("#score_date:2026-01-01T00:00:00+0000\ncve,epss,percentile\nCVE-1,0.2,0.3\n")
    assert csv_rows[0]["cve_id"] == "CVE-1"
    assert parse_kev({"vulnerabilities": [{"cveID": "CVE-1", "requiredAction": "patch"}]})[0]["cve_id"] == "CVE-1"


def test_load_document_replaces_cpe(tmp_path):
    with Database(tmp_path / "t.db") as db:
        load_nvd_document(db, _document("CVE-2024-0001", 0, 1))
        load_nvd_document(db, _document("CVE-2024-0001", 0, 1))
        rows = db.cpe_rows("a", "example", "widget")
        assert len(rows) == 1
