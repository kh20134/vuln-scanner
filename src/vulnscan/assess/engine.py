"""인벤토리를 로컬 CVE와 맞춰 발견 사항을 저장한다."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from vulnscan.assess.models import ManualFinding, SoftwareItem
from vulnscan.db import Database
from vulnscan.match.cpe import cpe_matches_version
from vulnscan.match.version import combine_cpe_version, compare_versions, upstream_version

_SEVERITY_WEIGHT = {"CRITICAL": 40.0, "HIGH": 30.0, "MEDIUM": 20.0, "LOW": 10.0, "NONE": 0.0}


def risk_score(*, kev: bool, cvss: float | None, epss: float | None, severity: str | None) -> float:
    score = (100.0 if kev else 0.0) + float(cvss or 0.0) * 10.0 + float(epss or 0.0) * 10.0
    score += _SEVERITY_WEIGHT.get((severity or "").upper(), 0.0)
    return round(score, 4)


def new_scan_id(kind: str) -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}-{kind}-{uuid.uuid4().hex[:8]}"


def _describe_row(row: object) -> str:
    version = row["version"] or ""
    update = row["update_ver"] or ""
    if version not in {"", "*", "-"}:
        return f"버전 {combine_cpe_version(version, update)}"
    chunks: list[str] = []
    if row["version_start_including"]:
        chunks.append(f"{row['version_start_including']} 이상")
    if row["version_start_excluding"]:
        chunks.append(f"{row['version_start_excluding']} 초과")
    if row["version_end_including"]:
        chunks.append(f"{row['version_end_including']} 이하")
    if row["version_end_excluding"]:
        chunks.append(f"{row['version_end_excluding']} 미만")
    return ", ".join(chunks) if chunks else "범위 없음"


def remediation_text(
    db: Database,
    cve_id: str,
    installed: str,
    upstream: str,
    matched_rows: list,
) -> str:
    ranges = "; ".join(_describe_row(row) for row in matched_rows)
    shown = installed if installed == upstream else f"{installed} (비교 기준 {upstream})"
    parts = [f"설치 버전 {shown}이 NVD 영향 범위({ranges})에 해당합니다."]
    ends = [row["version_end_excluding"] for row in matched_rows if row["version_end_excluding"]]
    if len(matched_rows) == 1 and ends:
        bound = str(ends[0])
        row = matched_rows[0]
        exacts: list[str] = []
        for sibling in db.product_rows(row["part"], row["vendor"], row["product"]):
            if sibling["cve_id"] != cve_id or int(sibling["vulnerable"]) != 1:
                continue
            if (sibling["version"] or "") in {"", "*", "-"}:
                continue
            exact = combine_cpe_version(sibling["version"], sibling["update_ver"] or "")
            if compare_versions(exact, bound) >= 0:
                exacts.append(exact)
        if exacts:
            listed = ", ".join(sorted(set(exacts)))
            parts.append(
                f"{bound} 이상으로 올리는 것만으로는 부족할 수 있습니다. "
                f"같은 CVE에 개별 취약 버전({listed})이 남아 있습니다. 벤더 권고를 확인하세요."
            )
        else:
            parts.append(
                f"이 CPE 조건에는 {bound}부터 포함되지 않습니다. 그 버전이 실제 수정 버전인지는 벤더 권고로 확인하세요."
            )
    else:
        inclusive = [row["version_end_including"] for row in matched_rows if row["version_end_including"]]
        if len(matched_rows) == 1 and inclusive:
            parts.append(f"NVD 상 취약 상한은 {inclusive[0]}(포함)입니다. 그보다 높은 릴리스로 업데이트하세요.")
        else:
            parts.append("수정 버전은 제조사 보안 권고에서 확인하세요.")
    parts.append("배포판 백포트 패치는 업스트림 버전 번호만으로 구분되지 않을 수 있습니다.")
    action = db.kev_action(cve_id)
    if action:
        parts.append(f"CISA KEV: {action}")
    return " ".join(parts)


def _ordered_cwes(rows: list) -> list[str]:
    primary: list[str] = []
    other: list[str] = []
    for row in rows:
        cwe_id = str(row["cwe_id"])
        if row["cwe_type"] == "Primary" and not cwe_id.startswith("NVD-CWE"):
            primary.append(cwe_id)
        else:
            other.append(cwe_id)
    ordered: list[str] = []
    for cwe_id in primary + other:
        if cwe_id not in ordered:
            ordered.append(cwe_id)
    return ordered


def _cwe_names(db: Database, cwe_ids: list[str]) -> list[str]:
    names: list[str] = []
    for cwe_id in cwe_ids:
        if cwe_id == "NVD-CWE-noinfo":
            names.append("NVD가 CWE를 지정하지 않음")
            continue
        if cwe_id == "NVD-CWE-Other":
            names.append("NVD가 기타로 분류")
            continue
        name = db.cwe_name(cwe_id)
        names.append(name or "")
    return names


def _short_title(description: str, cve_id: str) -> str:
    text = " ".join(description.split())
    if not text:
        return cve_id
    sentence = text.split(". ")[0]
    if len(sentence) > 220:
        return sentence[:217] + "..."
    return sentence


def run_assessment(
    db: Database,
    *,
    kind: str,
    scope: str,
    sample: bool,
    items: list[SoftwareItem],
    manuals: list[ManualFinding] | None = None,
) -> str:
    manuals = manuals or []
    scan_id = new_scan_id(kind)
    started = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    db.add_scan(scan_id, kind, started, scope, sample)
    inventory: list[dict] = []
    findings: list[dict] = []
    for item in items:
        mapped = bool(item.candidates)
        inventory.append(
            {
                "scan_id": scan_id,
                "asset": item.asset,
                "asset_kind": item.asset_kind,
                "component": item.component,
                "version": item.version,
                "source": item.source,
                "mapped": 1 if mapped else 0,
                "evidence": item.evidence,
            }
        )
        if not mapped or not item.version:
            continue
        upstream = upstream_version(item.version)
        matched: dict[str, list] = {}
        for part, vendor, product in item.candidates:
            for row in db.cpe_rows(part, vendor, product):
                if cpe_matches_version(upstream, row):
                    matched.setdefault(str(row["cve_id"]), []).append(row)
        for cve_id, rows in matched.items():
            cve = db.get_cve(cve_id)
            if cve is None:
                continue
            cwe_ids = _ordered_cwes(db.cwes_for(cve_id))
            score = cve["cvss_v3_score"]
            version = cve["cvss_v3_version"]
            vector = cve["cvss_v3_vector"]
            severity = cve["cvss_v3_severity"]
            if score is None and cve["cvss_v4_score"] is not None:
                score = cve["cvss_v4_score"]
                version = "4.0"
                vector = cve["cvss_v4_vector"]
                severity = cve["cvss_v4_severity"]
            findings.append(
                {
                    "scan_id": scan_id,
                    "asset": item.asset,
                    "asset_kind": item.asset_kind,
                    "component": item.component,
                    "installed_version": item.version,
                    "cve_id": cve_id,
                    "cwe_ids": cwe_ids,
                    "cwe_names": _cwe_names(db, cwe_ids),
                    "title": _short_title(str(cve["description"] or ""), cve_id),
                    "cvss_score": score,
                    "cvss_vector": vector,
                    "cvss_severity": severity,
                    "cvss_version": version,
                    "cvss_v4_score": cve["cvss_v4_score"],
                    "kev": int(cve["kev"] or 0),
                    "epss_score": cve["epss_score"],
                    "epss_percentile": cve["epss_percentile"],
                    "remediation": remediation_text(db, cve_id, item.version, upstream, rows),
                    "evidence": item.evidence,
                    "risk_score": risk_score(
                        kev=bool(cve["kev"]),
                        cvss=score,
                        epss=cve["epss_score"],
                        severity=severity,
                    ),
                }
            )
    for manual in manuals:
        cwe_ids = [manual.cwe_id] if manual.cwe_id else []
        findings.append(
            {
                "scan_id": scan_id,
                "asset": manual.asset,
                "asset_kind": manual.asset_kind,
                "component": manual.component,
                "installed_version": "",
                "cve_id": None,
                "cwe_ids": cwe_ids,
                "cwe_names": _cwe_names(db, cwe_ids),
                "title": manual.title,
                "cvss_score": None,
                "cvss_vector": None,
                "cvss_severity": manual.severity,
                "cvss_version": None,
                "cvss_v4_score": None,
                "kev": 0,
                "epss_score": None,
                "epss_percentile": None,
                "remediation": manual.remediation,
                "evidence": manual.evidence,
                "risk_score": risk_score(kev=False, cvss=None, epss=None, severity=manual.severity),
            }
        )
    if inventory:
        db.add_inventory(inventory)
    if findings:
        db.add_findings(findings)
    db.finish_scan()
    return scan_id
