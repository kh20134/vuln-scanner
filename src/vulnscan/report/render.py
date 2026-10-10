"""터미널, JSON, CSV, 단일 HTML 보고서."""

from __future__ import annotations

import csv
import html
import io
import json
import unicodedata
from datetime import UTC, datetime
from typing import Any

from vulnscan import NVD_DISCLAIMER
from vulnscan.db import Database

SEVERITY_KO = {
    "CRITICAL": "긴급",
    "HIGH": "높음",
    "MEDIUM": "중간",
    "LOW": "낮음",
    "NONE": "없음",
}
KIND_KO = {
    "network": "네트워크",
    "server": "서버",
    "endpoint": "엔드포인트",
}


def _loads(value: str | None) -> list[str]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    return [str(item) for item in parsed]


def finding_dict(row: Any) -> dict[str, Any]:
    cwe_ids = _loads(row["cwe_ids"])
    cwe_names = _loads(row["cwe_names"])
    return {
        "asset": row["asset"],
        "asset_kind": row["asset_kind"],
        "asset_kind_ko": KIND_KO.get(row["asset_kind"], row["asset_kind"]),
        "component": row["component"],
        "installed_version": row["installed_version"] or "",
        "cve_id": row["cve_id"],
        "cwe_ids": cwe_ids,
        "cwe_names": cwe_names,
        "title": row["title"],
        "cvss_score": row["cvss_score"],
        "cvss_vector": row["cvss_vector"],
        "cvss_severity": row["cvss_severity"],
        "cvss_severity_ko": SEVERITY_KO.get(row["cvss_severity"] or "", ""),
        "cvss_version": row["cvss_version"],
        "cvss_v4_score": row["cvss_v4_score"],
        "kev": bool(row["kev"]),
        "epss_score": row["epss_score"],
        "epss_percentile": row["epss_percentile"],
        "remediation": row["remediation"] or "",
        "evidence": row["evidence"] or "",
        "risk_score": row["risk_score"],
        "scan_id": row["scan_id"],
    }


def build_report(db: Database, scan_id: str | None, *, sample: bool) -> dict[str, Any]:
    selected = scan_id or db.latest_scan_id()
    if selected is None:
        selected = "all"
    findings = [finding_dict(row) for row in db.findings(selected)]
    summary = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0, "kev": 0, "info": 0}
    for item in findings:
        severity = (item["cvss_severity"] or "").upper()
        if severity == "CRITICAL":
            summary["critical"] += 1
        elif severity == "HIGH":
            summary["high"] += 1
        elif severity == "MEDIUM":
            summary["medium"] += 1
        elif severity == "LOW":
            summary["low"] += 1
        else:
            summary["info"] += 1
        if item["kev"]:
            summary["kev"] += 1
    scan_sample = sample
    scope = ""
    if selected not in {None, "all"}:
        scan = db.scan_row(str(selected))
        if scan is not None:
            scan_sample = scan_sample or bool(scan["sample"])
            scope = scan["scope"] or ""
    elif selected == "all":
        scan_sample = scan_sample or any(bool(row["sample"]) for row in db.scans())
    return {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scan_id": selected,
        "scope": scope,
        "sample": scan_sample,
        "inventory": db.inventory_count(selected),
        "summary": summary,
        "disclaimer": NVD_DISCLAIMER,
        "findings": findings,
    }


def render_json(report: dict[str, Any]) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2) + "\n"


def render_csv(report: dict[str, Any]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "자산",
            "구분",
            "구성요소",
            "설치버전",
            "CVE",
            "CVSS",
            "심각도",
            "CWE",
            "CWE이름",
            "KEV",
            "EPSS",
            "위험점수",
            "제목",
            "조치",
            "근거",
        ]
    )
    for item in report["findings"]:
        writer.writerow(
            [
                item["asset"],
                item["asset_kind_ko"],
                item["component"],
                item["installed_version"],
                item["cve_id"] or "",
                "" if item["cvss_score"] is None else item["cvss_score"],
                item["cvss_severity_ko"] or item["cvss_severity"] or "",
                " ".join(item["cwe_ids"]),
                " / ".join(name for name in item["cwe_names"] if name),
                "예" if item["kev"] else "아니오",
                "" if item["epss_score"] is None else f"{item['epss_score']:.5f}",
                item["risk_score"],
                item["title"],
                item["remediation"],
                item["evidence"],
            ]
        )
    return buffer.getvalue()


def render_table(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "취약점 점검 결과",
        f"생성 시각(UTC): {report['generated_at']}  스캔: {report['scan_id']}",
        (
            f"합계 {summary['total']}  긴급 {summary['critical']}  높음 {summary['high']}  "
            f"중간 {summary['medium']}  낮음 {summary['low']}  KEV {summary['kev']}  "
            f"인벤토리 {report['inventory']}"
        ),
    ]
    if report["sample"]:
        lines.append("표본 보고서입니다. 운영 환경의 실제 점검 결과가 아닙니다.")
    if not report["findings"]:
        lines.append("발견 사항이 없습니다.")
        lines.append(NVD_DISCLAIMER)
        return "\n".join(lines) + "\n"
    headers = ["자산", "구성요소", "CVE", "CVSS", "심각도", "CWE", "KEV", "EPSS", "조치"]
    body: list[list[str]] = []
    for item in report["findings"]:
        cwe = item["cwe_ids"][0] if item["cwe_ids"] else ""
        if item["cwe_names"] and item["cwe_names"][0]:
            cwe = f"{cwe} {item['cwe_names'][0]}"
        epss = "" if item["epss_score"] is None else f"{item['epss_score']:.3f}"
        score = "" if item["cvss_score"] is None else f"{item['cvss_score']:.1f}"
        body.append(
            [
                _clip(item["asset"], 28),
                _clip(item["component"], 18),
                item["cve_id"] or "(설정)",
                score,
                item["cvss_severity_ko"] or item["cvss_severity"] or "",
                _clip(cwe, 36),
                "예" if item["kev"] else "",
                epss,
                _clip(item["remediation"], 42),
            ]
        )
    widths = [_disp(header) for header in headers]
    for row in body:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], _disp(cell))

    def fmt(row: list[str]) -> str:
        return "  ".join(_pad(cell, widths[index]) for index, cell in enumerate(row))

    lines.append(fmt(headers))
    lines.append(fmt(["-" * width for width in widths]))
    lines.extend(fmt(row) for row in body)
    lines.append(NVD_DISCLAIMER)
    return "\n".join(lines) + "\n"


def _disp(text: str) -> int:
    """한글 등 전각 문자는 터미널에서 두 칸이다."""
    return sum(2 if unicodedata.east_asian_width(char) in {"W", "F"} else 1 for char in text)


def _pad(text: str, width: int) -> str:
    return text + " " * max(0, width - _disp(text))


def _clip(text: str, limit: int) -> str:
    text = " ".join(str(text).split())
    if _disp(text) <= limit:
        return text
    kept: list[str] = []
    used = 0
    for char in text:
        char_width = 2 if unicodedata.east_asian_width(char) in {"W", "F"} else 1
        if used + char_width > limit - 1:
            break
        kept.append(char)
        used += char_width
    return "".join(kept) + "…"


def render_html(report: dict[str, Any]) -> str:
    summary = report["summary"]
    sample = ""
    if report["sample"]:
        sample = (
            '<p class="sample">표본 보고서 (sample). 저장소의 표본 CVE와 예시 자산으로 생성했습니다. '
            "운영 환경의 실제 점검 결과가 아닙니다.</p>"
        )
    rows = []
    for item in report["findings"]:
        severity = (item["cvss_severity"] or "NONE").lower()
        cwe_bits = []
        for cwe_id, name in zip(item["cwe_ids"], item["cwe_names"] or [], strict=False):
            label = html.escape(cwe_id)
            if name:
                label += " " + html.escape(name)
            cwe_bits.append(label)
        cwe_html = "<br>".join(cwe_bits)
        kev = '<span class="kev">KEV</span>' if item["kev"] else ""
        epss = "" if item["epss_score"] is None else f"{item['epss_score']:.5f}"
        score = "" if item["cvss_score"] is None else f"{item['cvss_score']:.1f}"
        version = html.escape(item["cvss_version"] or "")
        score_html = html.escape(score)
        if version:
            score_html += f'<span class="muted"> {version}</span>'
        if item["cvss_v4_score"] is not None and item["cvss_version"] != "4.0":
            score_html += f'<span class="muted"> / v4 {item["cvss_v4_score"]:.1f}</span>'
        rows.append(
            "<tr>"
            f"<td>{html.escape(item['asset'])}<div class='muted'>{html.escape(item['asset_kind_ko'])}</div></td>"
            f"<td>{html.escape(item['component'])}"
            f"<div class='muted'>{html.escape(item['installed_version'])}</div></td>"
            f"<td>{html.escape(item['cve_id'] or '설정 점검')}</td>"
            f"<td>{score_html}</td>"
            f"<td><span class='sev {html.escape(severity)}'>"
            f"{html.escape(item['cvss_severity_ko'] or item['cvss_severity'] or '')}</span></td>"
            f"<td>{cwe_html}</td>"
            f"<td>{kev}</td>"
            f"<td>{html.escape(epss)}</td>"
            f"<td>{html.escape(item['title'])}<div class='rem'>{html.escape(item['remediation'])}</div>"
            f"<div class='muted'>{html.escape(item['evidence'])}</div></td>"
            "</tr>"
        )
    table = (
        "<p>발견 사항이 없습니다.</p>"
        if not rows
        else (
            "<table><thead><tr>"
            "<th>자산</th><th>구성요소</th><th>CVE</th><th>CVSS</th><th>심각도</th>"
            "<th>CWE</th><th>KEV</th><th>EPSS</th><th>내용과 조치</th>"
            "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
        )
    )
    scope = html.escape(report.get("scope") or "")
    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8">
<title>취약점 점검 보고서</title>
<style>
:root {{ color-scheme: light; }}
body {{ margin: 0; background: #f3f5f8; color: #1c2430;
  font-family: "Pretendard", "Noto Sans KR", "Malgun Gothic", "Apple SD Gothic Neo", sans-serif; }}
header {{ background: #10283f; color: #fff; padding: 28px 32px 22px; }}
header h1 {{ margin: 0 0 6px; font-size: 28px; font-weight: 700; }}
header p {{ margin: 0; color: #d5deea; }}
main {{ max-width: 1180px; margin: 0 auto; padding: 24px; }}
.sample {{ background: #fff4d6; border: 1px solid #e2c56a; padding: 12px 14px; border-radius: 8px; }}
.cards {{ display: grid; grid-template-columns: repeat(6, 1fr); gap: 10px; margin: 16px 0 18px; }}
.card {{ background: #fff; border-radius: 10px; padding: 12px 14px; box-shadow: 0 1px 2px rgba(16,40,63,.08); }}
.card b {{ display: block; font-size: 22px; }}
.card span {{ color: #5c6b7c; font-size: 13px; }}
table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 10px; overflow: hidden; }}
th, td {{ text-align: left; vertical-align: top; padding: 10px 12px;
  border-bottom: 1px solid #e6ebf1; font-size: 14px; }}
th {{ background: #e8eef5; font-weight: 650; }}
.muted {{ color: #66788b; font-size: 12px; margin-top: 3px; }}
.rem {{ margin-top: 6px; }}
.sev {{ display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 12px; font-weight: 700; }}
.sev.critical {{ background: #f8d0d0; color: #8d1d1d; }}
.sev.high {{ background: #fde2c8; color: #8a3d05; }}
.sev.medium {{ background: #fff1c2; color: #7a5b00; }}
.sev.low {{ background: #d9e8fb; color: #1d4e89; }}
.sev.none {{ background: #eceff3; color: #445; }}
.kev {{ background: #8d1d1d; color: #fff; border-radius: 4px; padding: 2px 6px; font-size: 12px; font-weight: 700; }}
footer {{ color: #5c6b7c; font-size: 12px; padding: 8px 0 28px; line-height: 1.5; }}
@media (max-width: 900px) {{ .cards {{ grid-template-columns: repeat(2, 1fr); }} }}
</style>
</head>
<body>
<header>
  <h1>취약점 점검 보고서</h1>
  <p>생성 {html.escape(report["generated_at"])} · 스캔 {html.escape(str(report["scan_id"]))}</p>
</header>
<main>
  {sample}
  <p class="muted">범위: {scope or "기록 없음"}</p>
  <section class="cards">
    <div class="card"><b>{summary["total"]}</b><span>합계</span></div>
    <div class="card"><b>{summary["critical"]}</b><span>긴급</span></div>
    <div class="card"><b>{summary["high"]}</b><span>높음</span></div>
    <div class="card"><b>{summary["medium"]}</b><span>중간</span></div>
    <div class="card"><b>{summary["low"]}</b><span>낮음</span></div>
    <div class="card"><b>{summary["kev"]}</b><span>CISA KEV</span></div>
  </section>
  {table}
  <footer>
    <p>{html.escape(NVD_DISCLAIMER)}</p>
    <p>CVE 설명은 NVD 영문 원문입니다. CVSS와 CPE 범위는 NVD 값을 그대로 사용합니다.
    CWE 이름은 MITRE CWE입니다. KEV는 CISA, EPSS는 FIRST 점수입니다.
    CPE 매칭은 오탐과 미탐이 있으며 상용 스캐너를 대체하지 않습니다.
    네트워크 점검은 인가된 대상에 한정해야 합니다.</p>
  </footer>
</main>
</body>
</html>
"""


def render(report: dict[str, Any], fmt: str) -> str:
    if fmt == "json":
        return render_json(report)
    if fmt == "csv":
        return render_csv(report)
    if fmt == "html":
        return render_html(report)
    if fmt == "table":
        return render_table(report)
    raise ValueError(f"알 수 없는 형식: {fmt}")
