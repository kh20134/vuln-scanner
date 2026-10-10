"""터미널 표시 폭, EPSS 자리수, HTML 범위·심각도 열."""

import unicodedata

from vulnscan.db import Database
from vulnscan.report.render import (
    REMEDIATION_LIMIT,
    _clip,
    _disp,
    _pad,
    build_report,
    format_epss,
    render_csv,
    render_html,
    render_table,
)

ROOT_REMEDIATION = "PermitRootLogin no 로 두고 관리자 개인 계정과 sudo를 사용하세요."


def _summary() -> dict[str, int]:
    return {"total": 2, "critical": 1, "high": 1, "medium": 0, "low": 0, "kev": 1, "info": 0}


def _finding(**overrides: object) -> dict[str, object]:
    item: dict[str, object] = {
        "asset": "server",
        "asset_kind": "server",
        "asset_kind_ko": "서버",
        "component": "sshd",
        "installed_version": "",
        "cve_id": None,
        "cwe_ids": ["CWE-250"],
        "cwe_names": ["Execution with Unnecessary Privileges"],
        "title": "SSH root 직접 로그인이 허용되어 있습니다.",
        "cvss_score": None,
        "cvss_vector": None,
        "cvss_severity": "HIGH",
        "cvss_severity_ko": "높음",
        "cvss_version": None,
        "cvss_v4_score": None,
        "kev": False,
        "epss_score": None,
        "epss_percentile": None,
        "remediation": ROOT_REMEDIATION,
        "evidence": "PermitRootLogin yes",
        "risk_score": 40,
        "scan_id": "s",
    }
    item.update(overrides)
    return item


def _report(findings: list[dict[str, object]], *, scope: str = "") -> dict[str, object]:
    return {
        "generated_at": "2026-10-10T00:00:00Z",
        "scan_id": "all",
        "scope": scope,
        "sample": True,
        "inventory": 1,
        "summary": _summary(),
        "disclaimer": "x",
        "findings": findings,
    }


def _column_ranges(separator: str) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    index = 0
    column = 0
    while index < len(separator):
        if separator[index] == "-":
            start = column
            while index < len(separator) and separator[index] == "-":
                index += 1
                column += 1
            ranges.append((start, column))
        else:
            index += 1
            column += 1
    return ranges


def _slice_display(line: str, start: int, end: int) -> str:
    piece: list[str] = []
    column = 0
    for char in line:
        width = 2 if unicodedata.east_asian_width(char) in {"W", "F"} else 1
        if column >= end:
            break
        if column >= start:
            piece.append(char)
        column += width
    return "".join(piece).strip()


def test_display_width_padding_counts_wide_hangul() -> None:
    assert unicodedata.east_asian_width("설") == "W"
    assert _disp("설정") == 4
    assert _disp("(설정)") == 6
    assert _disp("높음") == 4
    padded = _pad("(설정)", 14)
    assert _disp(padded) == 14
    assert _disp(_pad("CVE-2021-44228", 14)) == _disp(padded)
    assert padded.endswith(" " * 8)
    wide = _pad("가나다", 8)
    assert _disp(wide) == _disp(_pad("abcdefgh", 8)) == 8


def test_clip_stays_within_display_width_without_ambiguous_ellipsis() -> None:
    text = "가" * 40 + " tail"
    clipped = _clip(text, 15)
    assert _disp(clipped) <= 15
    assert clipped.endswith("...")
    assert "…" not in clipped
    short = "조치 문장"
    assert _clip(short, REMEDIATION_LIMIT) == short


def test_table_columns_align_for_korean_config_rows() -> None:
    cve_remediation = ("설치 버전 2.14.1이 NVD 영향 범위에 해당합니다. " * 8).strip()
    report = _report(
        [
            _finding(
                component="liblog4j2-java",
                cve_id="CVE-2021-44228",
                cvss_score=10.0,
                cvss_severity="CRITICAL",
                cvss_severity_ko="긴급",
                cwe_ids=["CWE-20"],
                cwe_names=["Improper Input Validation"],
                kev=True,
                epss_score=0.99999,
                remediation=cve_remediation,
            ),
            _finding(),
            _finding(
                cvss_severity="MEDIUM",
                cvss_severity_ko="중간",
                cwe_ids=["CWE-521"],
                cwe_names=["Weak Password Requirements"],
                remediation="PermitEmptyPasswords no 로 설정하세요.",
            ),
        ]
    )
    text = render_table(report)
    assert "…" not in text
    assert ROOT_REMEDIATION in text
    assert "PermitEmptyPasswords no 로 설정하세요." in text
    lines = text.splitlines()
    sep_index = next(index for index, line in enumerate(lines) if set(line) <= set("- "))
    header = lines[sep_index - 1]
    ranges = _column_ranges(lines[sep_index])
    assert len(ranges) == 9
    assert _disp(header) == _disp(lines[sep_index])
    header_cells = [_slice_display(header, start, end) for start, end in ranges]
    assert header_cells[2] == "CVE"
    assert header_cells[4] == "심각도"
    assert header_cells[5] == "CWE"
    assert header_cells[8] == "조치"
    data_lines = [line for line in lines[sep_index + 1 :] if line and not line.startswith("This product")]
    assert data_lines
    saw_config = False
    for line in data_lines:
        assert _disp(line) == _disp(header)
        cells = [_slice_display(line, start, end) for start, end in ranges]
        assert len(cells) == len(header_cells)
        if cells[2] == "(설정)":
            saw_config = True
            assert cells[3] == ""
            assert cells[4] in {"높음", "중간"}
            assert cells[5].startswith("CWE-")
            assert cells[8]
            assert not cells[8].endswith("...")
    assert saw_config


def test_epss_format_matches_across_table_html_and_csv() -> None:
    assert format_epss(0.99999) == "0.99999"
    assert format_epss(None) == ""
    report = _report(
        [
            _finding(
                cve_id="CVE-2021-44228",
                cvss_score=10.0,
                cvss_severity_ko="긴급",
                epss_score=0.99999,
                kev=True,
            )
        ]
    )
    table = render_table(report)
    html = render_html(report)
    csv_text = render_csv(report)
    assert "0.99999" in table
    assert "1.000" not in table
    assert ">0.99999<" in html
    assert "0.99999" in csv_text
    assert "1.000" not in csv_text.splitlines()[1]


def test_html_severity_column_and_scope_label() -> None:
    hidden = render_html(_report([_finding()], scope=""))
    assert "기록 없음" not in hidden
    assert "범위:" not in hidden
    assert "sevcol" in hidden
    assert "white-space: nowrap" in hidden
    assert "<th class='sevcol'>심각도</th>" in hidden
    shown = render_html(_report([_finding()], scope="nmap:examples/nmap-sample.xml; files; endpoint"))
    assert "범위: nmap:examples/nmap-sample.xml; files; endpoint" in shown
    assert "기록 없음" not in shown


def test_all_scans_join_real_scopes(tmp_path) -> None:
    with Database(tmp_path / "v.db") as db:
        db.add_scan("n", "network", "2026-10-10T00:00:00Z", "nmap:examples/nmap-sample.xml", True)
        db.add_scan("s", "server", "2026-10-10T00:00:01Z", "files", True)
        db.add_scan("e", "endpoint", "2026-10-10T00:00:02Z", "endpoint", True)
        db.add_scan("blank", "server", "2026-10-10T00:00:03Z", "  ", True)
        report = build_report(db, "all", sample=True)
        one = build_report(db, "s", sample=False)
    assert report["scope"] == "nmap:examples/nmap-sample.xml; files; endpoint"
    assert one["scope"] == "files"
    html = render_html(report)
    assert "범위: nmap:examples/nmap-sample.xml; files; endpoint" in html
    assert "기록 없음" not in html
