"""CPE 2.3 문자열 분해와 설치 버전의 매칭."""

from __future__ import annotations

import sqlite3

from vulnscan.match.version import combine_cpe_version, compare_versions, in_range, tokenize


def split_cpe(criteria: str) -> list[str]:
    """백슬래시 이스케이프를 존중하며 CPE를 콜론으로 나눈다."""
    parts: list[str] = []
    buffer: list[str] = []
    index = 0
    while index < len(criteria):
        char = criteria[index]
        if char == "\\" and index + 1 < len(criteria):
            buffer.append(criteria[index + 1])
            index += 2
            continue
        if char == ":":
            parts.append("".join(buffer))
            buffer = []
            index += 1
            continue
        buffer.append(char)
        index += 1
    parts.append("".join(buffer))
    return parts


def parse_cpe23(criteria: str) -> dict[str, str] | None:
    """CPE 2.3이면 part/vendor/product/version/update를 반환한다."""
    parts = split_cpe(criteria.strip())
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    return {
        "part": parts[2].lower(),
        "vendor": parts[3].lower(),
        "product": parts[4].lower(),
        "version": parts[5],
        "update": parts[6] if len(parts) > 6 else "*",
        "criteria": criteria.strip(),
    }


def cpe_matches_version(installed_upstream: str, row: sqlite3.Row) -> bool:
    """취약 CPE 한 줄이 설치 버전에 해당하면 True.

    버전이 ``*`` 또는 ``-``이고 범위도 없으면 모든 버전에 매칭되는데,
    오탐이 너무 커서 매칭하지 않는다. 구체적인 버전은 동일할 때만 맞춘다.
    """
    if not tokenize(installed_upstream):
        return False
    if int(row["vulnerable"]) != 1:
        return False
    cpe_version = row["version"] or ""
    cpe_update = row["update_ver"] or ""
    bounded = any(
        row[key]
        for key in (
            "version_start_including",
            "version_start_excluding",
            "version_end_including",
            "version_end_excluding",
        )
    )
    if cpe_version not in {"", "*", "-"}:
        target = combine_cpe_version(cpe_version, cpe_update)
        return compare_versions(installed_upstream, target) == 0
    if not bounded:
        return False
    return in_range(
        installed_upstream,
        row["version_start_including"],
        row["version_start_excluding"],
        row["version_end_including"],
        row["version_end_excluding"],
    )
