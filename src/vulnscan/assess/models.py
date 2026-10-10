"""점검 입력. 수집된 소프트웨어와 설정 점검 초안."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SoftwareItem:
    asset: str
    asset_kind: str
    component: str
    version: str
    candidates: list[tuple[str, str, str]] = field(default_factory=list)
    evidence: str = ""
    source: str = ""


@dataclass
class ManualFinding:
    """CVE가 아닌 설정 점검 결과."""

    asset: str
    asset_kind: str
    component: str
    title: str
    severity: str
    cwe_id: str
    remediation: str
    evidence: str
