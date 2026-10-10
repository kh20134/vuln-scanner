"""로컬 리눅스 패키지 인벤토리와 sshd 설정 점검.

원격 명령 실행은 하지 않는다. dpkg/rpm/pip와 sshd_config 파일만 읽는다.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from vulnscan.assess.models import ManualFinding, SoftwareItem
from vulnscan.errors import DataError
from vulnscan.match.catalog import package_candidates

_WEAK_CIPHERS = {"arcfour", "arcfour128", "arcfour256", "des", "3des-cbc", "blowfish-cbc"}


def parse_package_lines(text: str) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "\t" in line:
            name, version = line.split("\t", 1)
            rows.append((name.strip(), version.strip()))
            continue
        parts = line.split()
        if len(parts) >= 4 and parts[0] in {"ii", "hi", "iU", "rc"}:
            rows.append((parts[1], parts[2]))
            continue
        if len(parts) >= 2:
            rows.append((parts[0], parts[1]))
    return rows


def parse_pip_json(text: str) -> list[tuple[str, str]]:
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise DataError("pip JSON을 해석하지 못했습니다.") from exc
    if not isinstance(document, list):
        raise DataError("pip JSON은 배열이어야 합니다.")
    rows: list[tuple[str, str]] = []
    for item in document:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        version = str(item.get("version") or "").strip()
        if name and version:
            rows.append((name, version))
    return rows


def packages_to_items(
    rows: list[tuple[str, str]],
    *,
    asset: str,
    ecosystem: str,
    source: str,
) -> list[SoftwareItem]:
    items: list[SoftwareItem] = []
    for name, version in rows:
        candidates = package_candidates(name, ecosystem)
        items.append(
            SoftwareItem(
                asset=asset,
                asset_kind="server",
                component=name,
                version=version,
                candidates=candidates,
                evidence=f"{source}: {name} {version}",
                source=source,
            )
        )
    return items


def parse_sshd_config(text: str) -> dict[str, str]:
    """첫 Match 이전의 첫 값만 취한다. OpenSSH는 먼저 나온 값을 쓴다."""
    settings: dict[str, str] = {}
    in_match = False
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.lower().startswith("match "):
            in_match = True
            continue
        if in_match:
            continue
        parts = stripped.split(None, 1)
        if len(parts) < 2:
            continue
        key = parts[0].lower()
        if key not in settings:
            settings[key] = parts[1].strip().strip('"')
    return settings


def audit_sshd(text: str, asset: str = "sshd") -> list[ManualFinding]:
    settings = parse_sshd_config(text)
    findings: list[ManualFinding] = []

    def add(title: str, severity: str, cwe_id: str, remediation: str, evidence: str) -> None:
        findings.append(
            ManualFinding(
                asset=asset,
                asset_kind="server",
                component="sshd",
                title=title,
                severity=severity,
                cwe_id=cwe_id,
                remediation=remediation,
                evidence=evidence,
            )
        )

    root = settings.get("permitrootlogin", "").lower()
    if root == "yes":
        add(
            "SSH root 직접 로그인이 허용되어 있습니다.",
            "HIGH",
            "CWE-250",
            "PermitRootLogin no 로 두고 관리자 개인 계정과 sudo를 사용하세요.",
            "PermitRootLogin yes",
        )
    passwords = settings.get("passwordauthentication", "").lower()
    if passwords == "yes":
        add(
            "SSH 비밀번호 인증이 켜져 있습니다.",
            "MEDIUM",
            "CWE-521",
            "공개키 인증만 남기고 PasswordAuthentication no 를 검토하세요.",
            "PasswordAuthentication yes",
        )
    if settings.get("permitemptypasswords", "").lower() == "yes":
        add(
            "SSH 빈 비밀번호 로그인이 허용되어 있습니다.",
            "HIGH",
            "CWE-521",
            "PermitEmptyPasswords no 로 설정하세요.",
            "PermitEmptyPasswords yes",
        )
    protocol = settings.get("protocol", "")
    if protocol.strip() == "1":
        add(
            "SSH 프로토콜 1이 지정되어 있습니다.",
            "HIGH",
            "CWE-327",
            "프로토콜 1을 제거하고 프로토콜 2만 사용하세요.",
            f"Protocol {protocol}",
        )
    if settings.get("x11forwarding", "").lower() == "yes":
        add(
            "SSH X11 포워딩이 켜져 있습니다.",
            "LOW",
            "CWE-276",
            "필요하지 않으면 X11Forwarding no 로 두세요.",
            "X11Forwarding yes",
        )
    ciphers = [item.lower() for item in settings.get("ciphers", "").replace(",", " ").split() if item]
    weak = [item for item in ciphers if item in _WEAK_CIPHERS]
    if weak:
        add(
            "SSH에 취약한 암호 스위트가 포함되어 있습니다.",
            "HIGH",
            "CWE-327",
            "3des, arcfour, blowfish 계열을 제거하고 현재 OpenSSH 기본 암호군을 사용하세요.",
            "Ciphers " + ",".join(weak),
        )
    tries = settings.get("maxauthtries", "")
    if tries.isdigit() and int(tries) > 6:
        add(
            "SSH 인증 시도 허용 횟수가 큽니다.",
            "MEDIUM",
            "CWE-307",
            "MaxAuthTries 를 6 이하로 낮추고 실패 시 차단 정책을 함께 두세요.",
            f"MaxAuthTries {tries}",
        )
    return findings


def _run(command: list[str]) -> str | None:
    if shutil.which(command[0]) is None:
        return None
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout


def collect_local_packages() -> list[tuple[str, str, str]]:
    """(ecosystem, name, version). 없으면 빈 목록."""
    rows: list[tuple[str, str, str]] = []
    dpkg = _run(["dpkg-query", "-W", "-f", "${Package}\t${Version}\n"])
    if dpkg:
        rows.extend(("os", name, version) for name, version in parse_package_lines(dpkg))
        return rows
    rpm = _run(["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}\n"])
    if rpm:
        rows.extend(("os", name, version) for name, version in parse_package_lines(rpm))
    return rows


def collect_local_pip() -> list[tuple[str, str]]:
    import sys

    text = _run([sys.executable, "-m", "pip", "list", "--format=json"])
    if not text:
        return []
    try:
        return parse_pip_json(text)
    except DataError:
        return []


def read_text(path: str) -> str:
    file_path = Path(path)
    if not file_path.is_file():
        raise DataError(f"파일을 찾지 못했습니다: {path}")
    return file_path.read_text(encoding="utf-8", errors="replace")
