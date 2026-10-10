"""엔드포인트 설치 소프트웨어와 OS/커널 버전 인벤토리.

리눅스는 os-release와 패키지, macOS는 sw_vers/system_profiler,
윈도우는 제거 레지스트리(Uninstall 키)만 읽는다. 원격 접속은 하지 않는다.
"""

from __future__ import annotations

import json
import platform
import re
import shutil
import subprocess
from pathlib import Path

from vulnscan.assess.models import SoftwareItem
from vulnscan.errors import DataError
from vulnscan.match.catalog import app_name_candidates, package_candidates

_DISTRO_KERNEL = re.compile(
    r"(generic|lowlatency|amd64|ubuntu|debian|azure|aws|gcp|arch\d|\.el\d|fc\d)",
    re.IGNORECASE,
)


def parse_os_release(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def kernel_comparable(version: str) -> str | None:
    """업스트림처럼 보이는 커널 버전만 CPE 비교에 쓴다.

    ``5.15.0-119-generic`` 같은 배포판 버전은 백포트 때문에
    ``linux:linux_kernel`` 범위와 맞추면 오탐이 나므로 제외한다.
    """
    text = version.strip()
    if not text or _DISTRO_KERNEL.search(text):
        return None
    match = re.match(r"(\d+\.\d+(?:\.\d+)?)", text)
    if match is None:
        return None
    return match.group(1)


def os_release_item(values: dict[str, str], asset: str) -> SoftwareItem:
    pretty = values.get("PRETTY_NAME") or values.get("NAME") or "linux"
    version = values.get("VERSION_ID") or ""
    return SoftwareItem(
        asset=asset,
        asset_kind="endpoint",
        component=pretty,
        version=version,
        candidates=[],
        evidence="os-release: " + ", ".join(f"{key}={values[key]}" for key in ("ID", "VERSION_ID") if key in values),
        source="os-release",
    )


def kernel_item(raw_version: str, asset: str) -> SoftwareItem:
    comparable = kernel_comparable(raw_version)
    evidence = f"kernel: {raw_version}"
    if comparable is None:
        evidence += " (배포판 커널로 보여 linux_kernel CPE와 비교하지 않음)"
        version = raw_version
        candidates: list[tuple[str, str, str]] = []
    else:
        version = comparable
        candidates = [("o", "linux", "linux_kernel")]
    return SoftwareItem(
        asset=asset,
        asset_kind="endpoint",
        component="linux-kernel",
        version=version,
        candidates=candidates,
        evidence=evidence,
        source="kernel",
    )


def parse_uninstall_entries(entries: list[dict[str, object]]) -> list[SoftwareItem]:
    items: list[SoftwareItem] = []
    for entry in entries:
        name = str(entry.get("DisplayName") or "").strip()
        version = str(entry.get("DisplayVersion") or "").strip()
        if not name:
            continue
        items.append(
            SoftwareItem(
                asset="windows",
                asset_kind="endpoint",
                component=name,
                version=version,
                candidates=app_name_candidates(name),
                evidence=f"uninstall: {name} {version}".strip(),
                source="windows-uninstall",
            )
        )
    return items


def parse_uninstall_json(text: str) -> list[SoftwareItem]:
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise DataError("제거 프로그램 JSON을 해석하지 못했습니다.") from exc
    if not isinstance(document, list):
        raise DataError("제거 프로그램 JSON은 배열이어야 합니다.")
    entries = [item for item in document if isinstance(item, dict)]
    return parse_uninstall_entries(entries)


def read_windows_uninstall() -> list[dict[str, str]]:
    """윈도우에서만 레지스트리 Uninstall 키를 읽는다. 다른 OS에서는 빈 목록."""
    if platform.system() != "Windows":
        return []
    import winreg

    paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for hive, path in paths:
        try:
            key = winreg.OpenKey(hive, path)
        except OSError:
            continue
        try:
            count = winreg.QueryInfoKey(key)[0]
            for index in range(count):
                try:
                    subname = winreg.EnumKey(key, index)
                    with winreg.OpenKey(key, subname) as subkey:
                        name = _reg_value(winreg, subkey, "DisplayName")
                        version = _reg_value(winreg, subkey, "DisplayVersion")
                except OSError:
                    continue
                if not name:
                    continue
                identity = (name, version)
                if identity in seen:
                    continue
                seen.add(identity)
                rows.append({"DisplayName": name, "DisplayVersion": version})
        finally:
            key.Close()
    return rows


def _reg_value(winreg: object, key: object, name: str) -> str:
    try:
        value, _kind = winreg.QueryValueEx(key, name)  # type: ignore[attr-defined]
    except OSError:
        return ""
    return str(value).strip()


def parse_sw_vers(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in text.splitlines():
        if ":" not in raw:
            continue
        key, value = raw.split(":", 1)
        values[key.strip()] = value.strip()
    return values


def parse_macos_apps(document: dict[str, object]) -> list[SoftwareItem]:
    apps = document.get("SPApplicationsDataType")
    if not isinstance(apps, list):
        return []
    items: list[SoftwareItem] = []
    for app in apps:
        if not isinstance(app, dict):
            continue
        name = str(app.get("_name") or "").strip()
        version = str(app.get("version") or "").strip()
        if not name:
            continue
        items.append(
            SoftwareItem(
                asset="macos",
                asset_kind="endpoint",
                component=name,
                version=version,
                candidates=app_name_candidates(name),
                evidence=f"system_profiler: {name} {version}".strip(),
                source="macos-app",
            )
        )
    return items


def linux_package_items(rows: list[tuple[str, str]], asset: str) -> list[SoftwareItem]:
    items: list[SoftwareItem] = []
    for name, version in rows:
        items.append(
            SoftwareItem(
                asset=asset,
                asset_kind="endpoint",
                component=name,
                version=version,
                candidates=package_candidates(name, "os"),
                evidence=f"package: {name} {version}",
                source="package",
            )
        )
    return items


def local_os_release() -> str | None:
    path = Path("/etc/os-release")
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8", errors="replace")


def local_kernel() -> str | None:
    if shutil.which("uname") is None:
        return None
    try:
        completed = subprocess.run(["uname", "-r"], check=False, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip() or None
