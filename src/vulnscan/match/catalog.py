"""패키지·배너·설치 프로그램 이름을 NVD CPE vendor/product로 옮기는 목록.

매핑이 없는 제품은 추측하지 않는다. 전체 CPE 사전은 아니며,
표본과 자주 보는 서버 소프트웨어를 중심으로 둔다.
"""

from __future__ import annotations

import re

# (part, vendor, product)
CpeId = tuple[str, str, str]

PACKAGE_CPE: dict[str, list[CpeId]] = {
    "openssh-server": [("a", "openbsd", "openssh")],
    "openssh-client": [("a", "openbsd", "openssh")],
    "openssh": [("a", "openbsd", "openssh")],
    "openssl": [("a", "openssl", "openssl")],
    "libssl3": [("a", "openssl", "openssl")],
    "libssl1.1": [("a", "openssl", "openssl")],
    "nginx": [("a", "f5", "nginx"), ("a", "nginx", "nginx")],
    "nginx-core": [("a", "f5", "nginx"), ("a", "nginx", "nginx")],
    "nginx-common": [("a", "f5", "nginx"), ("a", "nginx", "nginx")],
    "apache2": [("a", "apache", "http_server")],
    "apache2-bin": [("a", "apache", "http_server")],
    "httpd": [("a", "apache", "http_server")],
    "xz-utils": [("a", "tukaani", "xz")],
    "xz": [("a", "tukaani", "xz")],
    "libc6": [("a", "gnu", "glibc")],
    "glibc": [("a", "gnu", "glibc")],
    "liblog4j2-java": [("a", "apache", "log4j")],
    "liblog4j-core-java": [("a", "apache", "log4j")],
    "sudo": [("a", "sudo_project", "sudo")],
    "curl": [("a", "haxx", "curl")],
    "libcurl4": [("a", "haxx", "curl")],
    "bind9": [("a", "isc", "bind")],
    "postgresql": [("a", "postgresql", "postgresql")],
    "postgresql-14": [("a", "postgresql", "postgresql")],
    "mariadb-server": [("a", "mariadb", "mariadb")],
    "mysql-server": [("a", "oracle", "mysql")],
    "redis-server": [("a", "redis", "redis")],
    "python3": [("a", "python", "python")],
}

PIP_CPE: dict[str, list[CpeId]] = {
    "django": [("a", "djangoproject", "django")],
    "flask": [("a", "palletsprojects", "flask")],
    "requests": [("a", "python-requests", "requests")],
    "urllib3": [("a", "python", "urllib3")],
    "cryptography": [("a", "cryptography.io", "cryptography")],
    "pillow": [("a", "python", "pillow")],
    "pyyaml": [("a", "pyyaml", "pyyaml")],
    "jinja2": [("a", "palletsprojects", "jinja2")],
    "werkzeug": [("a", "palletsprojects", "werkzeug")],
}

NMAP_PRODUCT_CPE: dict[str, list[CpeId]] = {
    "openssh": [("a", "openbsd", "openssh")],
    "apache httpd": [("a", "apache", "http_server")],
    "apache http server": [("a", "apache", "http_server")],
    "nginx": [("a", "f5", "nginx"), ("a", "nginx", "nginx")],
    "openssl": [("a", "openssl", "openssl")],
    "vsftpd": [("a", "vsftpd_project", "vsftpd")],
    "proftpd": [("a", "proftpd", "proftpd")],
    "mysql": [("a", "oracle", "mysql")],
    "mariadb": [("a", "mariadb", "mariadb")],
    "postgresql": [("a", "postgresql", "postgresql")],
    "redis": [("a", "redis", "redis")],
    "microsoft iis": [("a", "microsoft", "internet_information_services")],
    "iis": [("a", "microsoft", "internet_information_services")],
}

_BANNER_RULES: list[tuple[re.Pattern[str], list[CpeId]]] = [
    (re.compile(r"OpenSSH[_ ]([0-9][^\s]*)", re.IGNORECASE), [("a", "openbsd", "openssh")]),
    (
        re.compile(r"nginx/([0-9][^\s]*)", re.IGNORECASE),
        [("a", "f5", "nginx"), ("a", "nginx", "nginx")],
    ),
    (
        re.compile(r"Apache(?:/|\s+httpd/?\s*)([0-9][^\s]*)", re.IGNORECASE),
        [("a", "apache", "http_server")],
    ),
    (
        re.compile(r"Microsoft-IIS/([0-9][^\s]*)", re.IGNORECASE),
        [("a", "microsoft", "internet_information_services")],
    ),
    (re.compile(r"OpenSSL/([0-9][^\s]*)", re.IGNORECASE), [("a", "openssl", "openssl")]),
    (re.compile(r"vsftpd\s+([0-9][^\s]*)", re.IGNORECASE), [("a", "vsftpd_project", "vsftpd")]),
]

_APP_HINTS: list[tuple[re.Pattern[str], list[CpeId]]] = [
    (re.compile(r"log4j", re.IGNORECASE), [("a", "apache", "log4j")]),
    (re.compile(r"google chrome", re.IGNORECASE), [("a", "google", "chrome")]),
    (re.compile(r"mozilla firefox", re.IGNORECASE), [("a", "mozilla", "firefox")]),
    (re.compile(r"7-zip", re.IGNORECASE), [("a", "7-zip", "7-zip")]),
    (re.compile(r"vlc", re.IGNORECASE), [("a", "videolan", "vlc_media_player")]),
    (re.compile(r"adobe acrobat", re.IGNORECASE), [("a", "adobe", "acrobat_reader")]),
    (re.compile(r"openssl", re.IGNORECASE), [("a", "openssl", "openssl")]),
    (re.compile(r"python\s*3", re.IGNORECASE), [("a", "python", "python")]),
    (re.compile(r"nginx", re.IGNORECASE), [("a", "f5", "nginx"), ("a", "nginx", "nginx")]),
    (re.compile(r"openssh", re.IGNORECASE), [("a", "openbsd", "openssh")]),
]


def package_candidates(name: str, ecosystem: str = "os") -> list[CpeId]:
    key = name.strip().lower()
    if ecosystem == "pip":
        return list(PIP_CPE.get(key, []))
    return list(PACKAGE_CPE.get(key, []))


def nmap_candidates(product: str) -> list[CpeId]:
    return list(NMAP_PRODUCT_CPE.get(product.strip().lower(), []))


def banner_match(banner: str) -> tuple[str, list[CpeId]] | None:
    """배너에서 버전과 CPE 후보를 찾는다. 없으면 None."""
    for pattern, candidates in _BANNER_RULES:
        match = pattern.search(banner)
        if match:
            return match.group(1).rstrip("\\"), list(candidates)
    return None


def app_name_candidates(display_name: str) -> list[CpeId]:
    for pattern, candidates in _APP_HINTS:
        if pattern.search(display_name):
            return list(candidates)
    return []
