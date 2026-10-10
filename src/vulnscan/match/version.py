"""CPE/패키지 버전 비교.

NVD CPE 범위와 배포판 패키지 버전을 같은 축에서 비교하기 위한 근사 구현이다.
배포판 백포트(예: Ubuntu ``5.15.0-119-generic``)는 업스트림 버전과 다르므로
호출하는 쪽에서 그런 버전을 CPE 비교에서 제외한다.
"""

from __future__ import annotations

import re

_TOKEN = re.compile(r"\d+|[A-Za-z]+")
_EPOCH = re.compile(r"^(\d+):(.+)$")
_REVISION_HINT = re.compile(r"(ubuntu|debian|\.el\d|deb\d|dfsg)", re.IGNORECASE)


def tokenize(version: str) -> list[tuple[int, int | str]]:
    """숫자 토큰은 ``(0, int)``, 영문 토큰은 ``(1, 소문자)``."""
    tokens: list[tuple[int, int | str]] = []
    for match in _TOKEN.finditer(version):
        text = match.group(0)
        if text.isdigit():
            tokens.append((0, int(text)))
        else:
            tokens.append((1, text.lower()))
    return tokens


def compare_versions(left: str, right: str) -> int:
    """왼쪽이 작으면 -1, 같으면 0, 크면 1.

    공통 접두 뒤에 토큰이 더 있으면 더 큰 버전으로 본다.
    ``9.8 < 9.8p1``, ``1.0.2 < 1.0.2zd``, ``1.2 < 1.10``.
    """
    left_tokens = tokenize(left)
    right_tokens = tokenize(right)
    limit = max(len(left_tokens), len(right_tokens))
    for index in range(limit):
        if index >= len(left_tokens):
            return -1
        if index >= len(right_tokens):
            return 1
        left_token = left_tokens[index]
        right_token = right_tokens[index]
        if left_token[0] != right_token[0]:
            return -1 if left_token[0] < right_token[0] else 1
        if left_token[1] < right_token[1]:
            return -1
        if left_token[1] > right_token[1]:
            return 1
    return 0


def upstream_version(version: str) -> str:
    """에폭과 배포판 리비전을 벗겨 CPE 비교용 업스트림 버전을 만든다.

    ``1:8.9p1-3ubuntu0.10`` -> ``8.9p1``.
    ``1.0.0-rc1`` 처럼 리비전이 배포판 리비전으로 보이지 않으면 유지한다.
    """
    text = version.strip()
    epoch = _EPOCH.match(text)
    if epoch:
        text = epoch.group(2)
    if "-" in text:
        upstream, revision = text.rsplit("-", 1)
        if revision and (revision[0].isdigit() or _REVISION_HINT.search(revision)):
            return upstream
    return text


def combine_cpe_version(version: str, update: str) -> str:
    """CPE version과 update를 비교용 문자열로 합친다.

    update가 ``p1``이면 ``8.5`` + ``p1`` = ``8.5p1``. ``*``와 ``-``는 무시한다.
    """
    if update in {"", "*", "-", "NA", "na"}:
        return version
    if version.endswith(update):
        return version
    if update[0].isalpha():
        return f"{version}{update}"
    return f"{version}.{update}"


def in_range(
    version: str,
    start_including: str | None,
    start_excluding: str | None,
    end_including: str | None,
    end_excluding: str | None,
) -> bool:
    """NVD versionStart/End Including/Excluding 규칙."""
    if not tokenize(version):
        return False
    if start_including and compare_versions(version, start_including) < 0:
        return False
    if start_excluding and compare_versions(version, start_excluding) <= 0:
        return False
    if end_including and compare_versions(version, end_including) > 0:
        return False
    if end_excluding and compare_versions(version, end_excluding) >= 0:
        return False
    return True
