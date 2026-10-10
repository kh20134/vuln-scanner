"""표준 라이브러리 HTTP GET. 테스트는 opener를 주입한다."""

from __future__ import annotations

import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

Opener = Callable[..., Any]


@dataclass
class HttpResponse:
    status: int
    body: bytes
    headers: dict[str, str] = field(default_factory=dict)


class HttpClient:
    """urllib 래퍼. 4xx/5xx도 예외 대신 상태 코드로 돌려준다."""

    def __init__(self, opener: Opener | None = None, timeout: float = 60.0) -> None:
        self._opener = opener or urllib.request.urlopen
        self.timeout = timeout

    def get(self, url: str, headers: dict[str, str] | None = None) -> HttpResponse:
        request = urllib.request.Request(url, headers=headers or {}, method="GET")
        try:
            with self._opener(request, timeout=self.timeout) as response:
                status = int(getattr(response, "status", 200))
                header_items = getattr(response, "headers", {})
                raw = response.read()
                return HttpResponse(status, raw, _header_map(header_items))
        except urllib.error.HTTPError as exc:
            body = exc.read() if exc.fp is not None else b""
            return HttpResponse(exc.code, body, _header_map(exc.headers))


def _header_map(headers: Any) -> dict[str, str]:
    if headers is None:
        return {}
    try:
        return {str(key).lower(): str(value) for key, value in dict(headers).items()}
    except (TypeError, ValueError):
        return {}
