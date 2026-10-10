"""로컬 전용 웹 대시보드. 기본 바인드는 127.0.0.1이며 인증이 없다."""

from __future__ import annotations

import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from vulnscan.db import Database
from vulnscan.errors import ScopeError
from vulnscan.report.render import build_report, render_html, render_json

_LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


def serve(db_path: str | Path, host: str, port: int, *, allow_remote: bool = False) -> None:
    if host not in _LOCAL_HOSTS and not allow_remote:
        raise ScopeError("대시보드는 기본적으로 루프백 주소만 엽니다. 원격에서 열려면 --allow-remote 를 지정하세요.")
    if allow_remote:
        print(
            "경고: 대시보드에는 인증이 없습니다. 신뢰할 수 있는 망에서만 사용하세요.",
            file=sys.stderr,
        )
    path = Path(db_path)
    handler = _handler_factory(path)
    server = ThreadingHTTPServer((host, port), handler)
    print(f"대시보드 http://{host}:{port}/  (Ctrl+C로 종료)", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("대시보드를 종료합니다.", file=sys.stderr)
    finally:
        server.server_close()


def _handler_factory(db_path: Path) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - stdlib API
            parsed = urlparse(self.path)
            if parsed.path in {"/", "/report"}:
                scan_id = (parse_qs(parsed.query).get("scan_id") or [None])[0]
                with Database(db_path) as db:
                    body = render_html(build_report(db, scan_id, sample=False)).encode("utf-8")
                self._send(200, "text/html; charset=utf-8", body)
                return
            if parsed.path == "/api/findings":
                scan_id = (parse_qs(parsed.query).get("scan_id") or [None])[0]
                with Database(db_path) as db:
                    body = render_json(build_report(db, scan_id, sample=False)).encode("utf-8")
                self._send(200, "application/json; charset=utf-8", body)
                return
            if parsed.path == "/health":
                self._send(200, "text/plain; charset=utf-8", b"ok")
                return
            self._send(404, "text/plain; charset=utf-8", "없음".encode())

        def _send(self, status: int, content_type: str, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: object) -> None:
            message = fmt % args if args else fmt
            sys.stderr.write(f"{self.address_string()} - {message}\n")

    return Handler
