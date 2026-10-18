"""Loopback-only JSON control API with same-origin and per-process CSRF checks."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import secrets
from typing import Any
from urllib.parse import urlsplit


STATIC_ROOT = Path(__file__).resolve().parent / "static"
MAX_COMMAND_BYTES = 16_384


class G5HTTPServer(HTTPServer):
    allow_reuse_address = False

    def __init__(self, service: Any, host: str = "127.0.0.1", port: int = 8765):
        if host != "127.0.0.1":
            raise ValueError("G5 control server can bind only to 127.0.0.1")
        self.service = service
        self.csrf_token = secrets.token_urlsafe(32)
        super().__init__((host, port), _make_handler())


def _make_handler():
    class Handler(BaseHTTPRequestHandler):
        server_version = "G5Local/1"
        sys_version = ""

        def log_message(self, _format: str, *args: Any) -> None:
            # Request headers/bodies and exception content must never hit logs.
            del _format, args

        def _host_ok(self) -> bool:
            return self.headers.get("Host", "") == f"127.0.0.1:{self.server.server_port}"

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; connect-src 'self'; style-src 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True

        def _discard_bounded_request_body(self) -> None:
            """Drain only small declared bodies before rejecting same-socket POSTs."""
            try:
                length = int(self.headers.get("Content-Length", ""), 10)
            except (TypeError, ValueError):
                self.close_connection = True
                return
            if 0 <= length <= MAX_COMMAND_BYTES:
                try:
                    if len(self.rfile.read(length)) != length:
                        self.close_connection = True
                except OSError:
                    self.close_connection = True
            else:
                self.close_connection = True

        def _json(self, status: int, value: Any) -> None:
            body = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
            self._send(status, body, "application/json; charset=utf-8")

        def do_GET(self) -> None:  # noqa: N802
            if not self._host_ok():
                self._json(421, {"error": "invalid host"})
                return
            path = urlsplit(self.path).path
            if path == "/":
                source = (STATIC_ROOT / "index.html").read_text(encoding="utf-8")
                source = source.replace("__CSRF_TOKEN__", self.server.csrf_token)
                self._send(200, source.encode("utf-8"), "text/html; charset=utf-8")
            elif path == "/static/app.js":
                self._send(200, (STATIC_ROOT / "app.js").read_bytes(), "text/javascript; charset=utf-8")
            elif path == "/static/styles.css":
                self._send(200, (STATIC_ROOT / "styles.css").read_bytes(), "text/css; charset=utf-8")
            elif path == "/api/state":
                self._json(200, self.server.service.state())
            elif path == "/api/audit":
                self._json(200, self.server.service.audit())
            else:
                self._json(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            if not self._host_ok():
                self._json(421, {"error": "invalid host"})
                return
            expected_origin = f"http://127.0.0.1:{self.server.server_port}"
            if self.headers.get("Origin") != expected_origin:
                self._discard_bounded_request_body()
                self._json(403, {"error": "origin rejected"})
                return
            if self.headers.get("X-CSRF-Token") != self.server.csrf_token:
                self._discard_bounded_request_body()
                self._json(403, {"error": "csrf check failed"})
                return
            if self.headers.get("Content-Type", "").split(";", 1)[0].strip().casefold() != "application/json":
                self._discard_bounded_request_body()
                self._json(415, {"error": "JSON required"})
                return
            raw_length = self.headers.get("Content-Length")
            try:
                length = int(raw_length or "", 10)
            except ValueError:
                self._json(400, {"error": "content length required"})
                return
            if not 0 <= length <= MAX_COMMAND_BYTES:
                self._json(413, {"error": "command exceeds limit"})
                return
            try:
                value = json.loads(self.rfile.read(length).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._json(400, {"error": "invalid JSON"})
                return
            if not isinstance(value, dict):
                self._json(400, {"error": "JSON object required"})
                return
            path = urlsplit(self.path).path
            if path == "/api/refresh":
                result = self.server.service.refresh()
            elif path == "/api/actions/start":
                result = self.server.service.request_action("START_GROUP", value)
            elif path == "/api/actions/stop":
                result = self.server.service.request_action("STOP_GROUP", value)
            elif path == "/api/actions/reallocate":
                result = self.server.service.request_action("REALLOCATE_INSTANCE", value)
            elif path == "/api/auto-reallocate":
                result = self.server.service.set_auto_reallocate(value.get("armed"))
            elif path == "/api/kill-switch":
                result = self.server.service.set_kill_switch(value.get("engaged"))
            else:
                self._json(404, {"error": "not found"})
                return
            self._json(200, result)

    return Handler


def create_server(service: Any, host: str = "127.0.0.1", port: int = 8765) -> G5HTTPServer:
    return G5HTTPServer(service, host, port)
