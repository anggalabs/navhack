"""Loopback lab server used by the tests (stdlib only, every platform)."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

APP = b"""<!doctype html><html><head><title>lab</title></head><body>
<a href="/search?q=hello">search</a>
<form action="/login" method="post"><input name="username"><input name="password" type="password"></form>
</body></html>"""


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, status: int, body: bytes, extra=None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_GET(self) -> None:  # noqa: N802
        server = self.server
        parts = urlsplit(self.path)
        path = parts.path
        query = parse_qs(parts.query)
        server.hits.append(self.path)  # type: ignore[attr-defined]
        if path == "/":
            self._send(200, APP)
        elif path == "/.git/config":
            self._send(200, b"[core]\n\trepositoryformatversion = 0\n")
        elif path == "/.env":
            self._send(200, b"DB_PASSWORD=labpass\nSECRET_KEY=0123456789abcdef\n")
        elif path == "/search":
            value = (query.get("q") or [""])[0]
            body = "<html><body>results for %s</body></html>" % value
            # Mimic an SSRF-capable parameter.
            if query.get("url"):
                import urllib.request

                try:
                    with urllib.request.urlopen(query["url"][0], timeout=2) as response:
                        body = body.replace("</body>", "|fetched:%s</body>" % response.read(40).decode("utf-8", "replace"))
                except Exception as exc:
                    body = body.replace("</body>", "|fetch-error:%s</body>" % exc)
            self._send(200, body.encode())
        elif path == "/file":
            self._send(200, b"root:x:0:0:root:/root:/bin/sh\n")
        elif path == "/redirect":
            self._send(302, b"", {"Location": (query.get("next") or ["/"]).pop()})
        elif path == "/big":
            self._send(200, b"x" * 5000)
        elif path == "/flaky":
            server.flaky_count += 1  # type: ignore[attr-defined]
            self._send(500, b"boom")
        else:
            self._send(404, b"not found")

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("content-length") or 0)
        data = self.rfile.read(length).decode("utf-8", "replace")
        if "admin=admin" in data or "username=admin" in data:
            self._send(200, b"<html><body>logout</body></html>")
        else:
            self._send(401, b"<html><body>login failed</body></html>")

    def log_message(self, *_args) -> None:
        return


class Lab:
    def __init__(self) -> None:
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.server.daemon_threads = True
        self.server.hits = []  # type: ignore[attr-defined]
        self.server.flaky_count = 0  # type: ignore[attr-defined]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base(self) -> str:
        return "http://127.0.0.1:%d" % self.server.server_address[1]

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    @property
    def hits(self):
        return self.server.hits  # type: ignore[attr-defined]

    def start(self) -> "Lab":
        self.thread.start()
        return self

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def __enter__(self) -> "Lab":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
