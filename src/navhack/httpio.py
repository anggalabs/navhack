"""Minimal HTTP client: scope-gated, rate-limited, redirect-aware, capped.

Built on ``http.client`` so there is no dependency on ``requests``/``curl`` and
it behaves identically on Termux, Linux, macOS and Windows.

Redirects are followed manually for two reasons:
1. the hop target is re-checked against scope, and
2. the full chain is recorded, because an out-of-scope redirect is itself a
   finding worth reporting.
"""

from __future__ import annotations

import http.client
import ssl
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlsplit

from . import __version__, util
from .policy import Policy, PolicyError
from .scope import ScopeError

UA = "navhack/%s (+https://example.invalid/navhack)" % __version__
MAX_BODY = 262144
REDIRECT_CODES = (301, 302, 303, 307, 308)

_ssl_lock = threading.Lock()
_ssl_contexts: Dict[bool, ssl.SSLContext] = {}


def ssl_context(verify: bool) -> ssl.SSLContext:
    with _ssl_lock:
        ctx = _ssl_contexts.get(verify)
        if ctx is None:
            ctx = ssl.create_default_context()
            if not verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.set_alpn_protocols(["http/1.1"])
            except NotImplementedError:  # pragma: no cover - old OpenSSL
                pass
            _ssl_contexts[verify] = ctx
        return ctx


@dataclass
class Response:
    url: str
    status: int = 0
    headers: List[Tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    elapsed: float = 0.0
    error: str = ""
    truncated: bool = False
    redirects: List[str] = field(default_factory=list)
    scope_note: str = ""
    method: str = "GET"

    @property
    def ok(self) -> bool:
        return self.status > 0 and not self.error

    def header(self, name: str, default: str = "") -> str:
        lowered = name.lower()
        for key, value in self.headers:
            if key.lower() == lowered:
                return value
        return default

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    @property
    def content_type(self) -> str:
        return self.header("content-type").lower()

    @property
    def is_text(self) -> bool:
        return any(
            token in self.content_type
            for token in ("text/", "json", "xml", "javascript", "x-www-form-urlencoded")
        )

    def summary(self, limit: int = 120) -> str:
        if self.error:
            return "ERR %s" % util.clip(self.error, limit)
        return "%d %s" % (self.status, util.clip(self.header("content-type"), 40))


def _connection(scheme: str, host: str, port: int, timeout: float, verify: bool):
    if scheme == "https":
        return http.client.HTTPSConnection(
            host, port, timeout=timeout, context=ssl_context(verify)
        )
    return http.client.HTTPConnection(host, port, timeout=timeout)


def request(
    method: str,
    url: str,
    *,
    policy: Policy,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[bytes] = None,
    timeout: float = 8.0,
    max_bytes: int = MAX_BODY,
    allow_redirects: bool = True,
    max_redirects: int = 5,
    verify_tls: bool = False,
) -> Response:
    """Perform one logical request (plus redirects), enforcing policy."""
    started = time.monotonic()
    response = Response(url=url, method=method)
    current = url
    hops = 0
    while True:
        parts = urlsplit(current)
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https"):
            response.error = "unsupported scheme: %s" % scheme
            break
        host = parts.hostname or ""
        port = parts.port or (443 if scheme == "https" else 80)
        try:
            response.scope_note = policy.gate_host(host, port)
        except (ScopeError, PolicyError) as exc:
            response.error = "out of scope: %s" % exc
            break
        policy.wait_turn()
        policy.spend(requests=1)
        target = parts.path or "/"
        if parts.query:
            target += "?" + parts.query
        hdrs = {
            "User-Agent": UA,
            "Accept": "text/html,application/json,text/plain,*/*",
            "Accept-Language": "en",
            "Connection": "close",
        }
        if headers:
            hdrs.update(headers)
        conn = None
        try:
            conn = _connection(scheme, host, port, timeout, verify_tls)
            conn.request(method, target, body=body, headers=hdrs)
            raw = conn.getresponse()
            data = raw.read(max_bytes + 1)
            response.status = raw.status
            response.headers = raw.getheaders()
            response.truncated = len(data) > max_bytes
            response.body = data[:max_bytes]
            response.url = current
            policy.note_status(raw.status)
            policy.spend(nbytes=len(response.body))
            location = raw.getheader("location")
        except ssl.SSLError as exc:
            if verify_tls:
                # One transparent downgrade attempt: expired certs are common.
                verify_tls = False
                continue
            response.error = "tls: %s" % exc
            break
        except (OSError, http.client.HTTPException) as exc:
            response.error = "%s: %s" % (type(exc).__name__, exc)
            break
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

        if allow_redirects and response.status in REDIRECT_CODES and location:
            hops += 1
            if hops > max_redirects:
                response.error = "too many redirects"
                break
            nxt = urljoin(current, location)
            response.redirects.append(nxt)
            current = nxt
            if response.status == 303:
                method, body = "GET", None
            continue
        break

    response.elapsed = time.monotonic() - started
    return response


def get(url: str, **kwargs) -> Response:
    return request("GET", url, **kwargs)


def head(url: str, **kwargs) -> Response:
    return request("HEAD", url, **kwargs)


def post(url: str, data: bytes, **kwargs) -> Response:
    headers = kwargs.pop("headers", {}) or {}
    headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    return request("POST", url, headers=headers, body=data, **kwargs)


def probe_tcp(
    host: str, port: int, *, policy: Policy, timeout: float = 2.5
) -> Tuple[bool, float, str]:
    """Plain connect scan; returns (open, elapsed, error)."""
    import socket

    started = time.monotonic()
    try:
        policy.gate_host(host, port)
    except (ScopeError, PolicyError) as exc:
        return False, 0.0, str(exc)
    policy.wait_turn()
    policy.spend(requests=1, noise=1)
    sock = None
    try:
        sock = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        return True, time.monotonic() - started, ""
    except OSError as exc:
        return False, time.monotonic() - started, str(exc)
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


__all__ = ["Response", "request", "get", "head", "post", "probe_tcp", "UA"]
