"""Small shared helpers: colour, glyphs, JSON, time, text, atomic IO."""

from __future__ import annotations

import base64
import datetime as _dt
import json
import os
import re
import secrets
import sys
import unicodedata
from pathlib import Path
from typing import Any, Dict, Iterable, Optional
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit

from . import platform_compat as plat

# --------------------------------------------------------------------------- #
# Glyphs
# --------------------------------------------------------------------------- #
_UNICODE_GLYPHS = {
    "entry": "\u25c6",
    "host": "\u25a0",
    "port": "\u25cb",
    "service": "\u25c7",
    "url": "\u2192",
    "path": "\u00b7",
    "tech": "\u2699",
    "dns": "\u2234",
    "cert": "\u26bf",
    "cred": "\u26bf",
    "identity": "\u265f",
    "finding": "\u2691",
    "objective": "\u2605",
    "unknown": "?",
    "never": "\u00b7",
    "dead": "\u00d7",
    "ok": "\u2713",
    "bad": "\u2717",
    "warn": "\u26a0",
    "arrow": "\u2192",
    "up": "\u2191",
    "down": "\u2193",
    "bullet": "\u2022",
    "bar": "\u2502",
    "tee": "\u251c",
    "ell": "\u2514",
    "hline": "\u2500",
    "box": "\u250c",
}

_ASCII_GLYPHS = {
    "entry": "*",
    "host": "#",
    "port": "o",
    "service": "s",
    "url": ">",
    "path": ".",
    "tech": "t",
    "dns": ":",
    "cert": "c",
    "cred": "k",
    "identity": "i",
    "finding": "!",
    "objective": "*",
    "unknown": "?",
    "never": ".",
    "dead": "x",
    "ok": "+",
    "bad": "x",
    "warn": "!",
    "arrow": "->",
    "up": "^",
    "down": "v",
    "bullet": "-",
    "bar": "|",
    "tee": "+-",
    "ell": "+-",
    "hline": "-",
    "box": "+",
}


class Theme:
    """ANSI styling that silently no-ops when colour is unavailable."""

    CODES = {
        "reset": "\x1b[0m",
        "bold": "\x1b[1m",
        "dim": "\x1b[2m",
        "italic": "\x1b[3m",
        "red": "\x1b[31m",
        "green": "\x1b[32m",
        "yellow": "\x1b[33m",
        "blue": "\x1b[34m",
        "magenta": "\x1b[35m",
        "cyan": "\x1b[36m",
        "gray": "\x1b[90m",
        "bright_red": "\x1b[91m",
        "bright_green": "\x1b[92m",
        "bright_yellow": "\x1b[93m",
        "bright_blue": "\x1b[94m",
    }

    def __init__(self, enabled: Optional[bool] = None, ascii_only: Optional[bool] = None):
        self.enabled = plat.color_enabled() if enabled is None else enabled
        self.ascii_only = (
            (not plat.supports_unicode()) if ascii_only is None else ascii_only
        )
        self.glyphs = _ASCII_GLYPHS if self.ascii_only else _UNICODE_GLYPHS

    def __call__(self, text: Any, *styles: str) -> str:
        body = str(text)
        if not self.enabled or not styles:
            return body
        prefix = "".join(self.CODES[s] for s in styles if s in self.CODES)
        return "%s%s%s" % (prefix, body, self.CODES["reset"])

    def glyph(self, name: str) -> str:
        return self.glyphs.get(name, "?")

    def kind_color(self, kind: str) -> str:
        return {
            "entry": "bright_cyan",
            "host": "cyan",
            "port": "blue",
            "service": "bright_blue",
            "url": "magenta",
            "path": "gray",
            "tech": "bright_magenta",
            "dns": "bright_blue",
            "cert": "bright_yellow",
            "cred": "bright_yellow",
            "identity": "yellow",
            "finding": "bright_red",
            "objective": "bright_green",
            "dead": "gray",
        }.get(kind, "gray")


DEFAULT_THEME = Theme()


def severity_color(theme: Theme, severity: str) -> str:
    return {
        "critical": "bright_red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "gray",
    }.get(severity.lower(), "gray")


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #
def jdump(value: Any, *, pretty: bool = False) -> str:
    if pretty:
        return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False)
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def jload(text: str, default: Any = None) -> Any:
    try:
        return json.loads(text)
    except Exception:
        return default


def atomic_write(path: Path, text: str, *, newline: str = "\n") -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(".%s.%s.tmp" % (path.name, secrets.token_hex(4)))
    with open(plat.long_path(tmp), "w", encoding="utf-8", newline=newline) as handle:
        handle.write(text)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(plat.long_path(tmp), plat.long_path(path))
    return path


def append_jsonl(path: Path, record: Dict[str, Any]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    line = jdump(record) + "\n"
    with open(plat.long_path(path), "a", encoding="utf-8", newline="\n") as handle:
        handle.write(line)
        handle.flush()
        os.fsync(handle.fileno())


# --------------------------------------------------------------------------- #
# Time
# --------------------------------------------------------------------------- #
def utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def now_iso() -> str:
    return utcnow().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_iso(value: str) -> Optional[_dt.datetime]:
    text = (value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = _dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    return parsed.astimezone(_dt.timezone.utc)


def human_delta(seconds: float) -> str:
    seconds = max(0, int(round(seconds)))
    if seconds < 60:
        return "%ds" % seconds
    if seconds < 3600:
        return "%dm%02ds" % (seconds // 60, seconds % 60)
    if seconds < 86400:
        return "%dh%02dm" % (seconds // 3600, (seconds % 3600) // 60)
    return "%dd%02dh" % (seconds // 86400, (seconds % 86400) // 3600)


_DURATION_RE = re.compile(r"(\d+(?:\.\d+)?)\s*([smhdw]?)", re.I)
_UNIT_SECONDS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def parse_duration(text: str, default: float = 0.0) -> float:
    """``90``, ``90s``, ``10m``, ``1h30m`` -> seconds."""
    if not text:
        return default
    total = 0.0
    found = False
    for amount, unit in _DURATION_RE.findall(str(text)):
        found = True
        total += float(amount) * _UNIT_SECONDS[unit.lower()]
    return total if found else default


# --------------------------------------------------------------------------- #
# Text
# --------------------------------------------------------------------------- #
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def visible_len(text: str) -> int:
    return len(strip_ansi(text))


def clip(text: str, limit: int) -> str:
    clean = " ".join(str(text).split())
    if len(clean) <= limit:
        return clean
    return clean[: max(0, limit - 1)] + "\u2026" if not plat.IS_WINDOWS else clean[: max(0, limit - 3)] + "..."


def pad(text: str, width: int, align: str = "left") -> str:
    missing = max(0, width - visible_len(text))
    if align == "right":
        return " " * missing + text
    if align == "center":
        left = missing // 2
        return " " * left + text + " " * (missing - left)
    return text + " " * missing


def slugify(text: str, limit: int = 48) -> str:
    normal = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", normal).strip("-._").lower()
    return (slug or "engagement")[:limit]


def redact(value: str, keep: int = 4) -> str:
    if not value:
        return ""
    if len(value) <= keep * 2:
        return value[:2] + "***"
    return "%s***%s" % (value[:keep], value[-keep:])


def printable(data: bytes, limit: int = 4000) -> str:
    text = data.decode("utf-8", "replace")
    return "".join(ch if ch.isprintable() or ch in "\n\t" else "." for ch in text)[:limit]


def html_title(body: str, limit: int = 120) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if not match:
        return ""
    text = re.sub(r"\s+", " ", match.group(1)).strip()
    return text[:limit]


# --------------------------------------------------------------------------- #
# URLs
# --------------------------------------------------------------------------- #
DEFAULT_PORTS = {"http": 80, "https": 443, "ftp": 21, "ssh": 22, "smb": 445}


def parse_target(raw: str) -> Dict[str, Any]:
    """``example.com:8080/x`` -> structured dict; tolerant of missing scheme."""
    text = (raw or "").strip()
    if not text:
        raise ValueError("empty target")
    if "://" not in text:
        text = "http://" + text
    parts = urlsplit(text)
    if not parts.hostname:
        raise ValueError("cannot parse target: %r" % raw)
    scheme = parts.scheme.lower()
    port = parts.port or DEFAULT_PORTS.get(scheme, 0)
    return {
        "scheme": scheme,
        "host": parts.hostname.lower(),
        "port": port,
        "path": parts.path or "/",
        "query": parts.query,
        "userinfo": parts.username,
        "is_ip": is_ip(parts.hostname),
        "explicit_port": parts.port is not None,
    }


def build_url(scheme: str, host: str, port: int, path: str = "/", query: str = "") -> str:
    netloc = host
    if port and port != DEFAULT_PORTS.get(scheme):
        netloc = "%s:%d" % (host, port)
    if ":" in host and not host.startswith("["):
        netloc = "[%s]" % host if not port else "[%s]:%d" % (host, port)
    return urlunsplit((scheme, netloc, path or "/", query, ""))


def origin_of(url: str) -> str:
    parts = urlsplit(url)
    return "%s://%s" % (parts.scheme, parts.netloc)


def with_query(base: str, **extra: str) -> str:
    """Set/replace query parameters instead of appending duplicates."""
    parts = urlsplit(base)
    pairs = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k not in extra]
    pairs.extend(extra.items())
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), parts.fragment))


def path_join(base: str, *segments: str) -> str:
    parts = urlsplit(base)
    path = parts.path.rstrip("/")
    for segment in segments:
        path += "/" + quote(segment.strip("/"), safe="/:@!$&'()*+,;=~")
    return urlunsplit((parts.scheme, parts.netloc, path or "/", parts.query, ""))


def is_ip(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def unb64(text: str) -> str:
    try:
        return base64.b64decode(text.encode("ascii")).decode("utf-8", "replace")
    except Exception:
        return ""


def token(nbytes: int = 12) -> str:
    return secrets.token_hex(nbytes)


def mask_headers(headers: Iterable[tuple]) -> Dict[str, str]:
    out = {}
    for key, value in headers:
        key_l = key.lower()
        if key_l in ("set-cookie", "authorization", "x-api-key", "cookie"):
            out[key] = redact(value, 6)
        else:
            out[key] = clip(value, 300)
    return out


def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)
