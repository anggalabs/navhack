"""Portable platform facts and workarounds.

Everything that differs between Termux, Linux, macOS and Windows lives here so
that no other module has to guess.  Rules of the road:

* no POSIX-only imports at module import time (``pwd``, ``grp``, ``fcntl``,
  ``resource``, ``termios``);
* no assumption that ``/tmp`` exists or is writable;
* no assumption that a shell, ``/bin/sh`` or ``bash`` exists;
* no assumption that the console is UTF-8 capable;
* Windows console is put into VT (ANSI) mode before colour is emitted.

The module is import-safe on every supported runtime and degrades to plain
ASCII output instead of crashing.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import Dict, Optional

APP_NAME = "navhack"

IS_WINDOWS = os.name == "nt"
IS_MACOS = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")
IS_POSIX = not IS_WINDOWS


def _detect_termux() -> bool:
    """Termux exposes neither ``sys.platform == 'android'`` guarantees nor root."""
    if os.environ.get("TERMUX_VERSION"):
        return True
    env_prefix = os.environ.get("PREFIX", "")
    if "com.termux" in env_prefix:
        return True
    return Path("/data/data/com.termux/files/usr").is_dir()


IS_TERMUX = IS_LINUX and _detect_termux()
IS_ANDROID = IS_TERMUX
IS_WSL = IS_LINUX and "microsoft" in os.uname().release.lower() if IS_LINUX else False

PLATFORM_TAG = (
    "termux"
    if IS_TERMUX
    else "windows"
    if IS_WINDOWS
    else "macos"
    if IS_MACOS
    else "wsl"
    if IS_WSL
    else "linux"
    if IS_LINUX
    else sys.platform
)

MIN_PYTHON = (3, 9)


# --------------------------------------------------------------------------- #
# Filesystem locations
# --------------------------------------------------------------------------- #
def _env_path(name: str) -> Optional[Path]:
    raw = os.environ.get(name)
    return Path(raw) if raw else None


def home_dir() -> Path:
    try:
        return Path.home()
    except RuntimeError:  # no HOME and no passwd entry (rare containers)
        return Path(os.path.abspath(os.sep + "tmp"))


def _raw_temp() -> Path:
    override = _env_path("NAVHACK_TMP")
    if override:
        return override
    if IS_TERMUX:
        return _env_path("TMPDIR") or home_dir() / ".cache" / APP_NAME / "tmp"
    import tempfile

    return Path(tempfile.gettempdir()) / APP_NAME


def _platform_data_home() -> Path:
    if IS_WINDOWS:
        base = _env_path("LOCALAPPDATA") or _env_path("APPDATA")
        return (base or home_dir() / "AppData" / "Local") / APP_NAME
    if IS_MACOS:
        return home_dir() / "Library" / "Application Support" / APP_NAME
    xdg = _env_path("XDG_DATA_HOME")
    if xdg:
        return xdg / APP_NAME
    # Termux has no XDG by default; ~/.local/share is the portable fallback.
    return home_dir() / ".local" / "share" / APP_NAME


def _writable(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".navhack-write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return True
    except Exception:
        return False


_DATA_HOME: Optional[Path] = None


def data_home() -> Path:
    """Writable per-user data root.

    Order: ``$NAVHACK_HOME``, the OS convention, then the temp directory.
    The temp fallback keeps the tool usable inside sandboxes and on locked-down
    phones where ``$HOME`` is readable but not writable; ``navhack doctor``
    reports which one was chosen.
    """
    global _DATA_HOME
    if _DATA_HOME is not None:
        return _DATA_HOME
    override = _env_path("NAVHACK_HOME")
    if override:
        _DATA_HOME = override
        return override
    primary = _platform_data_home()
    if _writable(primary):
        _DATA_HOME = primary
        return primary
    # Sandboxes and read-only homes: keep state beside the project instead.
    local = Path.cwd() / (".%s" % APP_NAME)
    if _writable(local):
        _DATA_HOME = local
        return local
    fallback = _raw_temp() / "data"
    _DATA_HOME = fallback if _writable(fallback) else primary
    return _DATA_HOME


def cache_home() -> Path:
    override = _env_path("NAVHACK_CACHE")
    if override:
        return override
    if IS_WINDOWS:
        base = _env_path("LOCALAPPDATA") or _env_path("TEMP")
        return (base or home_dir()) / APP_NAME / "cache"
    if IS_MACOS:
        return home_dir() / "Library" / "Caches" / APP_NAME
    xdg = _env_path("XDG_CACHE_HOME")
    if xdg:
        return xdg / APP_NAME
    return home_dir() / ".cache" / APP_NAME


def temp_dir() -> Path:
    """Writable scratch dir that survives being relocated by the sandbox."""
    path = _raw_temp()
    path.mkdir(parents=True, exist_ok=True)
    return path


def reset_paths() -> None:
    """Forget the cached data dir (tests and long-lived in-process callers)."""
    global _DATA_HOME
    _DATA_HOME = None


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def make_scratch(prefix: str = APP_NAME, parent: Optional[Path] = None) -> Path:
    """Create a scratch directory that is writable *inside*.

    ``tempfile.mkdtemp`` calls ``os.mkdir(..., 0o700)``; on Windows that yields
    a directory whose DACL does not inherit, so creating children inside it can
    fail with ``WinError 5`` under a sandbox.  Default-mode ``mkdir`` inherits
    properly, so do that instead.
    """
    import secrets

    base = parent or _raw_temp()
    base.mkdir(parents=True, exist_ok=True)
    for _ in range(20):
        candidate = base / ("%s-%s" % (prefix, secrets.token_hex(4)))
        try:
            candidate.mkdir()
            return candidate
        except FileExistsError:
            continue
        except OSError:
            break
    fallback = base / ("%s-%d" % (prefix, int(__import__("time").time() * 1000)))
    fallback.mkdir(exist_ok=True)
    return fallback


def long_path(path: Path) -> str:
    """Windows: prefix very long absolute paths so MAX_PATH stops biting."""
    text = str(path)
    if IS_WINDOWS and len(text) > 240 and not text.startswith("\\\\?\\"):
        absolute = os.path.abspath(text)
        if absolute.startswith("\\\\"):
            return "\\\\?\\UNC\\" + absolute.lstrip("\\")
        return "\\\\?\\" + absolute
    return text


# --------------------------------------------------------------------------- #
# Console
# --------------------------------------------------------------------------- #
def enable_vt() -> bool:
    """Best-effort ANSI enablement on Windows 10+; True if colour is safe."""
    if not IS_WINDOWS:
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        if mode.value & ENABLE_VIRTUAL_TERMINAL_PROCESSING:
            return True
        return bool(
            kernel32.SetConsoleMode(handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING)
        )
    except Exception:
        return False


def is_tty(stream) -> bool:
    try:
        return bool(stream.isatty())
    except Exception:
        return False


def supports_unicode(stream=None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NAVHACK_ASCII"):
        return False
    encoding = (getattr(stream, "encoding", None) or "").lower()
    if any(token in encoding for token in ("utf-8", "utf8", "65001", "cp65001")):
        return True
    if IS_WINDOWS:
        try:
            import ctypes

            return ctypes.windll.kernel32.GetConsoleOutputCP() == 65001
        except Exception:
            return False
    return False


def color_enabled(stream=None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("NAVHACK_NO_COLOR"):
        return False
    if os.environ.get("TERM", "") == "dumb":
        return False
    if not is_tty(stream):
        return False
    if IS_WINDOWS:
        return enable_vt()
    return True


def term_width(default: int = 100) -> int:
    try:
        return max(40, shutil.get_terminal_size((default, 24)).columns)
    except Exception:
        return default


def default_concurrency() -> int:
    """Termux phones have fewer, slower cores than laptops."""
    if IS_TERMUX:
        return 4
    if IS_WINDOWS or IS_MACOS:
        return 8
    return 12


def reconfigure_stdio() -> None:
    """Force UTF-8 with replacement so a cp1252/cp437 console cannot crash us."""
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Process / signal
# --------------------------------------------------------------------------- #
def python_version_ok() -> bool:
    return sys.version_info >= MIN_PYTHON


def python_executable() -> str:
    return sys.executable or "python3"


def which(name: str) -> Optional[str]:
    return shutil.which(name)


def run_capture(argv, timeout: float = 20.0, cwd: Optional[Path] = None):
    """Run without a shell; returns (code, stdout, stderr). Never raises."""
    try:
        proc = subprocess.run(
            [str(a) for a in argv],
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
        return (
            proc.returncode,
            proc.stdout.decode("utf-8", "replace"),
            proc.stderr.decode("utf-8", "replace"),
        )
    except FileNotFoundError:
        return 127, "", "executable not found: %s" % argv[0]
    except subprocess.TimeoutExpired:
        return 124, "", "timeout after %.1fs" % timeout
    except Exception as exc:  # pragma: no cover - platform oddities
        return 1, "", "%s: %s" % (type(exc).__name__, exc)


def detach_flags() -> Dict[str, object]:
    """Keywords so a helper process outlives the parent on every OS."""
    if IS_WINDOWS:
        return {
            "creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            | getattr(subprocess, "CREATE_NO_WINDOW", 0)
        }
    return {"start_new_session": True}


def free_port(bind_host: str = "127.0.0.1") -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((bind_host, 0))
        return int(sock.getsockname()[1])


def cancel_key_name() -> str:
    return "Ctrl+Break" if IS_WINDOWS else "Ctrl+C"


# --------------------------------------------------------------------------- #
# Capability probe (used by ``navhack doctor``)
# --------------------------------------------------------------------------- #
def probe() -> Dict[str, object]:
    import platform
    import sqlite3
    import ssl

    ipv6 = False
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM):
            ipv6 = True
    except OSError:
        ipv6 = False

    report = {
        "platform": PLATFORM_TAG,
        "python": platform.python_version(),
        "python_ok": python_version_ok(),
        "executable": python_executable(),
        "machine": platform.machine(),
        "sqlite": sqlite3.sqlite_version,
        "sqlite_ok": sqlite3.sqlite_version_info >= (3, 30, 0),
        "tls": ssl.OPENSSL_VERSION,
        "ipv6": ipv6,
        "unicode_console": supports_unicode(),
        "color": color_enabled(),
        "data_dir": str(data_home()),
        "temp_dir": str(temp_dir()),
        "tools": {
            name: which(name)
            for name in ("git", "curl", "openssl", "nmap", "dig", "nslookup", "ncat", "nc")
        },
    }
    try:
        probe_dir = data_home()
        probe_dir.mkdir(parents=True, exist_ok=True)
        marker = probe_dir / ".write-probe"
        marker.write_text("ok", encoding="utf-8")
        probe_dir.joinpath(".write-probe").unlink(missing_ok=True)
        report["data_writable"] = True
    except Exception as exc:
        report["data_writable"] = False
        report["data_error"] = str(exc)
    return report


def describe() -> str:
    bits = [PLATFORM_TAG, "py%s" % ".".join(map(str, sys.version_info[:3]))]
    return " ".join(bits)
