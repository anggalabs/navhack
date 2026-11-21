"""Append-only, tamper-evident flight recorder.

Every run writes a hash-chained JSON Lines log: each record carries the previous
record's digest and an HMAC-SHA256 over itself keyed with the engagement key.
Editing a historical line breaks the chain at that point, and ``verify`` names
the first broken sequence number.

This is *tamper-evident*, not a signature by a third party: a holder of the key
could rebuild the file.  Say so in reports; do not oversell it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import util
from . import platform_compat as plat

GENESIS = "0" * 64


class Recorder:
    def __init__(self, path: Path, key: bytes):
        self.path = Path(path)
        self.key = key
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._seq, self._head = self._load_tail()

    def _load_tail(self) -> Tuple[int, str]:
        if not self.path.exists():
            return 0, GENESIS
        last = None
        try:
            with open(plat.long_path(self.path), "r", encoding="utf-8") as handle:
                for line in handle:
                    if line.strip():
                        last = line
        except OSError:
            return 0, GENESIS
        if not last:
            return 0, GENESIS
        try:
            record = json.loads(last)
        except ValueError:
            return 0, GENESIS
        return int(record.get("seq", 0)), str(record.get("hash", GENESIS))

    def _digest(self, body: Dict[str, Any]) -> str:
        material = util.jdump(body).encode("utf-8")
        return hmac.new(self.key, material, hashlib.sha256).hexdigest()

    def event(self, kind: str, **fields: Any) -> Dict[str, Any]:
        with self._lock:
            self._seq += 1
            body = {
                "seq": self._seq,
                "ts": util.now_iso(),
                "kind": kind,
                "prev": self._head,
                "data": fields,
            }
            body["hash"] = self._digest(body)
            with open(plat.long_path(self.path), "a", encoding="utf-8", newline="\n") as handle:
                handle.write(util.jdump(body) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            self._head = body["hash"]
            return body

    def records(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        if not self.path.exists():
            return out
        with open(plat.long_path(self.path), "r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        out.append({"broken": True, "raw": line})
        return out

    def verify(self) -> Tuple[bool, int, str]:
        prev = GENESIS
        expected = 1
        for record in self.records():
            if record.get("broken"):
                return False, expected, "line %d is not valid JSON" % expected
            if int(record.get("seq", -1)) != expected:
                return False, expected, "sequence gap at %d" % expected
            if record.get("prev") != prev:
                return False, expected, "broken chain at seq %d" % expected
            body = dict(record)
            claimed = body.pop("hash", "")
            if not hmac.compare_digest(self._digest(body), claimed):
                return False, expected, "hmac mismatch at seq %d" % expected
            prev = claimed
            expected += 1
        return True, expected - 1, "chain intact"


def load_key(path: Path, create: bool = True) -> bytes:
    path = Path(path)
    if path.exists():
        raw = path.read_bytes().strip()
        if raw:
            return raw
    if not create:
        return b"navhack-default"
    key = os.urandom(32)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


__all__ = ["Recorder", "load_key", "GENESIS"]
