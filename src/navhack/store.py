"""SQLite-backed world model.

One engagement == one database file.  SQLite is used because it is the only
database that is present, dependency-free and identical on Termux, Linux,
macOS and Windows.  Writes are serialized through a re-entrant lock; readers in
the same process share the connection (``check_same_thread=False``).

The store never invents facts.  Every row carries ``provenance`` (which adapter
or human produced it) and a confidence in ``[0,1]``, and observations decay so
a stale port does not stay "charted" forever.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import util
from .models import Edge, Finding, Fog, Kind, MoveSpec, Node, Plan, PlanStatus, PlanStep, confidence_clamp

SCHEMA_VERSION = 1

FOG_RANK = {
    Fog.UNKNOWN.value: 0,
    Fog.SEEN.value: 1,
    Fog.CHARTED.value: 2,
    Fog.VERIFIED.value: 3,
    Fog.DEAD.value: 4,
}

# Seconds an observation stays usable per kind before it is considered stale.
DECAY_SECONDS = {
    Kind.PORT.value: 900,
    Kind.SERVICE.value: 1800,
    Kind.URL.value: 1800,
    Kind.PATH.value: 3600,
    Kind.CRED.value: 7200,
    Kind.TECH.value: 3600,
    Kind.DNS.value: 600,
    Kind.CERT.value: 86400,
    Kind.HOST.value: 3600,
    Kind.FINDING.value: 7200,
    Kind.SHARE.value: 3600,
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS nodes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind       TEXT NOT NULL,
    key        TEXT NOT NULL,
    label      TEXT NOT NULL DEFAULT '',
    confidence REAL NOT NULL DEFAULT 0.5,
    provenance TEXT NOT NULL DEFAULT 'manual',
    fog        TEXT NOT NULL DEFAULT 'unknown',
    attrs      TEXT NOT NULL DEFAULT '{}',
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    decay_at   TEXT NOT NULL DEFAULT '',
    UNIQUE(kind, key)
);
CREATE INDEX IF NOT EXISTS nodes_kind ON nodes(kind);
CREATE INDEX IF NOT EXISTS nodes_fog ON nodes(fog);
CREATE TABLE IF NOT EXISTS edges (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    src_id     INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    dst_id     INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    rel        TEXT NOT NULL,
    confidence REAL NOT NULL DEFAULT 0.6,
    provenance TEXT NOT NULL DEFAULT 'manual',
    created_at TEXT NOT NULL,
    UNIQUE(src_id, dst_id, rel)
);
CREATE INDEX IF NOT EXISTS edges_src ON edges(src_id);
CREATE INDEX IF NOT EXISTS edges_dst ON edges(dst_id);
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT NOT NULL,
    primitive   TEXT NOT NULL DEFAULT '',
    target      TEXT NOT NULL DEFAULT '',
    severity    TEXT NOT NULL DEFAULT 'medium',
    kind        TEXT NOT NULL DEFAULT 'web',
    evidence    TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'hypothesis',
    confidence  REAL NOT NULL DEFAULT 0.5,
    cve         TEXT NOT NULL DEFAULT '',
    remediation TEXT NOT NULL DEFAULT '',
    node_key    TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS findings_status ON findings(status);
CREATE TABLE IF NOT EXISTS plans (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    goal       TEXT NOT NULL,
    direction  TEXT NOT NULL DEFAULT 'forward',
    payload    TEXT NOT NULL DEFAULT '{}',
    noise      INTEGER NOT NULL DEFAULT 0,
    seconds    REAL NOT NULL DEFAULT 0,
    confidence REAL NOT NULL DEFAULT 0,
    status     TEXT NOT NULL DEFAULT 'draft',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS steps (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    plan_id   INTEGER NOT NULL REFERENCES plans(id) ON DELETE CASCADE,
    seq       INTEGER NOT NULL,
    move_id   TEXT NOT NULL,
    target    TEXT NOT NULL DEFAULT '',
    note      TEXT NOT NULL DEFAULT '',
    status    TEXT NOT NULL DEFAULT 'pending',
    detail    TEXT NOT NULL DEFAULT '',
    evidence  TEXT NOT NULL DEFAULT '',
    elapsed   REAL NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS artifacts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    path       TEXT NOT NULL,
    sha256     TEXT NOT NULL DEFAULT '',
    kind       TEXT NOT NULL DEFAULT 'file',
    note       TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tags (
    tag        TEXT PRIMARY KEY,
    source     TEXT NOT NULL DEFAULT 'derived',
    created_at TEXT NOT NULL
);
"""


class Store:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            util.plat.long_path(self.path), timeout=30.0, check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute("PRAGMA busy_timeout=30000")
            self._conn.executescript(_SCHEMA)
            self._conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            self._conn.commit()

    # ------------------------------------------------------------------ #
    # lifecycle
    # ------------------------------------------------------------------ #
    def close(self) -> None:
        with self._lock:
            try:
                self._conn.commit()
            except sqlite3.Error:
                pass
            self._conn.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def meta(self, key: str, default: str = "") -> str:
        with self._lock:
            row = self._conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def set_meta(self, key: str, value: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )
            self._conn.commit()

    # ------------------------------------------------------------------ #
    # nodes
    # ------------------------------------------------------------------ #
    def upsert_node(self, node: Node, *, chart: Optional[str] = None) -> int:
        """Insert or merge a node.  Confidence only ever ratchets up."""
        now = util.now_iso()
        ttl = DECAY_SECONDS.get(node.kind, 3600)
        decay_iso = (
            util.utcnow()
            .replace(microsecond=0)
            .__add__(util._dt.timedelta(seconds=ttl))
            .isoformat()
            .replace("+00:00", "Z")
        )
        fog = chart or node.fog
        with self._lock:
            row = self._conn.execute(
                "SELECT id, key, confidence, fog, attrs FROM nodes WHERE kind=? AND key=?",
                (node.kind, node.key),
            ).fetchone()
            if row is None:
                cursor = self._conn.execute(
                    "INSERT INTO nodes(kind,key,label,confidence,provenance,fog,attrs,first_seen,last_seen,decay_at)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        node.kind,
                        node.key,
                        node.label or node.key,
                        confidence_clamp(node.confidence),
                        node.provenance,
                        fog,
                        util.jdump(node.attrs),
                        now,
                        now,
                        decay_iso,
                    ),
                )
                self._conn.commit()
                return int(cursor.lastrowid)
            merged_attrs = util.jload(row["attrs"], {}) or {}
            merged_attrs.update(node.attrs)
            old_fog = row["fog"]
            if FOG_RANK.get(fog, 0) < FOG_RANK.get(old_fog, 0) and fog != Fog.DEAD.value:
                fog = old_fog
            self._conn.execute(
                "UPDATE nodes SET label=?, confidence=?, fog=?, attrs=?, last_seen=?, decay_at=?,"
                " provenance=? WHERE id=?",
                (
                    node.label or row["key"],
                    max(float(row["confidence"]), confidence_clamp(node.confidence)),
                    fog,
                    util.jdump(merged_attrs),
                    now,
                    decay_iso,
                    node.provenance,
                    row["id"],
                ),
            )
            self._conn.commit()
            return int(row["id"])

    def get_node(self, node_id: int) -> Optional[Node]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM nodes WHERE id=?", (node_id,)).fetchone()
        return self._row_to_node(row) if row else None

    def node_by_key(self, kind: str, key: str) -> Optional[Node]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM nodes WHERE kind=? AND key=?", (kind, key)
            ).fetchone()
        return self._row_to_node(row) if row else None

    def find_nodes(
        self,
        kinds: Optional[Iterable[str]] = None,
        *,
        fog: Optional[Iterable[str]] = None,
        min_confidence: float = 0.0,
        limit: int = 500,
    ) -> List[Node]:
        clauses = ["confidence >= ?"]
        params: List[Any] = [min_confidence]
        kinds = list(kinds or [])
        if kinds:
            clauses.append("kind IN (%s)" % ",".join("?" * len(kinds)))
            params.extend(kinds)
        fog = list(fog or [])
        if fog:
            clauses.append("fog IN (%s)" % ",".join("?" * len(fog)))
            params.extend(fog)
        sql = "SELECT * FROM nodes WHERE %s ORDER BY confidence DESC, last_seen DESC LIMIT ?" % (
            " AND ".join(clauses)
        )
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_node(row) for row in rows]

    def count_nodes(self) -> Dict[str, int]:
        with self._lock:
            rows = self._conn.execute("SELECT kind, COUNT(*) n FROM nodes GROUP BY kind").fetchall()
        return {row["kind"]: row["n"] for row in rows}

    def set_fog(self, node_id: int, fog: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE nodes SET fog=? WHERE id=?", (fog, node_id))
            self._conn.commit()

    def expire_stale(self) -> int:
        now = util.now_iso()
        with self._lock:
            cursor = self._conn.execute(
                "UPDATE nodes SET fog='dead' WHERE decay_at != '' AND decay_at < ? AND fog != 'dead'",
                (now,),
            )
            self._conn.commit()
        return cursor.rowcount

    def _row_to_node(self, row: sqlite3.Row) -> Node:
        return Node(
            kind=row["kind"],
            key=row["key"],
            label=row["label"],
            confidence=row["confidence"],
            provenance=row["provenance"],
            fog=row["fog"],
            attrs=util.jload(row["attrs"], {}) or {},
            node_id=row["id"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            decay_at=row["decay_at"],
        )

    # ------------------------------------------------------------------ #
    # edges
    # ------------------------------------------------------------------ #
    def add_edge(self, edge: Edge) -> int:
        with self._lock:
            self._conn.execute(
                "INSERT INTO edges(src_id,dst_id,rel,confidence,provenance,created_at)"
                " VALUES(?,?,?,?,?,?) ON CONFLICT(src_id,dst_id,rel) DO UPDATE SET"
                " confidence=MAX(confidence, excluded.confidence)",
                (
                    edge.src_id,
                    edge.dst_id,
                    edge.rel,
                    confidence_clamp(edge.confidence),
                    edge.provenance,
                    util.now_iso(),
                ),
            )
            self._conn.commit()
        return 0

    def neighbours(self, node_id: int, rel: Optional[str] = None) -> List[Tuple[Edge, Node]]:
        sql = "SELECT * FROM edges WHERE (src_id=? OR dst_id=?)"
        params: List[Any] = [node_id, node_id]
        if rel:
            sql += " AND rel=?"
            params.append(rel)
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        out: List[Tuple[Edge, Node]] = []
        for row in rows:
            other_id = row["dst_id"] if row["src_id"] == node_id else row["src_id"]
            other = self.get_node(other_id)
            if other is None:
                continue
            out.append(
                (
                    Edge(row["src_id"], row["dst_id"], row["rel"], row["confidence"], row["provenance"]),
                    other,
                )
            )
        return out

    def edges(self, limit: int = 2000) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT e.*, s.kind sk, s.key sv, d.kind dk, d.key dv FROM edges e"
                " JOIN nodes s ON s.id=e.src_id JOIN nodes d ON d.id=e.dst_id LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {
                "src": {"kind": row["sk"], "key": row["sv"]},
                "dst": {"kind": row["dk"], "key": row["dv"]},
                "rel": row["rel"],
                "confidence": row["confidence"],
            }
            for row in rows
        ]

    # ------------------------------------------------------------------ #
    # findings
    # ------------------------------------------------------------------ #
    def add_finding(self, finding: Finding) -> int:
        with self._lock:
            cursor = self._conn.execute(
                "INSERT INTO findings(title,primitive,target,severity,kind,evidence,status,confidence,"
                "cve,remediation,node_key,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    finding.title,
                    finding.primitive,
                    finding.target,
                    finding.severity,
                    finding.kind,
                    finding.evidence,
                    finding.status,
                    confidence_clamp(finding.confidence),
                    finding.cve,
                    finding.remediation,
                    finding.node_key,
                    finding.created_at,
                    finding.updated_at,
                ),
            )
            self._conn.commit()
            return int(cursor.lastrowid)

    def update_finding(
        self,
        finding_id: int,
        *,
        status: Optional[str] = None,
        confidence: Optional[float] = None,
        evidence: Optional[str] = None,
    ) -> None:
        sets = ["updated_at=?"]
        params: List[Any] = [util.now_iso()]
        if status:
            sets.append("status=?")
            params.append(status)
        if confidence is not None:
            sets.append("confidence=?")
            params.append(confidence_clamp(confidence))
        if evidence is not None:
            sets.append("evidence=?")
            params.append(evidence)
        params.append(finding_id)
        with self._lock:
            self._conn.execute("UPDATE findings SET %s WHERE id=?" % ",".join(sets), params)
            self._conn.commit()

    def get_finding(self, finding_id: int) -> Optional[Finding]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
        return self._row_to_finding(row) if row else None

    def find_finding(self, title: str, target: str) -> Optional[Finding]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM findings WHERE title=? AND target=? ORDER BY confidence DESC LIMIT 1",
                (title, target),
            ).fetchone()
        return self._row_to_finding(row) if row else None

    def findings(
        self, *, status: Optional[str] = None, severity: Optional[str] = None, limit: int = 500
    ) -> List[Finding]:
        clauses: List[str] = []
        params: List[Any] = []
        if status:
            clauses.append("status=?")
            params.append(status)
        if severity:
            clauses.append("severity=?")
            params.append(severity)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        order = (
            "ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2"
            " WHEN 'low' THEN 3 ELSE 4 END, confidence DESC"
        )
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM findings %s %s LIMIT ?" % (where, order), params
            ).fetchall()
        return [self._row_to_finding(row) for row in rows]

    def _row_to_finding(self, row: sqlite3.Row) -> Finding:
        return Finding(
            title=row["title"],
            primitive=row["primitive"],
            target=row["target"],
            severity=row["severity"],
            kind=row["kind"],
            evidence=row["evidence"],
            status=row["status"],
            confidence=row["confidence"],
            cve=row["cve"],
            remediation=row["remediation"],
            finding_id=row["id"],
            node_key=row["node_key"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    # ------------------------------------------------------------------ #
    # tags / capabilities
    # ------------------------------------------------------------------ #
    def grant_tag(self, tag: str, source: str = "derived") -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO tags(tag, source, created_at) VALUES(?,?,?)",
                (tag, source, util.now_iso()),
            )
            self._conn.commit()

    def tags(self) -> List[str]:
        with self._lock:
            rows = self._conn.execute("SELECT tag FROM tags").fetchall()
        return [row["tag"] for row in rows]

    # ------------------------------------------------------------------ #
    # plans
    # ------------------------------------------------------------------ #
    def add_plan(self, plan: Plan) -> int:
        payload = {
            "unmet": plan.unmet,
            "over_budget": plan.over_budget,
            "steps": [step.move.move_id for step in plan.steps],
        }
        with self._lock:
            cursor = self._conn.execute(
                "INSERT INTO plans(goal,direction,payload,noise,seconds,confidence,status,created_at)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (
                    plan.goal,
                    plan.direction,
                    util.jdump(payload),
                    plan.noise,
                    plan.seconds,
                    plan.confidence,
                    plan.status,
                    plan.created_at,
                ),
            )
            plan_id = int(cursor.lastrowid)
            for step in plan.steps:
                self._conn.execute(
                    "INSERT INTO steps(plan_id,seq,move_id,target,note,status,updated_at)"
                    " VALUES(?,?,?,?,?,?,?)",
                    (
                        plan_id,
                        step.seq,
                        step.move.move_id,
                        step.target_key,
                        step.note,
                        "pending",
                        util.now_iso(),
                    ),
                )
            self._conn.commit()
        plan.plan_id = plan_id
        return plan_id

    def get_plan(self, plan_id: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM plans WHERE id=?", (plan_id,)).fetchone()
            if row is None:
                return None
            steps = self._conn.execute(
                "SELECT * FROM steps WHERE plan_id=? ORDER BY seq", (plan_id,)
            ).fetchall()
        return {
            "id": row["id"],
            "goal": row["goal"],
            "direction": row["direction"],
            "noise": row["noise"],
            "seconds": row["seconds"],
            "confidence": row["confidence"],
            "status": row["status"],
            "created_at": row["created_at"],
            "steps": [dict(step) for step in steps],
        }

    def plans(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM plans ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    def set_plan_status(self, plan_id: int, status: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE plans SET status=? WHERE id=?", (status, plan_id))
            self._conn.commit()

    def set_step_result(
        self, plan_id: int, seq: int, status: str, detail: str = "", evidence: str = "", elapsed: float = 0.0
    ) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE steps SET status=?, detail=?, evidence=?, elapsed=?, updated_at=?"
                " WHERE plan_id=? AND seq=?",
                (status, detail, evidence, elapsed, util.now_iso(), plan_id, seq),
            )
            self._conn.commit()

    # ------------------------------------------------------------------ #
    # artifacts & stats
    # ------------------------------------------------------------------ #
    def add_artifact(self, name: str, path: str, sha256: str, kind: str = "file", note: str = "") -> int:
        with self._lock:
            cursor = self._conn.execute(
                "INSERT INTO artifacts(name,path,sha256,kind,note,created_at) VALUES(?,?,?,?,?,?)",
                (name, path, sha256, kind, note, util.now_iso()),
            )
            self._conn.commit()
        return int(cursor.lastrowid)

    def artifacts(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM artifacts ORDER BY id").fetchall()
        return [dict(row) for row in rows]

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            node_counts = {
                row["kind"]: row["n"]
                for row in self._conn.execute("SELECT kind, COUNT(*) n FROM nodes GROUP BY kind")
            }
            fog_counts = {
                row["fog"]: row["n"]
                for row in self._conn.execute("SELECT fog, COUNT(*) n FROM nodes GROUP BY fog")
            }
            findings = {
                row["status"]: row["n"]
                for row in self._conn.execute(
                    "SELECT status, COUNT(*) n FROM findings GROUP BY status"
                )
            }
            plans = self._conn.execute("SELECT COUNT(*) n FROM plans").fetchone()["n"]
            edges = self._conn.execute("SELECT COUNT(*) n FROM edges").fetchone()["n"]
        return {
            "nodes": node_counts,
            "fog": fog_counts,
            "findings": findings,
            "plans": plans,
            "edges": edges,
            "tags": len(self.tags()),
            "db_bytes": self.path.stat().st_size if self.path.exists() else 0,
        }


def move_payload(plan: Plan) -> Dict[str, Any]:
    return {
        "goal": plan.goal,
        "direction": plan.direction,
        "steps": [
            {"seq": s.seq, "move": s.move.move_id, "target": s.target_key, "note": s.note}
            for s in plan.steps
        ],
    }


def steps_from_payload(payload: Dict[str, Any], lookup) -> List[PlanStep]:
    steps: List[PlanStep] = []
    for item in payload.get("steps", []):
        move = lookup(item.get("move", ""))
        if move is None:
            continue
        steps.append(
            PlanStep(
                seq=int(item.get("seq", len(steps) + 1)),
                move=move,
                target_key=item.get("target", ""),
                note=item.get("note", ""),
            )
        )
    return steps


__all__ = ["Store", "SCHEMA_VERSION", "DECAY_SECONDS", "FOG_RANK", "move_payload", "steps_from_payload"]
