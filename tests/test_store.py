from __future__ import annotations

import shutil
import unittest
from pathlib import Path

from navhack import platform_compat as plat, util
from navhack.models import Edge, Finding, Fog, Node, Plan, PlanStatus, PlanStep
from navhack.store import Store
from navhack import grammar


class StoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = plat.make_scratch("navhack-test", Path.cwd())
        self.store = Store(self.root / "nav.db")

    def tearDown(self) -> None:
        self.store.close()
        shutil.rmtree(self.root, ignore_errors=True)

    def test_upsert_conflict_merges(self) -> None:
        first = self.store.upsert_node(Node(kind="host", key="a.test", confidence=0.4))
        second = self.store.upsert_node(Node(kind="host", key="a.test", confidence=0.7, attrs={"x": 1}))
        self.assertEqual(first, second)
        node = self.store.get_node(first)
        assert node is not None
        self.assertEqual(node.confidence, 0.7)
        self.assertEqual(node.attrs.get("x"), 1)

    def test_confidence_never_downgrades(self) -> None:
        first = self.store.upsert_node(Node(kind="host", key="a.test", confidence=0.9))
        self.store.upsert_node(Node(kind="host", key="a.test", confidence=0.2))
        node = self.store.get_node(first)
        assert node is not None
        self.assertEqual(node.confidence, 0.9)

    def test_fog_never_downgrades_except_dead(self) -> None:
        node_id = self.store.upsert_node(Node(kind="host", key="a.test"), chart=Fog.VERIFIED.value)
        self.store.upsert_node(Node(kind="host", key="a.test"), chart=Fog.SEEN.value)
        self.assertEqual(self.store.get_node(node_id).fog, Fog.VERIFIED.value)
        self.store.upsert_node(Node(kind="host", key="a.test"), chart=Fog.DEAD.value)
        self.assertEqual(self.store.get_node(node_id).fog, Fog.DEAD.value)

    def test_edges_unique(self) -> None:
        a = self.store.upsert_node(Node(kind="host", key="a.test"))
        b = self.store.upsert_node(Node(kind="port", key="a.test:80"))
        self.store.add_edge(Edge(a, b, "exposes"))
        self.store.add_edge(Edge(a, b, "exposes", 0.9))
        self.assertEqual(len(self.store.edges()), 1)

    def test_neighbours_both_directions(self) -> None:
        a = self.store.upsert_node(Node(kind="host", key="a.test"))
        b = self.store.upsert_node(Node(kind="port", key="a.test:80"))
        self.store.add_edge(Edge(a, b, "exposes"))
        self.assertEqual(len(self.store.neighbours(b)), 1)
        self.assertEqual(self.store.neighbours(b)[0][1].key, "a.test")

    def test_finding_dedupe_lookup(self) -> None:
        self.store.add_finding(Finding(title="t", primitive="exposure", target="http://h/x"))
        found = self.store.find_finding("t", "http://h/x")
        self.assertIsNotNone(found)
        self.assertIsNone(self.store.find_finding("t", "http://h/y"))

    def test_finding_order_by_severity(self) -> None:
        self.store.add_finding(Finding(title="low", primitive="x", target="t", severity="low"))
        self.store.add_finding(Finding(title="crit", primitive="x", target="t", severity="critical"))
        self.assertEqual(self.store.findings()[0].severity, "critical")

    def test_finding_update(self) -> None:
        fid = self.store.add_finding(Finding(title="t", primitive="x", target="t"))
        self.store.update_finding(fid, status="confirmed", confidence=0.99, evidence="e")
        updated = self.store.get_finding(fid)
        self.assertEqual(updated.status, "confirmed")
        self.assertEqual(updated.confidence, 0.99)

    def test_expire_stale_marks_dead(self) -> None:
        node_id = self.store.upsert_node(Node(kind="port", key="a.test:80"))
        self.store._conn.execute("UPDATE nodes SET decay_at='1999-01-01T00:00:00Z' WHERE id=?", (node_id,))
        self.store._conn.commit()
        self.assertEqual(self.store.expire_stale(), 1)
        self.assertEqual(self.store.get_node(node_id).fog, Fog.DEAD.value)

    def test_tags(self) -> None:
        self.store.grant_tag("host:up")
        self.store.grant_tag("host:up")
        self.assertEqual(self.store.tags(), ["host:up"])

    def test_plan_roundtrip(self) -> None:
        step = PlanStep(seq=1, move=grammar.get("probe_host"), target_key="a.test")
        plan = Plan(goal="objective:file_read", steps=[step], noise=1, seconds=2, confidence=0.5, status=PlanStatus.READY.value)
        plan_id = self.store.add_plan(plan)
        loaded = self.store.get_plan(plan_id)
        self.assertEqual(loaded["steps"][0]["move_id"], "probe_host")
        self.store.set_step_result(plan_id, 1, "ok", "done")
        self.assertEqual(self.store.get_plan(plan_id)["steps"][0]["status"], "ok")

    def test_artifacts_and_stats(self) -> None:
        self.store.add_artifact("a.txt", "/tmp/a", "deadbeef")
        self.assertEqual(len(self.store.artifacts()), 1)
        stats = self.store.stats()
        self.assertIn("nodes", stats)
        self.assertIn("edges", stats)

    def test_wal_mode(self) -> None:
        mode = self.store._conn.execute("PRAGMA journal_mode").fetchone()[0]
        self.assertEqual(mode.lower(), "wal")

    def test_meta(self) -> None:
        self.store.set_meta("k", "v")
        self.assertEqual(self.store.meta("k"), "v")


if __name__ == "__main__":
    unittest.main()
