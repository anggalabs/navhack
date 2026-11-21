from __future__ import annotations

import shutil
import unittest
from pathlib import Path

from navhack import grammar, platform_compat as plat
from navhack.capability import Capabilities, collect
from navhack.models import Budget, Fog, Node
from navhack.planner import alternatives, backward, forward, frontier, plan
from navhack.store import Store


def caps_for(*tags: str) -> Capabilities:
    caps = Capabilities()
    for tag in tags:
        caps.add_tag(tag)
    return caps


class PlannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = plat.make_scratch("navhack-test", Path.cwd())
        self.store = Store(self.root / "nav.db")

    def tearDown(self) -> None:
        self.store.close()
        shutil.rmtree(self.root, ignore_errors=True)

    def test_forward_reaches_every_objective(self) -> None:
        caps = caps_for("entry", "host:resolved", "host:up", "port:tcp", "service:identified")
        for objective in grammar.OBJECTIVES:
            search = forward(caps, objective)
            self.assertTrue(search.reached(), objective)

    def test_ordering_respects_preconditions(self) -> None:
        caps = caps_for("entry", "host:resolved", "host:up")
        result = plan(self.store, caps, "objective:file_read", budget=Budget(max_steps=20))
        produced = set(caps.tags)
        for step in result.steps:
            for pre in step.move.pre:
                self.assertIn(pre, produced, "%s before %s" % (pre, step.move.move_id))
            produced.update(step.move.post)

    def test_unknown_goal_fails_with_unmet(self) -> None:
        result = plan(self.store, caps_for("entry"), "objective:nonexistent")
        self.assertEqual(result.status, "failed")
        self.assertTrue(result.unmet)

    def test_already_held_goal_is_empty(self) -> None:
        result = plan(self.store, caps_for("entry", "primitive:file_read"), "primitive:file_read")
        self.assertEqual(result.steps, [])
        self.assertEqual(result.confidence, 1.0)

    def test_step_cap_respected(self) -> None:
        caps = caps_for("entry", "host:resolved", "host:up")
        result = plan(self.store, caps, "objective:rce", budget=Budget(max_steps=2))
        self.assertLessEqual(len(result.steps), 2)
        self.assertTrue(result.unmet)

    def test_noise_budget_flagged(self) -> None:
        caps = caps_for("entry", "host:resolved", "host:up")
        result = plan(self.store, caps, "objective:file_read", budget=Budget(max_noise=1))
        self.assertTrue(result.over_budget)

    def test_backward_also_produces_chain(self) -> None:
        caps = caps_for("entry", "host:resolved", "host:up", "port:tcp", "service:identified")
        result = plan(self.store, caps, "objective:file_read", direction="backward")
        self.assertTrue(result.steps)
        self.assertGreater(result.noise, 0)

    def test_backward_search_expands_preconditions(self) -> None:
        search = backward(caps_for("entry"), "objective:file_read")
        self.assertIn("path:known", search.best)

    def test_grounding_marks_unbound_without_nodes(self) -> None:
        caps = caps_for("entry", "host:resolved", "host:up")
        result = plan(self.store, caps, "objective:file_read", budget=Budget(max_steps=3))
        self.assertTrue(any(not step.bound for step in result.steps))

    def test_grounding_uses_existing_nodes(self) -> None:
        host = self.store.upsert_node(Node(kind="host", key="a.test", confidence=0.9), chart=Fog.CHARTED.value)
        port = self.store.upsert_node(Node(kind="port", key="a.test:80", confidence=0.9), chart=Fog.CHARTED.value)
        self.store.upsert_node(Node(kind="path", key="http://a.test/.env", confidence=0.9), chart=Fog.CHARTED.value)
        self.store.grant_tag("entry")
        caps = collect(self.store, entry_hosts=["a.test"])
        result = plan(self.store, caps, "objective:file_read", budget=Budget(max_steps=10))
        targets = [step.target_key for step in result.steps]
        self.assertTrue(any("a.test" in target for target in targets))

    def test_confidence_is_product(self) -> None:
        caps = caps_for("entry", "host:resolved", "host:up", "port:tcp", "service:identified")
        result = plan(self.store, caps, "objective:file_read", budget=Budget(max_steps=20))
        self.assertLess(result.confidence, 1.0)
        self.assertGreater(result.confidence, 0.0)

    def test_frontier_excludes_finished_moves(self) -> None:
        caps = caps_for("entry", "host:resolved", "host:up")
        chosen = [move.move_id for move, _ in frontier(caps)]
        self.assertIn("scan_port", chosen)
        self.assertNotIn("resolve_target", chosen)

    def test_frontier_respects_tag_coverage(self) -> None:
        caps = caps_for("entry")
        moves = [move.move_id for move, _ in frontier(caps)]
        self.assertIn("resolve_target", moves)

    def test_alternatives_for_goal(self) -> None:
        caps = caps_for("entry", "path:known")
        self.assertTrue(alternatives(self.store, caps, "objective:file_read"))

    def test_plan_is_deterministic(self) -> None:
        caps = caps_for("entry", "host:resolved", "host:up")
        first = plan(self.store, caps, "objective:file_read", budget=Budget(max_steps=20))
        second = plan(self.store, caps, "objective:file_read", budget=Budget(max_steps=20))
        self.assertEqual([s.move.move_id for s in first.steps], [s.move.move_id for s in second.steps])


if __name__ == "__main__":
    unittest.main()
