from __future__ import annotations

import unittest

from navhack import adapters, grammar
from navhack.models import MoveSpec


class GrammarTests(unittest.TestCase):
    def test_no_structural_problems(self) -> None:
        self.assertEqual(grammar.validate(), [])

    def test_every_tag_reachable(self) -> None:
        self.assertEqual(list(grammar.unreachable_tags()), [])

    def test_objectives_are_producible(self) -> None:
        produced = {tag for move in grammar.all_moves() for tag in move.post}
        for objective in grammar.OBJECTIVES:
            self.assertIn(objective, produced, objective)

    def test_unique_ids(self) -> None:
        ids = [move.move_id for move in grammar.all_moves()]
        self.assertEqual(len(ids), len(set(ids)))

    def test_adapters_registered(self) -> None:
        known = set(adapters.available())
        for move in grammar.all_moves():
            if move.adapter:
                self.assertIn(move.adapter, known, move.move_id)

    def test_every_auto_move_has_recipe(self) -> None:
        for move in grammar.all_moves():
            if move.adapter:
                self.assertTrue(move.how, move.move_id)

    def test_domains_cover_requested_surface(self) -> None:
        for domain in ("web", "network", "active_directory", "cloud", "linux", "universal"):
            self.assertIn(domain, grammar.domains())

    def test_lookup_helpers(self) -> None:
        move = grammar.get("check_exposure")
        self.assertIsNotNone(move)
        self.assertIn(move, grammar.producers("primitive:file_read"))
        self.assertIn(move, grammar.consumers("path:known"))
        self.assertIsNone(grammar.get("nope"))

    def test_register_duplicate_raises(self) -> None:
        spec = MoveSpec(move_id="temp_move", title="t", domain="universal", pre=("entry",), post=("temp:tag",))
        grammar.register(spec)
        try:
            with self.assertRaises(ValueError):
                grammar.register(spec)
        finally:
            grammar.MOVES.pop("temp_move", None)
            grammar._ORDER.remove("temp_move")

    def test_move_cost_monotonic_in_noise(self) -> None:
        quiet = MoveSpec(move_id="a", title="a", domain="universal", pre=("entry",), post=("x",), noise=1)
        loud = MoveSpec(move_id="b", title="b", domain="universal", pre=("entry",), post=("y",), noise=5)
        self.assertLess(quiet.cost, loud.cost)

    def test_probability_clamped(self) -> None:
        self.assertEqual(MoveSpec(move_id="c", title="c", domain="u", pre=("entry",), post=("z",), p=5).p, 1.0)
        self.assertEqual(MoveSpec(move_id="d", title="d", domain="u", pre=("entry",), post=("z",), p=0).p, 0.01)

    def test_tag_labels(self) -> None:
        self.assertEqual(grammar.tag_label("objective:rce"), "Remote command execution")
        self.assertEqual(grammar.tag_label("primitive:file_read"), "file read")


if __name__ == "__main__":
    unittest.main()
