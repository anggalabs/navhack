from __future__ import annotations

import shutil
import unittest
from pathlib import Path

from navhack import platform_compat as plat
from navhack.recorder import GENESIS, Recorder, load_key


class RecorderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = plat.make_scratch("navhack-test", Path.cwd())
        self.path = self.root / "rec.jsonl"

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_chain_starts_at_genesis(self) -> None:
        record = Recorder(self.path, b"k").event("one", a=1)
        self.assertEqual(record["prev"], GENESIS)
        self.assertEqual(record["seq"], 1)
        self.assertEqual(len(record["hash"]), 64)

    def test_verify_ok(self) -> None:
        recorder = Recorder(self.path, b"k")
        recorder.event("a")
        recorder.event("b")
        ok, count, detail = recorder.verify()
        self.assertTrue(ok)
        self.assertEqual(count, 2)
        self.assertEqual(detail, "chain intact")

    def test_append_continues_chain(self) -> None:
        first = Recorder(self.path, b"k")
        first.event("a")
        second = Recorder(self.path, b"k")
        record = second.event("b")
        self.assertEqual(record["seq"], 2)
        self.assertEqual(second.verify()[0], True)

    def test_tamper_detected(self) -> None:
        recorder = Recorder(self.path, b"k")
        recorder.event("a", value=1)
        recorder.event("b", value=2)
        raw = self.path.read_text(encoding="utf-8").splitlines()
        raw[0] = raw[0].replace('"value":1', '"value":9')
        self.path.write_text("\n".join(raw) + "\n", encoding="utf-8")
        ok, _count, detail = recorder.verify()
        self.assertFalse(ok)
        self.assertIn("mismatch", detail)

    def test_wrong_key_detected(self) -> None:
        Recorder(self.path, b"k").event("a")
        ok, _count, detail = Recorder(self.path, b"other").verify()
        self.assertFalse(ok)

    def test_sequence_gap_detected(self) -> None:
        recorder = Recorder(self.path, b"k")
        recorder.event("a")
        recorder.event("b")
        lines = self.path.read_text(encoding="utf-8").splitlines()
        self.path.write_text(lines[1] + "\n", encoding="utf-8")
        ok, _count, detail = recorder.verify()
        self.assertFalse(ok)
        self.assertIn("sequence", detail)

    def test_records_are_json(self) -> None:
        recorder = Recorder(self.path, b"k")
        recorder.event("a", nested={"x": [1, 2]})
        records = recorder.records()
        self.assertEqual(records[0]["data"]["nested"]["x"], [1, 2])

    def test_load_key_creates_and_is_stable(self) -> None:
        key_path = self.root / "k.bin"
        first = load_key(key_path)
        self.assertEqual(len(first), 32)
        self.assertEqual(load_key(key_path), first)

    def test_default_key_when_missing(self) -> None:
        self.assertEqual(load_key(self.root / "missing.bin", create=False), b"navhack-default")


if __name__ == "__main__":
    unittest.main()
