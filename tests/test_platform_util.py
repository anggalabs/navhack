from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

from navhack import platform_compat as plat, util


class PlatformTests(unittest.TestCase):
    def test_python_supported(self) -> None:
        self.assertTrue(plat.python_version_ok())

    def test_platform_tag_is_known(self) -> None:
        self.assertIn(
            plat.PLATFORM_TAG,
            {"termux", "windows", "macos", "linux", "wsl", "android", "cygwin", "freebsd"},
        )

    def test_scratch_children_writable(self) -> None:
        root = plat.make_scratch("navhack-test", Path.cwd())
        try:
            child = root / "nested" / "deeper"
            child.mkdir(parents=True)
            (child / "file.txt").write_text("ok", encoding="utf-8")
            self.assertEqual((child / "file.txt").read_text(encoding="utf-8"), "ok")
        finally:
            import shutil

            shutil.rmtree(root, ignore_errors=True)

    def test_long_path_prefix_only_when_needed(self) -> None:
        short = plat.long_path(Path("a/b"))
        self.assertFalse(short.startswith("\\\\?\\"))
        if plat.IS_WINDOWS:
            long = plat.long_path(Path("a" * 300))
            self.assertTrue(long.startswith("\\\\?\\"))

    def test_stdio_reconfigure_does_not_raise(self) -> None:
        plat.reconfigure_stdio()

    def test_probe_contains_required_keys(self) -> None:
        report = plat.probe()
        for key in ("platform", "python_ok", "sqlite", "data_dir", "data_writable"):
            self.assertIn(key, report)

    def test_ansi_enable_is_bool(self) -> None:
        self.assertIsInstance(plat.enable_vt(), bool)

    def test_default_concurrency_positive(self) -> None:
        self.assertGreater(plat.default_concurrency(), 0)


class UtilTests(unittest.TestCase):
    def test_parse_target_fills_defaults(self) -> None:
        parsed = util.parse_target("example.com:8080/x?y=1")
        self.assertEqual(parsed["host"], "example.com")
        self.assertEqual(parsed["port"], 8080)
        self.assertEqual(parsed["path"], "/x")

    def test_parse_target_rejects_empty(self) -> None:
        with self.assertRaises(ValueError):
            util.parse_target("")

    def test_with_query_replaces(self) -> None:
        url = util.with_query("http://h/p?q=old&keep=1", q="new")
        self.assertIn("q=new", url)
        self.assertNotIn("q=old", url)
        self.assertIn("keep=1", url)

    def test_build_url_omits_default_port(self) -> None:
        self.assertEqual(util.build_url("http", "h", 80, "/x"), "http://h/x")

    def test_build_url_brackets_ipv6(self) -> None:
        self.assertIn("[::1]", util.build_url("http", "::1", 8080, "/"))

    def test_redact_keeps_edges(self) -> None:
        masked = util.redact("supersecretvalue")
        self.assertTrue(masked.startswith("supe"))
        self.assertNotIn("secret", masked)

    def test_duration_parsing(self) -> None:
        self.assertEqual(util.parse_duration("1h30m"), 5400)
        self.assertEqual(util.parse_duration("90s"), 90)
        self.assertEqual(util.parse_duration("nonsense", 7), 7)

    def test_human_delta(self) -> None:
        self.assertEqual(util.human_delta(59), "59s")
        self.assertEqual(util.human_delta(3661), "1h01m")

    def test_atomic_write_creates_dirs(self) -> None:
        root = plat.make_scratch("navhack-test", Path.cwd())
        try:
            path = util.atomic_write(root / "a" / "b.txt", "hello")
            self.assertEqual(path.read_text(encoding="utf-8"), "hello")
        finally:
            import shutil

            shutil.rmtree(root, ignore_errors=True)

    def test_slugify(self) -> None:
        self.assertEqual(util.slugify("My Engagement!!"), "my-engagement")
        self.assertEqual(util.slugify("***"), "engagement")

    def test_clip_and_pad(self) -> None:
        self.assertLessEqual(len(util.clip("x" * 200, 20)), 23)
        self.assertEqual(util.visible_len(util.pad("ab", 5)), 5)

    def test_missing_home_falls_back(self) -> None:
        original = os.environ.get("HOME")
        try:
            os.environ["HOME"] = ""
            self.assertTrue(plat.home_dir())
        finally:
            if original is not None:
                os.environ["HOME"] = original

    def test_json_roundtrip(self) -> None:
        payload = {"b": 1, "a": [1, 2]}
        self.assertEqual(util.jload(util.jdump(payload)), payload)
        self.assertIsNone(util.jload("not json"))

    def test_printable_strips_control(self) -> None:
        self.assertNotIn("\x00", util.printable(b"a\x00b"))


if __name__ == "__main__":
    unittest.main()
