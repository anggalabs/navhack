from __future__ import annotations

import json
import shutil
import unittest
from pathlib import Path

from navhack import platform_compat as plat
from navhack.cli import main


class SelftestTests(unittest.TestCase):
    def test_selftest_passes(self) -> None:
        home = plat.make_scratch("navhack-selftest-home", Path.cwd())
        original = __import__("os").environ.get("NAVHACK_HOME")
        __import__("os").environ["NAVHACK_HOME"] = str(home)
        try:
            code = main(["selftest", "--json", "--no-color"])
        finally:
            if original is None:
                __import__("os").environ.pop("NAVHACK_HOME", None)
            else:
                __import__("os").environ["NAVHACK_HOME"] = original
            shutil.rmtree(home, ignore_errors=True)
        self.assertEqual(code, 0)

    def test_selftest_json_shape(self) -> None:
        import contextlib
        import io

        buffer = io.StringIO()
        home = plat.make_scratch("navhack-selftest-json", Path.cwd())
        import os

        original = os.environ.get("NAVHACK_HOME")
        os.environ["NAVHACK_HOME"] = str(home)
        plat.reset_paths()
        try:
            with contextlib.redirect_stdout(buffer):
                code = main(["selftest", "--json", "--no-color"])
        finally:
            if original is None:
                os.environ.pop("NAVHACK_HOME", None)
            else:
                os.environ["NAVHACK_HOME"] = original
            shutil.rmtree(home, ignore_errors=True)
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["passed"], payload["total"])
        self.assertTrue(payload["checks"])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
