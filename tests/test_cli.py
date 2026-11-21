from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

from navhack import platform_compat as plat

from .labserver import Lab

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"


class CliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.home = plat.make_scratch("navhack-cli", Path.cwd())
        cls.lab = Lab().start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.lab.stop()
        shutil.rmtree(cls.home, ignore_errors=True)

    def env(self) -> dict:
        env = dict(os.environ)
        env["NAVHACK_HOME"] = str(self.home)
        env["NAVHACK_ASCII"] = "1"
        env["NO_COLOR"] = "1"
        env["PYTHONPATH"] = str(SRC) + os.pathsep + env.get("PYTHONPATH", "")
        return env

    def run_cli(self, *args: str, expect: int = 0) -> subprocess.CompletedProcess:
        proc = subprocess.run(
            [sys.executable, "-m", "navhack", *args],
            cwd=str(SRC),
            env=self.env(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
        self.assertEqual(
            proc.returncode,
            expect,
            "exit %d for %s\nstdout:\n%s\nstderr:\n%s" % (proc.returncode, args, proc.stdout, proc.stderr),
        )
        return proc

    def test_help(self) -> None:
        self.assertIn("usage", self.run_cli("--help").stdout.lower())

    def test_version(self) -> None:
        out = self.run_cli("version").stdout
        self.assertIn("navhack", out)
        self.assertIn(plat.PLATFORM_TAG, out)

    def test_doctor_json(self) -> None:
        payload = json.loads(self.run_cli("doctor", "--json").stdout)
        self.assertTrue(payload["python_ok"])
        self.assertTrue(payload["data_writable"])

    def test_init_requires_scope(self) -> None:
        self.run_cli("init", "no-scope", expect=2)

    def test_full_flow(self) -> None:
        self.run_cli("init", "flow", "--scope", "127.0.0.1", "--max-requests", "400")
        self.run_cli("scope", "add", "localhost")
        scope = json.loads(self.run_cli("scope", "list", "--json").stdout)
        self.assertIn("localhost", scope["scope"])

        recon = self.run_cli("recon", self.lab.base, "--fast", "--active")
        self.assertIn("identify_http", recon.stdout)

        findings = json.loads(self.run_cli("find", "--json").stdout)
        self.assertTrue(findings, "expected at least one finding")

        plan = json.loads(self.run_cli("plan", "--goal", "objective:file_read", "--save", "--json").stdout)
        self.assertEqual(plan["status"], "ready")
        plan_id = plan["plan_id"]

        run = self.run_cli("run", str(plan_id), "--live", "--yes", "--json")
        self.assertIn(json.loads(run.stdout)["status"], ("done", "dry-run"))

        target = findings[0]["id"]
        self.run_cli("verify", str(target), "--live")

        report = json.loads(self.run_cli("report", "--format", "json", "--json").stdout)
        self.assertTrue(report["files"])
        self.assertTrue(report["chain_ok"])
        self.run_cli("replay", "--verify-chain")

    def test_map_json(self) -> None:
        payload = json.loads(self.run_cli("map", "--json").stdout)
        self.assertIn("nodes", payload)

    def test_moves_catalog(self) -> None:
        self.assertIn("check_exposure", self.run_cli("moves", "--domain", "web").stdout)

    def test_module_entrypoint_from_repo_root(self) -> None:
        """navhack.py shadows the package; `python -m navhack` must still work."""
        proc = subprocess.run(
            [sys.executable, "-m", "navhack", "version"],
            cwd=str(ROOT),
            env=self.env(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("navhack", proc.stdout)

    def test_unknown_engagement(self) -> None:
        self.run_cli("--slug", "does-not-exist", "find", expect=5)

    def test_out_of_scope_recon(self) -> None:
        self.run_cli("init", "scoped", "--scope", "example.com")
        proc = self.run_cli("recon", "http://127.0.0.1:1", "--fast", expect=3)
        self.assertIn("out of scope", proc.stderr)


if __name__ == "__main__":
    unittest.main()
