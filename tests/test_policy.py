from __future__ import annotations

import time
import unittest

from navhack import grammar
from navhack.models import Budget
from navhack.policy import BudgetExceeded, Decision, Policy, PolicyError, RateLimiter
from navhack.scope import Scope, ScopeError


def make_policy(**budget_kwargs) -> Policy:
    defaults = dict(max_requests=100, max_noise=20, max_seconds=60, rate_per_second=1000.0)
    defaults.update(budget_kwargs)
    return Policy(Scope.parse(["example.com"]), Budget(**defaults))


class RateLimiterTests(unittest.TestCase):
    def test_burst_then_throttle(self) -> None:
        limiter = RateLimiter(50.0, burst=2)
        self.assertEqual(limiter.acquire(), 0.0)
        self.assertEqual(limiter.acquire(), 0.0)
        started = time.monotonic()
        limiter.acquire()
        self.assertGreater(time.monotonic() - started, 0.0)

    def test_retune(self) -> None:
        limiter = RateLimiter(1.0)
        limiter.retune(100.0)
        self.assertEqual(limiter.rate, 100.0)


class PolicyTests(unittest.TestCase):
    def test_scope_gate(self) -> None:
        policy = make_policy()
        policy.gate_host("example.com", 443)
        with self.assertRaises((PolicyError, ScopeError)):
            policy.gate_host("evil.test", 443)

    def test_request_budget(self) -> None:
        policy = make_policy(max_requests=1)
        policy.gate_host("example.com")
        policy.spend(requests=1)
        with self.assertRaises(BudgetExceeded):
            policy.gate_host("example.com")

    def test_time_budget(self) -> None:
        policy = make_policy(max_seconds=0.01)
        time.sleep(0.05)
        with self.assertRaises(BudgetExceeded):
            policy.gate_host("example.com")

    def test_noise_budget_blocks_move(self) -> None:
        policy = make_policy(max_noise=2)
        policy.budget.dry_run = False
        move = grammar.get("scan_port")
        policy.spend(noise=2)
        decision = policy.gate_move(move)
        self.assertFalse(decision.allowed)
        self.assertIn("noise", decision.reason)

    def test_safe_mode_blocks_mutating_without_yes(self) -> None:
        policy = make_policy()
        policy.budget.dry_run = False
        decision = policy.gate_move(grammar.get("deploy_webshell"))
        self.assertFalse(decision.allowed)
        self.assertTrue(decision.requires_confirmation)

    def test_yes_allows_mutating(self) -> None:
        policy = Policy(Scope.parse(["example.com"]), Budget(dry_run=False, safe_mode=True), assume_yes=True)
        self.assertTrue(policy.gate_move(grammar.get("deploy_webshell")).allowed)

    def test_dry_run_allows_everything(self) -> None:
        policy = make_policy()
        self.assertTrue(policy.gate_move(grammar.get("dcsync")).allowed)

    def test_five_xx_storm_aborts(self) -> None:
        policy = make_policy(abort_5xx=3)
        for _ in range(3):
            policy.note_status(500)
        self.assertTrue(policy.aborted)
        with self.assertRaises(PolicyError):
            policy.gate_host("example.com")

    def test_success_resets_storm(self) -> None:
        policy = make_policy(abort_5xx=2)
        policy.note_status(500)
        policy.note_status(200)
        policy.note_status(500)
        self.assertFalse(policy.aborted)

    def test_budget_report_shape(self) -> None:
        report = make_policy().budget_report()
        for key in ("requests", "noise", "aborted", "hosts"):
            self.assertIn(key, report)

    def test_decision_defaults(self) -> None:
        self.assertTrue(Decision(True).allowed)


if __name__ == "__main__":
    unittest.main()
