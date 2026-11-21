"""Execution policy: scope gate, token bucket, budgets, safe mode, kill switch."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import util
from .models import Budget, MoveSpec
from .scope import Scope, ScopeError


class PolicyError(RuntimeError):
    pass


class BudgetExceeded(PolicyError):
    pass


@dataclass
class Decision:
    allowed: bool
    reason: str = ""
    requires_confirmation: bool = False


class RateLimiter:
    """Token bucket, monotonic clock, thread safe."""

    def __init__(self, rate_per_second: float, burst: Optional[float] = None):
        self.rate = max(0.1, float(rate_per_second))
        self.burst = max(1.0, float(burst if burst is not None else self.rate))
        self._tokens = self.burst
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, tokens: float = 1.0) -> float:
        """Block until tokens are available; returns the seconds waited."""
        waited = 0.0
        while True:
            with self._lock:
                now = time.monotonic()
                self._tokens = min(self.burst, self._tokens + (now - self._last) * self.rate)
                self._last = now
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return waited
                deficit = tokens - self._tokens
                sleep_for = deficit / self.rate
            time.sleep(min(sleep_for, 1.0))
            waited += min(sleep_for, 1.0)

    def retune(self, rate_per_second: float) -> None:
        with self._lock:
            self.rate = max(0.1, float(rate_per_second))
            self.burst = max(1.0, self.rate)


class Policy:
    """Per-run gate.  One instance per engagement run, shared across threads."""

    def __init__(
        self,
        scope: Scope,
        budget: Budget,
        *,
        assume_yes: bool = False,
        recorder=None,
        clock=time.monotonic,
    ):
        self.scope = scope
        self.budget = budget
        self.assume_yes = assume_yes
        self.recorder = recorder
        self.limiter = RateLimiter(budget.rate_per_second)
        self.clock = clock
        self.started = clock()
        self._lock = threading.Lock()
        self.requests = 0
        self.bytes_in = 0
        self.noise_spent = 0
        self.server_errors = 0
        self.deadline = self.started + budget.max_seconds if budget.max_seconds else 0.0
        self.aborted = False
        self.abort_reason = ""
        self.notes: List[str] = []
        self._host_hits: Dict[str, int] = {}

    # ------------------------------------------------------------------ #
    # gates
    # ------------------------------------------------------------------ #
    def gate_host(self, host: str, port: Optional[int] = None) -> str:
        if self.aborted:
            raise PolicyError("run aborted: %s" % self.abort_reason)
        reason = self.scope.require(host, port)
        remaining = self.remaining_seconds()
        if self.deadline and remaining <= 0:
            self.abort("time budget exhausted")
            raise BudgetExceeded("time budget exhausted")
        with self._lock:
            if self.requests >= self.budget.max_requests:
                raise BudgetExceeded("request budget exhausted (%d)" % self.budget.max_requests)
            self._host_hits[host] = self._host_hits.get(host, 0) + 1
        return reason

    def wait_turn(self) -> float:
        waited = self.limiter.acquire()
        if waited:
            self.record("throttle", seconds=round(waited, 3))
        return waited

    def gate_move(self, move: MoveSpec, *, confirmed: bool = False) -> Decision:
        """Decide whether a move may run now (dry-run aware, safe-mode aware)."""
        if self.budget.dry_run and not confirmed:
            return Decision(True, "dry-run", requires_confirmation=False)
        if self.budget.safe_mode and move.mutating and not self.assume_yes:
            return Decision(False, "safe mode: mutating move needs --yes", requires_confirmation=True)
        if self.noise_spent + move.noise > self.budget.max_noise:
            return Decision(
                False,
                "noise budget: %d/%d spent, move needs %d"
                % (self.noise_spent, self.budget.max_noise, move.noise),
            )
        remaining = self.remaining_seconds()
        if self.deadline and remaining <= 0:
            return Decision(False, "time budget exhausted")
        return Decision(True, "ok")

    # ------------------------------------------------------------------ #
    # accounting
    # ------------------------------------------------------------------ #
    def spend(self, *, requests: int = 0, nbytes: int = 0, noise: int = 0) -> None:
        with self._lock:
            self.requests += requests
            self.bytes_in += nbytes
            self.noise_spent += noise
            if self.deadline and self.requests and self.requests % 25 == 0:
                usage = self.requests / max(1, self.budget.max_requests)
                if usage > 0.75:
                    self.limiter.retune(max(1.0, self.limiter.rate * 0.7))

    def note_status(self, status: int) -> None:
        """Abort on a sustained 5xx storm so we stop hammering a broken target."""
        with self._lock:
            if 500 <= status < 600:
                self.server_errors += 1
                if self.budget.abort_5xx and self.server_errors >= self.budget.abort_5xx:
                    self.abort("target returned %d consecutive 5xx" % self.server_errors)
            elif status:
                self.server_errors = 0

    def remaining_seconds(self) -> float:
        if not self.deadline:
            return float("inf")
        return self.deadline - self.clock()

    def elapsed(self) -> float:
        return self.clock() - self.started

    def abort(self, reason: str) -> None:
        if not self.aborted:
            self.aborted = True
            self.abort_reason = reason
            self.notes.append("abort: %s" % reason)
            self.record("abort", reason=reason)

    def budget_report(self) -> Dict[str, object]:
        return {
            "requests": self.requests,
            "max_requests": self.budget.max_requests,
            "noise": self.noise_spent,
            "max_noise": self.budget.max_noise,
            "bytes_in": self.bytes_in,
            "elapsed": round(self.elapsed(), 1),
            "max_seconds": self.budget.max_seconds,
            "aborted": self.aborted,
            "abort_reason": self.abort_reason,
            "hosts": dict(self._host_hits),
        }

    def record(self, kind: str, **fields) -> None:
        if self.recorder is not None:
            try:
                self.recorder.event(kind, **fields)
            except Exception:
                pass


__all__ = [
    "Policy",
    "PolicyError",
    "BudgetExceeded",
    "Decision",
    "RateLimiter",
    "Scope",
    "ScopeError",
    "util",
]
