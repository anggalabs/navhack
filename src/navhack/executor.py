"""Plan execution: policy gate -> adapter -> evidence -> recorder.

Failure handling is deliberately boring: when a step fails the run stops and
says which precondition is now unmet, so the operator (or ``navhack plan`` on
the fresh state) can re-route from the current node instead of replaying the
whole chain from the entry point.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import grammar, planner
from .adapters import ADAPTERS
from .adapters.base import ExecCtx
from .capability import collect
from .models import Plan, PlanStep, StepResult


@dataclass
class StepOutcome:
    seq: int
    move_id: str
    target: str
    status: str
    detail: str = ""
    needs_tool: str = ""
    elapsed: float = 0.0
    findings: int = 0
    nodes: int = 0
    recipe: str = ""

    @property
    def ok(self) -> bool:
        return self.status in ("ok", "dry-run")


@dataclass
class RunSummary:
    plan_id: int
    status: str = "done"
    outcomes: List[StepOutcome] = field(default_factory=list)
    replan_to: List[str] = field(default_factory=list)
    note: str = ""

    @property
    def ok(self) -> bool:
        return self.status in ("done", "dry-run")

    def counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for outcome in self.outcomes:
            counts[outcome.status] = counts.get(outcome.status, 0) + 1
        return counts


class Runner:
    def __init__(self, ctx: ExecCtx, plan: Plan, *, assume_yes: bool = False, keep_going: bool = False):
        self.ctx = ctx
        self.plan = plan
        self.assume_yes = assume_yes
        self.keep_going = keep_going

    def run(self) -> RunSummary:
        summary = RunSummary(plan_id=self.plan.plan_id or 0)
        if not self.plan.steps:
            summary.status = "empty"
            return summary

        for step in self.plan.steps:
            move = step.move
            decision = self.ctx.policy.gate_move(move, confirmed=self.assume_yes)
            if not decision.allowed:
                outcome = StepOutcome(
                    seq=step.seq,
                    move_id=move.move_id,
                    target=step.target_key,
                    status="blocked",
                    detail=decision.reason,
                    recipe=move.how,
                )
                summary.outcomes.append(outcome)
                if self.plan.plan_id:
                    self.ctx.store.set_step_result(self.plan.plan_id, step.seq, "blocked", decision.reason)
                summary.status = "blocked"
                summary.note = decision.reason
                self._record("step-blocked", step, decision.reason)
                break

            if self.ctx.dry_run:
                outcome = StepOutcome(
                    seq=step.seq,
                    move_id=move.move_id,
                    target=step.target_key,
                    status="dry-run",
                    detail=move.title,
                    recipe=move.how,
                )
                summary.outcomes.append(outcome)
                summary.status = "dry-run"
                self._record("step-dry", step, move.how)
                continue

            outcome = self._execute(step)
            summary.outcomes.append(outcome)
            if outcome.status == "failed" and not self.keep_going:
                summary.status = "failed"
                summary.replan_to = self._replan()
                summary.note = outcome.detail
                self.ctx.policy.record("run-failed", seq=step.seq, move=move.move_id, detail=outcome.detail)
                break
            if self.ctx.policy.aborted:
                summary.status = "aborted"
                summary.note = self.ctx.policy.abort_reason
                break

        else:
            summary.status = "dry-run" if self.ctx.dry_run else "done"

        if self.plan.plan_id and summary.status not in ("dry-run", "done"):
            self.ctx.store.set_plan_status(self.plan.plan_id, summary.status)
        elif self.plan.plan_id:
            self.ctx.store.set_plan_status(self.plan.plan_id, "done" if summary.status == "done" else "draft")
        return summary

    def _execute(self, step: PlanStep) -> StepOutcome:
        move = step.move
        adapter = ADAPTERS.get(move.adapter)
        started = time.monotonic()
        if adapter is None:
            result = StepResult(False, "adapter %r not implemented" % move.adapter, needs_tool=move.adapter)
        else:
            try:
                result = adapter(self.ctx, step)
            except Exception as exc:  # noqa: BLE001 - one bad adapter must not kill the run
                result = StepResult(False, "%s: %s" % (type(exc).__name__, exc))
        elapsed = time.monotonic() - started
        self.ctx.policy.spend(noise=move.noise)
        if result.nodes:
            for node in result.nodes:
                if node.node_id is None:
                    node.node_id = self.ctx.store.upsert_node(node)
        findings = []
        for finding in result.findings:
            if finding.finding_id is None:
                finding.finding_id = self.ctx.store.add_finding(finding)
            findings.append(finding.finding_id)

        status = "ok" if result.ok else ("needs-tool" if result.needs_tool else "failed")
        if self.plan.plan_id:
            self.ctx.store.set_step_result(
                self.plan.plan_id, step.seq, status, result.detail, result.evidence, elapsed
            )
        self._record("step-" + status, step, result.detail, evidence=result.evidence, needs=result.needs_tool)
        if result.evidence:
            self.ctx.save(
                "step-%02d-%s.txt" % (step.seq, move.move_id),
                result.evidence.encode("utf-8"),
                kind="evidence",
                note=result.detail,
            )
        return StepOutcome(
            seq=step.seq,
            move_id=move.move_id,
            target=step.target_key,
            status=status,
            detail=result.detail,
            needs_tool=result.needs_tool,
            elapsed=elapsed,
            findings=len(findings),
            nodes=len(result.nodes),
            recipe=move.how,
        )

    def _replan(self) -> List[str]:
        try:
            caps = collect(
                self.ctx.store,
                granted=self.ctx.store.tags(),
                entry_hosts=[node.key for node in self.ctx.store.find_nodes(kinds=["entry"], limit=20)],
            )
            return [move.move_id for move, _missing in planner.frontier(caps)[:5]]
        except Exception:
            return []

    def _record(self, kind: str, step: PlanStep, detail: str, *, evidence: str = "", needs: str = "") -> None:
        if self.ctx.recorder is None:
            return
        try:
            self.ctx.recorder.event(
                kind,
                seq=step.seq,
                move=step.move.move_id,
                target=step.target_key,
                detail=detail,
                evidence=evidence[:2000],
                needs_tool=needs,
            )
        except Exception:
            pass


def execute_one(ctx: ExecCtx, move_id: str, target: str) -> StepOutcome:
    move = grammar.get(move_id)
    if move is None:
        return StepOutcome(0, move_id, target, "failed", "unknown move")
    step = PlanStep(seq=1, move=move, target_key=target, target_kind=move.target_kind, bound=True)
    return Runner(ctx, Plan(goal="ad-hoc"))._execute(step)


__all__ = ["Runner", "RunSummary", "StepOutcome", "execute_one"]
