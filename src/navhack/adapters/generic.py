"""Local-only finishing adapters."""

from __future__ import annotations

import time

from .. import util
from ..models import Kind, PlanStep, StepResult
from .base import ExecCtx, adapter


@adapter("generic.collect")
def collect(ctx: ExecCtx, step: PlanStep) -> StepResult:
    findings = ctx.store.findings(limit=200)
    if not findings:
        return StepResult(False, "nothing confirmed yet")
    lines = []
    for finding in findings:
        lines.append(
            "#%d [%s/%s] %s -> %s\n  confidence=%.2f status=%s\n  evidence: %s"
            % (
                finding.finding_id or 0,
                finding.severity,
                finding.primitive,
                finding.title,
                finding.target,
                finding.confidence,
                finding.status,
                util.clip(finding.evidence, 300),
            )
        )
    path = ctx.save("evidence-index.md", ("\n\n".join(lines) + "\n").encode(), kind="evidence", note="finding index")
    return StepResult(True, "%d finding(s) indexed -> %s" % (len(findings), path.name))


@adapter("generic.report")
def report(ctx: ExecCtx, step: PlanStep) -> StepResult:
    return StepResult(True, "run `navhack report` to assemble markdown + json")


__all__ = ["collect", "report"]
