"""Report generation: Markdown for humans, JSON for machines.

The report is deliberately blunt about provenance: every finding carries its
confidence, status and evidence hash, and every chain shows which steps are
still only hypotheses.  A finding with no evidence is reported as a lead, not
as a vulnerability.
"""

from __future__ import annotations

import datetime as dt
from typing import Any, Dict, List, Optional

from . import __version__, grammar, util
from .capability import collect
from .models import Finding, FindingStatus
from .store import Store

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _banner(engagement) -> List[str]:
    return [
        "# Penetration test report — %s" % engagement.name,
        "",
        "| Field | Value |",
        "|---|---|",
        "| Engagement | %s |" % engagement.name,
        "| Slug | `%s` |" % engagement.slug,
        "| Generated | %s |" % util.now_iso(),
        "| Tool | navhack %s |" % __version__,
        "| Scope | %s |" % (", ".join("`%s`" % entry for entry in engagement.scope) or "(none)"),
        "",
    ]


def _severity_table(findings: List[Finding]) -> List[str]:
    counts: Dict[str, int] = {}
    for finding in findings:
        counts[finding.status] = counts.get(finding.status, 0) + 1
    confirmed = sum(counts.get(s, 0) for s in ("confirmed",))
    lines = ["## Summary", ""]
    lines.append("| Severity | Confirmed | Hypotheses |")
    lines.append("|---|---|---|")
    for severity in SEVERITY_ORDER:
        conf = sum(1 for f in findings if f.severity == severity and f.status == "confirmed")
        hyp = sum(1 for f in findings if f.severity == severity and f.status == "hypothesis")
        lines.append("| %s | %d | %d |" % (severity, conf, hyp))
    lines.append("")
    lines.append(
        "%d finding(s) total, %d confirmed by evidence. Unconfirmed rows are leads to retest."
        % (len(findings), confirmed)
    )
    lines.append("")
    return lines


def _finding_block(finding: Finding, index: int, slug: str = "") -> List[str]:
    lines = [
        "### %d. %s" % (index, finding.title),
        "",
        "| | |",
        "|---|---|",
        "| Severity | **%s** |" % finding.severity.upper(),
        "| Status | %s (confidence %.0f%%) |" % (finding.status, finding.confidence * 100),
        "| Primitive | `%s` |" % (finding.primitive or "-"),
        "| Target | `%s` |" % (finding.target or "-"),
    ]
    if finding.cve:
        lines.append("| CVE | %s |" % finding.cve)
    lines.append("")
    if finding.evidence:
        lines += ["**Evidence**", "", "```", util.clip(finding.evidence, 1800), "```", ""]
    if finding.remediation:
        lines += ["**Remediation**", "", finding.remediation, ""]
    lines += [
        "**Retest**",
        "",
        "```",
        "navhack verify %d --slug %s --live" % (finding.finding_id or 0, slug),
        "```",
        "",
    ]
    return lines


def _chain_block(plan: Dict[str, Any]) -> List[str]:
    lines = [
        "### Chain %d — %s" % (plan["id"], plan["goal"]),
        "",
        "Direction: %s · noise %s · est. %s · confidence %.0f%% · status: %s"
        % (plan["direction"], plan["noise"], util.human_delta(plan["seconds"]), plan["confidence"] * 100, plan["status"]),
        "",
        "| # | Move | Target | Result | Detail |",
        "|---|---|---|---|---|",
    ]
    for step in plan.get("steps", []):
        mark = {"ok": "PASS", "failed": "FAIL", "blocked": "BLOCKED", "needs-tool": "MANUAL", "dry-run": "PLANNED"}.get(
            step.get("status", ""), step.get("status", "")
        )
        lines.append(
            "| %s | `%s` | `%s` | %s | %s |"
            % (step.get("seq"), step.get("move_id"), step.get("target") or "-", mark, util.clip(step.get("detail", ""), 120))
        )
    lines.append("")
    return lines


def _objectives(store: Store, engagement) -> List[str]:
    caps = collect(store)
    lines = ["## Reachable objectives", ""]
    reachable = 0
    for tag, label in grammar.OBJECTIVES.items():
        if tag in caps.tags:
            lines.append("- **%s** — already held" % label)
            reachable += 1
            continue
        from . import planner as planner_mod

        plan = planner_mod.plan(store, caps, tag)
        if plan.status == "ready" and plan.steps:
            reachable += 1
            lines.append(
                "- %s — %d steps, %d noise, confidence %.0f%%" % (label, plan.length, plan.noise, plan.confidence * 100)
            )
        elif plan.unmet:
            lines.append("- %s — blocked on %s" % (label, ", ".join("`%s`" % tag for tag in plan.unmet[:4])))
    if not reachable:
        lines.append("Nothing reachable yet; the map needs more recon.")
    lines.append("")
    return lines


def _surface(store: Store) -> List[str]:
    lines = ["## Charted surface", ""]
    for kind in ("host", "port", "service", "url", "path", "tech", "cred", "identity", "share"):
        nodes = store.find_nodes(kinds=[kind], limit=60)
        if not nodes:
            continue
        lines.append("**%s**" % kind)
        for node in nodes:
            lines.append(
                "- `%s` — conf %.0f%%, fog %s, seen %s" % (node.key, node.confidence * 100, node.fog, node.last_seen)
            )
        lines.append("")
    if len(lines) == 2:
        lines.append("(empty)")
        lines.append("")
    return lines


def _negatives(store: Store) -> List[str]:
    tested = []
    for plan in store.plans(limit=20):
        for step in plan.get("steps", []):
            if step.get("status") == "failed":
                tested.append("`%s` on `%s` — %s" % (step.get("move_id"), step.get("target") or "-", util.clip(step.get("detail", ""), 100)))
    lines = ["## Ruled out / negative results", ""]
    lines += ["- " + item for item in tested[:40]] if tested else ["(none recorded)"]
    lines.append("")
    return lines


def _artifacts(store: Store) -> List[str]:
    items = store.artifacts()
    lines = ["## Evidence artefacts", ""]
    if not items:
        return lines + ["(none)", ""]
    lines.append("| Name | SHA-256 | Note |")
    lines.append("|---|---|---|")
    for item in items:
        lines.append("| `%s` | `%s` | %s |" % (item["name"], item["sha256"][:24] + "…", util.clip(item["note"], 80)))
    lines.append("")
    return lines


def _limitations(engagement, budget_report: Dict[str, Any]) -> List[str]:
    return [
        "## Coverage and limitations",
        "",
        "- Recon is budgeted: %s requests, noise %s. Port scans are connect scans from the built-in list, not a full SYN sweep."
        % (budget_report.get("requests", 0), budget_report.get("noise", 0)),
        "- Active checks are non-destructive unless a step is marked mutating and `--yes` was passed.",
        "- Adapters marked MANUAL need an external tool; the exact command is in the chain table.",
        "- A finding is only *confirmed* when an OOB callback, marker or hash proves it.",
        "",
        "## Reproducibility",
        "",
        "```",
        "navhack replay --slug %s --verify-chain" % engagement.slug,
        "navhack report --slug %s --format json" % engagement.slug,
        "```",
        "",
        "The flight recorder is an HMAC-SHA256 hash chain keyed per engagement: "
        "silent edits break the chain at the edited record.",
        "",
        "---",
        "Generated by navhack %s. Confirm business impact before publishing." % __version__,
        "",
    ]


def build_markdown(store: Store, engagement, budget_report: Optional[Dict[str, Any]] = None) -> str:
    budget_report = budget_report or {}
    findings = store.findings(limit=500)
    lines = _banner(engagement)
    lines += _severity_table(findings)
    lines += _objectives(store, engagement)
    lines += ["## Findings", ""]
    if not findings:
        lines += ["No findings recorded.", ""]
    for index, finding in enumerate(findings, start=1):
        lines += _finding_block(finding, index, engagement.slug)
    plans = [plan for plan in store.plans(limit=20) if plan.get("steps")]
    lines += ["## Chains", ""]
    if plans:
        for plan in plans:
            lines += _chain_block(plan)
    else:
        lines += ["No chain executed yet.", ""]
    lines += _surface(store)
    lines += _negatives(store)
    lines += _artifacts(store)
    lines += _limitations(engagement, budget_report)
    return "\n".join(lines).replace("navhack verify", "navhack verify")


def build_json(store: Store, engagement, budget_report: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    findings = store.findings(limit=500)
    return {
        "tool": "navhack",
        "version": __version__,
        "generated": util.now_iso(),
        "engagement": engagement.to_dict(),
        "budget": budget_report,
        "summary": {
            "findings": len(findings),
            "confirmed": sum(1 for f in findings if f.status == FindingStatus.CONFIRMED.value),
            "by_severity": {severity: sum(1 for f in findings if f.severity == severity) for severity in SEVERITY_ORDER},
        },
        "findings": [
            {
                "id": f.finding_id,
                "title": f.title,
                "severity": f.severity,
                "status": f.status,
                "confidence": f.confidence,
                "primitive": f.primitive,
                "target": f.target,
                "evidence": f.evidence,
                "remediation": f.remediation,
                "cve": f.cve,
            }
            for f in findings
        ],
        "plans": store.plans(limit=20),
        "nodes": [
            {"kind": n.kind, "key": n.key, "confidence": n.confidence, "fog": n.fog}
            for n in store.find_nodes(limit=2000)
        ],
        "artifacts": store.artifacts(),
        "stats": store.stats(),
    }


def write_report(store: Store, engagement, out_dir, fmt: str = "md", budget_report=None) -> List[str]:
    out_dir = out_dir.__class__(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%dT%H%M%S")
    written: List[str] = []
    if fmt in ("md", "both"):
        path = out_dir / ("report-%s.md" % stamp)
        util.atomic_write(path, build_markdown(store, engagement, budget_report))
        written.append(str(path))
    if fmt in ("json", "both"):
        path = out_dir / ("report-%s.json" % stamp)
        util.atomic_write(path, util.jdump(build_json(store, engagement, budget_report), pretty=True))
        written.append(str(path))
    return written


__all__ = ["build_markdown", "build_json", "write_report", "SEVERITY_ORDER"]
