"""Adapter contract and shared helpers.

An adapter is a callable ``(ctx, step) -> StepResult``.  It receives the step's
target key, which the planner has already grounded to a real node in the world
model.  Adapters must be:

* **honest** — return ``needs_tool`` instead of pretending work happened;
* **idempotent** — a rerun must not duplicate half the graph;
* **quiet** — no printing; the CLI renders results;
* **bounded** — never read an unbounded body, never leave a socket open.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .. import util
from ..models import Engagement, Finding, Fog, Kind, Node, PlanStep, StepResult
from ..policy import Policy
from ..store import Store


@dataclass
class ExecCtx:
    store: Store
    policy: Policy
    engagement: Engagement
    artifacts: Path
    oob: Any = None
    verbose: bool = False
    dry_run: bool = True
    recorder: Any = None
    scope_notes: List[str] = field(default_factory=list)

    def node(
        self,
        kind: str,
        key: str,
        *,
        confidence: float = 0.6,
        fog: str = Fog.CHARTED.value,
        attrs: Optional[Dict[str, Any]] = None,
        provenance: str = "",
        label: str = "",
    ) -> Node:
        spec = Node(
            kind=kind,
            key=key,
            label=label,
            confidence=confidence,
            provenance=provenance or "adapter",
            fog=fog,
            attrs=attrs or {},
        )
        spec.node_id = self.store.upsert_node(spec, chart=fog)
        return spec

    def finding(
        self,
        title: str,
        primitive: str,
        target: str,
        *,
        severity: str = "medium",
        kind: str = "web",
        evidence: str = "",
        confidence: float = 0.6,
        remediation: str = "",
    ) -> Finding:
        from ..verifier import DEFAULT_REMEDIATION

        existing = self.store.find_finding(title, target)
        if existing is not None:
            self.store.update_finding(
                existing.finding_id or 0,
                confidence=max(existing.confidence, confidence),
                evidence=evidence or existing.evidence,
            )
            existing.confidence = max(existing.confidence, confidence)
            return existing
        record = Finding(
            title=title,
            primitive=primitive,
            target=target,
            severity=severity,
            kind=kind,
            evidence=evidence,
            confidence=confidence,
            remediation=remediation or DEFAULT_REMEDIATION.get(primitive, ""),
        )
        record.finding_id = self.store.add_finding(record)
        marker = self.node(
            Kind.FINDING.value,
            "%s @ %s" % (title, target),
            confidence=confidence,
            fog=Fog.CHARTED.value,
            attrs={"severity": severity, "primitive": primitive, "finding_id": record.finding_id},
            label=title,
        )
        record.node_key = marker.key
        return record

    def save(self, name: str, data: bytes, *, kind: str = "file", note: str = "") -> Path:
        safe = util.slugify(name, 80) or "artifact"
        stamp = util.utcnow().strftime("%Y%m%dT%H%M%S")
        path = self.artifacts / ("%s-%s" % (stamp, safe))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        import hashlib

        self.store.add_artifact(safe, str(path), hashlib.sha256(data).hexdigest(), kind, note)
        return path

    def log(self, message: str) -> None:
        if self.recorder is not None:
            try:
                self.recorder.event("adapter", message=message)
            except Exception:
                pass


AdapterFn = Callable[[ExecCtx, PlanStep], StepResult]

ADAPTERS: Dict[str, AdapterFn] = {}


def adapter(name: str) -> Callable[[AdapterFn], AdapterFn]:
    def wrap(fn: AdapterFn) -> AdapterFn:
        if name in ADAPTERS:
            raise ValueError("duplicate adapter: %s" % name)
        ADAPTERS[name] = fn
        return fn

    return wrap


def register_all() -> None:
    """Import adapter modules for their registration side effects."""
    from . import dns, external, generic, network, web  # noqa: F401


def needs_tool(tool: str, note: str = "") -> StepResult:
    return StepResult(False, detail=note or "external tool required: %s" % tool, needs_tool=tool)


def not_in_dry_run(ctx: ExecCtx) -> Optional[StepResult]:
    if ctx.dry_run:
        return StepResult(True, detail="dry-run")
    return None


def upsert_edge(ctx: ExecCtx, src: Node, dst: Node, rel: str, confidence: float = 0.7) -> None:
    if src.node_id and dst.node_id:
        from ..models import Edge

        ctx.store.add_edge(Edge(src.node_id, dst.node_id, rel, confidence, "adapter"))


__all__ = [
    "ExecCtx",
    "AdapterFn",
    "ADAPTERS",
    "adapter",
    "register_all",
    "needs_tool",
    "not_in_dry_run",
    "upsert_edge",
    "Kind",
    "Fog",
]
