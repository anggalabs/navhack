"""Typed domain model: world-model nodes, edges, findings, moves, plans."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from . import util


class Kind(str, Enum):
    ENTRY = "entry"
    HOST = "host"
    PORT = "port"
    SERVICE = "service"
    URL = "url"
    PATH = "path"
    TECH = "tech"
    DNS = "dns"
    CERT = "cert"
    CRED = "cred"
    IDENTITY = "identity"
    SOURCE = "source"
    SHARE = "share"
    FINDING = "finding"
    OBJECTIVE = "objective"
    NOTE = "note"


class Fog(str, Enum):
    """Visibility of a node on the map."""

    UNKNOWN = "unknown"      # suspected, never touched
    SEEN = "seen"            # observed passively or by a single probe
    CHARTED = "charted"      # confirmed reachable, properties known
    VERIFIED = "verified"    # a primitive has been proven useful
    DEAD = "dead"            # gone, filtered, or ruled out


class Risk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FindingStatus(str, Enum):
    HYPOTHESIS = "hypothesis"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    FIXED = "fixed"


class PlanStatus(str, Enum):
    DRAFT = "draft"
    READY = "ready"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    ABANDONED = "abandoned"


SEVERITIES = ("critical", "high", "medium", "low", "info")


def confidence_clamp(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


@dataclass
class Node:
    kind: str
    key: str
    label: str = ""
    confidence: float = 0.5
    provenance: str = "manual"
    fog: str = Fog.UNKNOWN.value
    attrs: Dict[str, Any] = field(default_factory=dict)
    node_id: Optional[int] = None
    first_seen: str = ""
    last_seen: str = ""
    decay_at: str = ""

    def __post_init__(self) -> None:
        self.kind = str(getattr(self.kind, "value", self.kind))
        self.fog = str(getattr(self.fog, "value", self.fog))
        self.confidence = confidence_clamp(self.confidence)
        self.key = self.key.strip()
        if not self.label:
            self.label = self.key
        if not self.first_seen:
            self.first_seen = util.now_iso()
        self.last_seen = self.last_seen or self.first_seen

    def tags(self) -> Tuple[str, ...]:
        return (self.kind, self.key)


@dataclass
class Edge:
    src_id: int
    dst_id: int
    rel: str
    confidence: float = 0.6
    provenance: str = "manual"

    def __post_init__(self) -> None:
        self.confidence = confidence_clamp(self.confidence)


@dataclass
class Finding:
    title: str
    primitive: str
    target: str
    severity: str = "medium"
    kind: str = "web"
    evidence: str = ""
    status: str = FindingStatus.HYPOTHESIS.value
    confidence: float = 0.5
    cve: str = ""
    remediation: str = ""
    finding_id: Optional[int] = None
    node_key: str = ""
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self) -> None:
        self.status = str(getattr(self.status, "value", self.status))
        self.severity = self.severity.lower() if self.severity.lower() in SEVERITIES else "medium"
        self.confidence = confidence_clamp(self.confidence)
        if not self.created_at:
            self.created_at = util.now_iso()
        self.updated_at = self.updated_at or self.created_at


@dataclass
class MoveSpec:
    """Declarative attack move: preconditions, effects, cost, recipe."""

    move_id: str
    title: str
    domain: str
    pre: Tuple[str, ...]
    post: Tuple[str, ...]
    target_kind: str = "host"
    noise: int = 1
    seconds: float = 5.0
    p: float = 0.7
    risk: str = Risk.LOW.value
    mutating: bool = False
    adapter: str = ""
    how: str = ""
    doc: str = ""

    def __post_init__(self) -> None:
        self.pre = tuple(self.pre)
        self.post = tuple(self.post)
        self.risk = str(getattr(self.risk, "value", self.risk))
        self.p = max(0.01, min(1.0, float(self.p)))

    @property
    def cost(self) -> float:
        return self.seconds + self.noise * 4.0

    def to_dict(self) -> Dict[str, Any]:
        data = dataclasses.asdict(self)
        data["pre"] = list(self.pre)
        data["post"] = list(self.post)
        return data


@dataclass
class PlanStep:
    seq: int
    move: MoveSpec
    target_key: str = ""
    target_kind: str = "host"
    note: str = ""
    bound: bool = False


@dataclass
class Plan:
    goal: str
    direction: str = "forward"
    steps: List[PlanStep] = field(default_factory=list)
    noise: int = 0
    seconds: float = 0.0
    confidence: float = 0.0
    unmet: List[str] = field(default_factory=list)
    over_budget: bool = False
    status: str = PlanStatus.DRAFT.value
    plan_id: Optional[int] = None
    created_at: str = ""

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = util.now_iso()

    @property
    def length(self) -> int:
        return len(self.steps)


@dataclass
class StepResult:
    ok: bool
    detail: str = ""
    evidence: str = ""
    nodes: List[Node] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    needs_tool: str = ""
    http_status: int = 0
    elapsed: float = 0.0


@dataclass
class Budget:
    max_noise: int = 120
    max_seconds: float = 900.0
    max_steps: int = 12
    max_requests: int = 400
    concurrency: int = 6
    rate_per_second: float = 8.0
    safe_mode: bool = True
    dry_run: bool = True
    abort_5xx: int = 5

    def scaled(self, factor: float) -> "Budget":
        clone = dataclasses.replace(self)
        clone.max_noise = max(1, int(clone.max_noise * factor))
        clone.max_seconds = max(5.0, clone.max_seconds * factor)
        clone.max_requests = max(10, int(clone.max_requests * factor))
        return clone


@dataclass
class Engagement:
    name: str
    slug: str
    scope: List[str]
    created_at: str = ""
    oob_public: str = ""
    budget: Budget = field(default_factory=Budget)
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = util.now_iso()

    def to_dict(self) -> Dict[str, Any]:
        data = dataclasses.asdict(self)
        data["version"] = 1
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Engagement":
        budget = data.get("budget") or {}
        return cls(
            name=data.get("name", "engagement"),
            slug=data.get("slug", "engagement"),
            scope=list(data.get("scope") or []),
            created_at=data.get("created_at", ""),
            oob_public=data.get("oob_public", ""),
            budget=Budget(**{k: v for k, v in budget.items() if k in Budget.__dataclass_fields__}),
            notes=data.get("notes", ""),
        )
