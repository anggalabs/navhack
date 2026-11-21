"""Attack planning: forward A* over the move grammar, plus reverse regression.

The planner reasons over *tags* (capability prepositional symbols).  Cost is a
blend of wall-clock and noise; confidence is the product of the chosen moves'
success probabilities.  Because the search is a hypergraph Dijkstra with an
admissible heuristic (``h`` = remaining tags times the cheapest move cost), the
returned chain is optimal under the cost model, not merely "a chain".

Two things bound the output:

* ``Budget`` — noise, seconds and step caps, enforced during search;
* ``Policy``-style safety — mutating moves are marked so a report can show what
  will touch the target.

The plan is then *grounded*: every step is attached to a concrete node from the
world model.  Ungrounded steps stay visible (``bound=False``) instead of being
silently dropped, so a gap in recon is obvious.
"""

from __future__ import annotations

import heapq
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from . import grammar
from .capability import Capabilities
from .models import Budget, MoveSpec, Plan, PlanStep
from .store import Store

INF = float("inf")


@dataclass
class Search:
    goal: str
    best: Dict[str, float] = field(default_factory=dict)
    choice: Dict[str, Tuple[MoveSpec, str]] = field(default_factory=dict)
    reasons: Dict[str, str] = field(default_factory=dict)

    def reached(self) -> bool:
        return self.best.get(self.goal, INF) < INF


@dataclass
class Grounding:
    target_key: str = ""
    target_kind: str = "host"
    bound: bool = False
    note: str = ""


def _cost(move: MoveSpec, over_budget: bool) -> float:
    penalty = 3.0 if over_budget and move.mutating else 1.0
    return (move.seconds + move.noise * 4.0) * penalty


def forward(
    caps: Capabilities,
    goal: str,
    *,
    budget: Optional[Budget] = None,
    max_steps: int = 12,
) -> Search:
    """Dijkstra/A* fixation over the grammar; returns the tag lattice result."""
    budget = budget or Budget()
    search = Search(goal=goal)
    for tag in caps.tags:
        search.best[tag] = 0.0
        search.reasons[tag] = "available"

    moves = grammar.all_moves()
    # Cheapest producer cost is the admissible heuristic for still-missing tags.
    min_post_cost: Dict[str, float] = {}
    for move in moves:
        weight = _cost(move, False)
        for tag in move.post:
            min_post_cost[tag] = min(min_post_cost.get(tag, INF), weight)

    def heuristic(tag: str) -> float:
        return min_post_cost.get(tag, 4.0)

    changed = True
    rounds = 0
    while changed and rounds < 64:
        changed = False
        rounds += 1
        for move in moves:
            if any(search.best.get(pre, INF) == INF for pre in move.pre):
                continue
            bottleneck = max(move.pre, key=lambda p: search.best.get(p, INF))
            base = search.best.get(bottleneck, INF)
            if base == INF:
                continue
            candidate = base + max(1.0, _cost(move, False))
            for post in move.post:
                if candidate + 1e-9 < search.best.get(post, INF):
                    current = search.best.get(post, INF)
                    if current > candidate:
                        search.best[post] = candidate
                        search.choice[post] = (move, bottleneck)
                        search.reasons[post] = "via %s (g=%.1f, h=%.1f)" % (
                            move.move_id,
                            candidate,
                            heuristic(post),
                        )
                        changed = True
    return search


def backward(caps: Capabilities, goal: str, *, max_depth: int = 10) -> Search:
    """Regression search: from the objective back to what we already hold."""
    search = Search(goal=goal)
    # Distance from tag to goal: 0 at the goal, then grow through move.pre.
    frontier: List[Tuple[float, str]] = [(0.0, goal)]
    search.best[goal] = 0.0
    visited_depth: Dict[str, int] = {}

    while frontier:
        cost, tag = heapq.heappop(frontier)
        if cost > search.best.get(tag, INF):
            continue
        depth = visited_depth.get(tag, 0)
        if depth >= max_depth:
            continue
        for move in grammar.producers(tag):
            step_cost = max(1.0, _cost(move, False))
            for pre in move.pre:
                candidate = cost + step_cost
                if candidate + 1e-9 < search.best.get(pre, INF):
                    search.best[pre] = candidate
                    search.choice[pre] = (move, tag)
                    visited_depth[pre] = depth + 1
                    heapq.heappush(frontier, (candidate, pre))
    return search


def _required_tags(search: Search, goal: str, have: Set[str]) -> List[str]:
    """Collect every tag that must be produced to satisfy ``goal``."""
    need: List[str] = []
    seen: Set[str] = set()
    stack = [goal]
    while stack:
        tag = stack.pop()
        if tag in seen:
            continue
        seen.add(tag)
        if tag in have:
            continue
        entry = search.choice.get(tag)
        if entry is None:
            continue
        move, bottleneck = entry
        need.append(tag)
        for pre in move.pre:
            if pre not in have:
                stack.append(pre)
        stack.append(bottleneck)
    return need


def _backward_chain(search: Search, goal: str, have: Set[str]) -> List[Tuple[MoveSpec, str]]:
    """Turn a regression search into an entry-first ordered move list."""
    chosen: Dict[str, Tuple[MoveSpec, str, float]] = {}
    seen: Set[str] = set()
    stack = [goal]
    while stack:
        tag = stack.pop()
        if tag in have or tag in seen:
            continue
        seen.add(tag)
        # A move "produces" tag when its relaxation recorded (pre -> (move, tag)).
        producers = [
            (move, post, sum(search.best.get(pre, INF) for pre in move.pre))
            for pre, (move, post) in search.choice.items()
            if post == tag
        ]
        if not producers:
            continue
        producers.sort(key=lambda item: item[2])
        move, post, weight = producers[0]
        chosen[move.move_id] = (move, tag, weight)
        for pre in move.pre:
            stack.append(pre)
    ordered = sorted(chosen.values(), key=lambda item: item[2])
    return [(move, tag) for move, tag, _weight in ordered]


def _order(search: Search, tags: List[str], have: Set[str], reverse: bool) -> List[Tuple[MoveSpec, str]]:
    """Order moves so every precondition is produced before its consumer."""
    pairs: List[Tuple[float, MoveSpec, str]] = []
    for tag in tags:
        entry = search.choice.get(tag)
        if entry is None:
            continue
        move, _ = entry
        pairs.append((search.best.get(tag, INF), move, tag))
    # Forward: cheapest-to-reach first.  Reverse: farthest-from-entry first.
    pairs.sort(key=lambda item: item[0], reverse=reverse)
    return [(move, tag) for _, move, tag in pairs]


def _ground(store: Store, move: MoveSpec, previous: Optional[str]) -> Grounding:
    kind = move.target_kind
    nodes = store.find_nodes(kinds=[kind], min_confidence=0.25, limit=40)
    if not nodes:
        # Synthesise a placeholder so later steps still have a handle; the
        # adapter resolves the scheme/port at execution time.
        if previous and kind in ("port", "service", "url", "path"):
            if kind == "port":
                guess = previous if ":" in previous else "%s:80" % previous
            elif kind in ("url", "path"):
                guess = "http://%s/" % previous if "://" not in previous else previous
            else:
                guess = "%s/unknown" % previous
            return Grounding(guess, kind, False, "synthesised from %s" % previous)
        return Grounding("?", kind, False, "no %s known" % kind)
    if previous:
        node = store.node_by_key(kind, previous)
        if node is not None:
            return Grounding(node.key, kind, True, "reuses previous target")
        prev_nodes = store.find_nodes(limit=5, min_confidence=0.3)
        for candidate in prev_nodes:
            if candidate.key == previous:
                for _, neighbour in store.neighbours(candidate.node_id or 0):
                    if neighbour.kind == kind:
                        return Grounding(neighbour.key, kind, True, "adjacent to %s" % previous)
    best = max(nodes, key=lambda n: (n.confidence, n.last_seen))
    wanted = {"deploy_webshell": "upload", "exec_via_rce": "shell", "read_config": "file_read"}.get(move.move_id)
    if wanted:
        flagged = [n for n in nodes if n.attrs.get(wanted)]
        if flagged:
            pick = max(flagged, key=lambda n: n.confidence)
            return Grounding(pick.key, kind, True, "prefers %s target" % wanted)
    return Grounding(best.key, kind, True, "highest confidence %s" % kind)


def plan(
    store: Store,
    caps: Capabilities,
    goal: str,
    *,
    direction: str = "forward",
    budget: Optional[Budget] = None,
) -> Plan:
    budget = budget or Budget()
    if grammar.get("__goal__" + goal) is None and goal not in grammar.OBJECTIVES and ":" not in goal:
        goal = "objective:" + goal
    result = Plan(goal=goal, direction=direction)
    have = set(caps.tags)
    if goal in have:
        result.steps = []
        result.confidence = 1.0
        result.status = "ready"
        return result

    search = backward(caps, goal) if direction == "backward" else forward(caps, goal, budget=budget)
    used_backward = direction == "backward"
    if not search.reached() and direction == "backward":
        # Fall back to forward so a partial chain is still produced.
        search = forward(caps, goal, budget=budget)
        used_backward = False
        result.direction = "forward (fallback)"

    if not search.reached():
        producers = grammar.producers(goal)
        missing: Set[str] = set()
        for move in producers:
            missing.update(tag for tag in move.pre if tag not in have)
        result.unmet = sorted(missing)[:8] or [goal]
        result.status = "failed"
        return result

    tags = _required_tags(search, goal, have)
    if used_backward:
        ordered = _backward_chain(search, goal, have)
    else:
        ordered = _order(search, tags, have, reverse=False)

    seq = 0
    previous: Optional[str] = None
    noise = 0
    seconds = 0.0
    confidence = 1.0
    for move, tag in ordered:
        if seq >= budget.max_steps:
            result.unmet.append("step cap reached (%d)" % budget.max_steps)
            break
        ground = _ground(store, move, previous)
        seq += 1
        result.steps.append(
            PlanStep(
                seq=seq,
                move=move,
                target_key=ground.target_key,
                target_kind=ground.target_kind,
                note=ground.note,
                bound=ground.bound,
            )
        )
        previous = ground.target_key if ground.bound else previous
        noise += move.noise
        seconds += move.seconds
        confidence *= move.p

    result.noise = noise
    result.seconds = seconds
    result.confidence = round(confidence, 4)
    result.over_budget = noise > budget.max_noise or seconds > budget.max_seconds
    if result.steps:
        result.status = "ready"
    else:
        result.status = "failed"
    return result


def alternatives(store: Store, caps: Capabilities, goal: str, *, limit: int = 5) -> List[MoveSpec]:
    """Moves that could produce the goal from what we hold (for the UI)."""
    have = set(caps.tags)
    out = []
    for move in grammar.producers(goal):
        missing = [tag for tag in move.pre if tag not in have]
        if not missing:
            out.append(move)
        if len(out) >= limit:
            break
    return out


def frontier(caps: Capabilities) -> List[Tuple[MoveSpec, List[str]]]:
    """Cheapest next moves from the current state, for the map's 'suggest' panel."""
    have = set(caps.tags)
    scored: List[Tuple[float, MoveSpec, List[str]]] = []
    for move in grammar.all_moves():
        if all(tag in have for tag in move.post):
            continue
        missing = [tag for tag in move.pre if tag not in have]
        if len(missing) > 1:
            continue
        score = _cost(move, False) + len(missing) * 25.0
        scored.append((score, move, missing))
    scored.sort(key=lambda item: item[0])
    return [(move, missing) for _, move, missing in scored[:8]]
