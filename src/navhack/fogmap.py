"""Fog-of-war map renderer.

The map is the navigation UI: what has been lit, what is still dark, and the
cheapest moves from where we stand.  It renders on an 80-column phone terminal
as well as a wide desktop, degrades to ASCII, and never wraps mid-glyph.

Sections are ordered like the attack itself (entry -> host -> service ->
surface -> material -> objective) so reading down the page is reading forward.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from . import grammar, util
from .capability import Capabilities
from .models import Fog, Kind, Node
from .planner import frontier
from .store import Store

SECTIONS = [
    ("ENTRY", [Kind.ENTRY.value, Kind.DNS.value]),
    ("HOSTS", [Kind.HOST.value]),
    ("SERVICES", [Kind.SERVICE.value, Kind.PORT.value]),
    ("SURFACE", [Kind.URL.value, Kind.PATH.value, Kind.TECH.value, Kind.SHARE.value]),
    ("MATERIAL", [Kind.CRED.value, Kind.IDENTITY.value, Kind.CERT.value]),
    ("FINDINGS", [Kind.FINDING.value]),
    ("OBJECTIVES", ["objective"]),
]

FOG_BAR = {
    Fog.UNKNOWN.value: (0, "unknown"),
    Fog.SEEN.value: (1, "seen"),
    Fog.CHARTED.value: (2, "charted"),
    Fog.VERIFIED.value: (3, "verified"),
    Fog.DEAD.value: (0, "dead"),
}


def _bar(confidence: float, width: int = 6) -> str:
    filled = int(round(max(0.0, min(1.0, confidence)) * width))
    return "[" + "#" * filled + "." * (width - filled) + "]"


def _node_row(theme, node: Node, width: int) -> str:
    glyph = theme.glyph(node.kind)
    color = theme.kind_color(node.fog if node.fog == Fog.DEAD.value else node.kind)
    label = node.key
    if node.label and node.label != node.key and node.kind != Kind.URL.value:
        label = "%s — %s" % (node.key, node.label)
    elif node.kind == Kind.URL.value and node.label:
        label = "%s (%s)" % (node.key, node.label)
    label = util.clip(label, max(20, width - 34))
    fog = str(node.fog)
    meta = "%s %s %2.0f%%" % (_bar(node.confidence), fog[:8], node.confidence * 100)
    if node.kind == "port":
        meta = "%s open" % _bar(node.confidence)
    if node.kind in ("finding", "path") and node.attrs.get("status"):
        meta += " %s" % node.attrs.get("status")
    row = "%s %-*s %s" % (theme(glyph, color), max(20, width - 34), label, theme(meta, "dim"))
    return row


def _coverage(store: Store, caps: Capabilities) -> str:
    stats = store.stats()
    fog = stats.get("fog", {}) or {}
    lit = fog.get(Fog.CHARTED.value, 0) + fog.get(Fog.VERIFIED.value, 0)
    seen = fog.get(Fog.SEEN.value, 0)
    total = max(1, sum(fog.values()))
    ratio = lit / total
    return "%d lit / %d seen / %d total   %s" % (lit, seen, total, _bar(ratio, 20))


def render(
    store: Store,
    *,
    theme,
    scope_text: str = "",
    budget: Optional[Dict[str, object]] = None,
    caps: Optional[Capabilities] = None,
    width: int = 100,
    suggestions: bool = True,
) -> str:
    width = max(56, min(width, 160))
    out: List[str] = []
    rule = theme.glyph("hline") * min(width, 78)
    out.append(theme("NAVHACK // fog map", "bold", "bright_cyan"))
    if scope_text:
        out.append("%s %s" % (theme("scope", "dim"), util.clip(scope_text, width - 8)))
    if budget:
        out.append(
            "%s requests %s/%s  %s noise %s/%s  %s %s"
            % (
                theme("budget", "dim"),
                budget.get("requests", 0),
                budget.get("max_requests", "-"),
                theme("·", "dim"),
                budget.get("noise", 0),
                budget.get("max_noise", "-"),
                theme("·", "dim"),
                util.human_delta(float(budget.get("elapsed", 0))),
            )
        )
    out.append(rule)

    found_any = False
    stats = store.stats()
    fog_counts = stats.get("fog", {}) or {}
    if fog_counts:
        out.append(theme("coverage", "dim") + " " + _coverage(store, caps) if caps else "")
    for title, kinds in SECTIONS:
        nodes: List[Node] = []
        if title == "OBJECTIVES":
            held = [tag for tag in grammar.OBJECTIVES if caps and caps.has(tag)]
            for tag in held:
                out.append(
                    "%s %s %s"
                    % (theme(theme.glyph("objective"), "bright_green"), theme(grammar.tag_label(tag), "bright_green"), theme("held", "dim"))
                )
                found_any = True
            continue
        for kind in kinds:
            nodes.extend(store.find_nodes(kinds=[kind], limit=80))
        if not nodes:
            continue
        found_any = True
        out.append("")
        out.append(theme(title, "bold"))
        nodes.sort(key=lambda n: (n.fog == Fog.DEAD.value, -n.confidence))
        for node in nodes[:40]:
            out.append(_node_row(theme, node, width))
        if len(nodes) > 40:
            out.append(theme("  … %d more" % (len(nodes) - 40), "dim"))

    if not found_any:
        out.append("")
        out.append(theme("  (nothing charted yet — run `navhack recon <target>`)", "dim"))

    edges = store.edges(limit=12)
    if edges:
        out.append("")
        out.append(theme("EDGES", "bold"))
        for edge in edges:
            out.append(
                "  %s %s %s %s"
                % (
                    util.clip(edge["src"]["key"], 26),
                    theme(theme.glyph("arrow"), "dim"),
                    theme(edge["rel"], "dim"),
                    util.clip(edge["dst"]["key"], 26),
                )
            )

    if suggestions and caps is not None:
        out.append("")
        out.append(theme("NEXT MOVES", "bold"))
        choices = frontier(caps)
        if not choices:
            out.append(theme("  (no move available)", "dim"))
        for move, missing in choices[:5]:
            gate = "" if not missing else theme(" needs %s" % ", ".join(grammar.tag_label(t) for t in missing), "yellow")
            out.append(
                "  %s %s %s%s"
                % (
                    theme(theme.glyph("arrow"), "cyan"),
                    theme(move.move_id, "bold"),
                    theme("· n%d p%.2f" % (move.noise, move.p), "dim"),
                    gate,
                )
            )

    out.append("")
    out.append(rule)
    out.append(
        theme(
            "legend: # host  o port  s service  > url  . path  ! finding  * objective   #bar = confidence",
            "dim",
        )
    )
    if budget and budget.get("aborted"):
        out.append(theme("ABORTED: %s" % budget.get("abort_reason", ""), "bright_red"))
    return "\n".join(out)


def render_brief(store: Store, caps: Capabilities, theme) -> str:
    stats = store.stats()
    fog = stats.get("fog", {}) or {}
    lit = fog.get(Fog.CHARTED.value, 0) + fog.get(Fog.VERIFIED.value, 0)
    return "%s | nodes %d (%d lit) | findings %d | plans %d | tags %d" % (
        theme("map", "dim"),
        sum(fog.values()),
        lit,
        stats.get("findings", {}).get("confirmed", 0),
        stats.get("plans", 0),
        stats.get("tags", 0),
    )


__all__ = ["render", "render_brief", "SECTIONS"]
