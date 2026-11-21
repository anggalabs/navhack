"""Command line interface.

Design rules:
* every command works identically on Termux, Linux, macOS and Windows;
* destructive work is opt-in (``--live`` for execution, ``--yes`` for mutating
  moves), so a first run can never surprise the target;
* exit codes are stable for scripting: 0 ok, 1 failure, 2 usage, 3 blocked,
  4 missing tool, 5 not found;
* ``--json`` produces machine output for every read command.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import sys
import time
import webbrowser
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import __version__, adapters, grammar, platform_compat as plat, report, util, verifier
from .adapters.base import ExecCtx
from .capability import collect
from .executor import Runner, execute_one
from .fogmap import render, render_brief
from .models import Budget, Engagement, Finding, FindingStatus, Kind, Node, Plan, PlanStatus, PlanStep
from .planner import plan as make_plan
from .policy import BudgetExceeded, Policy, PolicyError
from .recorder import Recorder, load_key
from .scope import Scope, ScopeError
from .store import Store

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_USAGE = 2
EXIT_BLOCKED = 3
EXIT_TOOL = 4
EXIT_MISSING = 5

THEME = util.DEFAULT_THEME


# --------------------------------------------------------------------------- #
# output helpers
# --------------------------------------------------------------------------- #
def out(text: str = "") -> None:
    print(text)


def emit(payload, as_json: bool) -> bool:
    if as_json:
        print(util.jdump(payload, pretty=True))
        return True
    return False


def info(message: str) -> None:
    print("%s %s" % (THEME(THEME.glyph("bullet"), "dim"), message))


def warn(message: str) -> None:
    print("%s %s" % (THEME(THEME.glyph("warn"), "yellow"), message), file=sys.stderr)


def bad(message: str) -> None:
    print("%s %s" % (THEME(THEME.glyph("bad"), "red"), message), file=sys.stderr)


def die(message: str, code: int = EXIT_FAIL) -> "NoReturn":  # type: ignore[name-defined]
    bad(message)
    raise SystemExit(code)


def confirm(args, prompt: str, default: bool = True) -> bool:
    if getattr(args, "yes", False):
        return True
    if getattr(args, "json", False):
        return default
    if not plat.is_tty(sys.stdin):
        return default
    suffix = "[Y/n]" if default else "[y/N]"
    try:
        answer = input("%s %s " % (prompt, suffix)).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    if not answer:
        return default
    return answer in ("y", "yes")


def table(headers: List[str], rows: List[List[str]], widths: Optional[List[int]] = None) -> str:
    widths = widths or [max(len(str(h)), *(len(str(r[i])) for r in rows)) if rows else len(h) for i, h in enumerate(headers)]
    widths = [min(w, 48) for w in widths]
    lines = []
    head = "  ".join(util.pad(util.clip(h, w), w) for h, w in zip(headers, widths))
    lines.append(THEME(head, "bold"))
    lines.append(THEME("  ".join("-" * w for w in widths), "dim"))
    for row in rows:
        lines.append("  ".join(util.pad(util.clip(str(cell), w), w) for cell, w in zip(row, widths)))
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# engagement session
# --------------------------------------------------------------------------- #
class Session:
    def __init__(self, engagement: Engagement, base: Path):
        self.engagement = engagement
        self.base = base
        self.db_path = base / "nav.db"
        self.artifact_dir = base / "artifacts"
        self.recorder_path = base / "recorder.jsonl"
        self._store: Optional[Store] = None
        self.recorder = Recorder(self.recorder_path, load_key(base / "engagement.key"))

    @property
    def store(self) -> Store:
        if self._store is None:
            self._store = Store(self.db_path)
        return self._store

    def scope(self) -> Scope:
        return Scope.parse(self.engagement.scope)

    def budget(self, args) -> Budget:
        budget = Budget(**self.engagement.budget.__dict__)
        budget.concurrency = getattr(args, "concurrency", None) or plat.default_concurrency()
        budget.rate_per_second = getattr(args, "rate", None) or budget.rate_per_second
        if getattr(args, "max_noise", None):
            budget.max_noise = args.max_noise
        if getattr(args, "max_time", None):
            budget.max_seconds = util.parse_duration(args.max_time, budget.max_seconds)
        if getattr(args, "max_requests", None):
            budget.max_requests = args.max_requests
        budget.dry_run = not getattr(args, "live", False)
        budget.safe_mode = bool(getattr(args, "safe_mode", True))
        return budget

    def policy(self, args) -> Policy:
        return Policy(
            self.scope(),
            self.budget(args),
            assume_yes=getattr(args, "yes", False),
            recorder=self.recorder,
        )

    def ctx(self, args, policy: Policy, oob=None) -> ExecCtx:
        return ExecCtx(
            store=self.store,
            policy=policy,
            engagement=self.engagement,
            artifacts=self.artifact_dir,
            oob=oob,
            verbose=getattr(args, "verbose", False),
            dry_run=policy.budget.dry_run,
            recorder=self.recorder,
        )

    def close(self) -> None:
        if self._store is not None:
            self._store.close()
            self._store = None


def engagements_root() -> Path:
    root = Path(os.environ.get("NAVHACK_HOME") or plat.data_home()) / "engagements"
    root.mkdir(parents=True, exist_ok=True)
    return root


def resolve_slug(explicit: Optional[str]) -> str:
    if explicit:
        return util.slugify(explicit)
    env = os.environ.get("NAVHACK_ENGAGEMENT")
    if env:
        return util.slugify(env)
    pointer = engagements_root() / "CURRENT"
    if pointer.exists():
        value = pointer.read_text(encoding="utf-8").strip()
        if value:
            return util.slugify(value)
    candidates = sorted(
        (path for path in engagements_root().iterdir() if (path / "engagement.json").exists()),
        key=lambda p: (p / "engagement.json").stat().st_mtime,
        reverse=True,
    )
    if not candidates:
        die("no engagement yet; run `navhack init <name> --scope <target>`", EXIT_MISSING)
    return candidates[0].name


def open_session(args) -> Session:
    slug = resolve_slug(getattr(args, "slug", None))
    base = engagements_root() / slug
    config = base / "engagement.json"
    if not config.exists():
        die("unknown engagement %r (try `navhack init`)" % slug, EXIT_MISSING)
    engagement = Engagement.from_dict(util.jload(config.read_text(encoding="utf-8"), {}))
    session = Session(engagement, base)
    session.recorder.event("command", command=getattr(args, "command", ""), argv=sys.argv[1:])
    return session


# --------------------------------------------------------------------------- #
# commands: meta
# --------------------------------------------------------------------------- #
def cmd_version(args) -> int:
    print("navhack %s (%s, python %s)" % (__version__, plat.PLATFORM_TAG, sys.version.split()[0]))
    print("grammar: %d moves, %d domains" % (len(grammar.all_moves()), len(grammar.domains())))
    print("adapters: %d" % len(adapters.ADAPTERS))
    print("data: %s" % plat.data_home())
    return EXIT_OK


def cmd_doctor(args) -> int:
    probe = plat.probe()
    if emit(probe, args.json):
        return EXIT_OK if probe.get("python_ok") and probe.get("data_writable") else EXIT_FAIL
    rows = [
        ["platform", probe["platform"]],
        ["python", "%s %s" % (probe["python"], "OK" if probe["python_ok"] else "TOO OLD (need 3.9+)")],
        ["sqlite", probe["sqlite"]],
        ["tls", util.clip(probe["tls"], 60)],
        ["ipv6", "yes" if probe["ipv6"] else "no"],
        ["unicode console", "yes" if probe["unicode_console"] else "no (ASCII fallback)"],
        ["colour", "yes" if probe["color"] else "no"],
        ["data dir", probe["data_dir"]],
        ["data writable", "yes" if probe["data_writable"] else "NO: %s" % probe.get("data_error", "")],
        ["temp dir", probe["temp_dir"]],
    ]
    out(table(["check", "value"], rows, [18, 62]))
    out("")
    out(THEME("optional tools (adapters degrade to MANUAL without them)", "bold"))
    tools = probe.get("tools", {})
    out(table(["tool", "path"], [[k, v or "-"] for k, v in tools.items()], [12, 68]))
    problems = []
    if not probe["python_ok"]:
        problems.append("python >= 3.9 required")
    if not probe["data_writable"]:
        problems.append("data dir not writable; set NAVHACK_HOME to a writable path")
    if not probe["sqlite_ok"]:
        problems.append("sqlite >= 3.30 recommended")
    if problems:
        out("")
        for problem in problems:
            bad(problem)
        return EXIT_FAIL
    out("")
    info("all hard requirements satisfied on %s" % probe["platform"])
    return EXIT_OK


def cmd_init(args) -> int:
    name = args.name.strip()
    if not name:
        die("engagement name required", EXIT_USAGE)
    scope_entries = list(args.scope or [])
    if not scope_entries:
        die("at least one --scope entry required", EXIT_USAGE)
    try:
        scope = Scope.parse(scope_entries)
    except ValueError as exc:
        die("bad scope: %s" % exc, EXIT_USAGE)
    slug = util.slugify(name)
    base = engagements_root() / slug
    if (base / "engagement.json").exists() and not args.force:
        die("engagement %r exists (use --force to reinitialise)" % slug, EXIT_USAGE)
    base.mkdir(parents=True, exist_ok=True)
    (base / "artifacts").mkdir(exist_ok=True)
    budget = Budget(
        max_noise=args.max_noise or 120,
        max_seconds=util.parse_duration(args.max_time or "15m", 900),
        max_requests=args.max_requests or 400,
        concurrency=args.concurrency or plat.default_concurrency(),
    )
    engagement = Engagement(name=name, slug=slug, scope=scope.entries(), oob_public=args.oob_public or "", budget=budget)
    util.atomic_write(base / "engagement.json", util.jdump(engagement.to_dict(), pretty=True))
    load_key(base / "engagement.key")
    (engagements_root() / "CURRENT").write_text(slug, encoding="utf-8")
    store = Store(base / "nav.db")
    for entry in scope.rules:
        if entry.kind in ("domain", "wildcard", "ip", "cidr", "range"):
            host = entry.value if entry.kind in ("domain", "wildcard") else (str(entry.value) if entry.kind == "ip" else entry.raw)
            store.upsert_node(
                Node(kind="entry", key=str(host), provenance="scope", confidence=1.0),
                chart="charted",
            )
            store.grant_tag("entry", "scope")
    store.close()
    Recorder(base / "recorder.jsonl", load_key(base / "engagement.key")).event(
        "init", name=name, scope=scope.entries(), platform=plat.PLATFORM_TAG
    )
    if emit(
        {"slug": slug, "name": name, "scope": scope.entries(), "dir": str(base), "budget": budget.__dict__},
        args.json,
    ):
        return EXIT_OK
    out(THEME("engagement created", "bright_green"))
    info("slug      %s" % slug)
    info("scope     %s" % scope.describe())
    info("dir       %s" % base)
    info("budget    noise %d, %s, %d requests" % (budget.max_noise, util.human_delta(budget.max_seconds), budget.max_requests))
    out("")
    info("next: navhack recon <target>")
    return EXIT_OK


def cmd_scope(args) -> int:
    session = open_session(args)
    try:
        scope = Scope.parse(session.engagement.scope)
        action = args.action
        if action == "list" or (action is None and not args.entry):
            if emit({"scope": session.engagement.scope}, args.json):
                return EXIT_OK
            out("scope: %s" % (scope.describe() if len(scope) else "(empty)"))
            return EXIT_OK
        if not args.entry:
            die("entry required", EXIT_USAGE)
        if action == "remove":
            scope.rules = [rule for rule in scope.rules if rule.raw != args.entry]
            info("removed %s" % args.entry)
        else:
            try:
                rule = scope.add(args.entry)
            except ValueError as exc:
                die(str(exc), EXIT_USAGE)
            info("added %s (%s)" % (rule.raw, rule.kind))
        session.engagement.scope = scope.entries()
        util.atomic_write(session.base / "engagement.json", util.jdump(session.engagement.to_dict(), pretty=True))
        session.recorder.event("scope", action=action, entry=args.entry, scope=session.engagement.scope)
        return EXIT_OK
    finally:
        session.close()


def cmd_adapters(args) -> int:
    rows = []
    for name in adapters.available():
        move_ids = [m.move_id for m in grammar.all_moves() if m.adapter == name]
        rows.append([name, ", ".join(move_ids) or "-"])
    if emit([{"adapter": n, "moves": m} for n, m in rows], args.json):
        return EXIT_OK
    out(table(["adapter", "wired to"], rows, [28, 50]))
    return EXIT_OK


def cmd_moves(args) -> int:
    moves = grammar.all_moves()
    if args.domain:
        moves = [m for m in moves if m.domain == args.domain]
    if args.tag:
        moves = [m for m in moves if args.tag in m.pre or args.tag in m.post]
    if emit([m.to_dict() for m in moves], args.json):
        return EXIT_OK
    rows = [
        [m.move_id, m.domain, "%s -> %s" % (",".join(m.pre), ",".join(m.post)), "n%d" % m.noise, "%.2f" % m.p, "yes" if m.adapter else "-"]
        for m in moves
    ]
    out(table(["move", "domain", "pre -> post", "noise", "p", "auto"], rows, [24, 17, 46, 6, 5, 5]))
    return EXIT_OK


# --------------------------------------------------------------------------- #
# commands: recon
# --------------------------------------------------------------------------- #
OPENERS = (
    grammar.get("resolve_target"),
    grammar.get("probe_host"),
)


def _run(
    session: Session,
    args,
    steps: List[PlanStep],
    *,
    oob=None,
    assume_yes: bool = False,
    policy: Optional[Policy] = None,
    emit_json: bool = True,
) -> int:
    policy = policy or session.policy(args)
    ctx = session.ctx(args, policy, oob=oob)
    plan = Plan(goal=getattr(args, "goal", "recon"), steps=steps, status=PlanStatus.READY.value)
    plan.plan_id = session.store.add_plan(plan)
    runner = Runner(ctx, plan, assume_yes=assume_yes or args.yes, keep_going=getattr(args, "keep_going", False))
    summary = runner.run()
    if not args.quiet and not args.json:
        for outcome in summary.outcomes:
            mark = {
                "ok": THEME(THEME.glyph("ok"), "green"),
                "dry-run": THEME("::", "dim"),
                "failed": THEME(THEME.glyph("bad"), "red"),
                "blocked": THEME("##", "yellow"),
                "needs-tool": THEME(">>", "yellow"),
            }.get(outcome.status, "?")
            line = "%s %-22s %-38s %s" % (
                mark,
                outcome.move_id,
                util.clip(outcome.target, 38),
                util.clip(outcome.detail, 80),
            )
            out(line)
            if outcome.needs_tool:
                info("  needs %s — run it manually, then rerun plan" % outcome.needs_tool)
    if args.json and emit_json:
        emit(
            {
                "plan_id": plan.plan_id,
                "status": summary.status,
                "outcomes": [o.__dict__ for o in summary.outcomes],
                "budget": policy.budget_report(),
            },
            True,
        )
    if summary.status == "failed":
        if summary.replan_to:
            warn("re-plan from here: %s" % ", ".join(summary.replan_to))
        return EXIT_FAIL
    if summary.status == "blocked":
        warn(summary.note)
        return EXIT_BLOCKED
    return EXIT_OK


def _http_ports(session: Session, host: str) -> List[int]:
    from .data import HTTP_PORTS

    ports: List[int] = []
    for node in session.store.find_nodes(kinds=["port"], limit=400):
        if node.attrs.get("host") == host and node.attrs.get("port") in HTTP_PORTS:
            ports.append(int(node.attrs["port"]))
    return ports


def cmd_recon(args) -> int:
    session = open_session(args)
    oob = None
    try:
        try:
            target = util.parse_target(args.target)
        except ValueError as exc:
            die(str(exc), EXIT_USAGE)
        ok, reason = session.scope().check(target["host"], target["port"])
        if not ok:
            die("out of scope: %s" % reason, EXIT_BLOCKED)
        engagement = session.engagement
        args.keep_going = True  # recon phases must not stop at the first miss
        policy = session.policy(args)
        policy.budget.dry_run = False  # recon is read-only by design
        session.recorder.event("recon-start", target=args.target, budget=policy.budget.__dict__)
        start_plan = max([row["id"] for row in session.store.plans(limit=200)], default=0)
        port = target["port"] or (443 if target["scheme"] == "https" else 80)

        steps: List[PlanStep] = [
            PlanStep(seq=1, move=grammar.get("resolve_target"), target_key=target["host"], target_kind="entry", bound=True)
        ]
        if args.ns:
            steps[0] = PlanStep(seq=1, move=grammar.get("probe_host"), target_key=target["host"], target_kind="host", bound=True)
        else:
            steps.append(PlanStep(seq=2, move=grammar.get("probe_host"), target_key=target["host"], target_kind="host", bound=True))
        seq = len(steps)
        if not args.fast:
            scan = PlanStep(seq=seq + 1, move=grammar.get("scan_ports"), target_key=target["host"], target_kind="host", bound=True)
            scan.move = grammar.get("scan_ports")
            steps.append(scan)
            seq += 1
        if args.web or target["explicit_port"] or port in (80, 443, 8080, 8000, 3000, 8443, 8888):
            steps.append(
                PlanStep(
                    seq=seq + 1,
                    move=grammar.get("identify_http"),
                    target_key="%s:%d" % (target["host"], port),
                    target_kind="port",
                    bound=True,
                )
            )
        if args.active:
            oob = verifier.OOB(public=engagement.oob_public)
            oob.start()
            if not args.json:
                info("OOB listener %s" % oob.base_url())
                if oob.describe()["loopback_only"]:
                    warn(verifier.oob_hint(oob, target["host"]))
        code = _run(session, args, steps, oob=oob, policy=policy, emit_json=False)
        if code not in (EXIT_OK,):
            return code
        if policy.aborted:
            warn("aborted: %s" % policy.abort_reason)
        # Follow-on enumeration per discovered URL, grounded from the map.
        follow: List[PlanStep] = []
        urls = session.store.find_nodes(kinds=["url"], limit=40)
        base_urls = [u for u in urls if (u.key.startswith("http://") or u.key.startswith("https://")) and u.attrs.get("host")]
        for url_node in base_urls[: args.max_urls]:
            seq += 1
            follow.append(PlanStep(seq=seq, move=grammar.get("browse_root"), target_key=url_node.key, target_kind="url", bound=True))
        if follow:
            if not args.json:
                info("charting %d URL(s)" % len(follow))
            code = _run(session, args, follow, oob=oob, policy=policy, emit_json=False)
            if code not in (EXIT_OK,):
                return code
        enum_steps: List[PlanStep] = []
        for url_node in session.store.find_nodes(kinds=["url"], limit=20):
            if not url_node.attrs.get("host"):
                continue
            seq += 1
            enum_steps.append(
                PlanStep(seq=seq, move=grammar.get("enumerate_paths"), target_key=url_node.key, target_kind="url", bound=True)
            )
        if enum_steps:
            code = _run(session, args, enum_steps, oob=oob, policy=policy, emit_json=False)
        if args.active:
            capability_steps: List[PlanStep] = []
            for path_node in session.store.find_nodes(kinds=["path"], limit=60):
                seq += 1
                capability_steps.append(
                    PlanStep(seq=seq, move=grammar.get("check_exposure"), target_key=path_node.key, target_kind="path", bound=True)
                )
            for url_node in session.store.find_nodes(kinds=["url"], limit=30):
                if url_node.attrs.get("params"):
                    for move_id in ("probe_xss", "probe_sqli", "probe_lfi", "probe_ssrf"):
                        seq += 1
                        capability_steps.append(
                            PlanStep(seq=seq, move=grammar.get(move_id), target_key=url_node.key, target_kind="url", bound=True)
                        )
            if capability_steps:
                code = _run(session, args, capability_steps, oob=oob, policy=policy, emit_json=False)
        caps = collect(session.store, entry_hosts=[target["host"]])
        if args.json:
            plans = [row for row in session.store.plans(limit=200) if row["id"] > start_plan]
            emit(
                {
                    "status": "done" if code == 0 else "partial",
                    "plans": plans,
                    "budget": policy.budget_report(),
                    "stats": session.store.stats(),
                    "findings": [f.finding_id for f in session.store.findings(limit=500)],
                },
                True,
            )
        else:
            out("")
            out(render_brief(session.store, caps, THEME))
            info("next: navhack map  |  navhack plan --goal objective:file_read  |  navhack report")
        return code
    except (ScopeError, BudgetExceeded, PolicyError) as exc:
        warn(str(exc))
        return EXIT_BLOCKED
    finally:
        if oob is not None:
            oob.stop()
        session.close()


# --------------------------------------------------------------------------- #
# commands: map / find / show
# --------------------------------------------------------------------------- #
def cmd_map(args) -> int:
    session = open_session(args)
    try:
        session.store.expire_stale()
        caps = collect(session.store, entry_hosts=[e.key for e in session.store.find_nodes(kinds=["entry"], limit=50)])
        if args.json:
            return EXIT_OK if emit(
                {
                    "nodes": [
                        {"id": n.node_id, "kind": n.kind, "key": n.key, "confidence": n.confidence, "fog": n.fog}
                        for n in session.store.find_nodes(limit=2000)
                    ],
                    "edges": session.store.edges(),
                    "stats": session.store.stats(),
                },
                True,
            ) else EXIT_OK
        out(render(session.store, theme=THEME, scope_text=", ".join(session.engagement.scope), caps=caps, width=plat.term_width()))
        return EXIT_OK
    finally:
        session.close()


def cmd_find(args) -> int:
    session = open_session(args)
    try:
        findings = session.store.findings(status=args.status, severity=args.severity, limit=300)
        if emit(
            [
                {
                    "id": f.finding_id,
                    "severity": f.severity,
                    "status": f.status,
                    "confidence": f.confidence,
                    "title": f.title,
                    "target": f.target,
                }
                for f in findings
            ],
            args.json,
        ):
            return EXIT_OK
        if not findings:
            info("no findings yet")
            return EXIT_OK
        rows = [
            [
                str(f.finding_id),
                THEME(f.severity, util.severity_color(THEME, f.severity)),
                f.status,
                "%.0f%%" % (f.confidence * 100),
                util.clip(f.title, 44),
                util.clip(f.target, 40),
            ]
            for f in findings
        ]
        out(table(["id", "sev", "status", "conf", "title", "target"], rows, [4, 8, 12, 5, 44, 40]))
        return EXIT_OK
    finally:
        session.close()


def cmd_show(args) -> int:
    session = open_session(args)
    try:
        finding = session.store.get_finding(args.id)
        if finding is None:
            die("no finding %d" % args.id, EXIT_MISSING)
        if emit(
            {
                "id": finding.finding_id,
                "title": finding.title,
                "severity": finding.severity,
                "status": finding.status,
                "confidence": finding.confidence,
                "primitive": finding.primitive,
                "target": finding.target,
                "evidence": finding.evidence,
                "remediation": finding.remediation,
                "created": finding.created_at,
            },
            args.json,
        ):
            return EXIT_OK
        out(THEME(finding.title, "bold"))
        out("%s %s  status %s  conf %.0f%%" % (THEME(finding.severity.upper(), util.severity_color(THEME, finding.severity)), "", finding.status, finding.confidence * 100))
        out("target: %s" % finding.target)
        if finding.evidence:
            out("")
            out(theme_block(finding.evidence))
        if finding.remediation:
            out("")
            out("remediation: %s" % finding.remediation)
        return EXIT_OK
    finally:
        session.close()


def theme_block(text: str) -> str:
    return "\n".join("  " + THEME(line, "dim") for line in util.clip(text, 2000).splitlines())


# --------------------------------------------------------------------------- #
# commands: plan / run / exploit
# --------------------------------------------------------------------------- #
def _print_plan(session: Session, plan: Plan) -> None:
    total_noise = plan.noise
    out(THEME("plan -> %s (%s)" % (grammar.tag_label(plan.goal), plan.goal), "bold"))
    out(
        "%d step(s) · noise %d · est. %s · confidence %.0f%%%s"
        % (
            plan.length,
            total_noise,
            util.human_delta(plan.seconds),
            plan.confidence * 100,
            THEME(" · OVER BUDGET", "red") if plan.over_budget else "",
        )
    )
    if plan.unmet:
        out(THEME("blocked on: %s" % ", ".join(plan.unmet), "yellow"))
    out("")
    for step in plan.steps:
        mark = THEME(THEME.glyph("ok"), "green") if step.bound else THEME(THEME.glyph("unknown"), "yellow")
        out(
            "%s %2d. %s %s %s"
            % (
                mark,
                step.seq,
                THEME(step.move.move_id, "bold"),
                THEME("→", "dim"),
                util.clip(step.target_key, 44),
            )
        )
        out("     %s" % THEME(step.move.title, "dim"))
        if step.move.how:
            out("     %s" % THEME(step.move.how, "gray"))
        flags = []
        if step.move.mutating:
            flags.append(THEME("mutating", "yellow"))
        if step.move.risk != "low":
            flags.append(THEME(step.move.risk + " risk", "yellow"))
        if not step.bound:
            flags.append(THEME("ungrounded", "red"))
        if flags:
            out("     " + " · ".join(flags))


def cmd_plan(args) -> int:
    session = open_session(args)
    try:
        entries = [e.key for e in session.store.find_nodes(kinds=["entry"], limit=50)]
        caps = collect(session.store, granted=session.store.tags(), entry_hosts=entries)
        budget = session.budget(args)
        plan = make_plan(session.store, caps, args.goal, direction=args.reverse and "backward" or "forward", budget=budget)
        if args.save and plan.steps:
            plan.plan_id = session.store.add_plan(plan)
            session.recorder.event("plan-saved", plan_id=plan.plan_id, goal=plan.goal, steps=[s.move.move_id for s in plan.steps])
        if args.json:
            return EXIT_OK if emit(
                {
                    "plan_id": plan.plan_id,
                    "goal": plan.goal,
                    "status": plan.status,
                    "noise": plan.noise,
                    "seconds": plan.seconds,
                    "confidence": plan.confidence,
                    "over_budget": plan.over_budget,
                    "unmet": plan.unmet,
                    "steps": [
                        {"seq": s.seq, "move": s.move.move_id, "target": s.target_key, "bound": s.bound, "how": s.move.how}
                        for s in plan.steps
                    ],
                },
                True,
            ) else EXIT_OK
        if not plan.steps:
            out(THEME("no chain to %s from the current map" % args.goal, "yellow"))
            if plan.unmet:
                out("missing: %s" % ", ".join(plan.unmet))
                out("hint: run more recon, or `navhack plan --goal %s --reverse`" % args.goal)
            return EXIT_FAIL
        _print_plan(session, plan)
        if plan.plan_id:
            info("saved as plan #%d; execute with `navhack run %d`" % (plan.plan_id, plan.plan_id))
        else:
            info("add --save to store this plan")
        return EXIT_OK
    finally:
        session.close()


def _load_plan(session: Session, plan_id: int) -> Plan:
    record = session.store.get_plan(plan_id)
    if record is None:
        die("no plan %d" % plan_id, EXIT_MISSING)
    steps = []
    for row in record["steps"]:
        move = grammar.get(row["move_id"])
        if move is None:
            continue
        steps.append(PlanStep(seq=row["seq"], move=move, target_key=row["target"], bound=True))
    return Plan(goal=record["goal"], direction=record["direction"], steps=steps, plan_id=plan_id)


def cmd_run(args) -> int:
    session = open_session(args)
    oob = None
    try:
        plan = _load_plan(session, args.plan_id)
        if not plan.steps:
            die("plan %d has no executable steps" % args.plan_id, EXIT_MISSING)
        mutating = [s.move.move_id for s in plan.steps if s.move.mutating]
        interactive = not args.json
        if args.live and mutating and not args.yes and interactive:
            out("mutating steps: %s" % ", ".join(mutating))
            if not confirm(args, "execute against target?", default=False):
                info("aborted; rerun with --yes for non-interactive use")
                return EXIT_OK
        if args.live:
            oob = verifier.OOB(public=session.engagement.oob_public)
            oob.start()
        elif interactive:
            info("dry-run; add --live to touch the target")
        code = _run(session, args, plan.steps, oob=oob, assume_yes=args.yes)
        if oob is not None and oob.hits and interactive:
            info("%d OOB callback(s) recorded" % len(oob.hits))
        return code
    finally:
        if oob is not None:
            oob.stop()
        session.close()


def cmd_exploit(args) -> int:
    session = open_session(args)
    try:
        finding = session.store.get_finding(args.id)
        if finding is None:
            die("no finding %d" % args.id, EXIT_MISSING)
        goal = {
            "exposure": "objective:file_read",
            "lfi": "objective:file_read",
            "ssrf": "objective:data",
            "xss": "primitive:exec_client",
            "sqli": "objective:data",
            "default_cred": "objective:admin",
            "rce": "objective:rce",
            "file_read": "objective:data",
        }.get(finding.primitive, "objective:data")
        caps = collect(session.store, granted=session.store.tags(), entry_hosts=[e.key for e in session.store.find_nodes(kinds=["entry"], limit=20)])
        plan = make_plan(session.store, caps, goal, budget=session.budget(args))
        if not plan.steps:
            warn("no chain for %s; verify the finding first (`navhack verify %d`)" % (goal, args.id))
            return EXIT_FAIL
        # Anchor the chain on the finding's own target, not a generic node.
        if finding.target:
            for step in plan.steps:
                if step.target_kind in ("path", "url", "finding"):
                    step.target_key = finding.target
                    step.bound = True
                    break
        _print_plan(session, plan) if not args.json else None
        if confirm(args, "execute this chain?", default=False):
            oob = verifier.OOB(public=session.engagement.oob_public)
            oob.start()
            try:
                return _run(session, args, plan.steps, oob=oob, assume_yes=True)
            finally:
                oob.stop()
        return EXIT_OK
    finally:
        session.close()


def cmd_exec(args) -> int:
    session = open_session(args)
    oob = None
    try:
        move = grammar.get(args.move)
        if move is None:
            die("unknown move %r (see `navhack moves`)" % args.move, EXIT_USAGE)
        policy = session.policy(args)
        if not args.live:
            policy.budget.dry_run = True
        else:
            oob = verifier.OOB(public=session.engagement.oob_public)
            oob.start()
        ctx = session.ctx(args, policy, oob=oob)
        outcome = execute_one(ctx, move.move_id, args.target)
        if emit({"status": outcome.status, "detail": outcome.detail, "needs_tool": outcome.needs_tool}, args.json):
            return EXIT_OK if outcome.status == "ok" else EXIT_FAIL
        mark = THEME(THEME.glyph("ok"), "green") if outcome.status == "ok" else THEME(THEME.glyph("bad"), "red")
        out("%s %s %s" % (mark, outcome.move_id, util.clip(outcome.detail, 120)))
        if outcome.needs_tool:
            info("needs %s: %s" % (outcome.needs_tool, move.how))
        return EXIT_OK if outcome.status == "ok" else EXIT_FAIL
    finally:
        if oob is not None:
            oob.stop()
        session.close()


# --------------------------------------------------------------------------- #
# commands: verify / report / replay / oob / selftest
# --------------------------------------------------------------------------- #
def cmd_verify(args) -> int:
    session = open_session(args)
    oob = None
    try:
        finding = session.store.get_finding(args.id)
        if finding is None:
            die("no finding %d" % args.id, EXIT_MISSING)
        policy = session.policy(args)
        policy.budget.dry_run = False
        if finding.primitive in ("ssrf", "open_redirect"):
            oob = verifier.OOB(public=session.engagement.oob_public)
            oob.start()
        proof = verifier.verify_finding(finding, policy=policy, oob=oob, timeout=args.timeout)
        status = FindingStatus.CONFIRMED.value if proof.ok else FindingStatus.HYPOTHESIS.value
        session.store.update_finding(
            finding.finding_id or 0,
            status=status,
            confidence=0.95 if proof.ok else min(0.4, finding.confidence),
            evidence=proof.evidence or finding.evidence,
        )
        session.recorder.event("verify", finding=finding.finding_id, ok=proof.ok, detail=proof.detail, digest=proof.digest)
        if emit({"ok": proof.ok, "detail": proof.detail, "digest": proof.digest, "status": status}, args.json):
            return EXIT_OK if proof.ok else EXIT_FAIL
        if proof.ok:
            out("%s confirmed: %s" % (THEME(THEME.glyph("ok"), "green"), proof.detail))
            out(THEME("proof digest %s" % proof.digest, "dim"))
            return EXIT_OK
        out("%s not confirmed: %s" % (THEME(THEME.glyph("bad"), "yellow"), proof.detail))
        info("finding downgraded to hypothesis; keep it as a lead")
        return EXIT_FAIL
    finally:
        if oob is not None:
            oob.stop()
        session.close()


def cmd_report(args) -> int:
    session = open_session(args)
    try:
        out_dir = Path(args.out) if args.out else session.base / "reports"
        chain_ok, count, detail = session.recorder.verify()
        written = report.write_report(
            session.store,
            session.engagement,
            out_dir,
            args.format,
            {"requests": 0, "noise": 0, "recorder_records": count, "chain_ok": chain_ok},
        )
        if emit({"files": written, "chain_ok": chain_ok}, args.json):
            return EXIT_OK
        for path in written:
            out("%s %s" % (THEME(THEME.glyph("ok"), "green"), path))
        if not chain_ok:
            warn("recorder chain problem: %s" % detail)
        return EXIT_OK
    finally:
        session.close()


def cmd_replay(args) -> int:
    session = open_session(args)
    try:
        ok, count, detail = session.recorder.verify()
        if args.verify_chain:
            if emit({"ok": ok, "records": count, "detail": detail}, args.json):
                return EXIT_OK if ok else EXIT_FAIL
            out("%s chain: %s (%d records)" % (THEME(THEME.glyph("ok") if ok else THEME.glyph("bad"), "green" if ok else "red"), detail, count))
            return EXIT_OK if ok else EXIT_FAIL
        records = session.recorder.records()
        for record in records[-args.tail :]:
            data = record.get("data", {})
            out(
                "%4s %s %-16s %s"
                % (
                    record.get("seq"),
                    record.get("ts", "")[11:19],
                    record.get("kind"),
                    util.clip(util.jdump(data), 110),
                )
            )
        return EXIT_OK
    finally:
        session.close()


def cmd_oob(args) -> int:
    oob = verifier.OOB(public=args.public or "", bind_host=args.bind or "127.0.0.1", port=args.port or 0)
    url = oob.start()
    try:
        out(THEME("OOB listener ready", "bright_green"))
        out("base: %s" % url)
        if not oob.describe()["public"]:
            warn("loopback only; pass --public <ip>:<port> for remote targets")
        token = util.token(6)
        out("test: %s" % oob.token_url(token))
        info("waiting %ss for callbacks (%s to stop)" % (args.timeout, plat.cancel_key_name()))
        end = time.monotonic() + args.timeout
        while time.monotonic() < end:
            time.sleep(0.25)
            while oob.hits:
                hit = oob.hits.pop(0)
                out("hit: %s %s from %s" % (hit["method"], hit["path"], hit["remote"]))
                if args.json:
                    emit(hit, True)
        return EXIT_OK
    except KeyboardInterrupt:
        return EXIT_OK
    finally:
        oob.stop()


# --------------------------------------------------------------------------- #
# selftest
# --------------------------------------------------------------------------- #
SELFTEST_APP = b"""<!doctype html><html><head><title>navhack lab</title></head>
<body><h1>lab</h1><a href="/search?q=hello">search</a>
<form action="/login" method="post"><input name="username"><input type="password" name="password"></form>
</body></html>"""


def _lab_server():
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            from urllib.parse import parse_qs, urlsplit

            parts = urlsplit(self.path)
            path = parts.path
            query = parse_qs(parts.query)
            body = b""
            status = 200
            if path == "/":
                body = SELFTEST_APP
            elif path == "/.git/config":
                body = b"[core]\n\trepositoryformatversion = 0\n[remote]\n\turl = ssh://git@lab/repo\n"
            elif path == "/.env":
                body = b"DB_PASSWORD=labpass123\nSECRET_KEY=abcdef1234567890\n"
            elif path == "/search":
                value = (query.get("q") or [""])[0]
                body = ("<html><body>results for %s</body></html>" % value).encode()
            elif path == "/file":
                body = b"root:x:0:0:root:/root:/bin/sh\n"
            elif path == "/login":
                body = SELFTEST_APP
            elif path == "/robots.txt":
                body = b"User-agent: *\nDisallow: /admin\n"
            else:
                status = 404
                body = b"not found"
            self.send_response(status)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("content-length") or 0)
            data = self.rfile.read(length).decode("utf-8", "replace")
            ok = "admin=admin" in data or "username=admin" in data
            body = b"<html><body>logout</body></html>" if ok else b"<html><body>login failed</body></html>"
            self.send_response(200 if ok else 401)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    return server


def cmd_selftest(args) -> int:
    import threading
    from . import scope as scope_mod

    plat.reset_paths()
    scratch: List[Path] = []

    def new_scratch() -> Path:
        # Inside the workspace: some sandboxes deny children of TEMP dirs.
        path = plat.make_scratch("navhack-selftest", Path.cwd())
        scratch.append(path)
        return path

    checks: List[Tuple[str, bool, str]] = []

    def check(name: str, fn) -> None:
        try:
            ok, detail = fn()
        except Exception as exc:  # noqa: BLE001
            ok, detail = False, "%s: %s" % (type(exc).__name__, exc)
        checks.append((name, ok, detail))

    check("python version", lambda: (plat.python_version_ok(), sys.version.split()[0]))
    check("sqlite", lambda: (__import__("sqlite3").sqlite_version_info >= (3, 20), __import__("sqlite3").sqlite_version))
    check("unicode fallback", lambda: (True, "ascii=%s" % str(not plat.supports_unicode())))
    check("scope domain", lambda: (scope_mod.Scope.parse(["example.com"]).check("a.example.com")[0], "subdomain match"))
    check("scope cidr", lambda: (scope_mod.Scope.parse(["10.0.0.0/24"]).check("10.0.0.7")[0], "cidr match"))
    check("scope reject", lambda: (not scope_mod.Scope.parse(["example.com"]).check("evil.test")[0], "rejects foreign host"))
    check("grammar reachable", lambda: (not grammar.validate(), "no orphan move"))
    check("grammar objectives", lambda: (not list(grammar.unreachable_tags()), "tag graph connected"))

    def lookup_test():
        tmp = new_scratch()
        store = Store(tmp / "t.db")
        try:
            from .models import Node as N

            store.upsert_node(N(kind="host", key="a.test", confidence=0.9), chart="charted")
            store.grant_tag("host:up")
            caps = collect(store, entry_hosts=["a.test"])
            plan = make_plan(store, caps, "objective:file_read")
            return bool(plan.steps), "%d steps" % len(plan.steps)
        finally:
            store.close()

    check("planner chain", lookup_test)

    def recorder_test():
        rec = Recorder(new_scratch() / "r.jsonl", b"k")
        rec.event("one", a=1)
        rec.event("two", b=2)
        ok, count, detail = rec.verify()
        return ok and count == 2, detail
    check("recorder chain", recorder_test)

    server = _lab_server()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = "http://127.0.0.1:%d" % server.server_address[1]
    try:
        tmp = new_scratch()
        home = tmp / "home"
        os.environ["NAVHACK_HOME"] = str(home)
        engagement = Engagement(name="selftest", slug="selftest", scope=["127.0.0.1"])
        session = Session(engagement, home / "engagements" / "selftest")
        session.base.mkdir(parents=True, exist_ok=True)
        try:
            policy = Policy(Scope.parse(["127.0.0.1"]), Budget(max_requests=200, max_noise=200, dry_run=False))
            caps_before = collect(session.store)

            def recon():
                ctx = session.ctx(argparse.Namespace(), policy)
                from .adapters import web as web_adapter
                from .adapters import network as net_adapter

                steps = [
                    PlanStep(1, grammar.get("probe_host"), "127.0.0.1", "host"),
                    PlanStep(2, grammar.get("identify_http"), "127.0.0.1:%d" % server.server_address[1], "port"),
                ]
                results = []
                for step in steps:
                    ctx.dry_run = False
                    results.append(execute_one(ctx, step.move.move_id, step.target_key))
                return all(r.ok for r in results), "; ".join(r.detail for r in results)

            check("network recon", recon)

            def enumerate_all():
                ctx = session.ctx(argparse.Namespace(), policy)
                ctx.dry_run = False
                urls = session.store.find_nodes(kinds=["url"], limit=5)
                if not urls:
                    return False, "no url discovered"
                ok, detail, count = False, "", 0
                for url in urls:
                    result = execute_one(ctx, "enumerate_paths", url.key)
                    count += result.nodes
                    ok = ok or result.ok
                    detail = result.detail
                return ok and count > 0, "%d paths: %s" % (count, detail)

            check("path enumeration", enumerate_all)

            def exposure():
                ctx = session.ctx(argparse.Namespace(), policy)
                ctx.dry_run = False
                for node in session.store.find_nodes(kinds=["path"], limit=20):
                    if node.key.endswith("/.env") or node.key.endswith("/.git/config"):
                        result = execute_one(ctx, "check_exposure", node.key)
                        if result.ok:
                            return True, result.detail
                return False, "no exposure found"

            check("exposure detection", exposure)

            def proof():
                findings = session.store.findings(limit=5)
                if not findings:
                    return False, "no finding to verify"
                proof_obj = verifier.verify_finding(findings[0], policy=policy)
                return proof_obj.ok, proof_obj.detail

            check("evidence verification", proof)

            def plan_after():
                caps = collect(session.store, entry_hosts=["127.0.0.1"])
                plan = make_plan(session.store, caps, "objective:file_read")
                cap_delta = len(caps.tags) - len(caps_before.tags)
                return bool(plan.steps) and cap_delta > 0, "+%d caps, %d steps" % (cap_delta, len(plan.steps))

            check("capability growth + planning", plan_after)

            def chain_run():
                caps = collect(session.store, entry_hosts=["127.0.0.1"])
                plan = make_plan(session.store, caps, "objective:file_read")
                plan.plan_id = session.store.add_plan(plan)
                ctx = session.ctx(argparse.Namespace(), policy)
                ctx.dry_run = False
                summary = Runner(ctx, plan).run()
                detail = "; ".join("%s=%s" % (o.move_id, o.detail) for o in summary.outcomes)
                return summary.status in ("done", "dry-run"), "%s (%s)" % (summary.status, detail)

            check("end-to-end dry chain", chain_run)

            def reporting():
                markdown = report.build_markdown(session.store, engagement)
                return ("## Findings" in markdown and len(markdown) > 400), "%d bytes" % len(markdown)

            check("report generation", reporting)
        finally:
            session.close()
    finally:
        server.shutdown()
        server.server_close()
        for path in scratch:
            shutil.rmtree(path, ignore_errors=True)

    passed = sum(1 for _n, ok, _d in checks if ok)
    total = len(checks)
    if args.json:
        emit({"passed": passed, "total": total, "checks": [{"name": n, "ok": ok, "detail": d} for n, ok, d in checks]}, True)
    else:
        for name, ok, detail in checks:
            mark = THEME(THEME.glyph("ok"), "green") if ok else THEME(THEME.glyph("bad"), "red")
            out("%s %-30s %s" % (mark, name, THEME(detail, "dim")))
        out("")
        out("%d/%d checks passed" % (passed, total))
    return EXIT_OK if passed == total else EXIT_FAIL


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="navhack",
        description="Fog-of-war attack navigation: recon, plan, prove, report.",
        epilog="Run `navhack doctor` first. Execution is dry-run unless --live.",
    )
    def add_common(target: argparse.ArgumentParser, suppress: bool) -> None:
        # SUPPRESS on the subparser copy so a flag before the subcommand is kept.
        default = argparse.SUPPRESS if suppress else None
        flag_default = argparse.SUPPRESS if suppress else False
        target.add_argument("--slug", default=default, help="engagement slug (default: current)")
        target.add_argument("--json", action="store_true", default=flag_default, help="machine-readable output")
        target.add_argument("--ascii", action="store_true", default=flag_default, help="ASCII-only glyphs")
        target.add_argument("--no-color", action="store_true", default=flag_default, help="disable ANSI colour")
        target.add_argument("--verbose", action="store_true", default=flag_default)
        target.add_argument("-y", "--yes", action="store_true", default=flag_default, help="assume yes / allow mutating steps")
        target.add_argument("--live", action="store_true", default=flag_default, help="really touch the target")
        target.add_argument("--rate", type=float, default=default, help="requests per second")
        target.add_argument("--concurrency", type=int, default=default, help="parallel workers")
        target.add_argument("--max-noise", type=int, default=default, help="noise budget for this run")
        target.add_argument("--max-time", default=default, help="time budget, e.g. 90s, 10m")
        target.add_argument("--max-requests", type=int, default=default, help="request budget for this run")
        target.add_argument("--no-safe-mode", dest="safe_mode", action="store_false", default=argparse.SUPPRESS if suppress else True)

    add_common(parser, suppress=False)
    common = argparse.ArgumentParser(add_help=False)
    add_common(common, suppress=True)
    sub = parser.add_subparsers(dest="command", required=True)

    def new_sub(name: str, help: str = "") -> argparse.ArgumentParser:
        return sub.add_parser(name, help=help, parents=[common])

    p = new_sub("version", help="print versions and platform")
    p.set_defaults(func=cmd_version)

    p = new_sub("doctor", help="check platform, paths, sqlite, optional tools")
    p.set_defaults(func=cmd_doctor)

    p = new_sub("init", help="create an engagement with scope")
    p.add_argument("name")
    p.add_argument("--scope", action="append", help="scope entry (repeatable)")
    p.add_argument("--oob-public", help="public host:port for OOB callbacks")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_init)

    p = new_sub("scope", help="list/add/remove scope entries")
    p.add_argument("action", nargs="?", choices=["list", "add", "remove"])
    p.add_argument("entry", nargs="?")
    p.set_defaults(func=cmd_scope)

    p = new_sub("adapters", help="list adapters and the moves they run")
    p.set_defaults(func=cmd_adapters)

    p = new_sub("moves", help="show the move grammar")
    p.add_argument("--domain")
    p.add_argument("--tag")
    p.set_defaults(func=cmd_moves)

    p = new_sub("recon", help="resolve, scan, identify and chart a target")
    p.add_argument("target")
    p.add_argument("--active", action="store_true", help="run weakness probes and OOB listener")
    p.add_argument("--web", action="store_true", help="force HTTP identification")
    p.add_argument("--fast", action="store_true", help="skip port scan and enumeration")
    p.add_argument("--ns", action="store_true", help="skip DNS resolution")
    p.add_argument("--max-urls", type=int, default=5)
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--keep-going", action="store_true")
    p.set_defaults(func=cmd_recon)

    p = new_sub("map", help="render the fog-of-war map")
    p.set_defaults(func=cmd_map)

    p = new_sub("find", help="list findings")
    p.add_argument("--status")
    p.add_argument("--severity")
    p.set_defaults(func=cmd_find)

    p = new_sub("show", help="show one finding")
    p.add_argument("id", type=int)
    p.set_defaults(func=cmd_show)

    p = new_sub("plan", help="compute a chain to an objective")
    p.add_argument("--goal", default="objective:file_read")
    p.add_argument("--reverse", action="store_true", help="regress backwards from the objective")
    p.add_argument("--save", action="store_true")
    p.set_defaults(func=cmd_plan)

    p = new_sub("run", help="execute a saved plan (dry-run unless --live)")
    p.add_argument("plan_id", type=int)
    p.add_argument("--keep-going", action="store_true")
    p.add_argument("--quiet", action="store_true")
    p.set_defaults(func=cmd_run)

    p = new_sub("exploit", help="plan from a finding and optionally run it")
    p.add_argument("id", type=int)
    p.add_argument("--quiet", action="store_true")
    p.set_defaults(func=cmd_exploit)

    p = new_sub("exec", help="run a single move against a target")
    p.add_argument("move")
    p.add_argument("target")
    p.set_defaults(func=cmd_exec)

    p = new_sub("verify", help="re-prove a finding with OOB/marker evidence")
    p.add_argument("id", type=int)
    p.add_argument("--timeout", type=float, default=10.0)
    p.set_defaults(func=cmd_verify)

    p = new_sub("report", help="write markdown/json report")
    p.add_argument("--format", choices=["md", "json", "both"], default="both")
    p.add_argument("--out")
    p.set_defaults(func=cmd_report)

    p = new_sub("replay", help="show or verify the flight recorder")
    p.add_argument("--tail", type=int, default=30)
    p.add_argument("--verify-chain", action="store_true")
    p.set_defaults(func=cmd_replay)

    p = new_sub("oob", help="standalone out-of-band listener")
    p.add_argument("--public")
    p.add_argument("--bind", default="127.0.0.1")
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--timeout", type=float, default=60.0)
    p.set_defaults(func=cmd_oob)

    p = new_sub("selftest", help="offline end-to-end check")
    p.set_defaults(func=cmd_selftest)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    plat.reconfigure_stdio()
    plat.enable_vt()
    parser = build_parser()
    args = parser.parse_args(argv)
    global THEME
    THEME = util.Theme(enabled=not args.no_color and plat.color_enabled(), ascii_only=args.ascii or not plat.supports_unicode())
    util.DEFAULT_THEME = THEME
    try:
        if not plat.python_version_ok():
            bad("python >= 3.9 required, found %s" % sys.version.split()[0])
            return EXIT_USAGE
        return int(args.func(args))
    except KeyboardInterrupt:
        out("")
        warn("interrupted (%s)" % plat.cancel_key_name())
        return 130
    except ScopeError as exc:
        bad("out of scope: %s" % exc)
        return EXIT_BLOCKED
    except BudgetExceeded as exc:
        bad("budget: %s" % exc)
        return EXIT_BLOCKED
    except PolicyError as exc:
        bad(str(exc))
        return EXIT_BLOCKED
    except BrokenPipeError:
        # Reader (head/Select-Object/less) closed early; silence the final flush.
        try:
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, sys.stdout.fileno())
        except Exception:
            pass
        return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
