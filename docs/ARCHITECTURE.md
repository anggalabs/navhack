# Architecture

navhack is a planner wrapped around a world model, not a scanner with a UI.

```
                 ┌──────────────────────────────────────────────┐
   sensors ─────▶│ world model (SQLite)                          │
 (adapters)      │ nodes/edges · confidence · provenance · decay │
                 └───────────────┬──────────────────────────────┘
                                 │ derive
                 ┌───────────────▼──────────────────────────────┐
                 │ capability engine (what is possible *now*)    │
                 └───────────────┬──────────────────────────────┘
                                 │ tags
                 ┌───────────────▼──────────────────────────────┐
                 │ planner: hypergraph A* / regression           │
                 │ cost = time + 4×noise · confidence = Π p      │
                 └───────────────┬──────────────────────────────┘
                                 │ grounded steps
                 ┌───────────────▼──────────────────────────────┐
                 │ policy gate: scope · budgets · safe mode      │
                 └───────────────┬──────────────────────────────┘
                                 │ allowed
                 ┌───────────────▼──────────────────────────────┐
                 │ executor → adapter → verifier → evidence      │
                 └───────────────┬──────────────────────────────┘
                                 │
                 ┌───────────────▼──────────────────────────────┐
                 │ report (md/json) · recorder (HMAC hash chain) │
                 └──────────────────────────────────────────────┘
```

## 1. World model

`store.py` — one SQLite database per engagement.

- Node kinds: `entry`, `host`, `port`, `service`, `url`, `path`, `tech`, `dns`,
  `cert`, `cred`, `identity`, `source`, `share`, `finding`, `objective`, `note`.
- Every node carries `confidence` (0–1), `provenance` (which adapter or human),
  first/last seen, and a per-kind `decay_at`. Stale observations expire to
  `dead` and drop out of planning.
- Fog states: `unknown → seen → charted → verified`, plus `dead`. Fog only moves
  forward in confidence; an explicit `dead` exception exists.
- Writes are serialised with an `RLock`; SQLite runs in WAL mode with a 30 s busy
  timeout, so parallel adapters cannot corrupt the graph.

Why SQLite: it is the only database that is guaranteed present, dependency-free
and byte-identical across Termux, Linux, macOS and Windows.

## 2. Capability engine

`capability.py` derives the tag set the planner is allowed to use. Tags come
from charted nodes (`port:tcp`, `service:http`, `path:known`, `cred:secret`),
confirmed findings (`primitive:file_read`, …), explicit `--grant`, and a small
closure (a known path implies a known URL and an HTTP service).

If a capability is not backed by a node, no move needing it can be planned. This
is the guard against plausible-but-fictional chains.

## 3. Planner

`planner.py` performs a fixpoint relaxation over hyperedges (a move is an edge
from its *whole* precondition set to each effect). The returned chain is optimal
under the cost model, not merely valid.

- Cost: `seconds + 4 × noise`; mutating moves are penalised when the budget is
  already exceeded.
- Confidence: product of the chosen moves' success probabilities — displayed,
  never used to prune.
- Ordering: forward chains are ordered by acquisition cost, so every
  precondition is produced before its consumer.
- Regression: `--reverse` relaxes from the objective to what is already held
  and orders backwards; if regression cannot reach the start it falls back to
  forward and says so.
- Budgets: step cap, noise and seconds are enforced during search and flagged
  (`over_budget`, `unmet`) rather than silently truncated.
- Grounding: each step is attached to a concrete node; steps with no candidate
  are emitted with `bound=False` and a synthesised placeholder so a recon gap is
  visible in the plan instead of hidden.

## 4. Policy gate

`policy.py` is consulted for *every* host connection and every move:

- `Scope.require` — domain/wildcard/CIDR/range/port rules, apex vs subdomain
  semantics, redirect hops re-checked individually.
- Token-bucket rate limiter, request/noise/time caps, step caps.
- Safe mode: mutating moves need `--yes`.
- Kill switch: 5xx storm detection aborts the run, and the abort is sticky.

## 5. Executor and adapters

`executor.py` runs one step at a time. Results are `ok`, `failed`,
`needs-tool`, `blocked` or `dry-run`. On failure the run stops and prints the
frontier from the *current* state — the GPS "recalculate" behaviour — instead of
replaying the chain from the entry point.

Adapters (`adapters/`) are `(ctx, step) -> StepResult`. They must be honest
(`needs_tool` instead of pretend work), idempotent, quiet and bounded. All HTTP
goes through `httpio.py`: manual redirects for scope checks, 256 KiB body cap,
UTF-8 replacement decoding, `Connection: close`, no keep-alive surprises.

## 6. Evidence and reporting

- `verify` re-runs a targeted, non-destructive proof: OOB callback (SSRF,
  redirect), marker (`root:x:0:0`, `[core]`), differential, or content hash.
  Success promotes to `confirmed` with a SHA-256 proof digest; failure demotes.
- `report.py` writes Markdown and JSON with severity table, chains, negative
  results, artefact SHA-256s, coverage limits and a retest command per finding.
- `recorder.py` is the flight recorder: append-only JSONL, each record chained
  with HMAC-SHA256 over its body and the previous digest. `replay
  --verify-chain` reports the first broken sequence.

Tamper-evidence honest framing: whoever holds the engagement key can rebuild the
file. It is not a third-party signature.

## 7. What is intentionally out of scope

- Raw sockets / SYN scan (needs root or Npcap; connect scan is portable).
- Exploit payload generation and shellcode. navhack plans, invokes, and proves;
  it exports the recipe for Metasploit/sqlmap/impacket instead of embedding them.
- Active Directory and cloud calls without their CLIs: those adapters return
  `needs-tool` with the exact command.
- Multi-engagement correlation.
