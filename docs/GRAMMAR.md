# Extending the grammar

A move is data, not code. Adding a move makes it plannable immediately; adding
an adapter makes it executable. Do the first before the second.

## 1. Pick the tags

Tags are the planner's alphabet. Reuse existing tags where possible.

Existing namespaces: `entry`, `host:*`, `port:tcp`, `service:*`, `url:*`,
`path:known`, `tech:known`, `auth:session`, `cred:*`, `primitive:*`,
`identity:*`, `iam:*`, `source:code`, `finding:*`, `network:internal`,
`objective:*`.

Rules:

- `pre` must be *achievable* — every tag has to exist in some move's `post`, or
  `tests/test_grammar.py::test_every_tag_reachable` fails.
- `post` must reflect what the adapter actually establishes, not what you hope.
- One observable effect per move where possible; hyperedges are allowed when a
  move genuinely needs several preconditions.

## 2. Declare it

```python
from navhack import grammar
from navhack.models import MoveSpec, Risk

grammar.register(
    MoveSpec(
        move_id="graphql_introspect",
        title="Introspect GraphQL schema",
        domain="web",
        pre=("url:base", "tech:known"),
        post=("finding:graphql", "source:schema"),
        target_kind="url",
        noise=2,
        seconds=10.0,
        p=0.5,
        risk=Risk.LOW.value,
        adapter="web.graphql_introspect",
        how="curl -s <base>/graphql -d '{\"query\":\"{__schema{types{name}}}\"}'",
        doc="Confirms introspection; mutations are only listed, never called.",
    )
)
```

Notes:

- `target_kind` is what the adapter receives. `host`, `port`, `url`, `path`,
  `finding` are the common groundings.
- `noise` is 0–8. One noise unit is roughly "a packet a defender would notice".
  0 = purely local, 8 = full directory replication.
- `p` is your honest success probability. It multiplies into plan confidence.
- Mark `mutating=True` for anything that writes, uploads or executes; safe mode
  will require `--yes`.
- Always fill `how` — it is printed in dry-runs and in the report.

## 3. Implement the adapter

```python
from navhack import httpio, util
from navhack.models import Kind, PlanStep, StepResult
from .base import ExecCtx, adapter, needs_tool

@adapter("web.graphql_introspect")
def graphql_introspect(ctx: ExecCtx, step: PlanStep) -> StepResult:
    url = step.target_key.rstrip("/") + "/graphql"
    response = httpio.post(url, b'{"query":"{__schema{types{name}}"}', policy=ctx.policy)
    if not response.ok:
        return StepResult(False, response.summary())
    if "__schema" not in response.text:
        return StepResult(False, "introspection disabled")
    node = ctx.node(Kind.URL.value, url, confidence=0.7, attrs={"graphql": True})
    finding = ctx.finding("GraphQL introspection enabled", "exposure", url,
                          severity="low", evidence=util.clip(response.text, 200))
    return StepResult(True, "schema returned", nodes=[node], findings=[finding])
```

Contract:

- register with the exact `adapter` string from the move;
- return `StepResult(False, reason)` instead of raising — the runner also
  catches, but failures read better this way;
- `needs_tool("binary", hint)` when an external CLI is required;
- create nodes through `ctx.node` and findings through `ctx.finding`
  (`ctx.finding` deduplicates by title+target);
- never print; never read unbounded bodies; close what you open;
- go through `httpio` so scope, rate and body caps apply.

Adapters that need a subprocess use `platform_compat.run_capture` (argv list, no
shell, hard timeout).

## 4. Test it

```python
# tests/test_adapters_extra.py
from navhack import grammar
from navhack.adapters import available

def test_registered():
    assert "web.graphql_introspect" in available()
    assert grammar.get("graphql_introspect").how
```

Add the move to the lab server if it needs a live endpoint, then run the gate:

```bash
python -m unittest discover -s tests -t .
python navhack.py selftest
```

`tests/test_grammar.py` already asserts that every auto move has an adapter, a
recipe, and reachable tags, so a half-finished move fails CI.

## 5. Extending to a new domain

A domain bundle is a module that registers moves with a `domain=` prefix plus
its own sensors. Keep the domain name stable: it is used by `navhack moves
--domain`. Domain modules still register into the single global grammar — the
planner stays domain-agnostic.

For tools you do not want to shell out to, port the technique into an adapter.
For everything else return `needs_tool` with the exact command; honesty beats
fake coverage.
