# Security policy

## Supported versions

`0.1.x` — current line, fixes land here.

## Reporting a vulnerability

Open a private advisory with: navhack version, OS/Python, the command line, the
recorder excerpt around the failure, and the smallest target that reproduces it.
Do not include live credentials unless they are already rotated.

## What navhack itself protects

- **Scope** is re-checked per connection and per redirect hop; a stale scope file
  cannot silently widen a run.
- **Dry-run by default** with an explicit `--live` gate and `--yes` for mutating
  moves; budgets and the 5xx kill switch bound blast radius.
- **Proof before claim**: a finding is a hypothesis until an OOB callback,
  marker or hash confirms it, and `verify` demotes regressions.
- **Tamper-evident log**: append-only HMAC-SHA256 hash chain; the key lives in
  `engagement.key` and should be shipped separately from the log.

## What it does not protect

- Credentials and evidence are stored in clear text in the engagement directory
  (SQLite + artefacts). Redaction applies to screen output only.
- The recorder is tamper-evident, not a third-party signature: whoever holds the
  key can rebuild the file.
- TLS verification is off by default (`--insecure` semantics) because testing
  expired/self-signed certificates is the normal case. Hostname mismatch
  therefore does not fail a request.
- There is no sandbox around subprocess adapters; they run with your privileges.
- Run only against systems you are authorized to test. See
  [docs/SAFETY.md](docs/SAFETY.md).
