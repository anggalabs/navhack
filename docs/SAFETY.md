# Rules of engagement

navhack is an offensive tool. It only reads by default, but it does open
connections, so agree on these before pointing it at anything.

## Authorization

- Get written permission naming the hosts, ports and time window.
- Scope entries are the contract. `navhack init` requires at least one.
- Everything, including redirect hops and resolved addresses, is checked
  against scope; out-of-scope hosts stop a chain.
- Third-party services reached through the target (CDNs, SaaS, metadata
  endpoints) are *not* implicitly in scope — add them explicitly if allowed.

## Defaults that protect the target

| Default | Meaning | Change with |
|---|---|---|
| dry-run | `run` only prints recipes | `--live` |
| safe mode | mutating moves need confirmation | `--yes` or `--no-safe-mode` |
| 400 requests | hard request cap per run | `--max-requests`, engagement budget |
| 120 noise | weighted intrusion budget | `--max-noise` |
| 15 min | wall-clock cap | `--max-time` |
| 5xx storm abort | stops hammering a broken target | budget `abort_5xx` |
| 256 KiB | body cap per response | adapter-level |

Connect scans are single-attempt with 1.2 s timeouts; there is no SYN flood, no
UDP storm, no fuzzing loop beyond the built-in wordlist.

## Before `--live`

1. `navhack doctor` — confirm platform and data dir.
2. `navhack scope list` — confirm the allowlist.
3. `navhack plan --goal …` — read every step, noise and risk flag.
4. `navhack run ID` (dry-run) — read the exact commands.
5. Only then `--live`, and only `--yes` for moves you have read.

## Stateful operations

- `upload_bypass` and `deploy_webshell` write files. Record the path; clean up
  afterwards if the client expects a pristine system.
- `secretsdump`, `dcsync` and directory replication are noisy and may lock
  account state — never run them during a change freeze.
- Account lockout: default-credential testing uses at most seven pairs, but a
  domain policy of 3 attempts still matters. Set `p` expectations accordingly.

## Data handling

- Evidence is written under `engagements/<slug>/artifacts/` with SHA-256.
- Credentials are stored in the clear in the SQLite database and *redacted* in
  screen output (`util.redact`). Treat the engagement directory as sensitive.
- Reports contain evidence excerpts; review before sending to a client.
- The recorder key (`engagement.key`) proves the log has not been edited; ship
  it separately from the log.

## Cleanup checklist

- [ ] Remove uploaded shells and test files.
- [ ] Note created accounts, roles or scheduled tasks.
- [ ] Restore any configuration changed for testing.
- [ ] Re-run `navhack verify <id>` after remediation and record the result.
- [ ] Archive `recorder.jsonl` + key + artefacts with the report.

## Known limits

- Connect scan only: filtered ports look closed and a SYN-only scan is not
  emulated. `nmap` (if installed) gives a better picture; navhack's built-in
  scanner is the portable floor, not a replacement.
- External adapters are recipes, not executions. If the report says MANUAL, a
  human still has to run it.
- Confidence is a heuristic. Confirm business impact before publishing.
- IPv6-only targets work through `getaddrinfo` but the port scanner uses the
  first address family it gets; pass an explicit literal if it picks wrong.
