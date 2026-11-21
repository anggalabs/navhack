# Changelog

All notable changes are recorded here. Format: keep-a-changelog, dates UTC.

## 0.1.0 — 2026-11-22

First public scaffold.

### Added

- Fog-of-war world model on SQLite: node/edge kinds, confidence, provenance,
  per-kind decay, monotonic fog states.
- Declarative move grammar (37 moves, 6 domains) with preconditions, effects,
  noise/time cost, success probability and printed recipes.
- Hypergraph A* planner with admissible heuristic, step/noise/time budgets,
  regression mode, capability grounding and unmet-reporting on failure.
- Capability engine derived strictly from charted nodes and confirmed findings.
- Scope guard (domain, wildcard, CIDR, IP range, port pinning, URL) enforced on
  every connection including redirect hops.
- Policy layer: token bucket, request/noise/time caps, safe mode, 5xx storm
  abort, dry-run default.
- Working adapters: HTTP identification, header/cookie hygiene, path
  enumeration, exposure signatures, XSS, error SQLi, LFI, SSRF with OOB,
  default credentials, `.git` metadata, secret harvesting, DNS, connect scan,
  banner grab, SNMP.
- Recipe-only adapters for AD, cloud, Linux privesc, pivoting, exfiltration,
  with `needs_tool` and install hints instead of fake execution.
- Verifier with OOB listener, marker and differential proofs, SHA-256 digests,
  automatic promotion/demotion of findings.
- HMAC-SHA256 hash-chained flight recorder plus `replay --verify-chain`.
- Markdown/JSON reporting with severity table, chains, negatives, artefacts,
  coverage limits and retest commands.
- CLI with 20 commands, stable exit codes, `--json` everywhere, ASCII/no-colour
  fallbacks.
- Cross-platform layer: writable data-dir fallback, `\\?\` long paths, VT
  enable, UTF-8 stdio, shell-free subprocess, `make_scratch` for the Windows
  `mkdtemp` ACL trap, no forks and no POSIX-only imports.
- 129 unit tests, a 17-check offline `selftest`, and a GitHub Actions matrix
  across Linux/macOS/Windows and Python 3.9–3.13, plus zero-install and
  Termux-branch jobs.

### Known limits

- Connect scan only (no SYN), no raw sockets.
- AD/cloud/privesc adapters need their external CLIs.
- No exploit payload synthesis; the tool plans, invokes and proves.
