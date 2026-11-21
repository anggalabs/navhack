# navhack

**Fog-of-war attack navigation.** recon → chart → plan → prove → report.

navhack keeps a probabilistic world model of the target as a *map*: hosts,
ports, services, paths, credentials and findings are nodes, and every action is
a move with preconditions, effects, cost and a concrete recipe. The planner
walks that map with A* under a noise/time budget, grounds every step onto a real
node, and refuses to run moves whose preconditions are not backed by evidence.

It is deliberately dependency-free (Python standard library only) so it runs
unchanged on **Termux, Linux, macOS and Windows**, including phones with no
root and locked-down corporate laptops.

```
$ navhack recon https://app.example.com --active
✓ resolve_target   app.example.com        2 addresses
✓ probe_host       app.example.com        open: 443
✓ identify_http    app.example.com:443    https://app.example.com/ -> 200 (nginx)
✓ browse_root      https://app.example.com/
✓ enumerate_paths  https://app.example.com/   4 interesting: .git/config:200 …
✓ check_exposure   https://…/.git/config  signatures: [core]
✓ probe_lfi        https://…/download?f=  marker 'root:x:0:0'

$ navhack map
coverage 12 lit / 3 seen / 18 total  [#############.......]
SURFACE
. https://app.example.com/.git/config   [####..] charted 200
! Exposed path /.git/config @ …         [#####.] charted 90%

$ navhack plan --goal objective:rce --save
1. dump_git        https://app.example.com/.git/config   curl/.git → source
2. harvest_secret  /src/config.php                       grep secrets
3. login_default_cred https://app.example.com/login      admin:admin
…
```

## Why another tool

| Typical scanner | navhack |
|---|---|
| Prints a flat list | Builds a navigable graph with confidence and decay |
| Re-runs a fixed checklist | Searches for a path to an objective, re-plans on failure |
| "Possible SQL injection" (unverified) | Hypothesis until an OOB/marker proof lands |
| Per-tool, per-OS scripts | One grammar, one planner, one map, every OS |
| No budget control | Noise/request/time budgets, safe mode, kill switch |

## Install

Full per-OS instructions, optional packages and troubleshooting:
**[docs/INSTALL.md](docs/INSTALL.md)**.

### Any OS, no install

```bash
cd navhack
python navhack.py doctor
python navhack.py init acme --scope acme.example
```

Requires Python **3.9+** only. No third-party package is needed for the core.

### pip (all platforms)

```bash
python -m venv .venv
# Linux/macOS/Termux: source .venv/bin/activate
# Windows:          .venv\Scripts\Activate.ps1
pip install .
navhack doctor
```

### Termux (Android)

```bash
pkg update && pkg install -y python git
git clone <repo> navhack && cd navhack
pip install .            # or: python navhack.py …   (no install)
termux-wake-lock        # keep the radio awake during long runs
navhack doctor
```

Optional: `pkg install nmap net-snmp curl openssl` unlocks the external-tool
adapters. Root is **not** required; scanning uses TCP connect.

### Debian/Ubuntu, Fedora, Arch, macOS

```bash
# Debian/Ubuntu
sudo apt install -y python3 python3-venv git
# Fedora: sudo dnf install python3 git  ·  Arch: sudo pacman -S python git
# macOS:  brew install python3  (system python3 works too)
python3 -m venv .venv && source .venv/bin/activate && pip install .
```

### Windows

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install .
navhack doctor
```

Windows Terminal / PowerShell 7 get ANSI colour automatically; older consoles
fall back to ASCII glyphs. No admin rights, no Npcap.

## Quickstart

```bash
navhack doctor
navhack init acme --scope acme.example --scope 10.20.0.0/24
navhack recon https://acme.example --active        # read-only probes
navhack map                                        # see the fog
navhack find                                       # leads, worst first
navhack plan --goal objective:file_read --save     # A* chain, no touching
navhack run 3                                      # dry-run: prints recipes
navhack run 3 --live --yes                         # execute
navhack verify 4 --live                            # re-prove finding #4
navhack report --format both                       # md + json
navhack replay --verify-chain                      # tamper-evident log check
```

## Command surface

| Command | Purpose |
|---|---|
| `doctor` | Platform, paths, sqlite, TLS, optional tools |
| `init NAME --scope …` | Create an engagement (scope is mandatory) |
| `scope add/list/remove` | Grow or trim scope mid-engagement |
| `recon TARGET [--active] [--fast] [--ns]` | Resolve, scan, identify, chart |
| `map` | Render the fog-of-war map (`--json` for data) |
| `find`, `show ID` | Review findings by severity |
| `plan --goal … [--reverse] [--save]` | Compute a chain; forward or regression |
| `run ID [--live] [-y]` | Execute a saved plan (dry-run by default) |
| `exploit ID` | Plan from a finding, optionally run |
| `exec MOVE TARGET` | One atomic move |
| `verify ID` | Re-prove a finding with OOB/marker evidence |
| `report [--format md\|json\|both]` | Evidence report with hashes and repro |
| `replay [--verify-chain]` | Inspect / validate the flight recorder |
| `oob [--public IP:PORT]` | Standalone out-of-band listener |
| `selftest` | Offline 17-check end-to-end test |
| `doctor`, `moves`, `adapters` | Inspect capability and grammar |

Exit codes: `0` ok · `1` failure · `2` usage · `3` blocked by scope/budget ·
`4` missing external tool · `5` not found.

## Safety model

- **Scope is enforced on every connection**, including redirect hops. A
  redirect to a CDN host stops the chain instead of silently leaving scope.
- Default is **dry-run**: `run` prints what would happen and the exact command.
  `--live` touches the target; mutating moves additionally need `--yes` unless
  safe mode is disabled.
- **Budgets** cap requests, noise, wall clock and steps; a run aborts itself
  after a 5xx storm and every limit is visible in `map` and the report.
- Findings are **hypotheses until proven** by an OOB callback, marker string or
  content hash. `verify` downgrades what no longer reproduces.
- The recorder is an **HMAC-SHA256 hash chain**; editing history breaks the
  chain at that record and `replay --verify-chain` names it.

See [docs/SAFETY.md](docs/SAFETY.md) for the full rules of engagement.

## Coverage today

Working adapters: HTTP(S) identification, header/cookie hygiene, path
enumeration, exposure signatures, reflected XSS, error-based SQLi, traversal,
SSRF with OOB, default-credential login, `.git` metadata, secret harvesting,
DNS, TCP connect scan, banner grab, SNMP.

Manual (recipe + `needs-tool`, no pretend work): Active Directory
(SMB/kerberoast/PtH/secretsdump/DCSync/ADCS), cloud (IMDS, IAM, STS, S3),
Linux privesc, pivoting, exfiltration.

See [docs/GRAMMAR.md](docs/GRAMMAR.md) to add a move or an adapter.

## How it works

```
perceive → world model (confidence, provenance, decay) → capability engine
        → A*/regression planner → policy gate → adapter → verifier → report
```

Full design, data model and threat model: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Platform support

| | Termux | Linux | macOS | Windows |
|---|---|---|---|---|
| Core, scan, plan, report | yes | yes | yes | yes |
| Colour / Unicode | yes | yes | yes | auto (ASCII fallback) |
| Data dir | `~/.local/share` | XDG | `Application Support` | `%LOCALAPPDATA%` |
| Sandbox / locked-down home | falls back to `./.navhack` then `$TMPDIR` | same | same | same |
| Root required | no | no | no | no |

Details and per-OS caveats: [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

## Development

```bash
python -m unittest discover -s tests -t .   # 129 tests, all OSes
python navhack.py selftest                   # offline end-to-end
python navhack.py doctor
```

`scripts/check.ps1` (Windows) and `scripts/check.sh` (POSIX) run the same gate.

## Bahasa Indonesia

`navhack doctor` dulu, lalu `navhack init <nama> --scope <target>`, `navhack
recon <url> --active`, `navhack map`, `navhack plan --goal objective:rce
--save`, dan `navhack run <id> --live --yes`. Semua aksi default-nya *dry-run*;
tidak ada yang menyentuh target sebelum `--live`. Butuh izin tertulis atas
target yang diuji.

## License

MIT. You are responsible for authorization on the targets you point it at.
