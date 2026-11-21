# Compatibility

Supported: **Termux (Android), Linux, macOS, Windows 10/11**. Python 3.9+.

Everything below is already handled in `platform_compat.py`; the notes explain
*why* the code looks the way it does, so a future change does not regress a
platform.

## Matrix

| Concern | Termux | Linux | macOS | Windows | Handling |
|---|---|---|---|---|---|
| ANSI colour | yes | yes | yes | VT enable + `NO_COLOR` | `enable_vt`, capability check |
| Unicode glyphs | yes | yes | yes | `chcp 65001` or ASCII | `supports_unicode`, `--ascii` |
| Data dir | `~/.local/share` | XDG | `Application Support` | `%LOCALAPPDATA%` | `data_home()` |
| Read-only home | fallback `./.navhack` → TMPDIR | same | same | same | writability probe |
| Nested temp dirs | ok | ok | ok | **mkdtemp(0700) breaks under ACL sandboxes** | `make_scratch()` uses default-mode mkdir |
| Raw sockets | no | root | root | admin/Npcap | connect scan only |
| `fork` | yes | yes | yes | no | threads only |
| `fcntl`/`msvcrt` | no/yes | yes | yes | yes | lock-free; WAL + busy timeout |
| Signals | SIGINT (+SIGTERM) | both | both | SIGINT only | guarded `signal` |
| Path length | fine | fine | fine | `MAX_PATH` | `\\?\` prefix above 240 chars |
| Shell | bash | sh | bash 3.2 | cmd/PowerShell | no shell; `subprocess` argv lists |
| Encoding | UTF-8 | UTF-8 | UTF-8 | cp1252 possible | force UTF-8 with `errors=replace` |

## Termux

- `pkg install python git` is enough for the core. No root, no proot.
- Use `termux-wake-lock` for long runs; Android may suspend the radio otherwise.
- The OOB listener binds `127.0.0.1` by default. For a target on the LAN, pass
  `--oob-public <phone-lan-ip>:<port>` and keep the port above 1024.
- `$PREFIX/var` is writable, but `$HOME/.local/share` is used for consistency.
- Storage permission is only needed if you want reports on shared storage
  (`termux-setup-storage`); otherwise use the engagement directory.
- Optional tools: `pkg install nmap net-snmp curl openssl`.

## Windows

- No admin rights required. Defender may slow the first scan; exclude the venv.
- `tempfile.mkdtemp` creates `0o700` directories whose DACL does not inherit
  under some sandboxes, so children of them fail with `WinError 5`. navhack
  always uses `make_scratch()`.
- `ctypes` enables VT processing before colour is emitted. If it fails, output
  stays plain instead of printing escape codes.
- `%LOCALAPPDATA%` is preferred; `%TEMP%` is the last resort.
- `os.chmod` only toggles read-only, so `0600` on the key file is best-effort.
- `Ctrl+Break` is the documented cancel key; `Ctrl+C` also works.
- Long engagement paths are prefixed with `\\?\` past 240 characters.

## macOS

- System `python3` works; Homebrew Python is also fine.
- `/usr/bin/openssl` is LibreSSL — irrelevant unless you call `openssl` by hand.
- Gatekeeper does not apply (pure Python, no binaries).
- `Application Support` is used for state; no Full Disk Access needed.

## Linux / WSL

- Any distro Python 3.9+; no `python3-dev`, no compiler.
- Rootless connect scan by design. `nmap` is optional and only used if you ask.
- WSL2 behaves like Linux; targets on the Windows host may need the WSL bridge
  address rather than `localhost`.

## Sandboxes and CI

`data_home()` probes writability and falls back to `./.navhack` and then
`$TMPDIR`, and `navhack doctor` prints the choice. `selftest` creates its
scratch dirs inside the workspace for the same reason.

## Explicit non-support

- Python < 3.9 (dataclasses, `functools`, typing features).
- 32-bit-only 3.9 builds without `ssl.ALPN` — ALPN is used best-effort.
- Raw SYN scans without root, kernel BPF tracing, packet injection.
