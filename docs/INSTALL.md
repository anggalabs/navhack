# Install

navhack has **zero runtime dependencies**. All you need is Python 3.9+; there is
no compiler, no `pip install -r`, no system library.

## 0. Get the folder

Until a remote exists, copy `navhack/` to the machine (zip, `scp`, USB, cloud
drive). If you have git access:

```bash
git clone <repo-url> navhack && cd navhack
```

Then pick one of the two install modes below.

## A. No install (recommended, works everywhere)

```bash
cd navhack
python navhack.py doctor
python navhack.py init acme --scope acme.example
```

`navhack.py` is a launcher; it needs no PATH entry and no site-packages. On
Termux this is the sane default. Optional shell alias:

```bash
# ~/.bashrc or ~/.zshrc
alias navhack='python /path/to/navhack/navhack.py'
```

## B. Install a console script

Installing gives you plain `navhack` plus tab completion in some shells.

### Linux

```bash
sudo apt install -y python3 python3-venv git      # Debian/Ubuntu
# Fedora: sudo dnf install python3 git
# Arch:   sudo pacman -S python git

cd navhack
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
navhack doctor
```

### macOS

```bash
brew install python3            # or use /usr/bin/python3 if 3.9+
cd navhack
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
navhack doctor
```

### Windows (PowerShell)

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install .
navhack doctor
```

If activation is blocked: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.
Without a venv: `py -3 -m pip install --user .` and run
`py -3 -m navhack doctor`.

### Termux (Android, no root)

```bash
pkg update && pkg install -y python
cd navhack
pip install .
termux-wake-lock
navhack doctor
```

`pkg install nmap net-snmp curl openssl` is optional and only unlocks the
external-tool adapters. If `pip` is missing: `pkg install python-pip`, or just
use mode A.

### Extras worth installing

| OS | Packages |
|---|---|
| Termux | `pkg install nmap net-snmp curl openssl` |
| Debian/Ubuntu | `sudo apt install nmap snmp curl iputils-ping` |
| Fedora | `sudo dnf install nmap net-snmp-utils curl` |
| Arch | `sudo pacman -S nmap net-snmp curl` |
| macOS | `brew install nmap net-snmp curl` |
| Windows | [nmap](https://nmap.org/download), curl already present |

AD/cloud adapters additionally need `impacket`, `netexec`, `certipy` and
`awscli`; `navhack doctor` lists what is present, `navhack moves` shows the
exact command each move would run.

## Verify

```bash
navhack version        # or: python navhack.py version
navhack doctor         # all hard requirements must be green
navhack selftest       # 17 offline end-to-end checks
```

Expected: `selftest` prints `17/17 checks passed` and exits 0.

## Uninstall

```bash
pip uninstall navhack        # inside the venv if you used one
rm -rf /path/to/navhack      # the code
rm -rf ~/.local/share/navhack  # state (Linux/Termux; XDG path)
# macOS: ~/Library/Application Support/navhack
# Windows: %LOCALAPPDATA%\navhack
```

Engagement data lives in whichever directory `navhack doctor` reports; copy it
out before deleting if it holds evidence.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `No module named pip` | `python -m ensurepip --user`, or install Python from python.org / your distro |
| `python` is 3.8 or older | install 3.9+, or run with an explicit `python3.12` |
| `Permission denied` in TEMP during `pip install` | point `TMP`/`TEMP`/`TMPDIR` at a writable folder, e.g. `TMPDIR=$PWD/.tmp pip install .` |
| `navhack: command not found` after install | venv not activated, or `~/.local/bin` not on `PATH`; use `python -m navhack` |
| `doctor` says data dir not writable | set `NAVHACK_HOME` to a writable path; navhack already falls back to `./.navhack` then TMPDIR |
| Windows: `running scripts is disabled` | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| Termux: radio sleeps mid-scan | `termux-wake-lock` |
| Corporate proxy | `HTTPS_PROXY` is honoured by Python's stdlib for `https` targets |

Sandboxed/CI note: if `pip install` ends with temp-cleanup warnings and exit 1
after a successful install, the install itself is fine — verify with
`navhack version`. Setting a writable `TMPDIR` avoids the warnings.

## Requirements recap

- Python **3.9+**, 64-bit recommended.
- ~2 MB disk, plus engagement data (SQLite grows with findings/artefacts).
- No root, no admin, no Npcap, no kernel module.
