#!/usr/bin/env bash
# Local gate: same checks CI runs. POSIX-ish; works on Termux, Linux, macOS.
set -eu

cd "$(dirname "$0")/.."

PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then
  PYTHON=python
fi

echo "== python =="
"$PYTHON" --version

echo "== doctor =="
"$PYTHON" navhack.py doctor

echo "== unit tests =="
NAVHACK_HOME="${NAVHACK_HOME:-$(pwd)/.navhack}" \
  PYTHONPATH="src" "$PYTHON" -m unittest discover -s tests -t . -v

echo "== selftest =="
NAVHACK_HOME="${NAVHACK_HOME:-$(pwd)/.navhack}" "$PYTHON" navhack.py selftest

echo "== help surface =="
"$PYTHON" navhack.py --help >/dev/null

echo "OK"
