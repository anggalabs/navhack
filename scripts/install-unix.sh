#!/usr/bin/env bash
# Installer for Linux and macOS: venv + pip, no sudo.
set -eu

cd "$(dirname "$0")/.."
PYTHON="${PYTHON:-python3}"

if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "python3 not found; install python 3.9+ first" >&2
  exit 1
fi

version=$("$PYTHON" -c 'import sys; print("%d.%d" % sys.version_info[:2])')
case "$version" in
  3.9|3.1[0-9]) : ;;
  *) echo "python >= 3.9 required, found $version" >&2; exit 1 ;;
esac

"$PYTHON" -m venv .venv
# shellcheck disable=SC1091
. .venv/bin/activate
python -m pip install --upgrade pip >/dev/null
python -m pip install .

echo
echo "installed. activate with: . .venv/bin/activate"
echo "then: navhack doctor"
