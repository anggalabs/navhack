#!/usr/bin/env bash
# Termux installer.
set -eu

PYTHON="${PYTHON:-python}"
MIN_MINOR=9

echo "navhack :: Termux install"

if [ -z "${TERMUX_VERSION:-}" ] && [ ! -d /data/data/com.termux ]; then
  echo "warning: this does not look like Termux; continuing anyway" >&2
fi

if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "installing python and git..." >&2
  pkg update -y
  pkg install -y python git
fi

version=$("$PYTHON" -c 'import sys; print("%d.%d" % sys.version_info[:2])')
major=${version%%.*}
minor=${version#*.}
if [ "$major" -lt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -lt "$MIN_MINOR" ]; }; then
  echo "python >= 3.9 required, found $version" >&2
  exit 1
fi

echo "optional extras (recommended):"
echo "  pkg install nmap net-snmp curl openssl"
echo

if command -v pip >/dev/null 2>&1 || "$PYTHON" -m pip --version >/dev/null 2>&1; then
  "$PYTHON" -m pip install --upgrade .
else
  echo "pip missing; using the zero-install launcher instead"
  echo "  python $(pwd)/navhack.py doctor"
fi

echo
echo "next:"
echo "  termux-wake-lock"
echo "  $(command -v navhack || echo "python $(pwd)/navhack.py") doctor"
echo "  $(command -v navhack || echo "python $(pwd)/navhack.py") init myjob --scope 192.168.1.0/24"
echo
echo "for LAN targets, pass --oob-public <phone-ip>:<port> when using --active"
