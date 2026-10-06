#!/data/data/com.termux/files/usr/bin/bash
# V4Z IP Guard - RASHDIPGuardTermuxx installer
# by V4Z RASHD | https://t.me/rashdteem
set -e

echo "[*] V4Z IP Guard installer"

# Packages: python (required). tor / curl are optional helpers.
if ! command -v python >/dev/null 2>&1 && ! command -v python3 >/dev/null 2>&1; then
  echo "[*] Installing python..."
  pkg install -y python
fi
if ! command -v tor >/dev/null 2>&1; then
  echo "[i] tor not found. Tor compare will need it:  pkg install tor"
  echo "    (skipping auto-install so setup stays fast)"
fi

PY=python3
command -v python >/dev/null 2>&1 && PY=python

RAW="https://raw.githubusercontent.com/v4zrashd/RASHDIPGuardTermuxx/main"
DIR="$(cd "$(dirname "$0" 2>/dev/null)" 2>/dev/null && pwd || echo "")"
SRC=""
if [ -n "$DIR" ] && [ -f "$DIR/v4zip.py" ]; then
  SRC="$DIR/v4zip.py"
else
  echo "[*] Downloading v4zip.py..."
  TMPD="$(mktemp -d)"
  curl -fsSL "$RAW/v4zip.py" -o "$TMPD/v4zip.py"
  SRC="$TMPD/v4zip.py"
fi
cp "$SRC" "$PREFIX/bin/v4zip"
chmod +x "$PREFIX/bin/v4zip"

mkdir -p "$HOME/.v4zip"

cat <<'BANNER'

  V4Z IP Guard installed.
  Run:  v4zip           (menu)
        v4zip check     (your public IP)
        v4zip compare   (direct vs Tor)
        v4zip proxy test (test proxies.txt)

  Channel: https://t.me/rashdteem
BANNER
