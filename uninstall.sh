#!/data/data/com.termux/files/usr/bin/bash
# V4Z IP Guard uninstaller
# by V4Z RASHD | https://t.me/rashdteem
set -e

rm -f "$PREFIX/bin/v4zip"
echo "[*] v4zip command removed."
echo "[i] Your IP history (~/.v4zip) was kept. Delete it with:  rm -rf ~/.v4zip"
