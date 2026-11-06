#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if [[ ! -x .venv/bin/python ]]; then
  echo "Virtual environment belum ada. Jalankan ./install.sh terlebih dahulu."
  exit 1
fi

HELPER="/usr/local/sbin/wifi-lab-priv"

setup_ok=0
if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
  setup_ok=1
elif command -v sudo >/dev/null 2>&1 && sudo -n "$HELPER" check >/dev/null 2>&1; then
  setup_ok=1
fi

if [[ "$setup_ok" -eq 0 ]]; then
  echo "Menyiapkan akses root untuk modul audit (sekali saja, butuh password sudo)..."
  if ! sudo "$(pwd)/setup_privileges.sh"; then
    echo
    echo "Peringatan: setup akses root gagal/dibatalkan."
    echo "Modul audit akan menampilkan panduan sampai ./setup_privileges.sh dijalankan."
    echo
  fi
fi

exec .venv/bin/python app.py
