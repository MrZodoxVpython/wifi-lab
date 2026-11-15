#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if [[ ! -x .venv/bin/python ]]; then
  echo "Virtual environment belum ada. Jalankan ./install.sh terlebih dahulu."
  exit 1
fi

HELPER="/usr/local/sbin/wifi-lab-priv"
HELPER_SOURCE="$(pwd)/privileged_helper.py"

setup_ok=0
if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
  setup_ok=1
elif command -v sudo >/dev/null 2>&1 && sudo -n "$HELPER" check >/dev/null 2>&1; then
  setup_ok=1
  # Helper yang sudah terpasang bisa lebih lama dari sumbernya setelah update
  # kode (mis. aksi restore baru). Pasang ulang agar menu pemulihan berfungsi.
  if [[ -f "$HELPER" && "$HELPER_SOURCE" -nt "$HELPER" ]]; then
    echo "Helper root perlu diperbarui karena kode privileged_helper.py lebih baru."
    setup_ok=0
  fi
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
