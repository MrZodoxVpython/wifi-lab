#!/usr/bin/env bash
# Pasang helper root sekali saja agar STRYKER bisa menjalankan modul audit
# (reaver, airodump-ng, aireplay-ng, tshark, aircrack-ng, apt-get) tanpa
# meminta password dan tanpa menjalankan Flask sebagai root.
set -euo pipefail
cd "$(dirname "$0")"

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Script ini butuh root. Jalankan:" >&2
  echo "  sudo ./setup_privileges.sh" >&2
  exit 1
fi

TARGET_USER="${SUDO_USER:-}"
if [[ -z "$TARGET_USER" || "$TARGET_USER" == "root" ]]; then
  TARGET_USER="$(logname 2>/dev/null || true)"
fi
if [[ -z "$TARGET_USER" || "$TARGET_USER" == "root" ]]; then
  echo "Jalankan lewat sudo dari akun user biasa, bukan langsung sebagai root:" >&2
  echo "  sudo ./setup_privileges.sh" >&2
  exit 1
fi

if [[ ! -f privileged_helper.py ]]; then
  echo "File privileged_helper.py tidak ditemukan di folder proyek." >&2
  exit 1
fi

HELPER="/usr/local/sbin/wifi-lab-priv"
SUDOERS="/etc/sudoers.d/wifi-lab"

install -o root -g root -m 0755 privileged_helper.py "$HELPER"

TMP_SUDOERS="$(mktemp)"
trap 'rm -f "$TMP_SUDOERS"' EXIT
cat > "$TMP_SUDOERS" <<EOF
# STRYKER Wi-Fi Audit Lab — helper root dengan daftar tool terbatas.
Defaults:$TARGET_USER !requiretty
$TARGET_USER ALL=(root) NOPASSWD: $HELPER
EOF
chmod 0440 "$TMP_SUDOERS"

if command -v visudo >/dev/null 2>&1; then
  visudo -cf "$TMP_SUDOERS" >/dev/null
fi

install -o root -g root -m 0440 "$TMP_SUDOERS" "$SUDOERS"

# Verifikasi sebagai user pemilik proyek (bukan sebagai root).
if sudo -u "$TARGET_USER" -H sudo -n "$HELPER" check >/dev/null 2>&1; then
  echo "OK: helper root aktif untuk user '$TARGET_USER'."
  echo "    $HELPER"
  echo "    $SUDOERS"
else
  echo "Peringatan: helper terpasang, tetapi verifikasi sudo gagal." >&2
  echo "Coba periksa: sudo -u $TARGET_USER sudo -n $HELPER check" >&2
  exit 1
fi
