#!/bin/bash
# ==============================================================================
# MFP WiFi Lab - Installer Semua Dependensi
# ==============================================================================
# Jalankan sebagai root / sudo:
#   sudo ./install-requirements.sh
# ==============================================================================

set -e

if [ "$EUID" -ne 0 ]; then
    echo "[!] Harap jalankan sebagai root: sudo $0"
    exit 1
fi

echo "[+] Memperbarui daftar paket apt..."
apt-get update -y

echo "[+] Menginstal paket sistem..."
# Baca requirements-system.txt, abaikan baris komentar dan kosong
while IFS= read -r pkg || [ -n "$pkg" ]; do
    # Hapus komentar dan spasi
    pkg="${pkg%%#*}"
    pkg="$(echo -e "${pkg}" | tr -d '[:space:]')"
    [ -z "$pkg" ] && continue
    echo "    -> $pkg"
    apt-get install -y "$pkg"
done < requirements-system.txt

echo "[+] Menginstal paket Python (pip)..."
pip3 install -r requirements.txt

echo ""
echo "[+] Semua dependensi terinstal."
echo "    Selanjutnya jalankan: sudo ./jalankan-semua.sh"
