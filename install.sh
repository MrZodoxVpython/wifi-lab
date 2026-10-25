#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
sudo apt update
sudo apt install -y python3-venv python3-pip iw network-manager wireshark-common
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
mkdir -p captures
echo
echo "Instalasi selesai. Jalankan: ./run.sh"
