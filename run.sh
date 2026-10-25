#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ ! -x .venv/bin/python ]]; then
  echo "Virtual environment belum ada. Jalankan ./install.sh terlebih dahulu."
  exit 1
fi
exec .venv/bin/python app.py
