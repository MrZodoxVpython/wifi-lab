#!/usr/bin/env bash
# run.sh — run WiFi Lab from the repo without installing.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
exec python3 main.py "$@"
