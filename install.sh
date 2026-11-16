#!/usr/bin/env bash
# install.sh — install WiFi Lab GUI: helper, icon, desktop entry, launcher.
# Run as root:  sudo ./install.sh
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${PREFIX:-/usr/local}"
BIN_DIR="$PREFIX/bin"
ICON_DIR="$PREFIX/share/icons/hicolor/scalable/apps"
APP_DIR_ICON="$PREFIX/share/applications"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: run as root:  sudo ./install.sh" >&2
    exit 1
fi

echo "==> Installing wifi-lab-priv helper"
install -m 755 "$APP_DIR/wifi-lab-priv" "$BIN_DIR/wifi-lab-priv"

echo "==> Installing wifi-lab launcher"
cat > "$BIN_DIR/wifi-lab" <<EOF
#!/usr/bin/env bash
exec python3 "$APP_DIR/main.py" "\$@"
EOF
chmod 755 "$BIN_DIR/wifi-lab"

echo "==> Installing icon + desktop entry"
mkdir -p "$ICON_DIR" "$APP_DIR_ICON"
install -m 644 "$APP_DIR/icons/wifi-lab.svg" "$ICON_DIR/wifi-lab.svg"
install -m 644 "$APP_DIR/wifi-lab.desktop" "$APP_DIR_ICON/wifi-lab.desktop"

echo "==> Updating icon cache"
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f "$PREFIX/share/icons/hicolor" >/dev/null 2>&1 || true
fi
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$APP_DIR_ICON" >/dev/null 2>&1 || true
fi

echo "==> Checking Python dependencies"
PYTHON_OK=1
python3 -c "import PyQt6" 2>/dev/null || PYTHON_OK=0
if [[ "$PYTHON_OK" -ne 1 ]]; then
    echo "PyQt6 is missing. Install it:"
    echo "  sudo apt install python3-pyqt6"
fi

echo
echo "Installation complete."
echo "Launch with:  wifi-lab   (or from the application menu: WiFi Lab)"
echo "First run: pick your wireless interface in Settings and click Scan."
