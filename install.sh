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

echo "==> Configuring sudoers (NOPASSWD) for the helper"
TARGET_USER="${SUDO_USER:-$(logname 2>/dev/null || echo root)}"
SUDOERS_FILE="/etc/sudoers.d/wifi-lab-gui"
TMP_SUDOERS="$(mktemp)"
{
    echo "# Managed by WiFi Lab install.sh — permit the GUI helper without a password"
    echo "$TARGET_USER ALL=(root) NOPASSWD: $BIN_DIR/wifi-lab-priv"
} > "$TMP_SUDOERS"
if visudo -cf "$TMP_SUDOERS" >/dev/null 2>&1; then
    install -o root -g root -m 0440 "$TMP_SUDOERS" "$SUDOERS_FILE"
    echo "    allowed user: $TARGET_USER -> $BIN_DIR/wifi-lab-priv"
else
    echo "    ERROR: generated sudoers rule failed validation; not installed." >&2
    rm -f "$TMP_SUDOERS"
    exit 1
fi
rm -f "$TMP_SUDOERS"

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
