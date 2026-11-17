#!/usr/bin/env python3
"""main.py — WiFi Lab GUI (PyQt6)."""
import json
import os
import shutil
import subprocess
import sys

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QAction, QFont, QIcon
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QFormLayout, QLabel, QPushButton, QLineEdit, QComboBox,
    QSpinBox, QTableWidget, QTableWidgetItem, QHeaderView, QSplitter,
    QTabWidget, QTextEdit, QGroupBox, QCheckBox, QMessageBox, QFileDialog,
    QProgressBar, QListWidget, QListWidgetItem, QDialog, QDialogButtonBox,
    QToolBar, QStatusBar, QMenu, QStyle, QAbstractItemView, QInputDialog,
)

from wifi_backend import WifiBackend, Network, CAPTURE_DIR, DATA_DIR, TOOL_PACKAGES

APP_NAME = "WiFi Lab"
VERSION = "1.0.0"
ICON_PATHS = [
    "/usr/share/icons/hicolor/128x128/apps/wifi-lab.png",
    "/usr/share/pixmaps/wifi-lab.png",
    os.path.join(os.path.expanduser("~"), ".local/share/icons/wifi-lab.png"),
]


def log_path():
    return os.path.join(DATA_DIR, "wifi-lab.log")


def setup_logging():
    os.makedirs(DATA_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# Settings dialog
# ---------------------------------------------------------------------------
class SettingsDialog(QDialog):
    def __init__(self, backend, parent=None):
        super().__init__(parent)
        self.backend = backend
        self.setWindowTitle("Settings")
        self.setMinimumWidth(440)

        form = QFormLayout()
        self.iface = QLineEdit(backend.config.get("interface", ""))
        self.iface.setPlaceholderText("e.g. wlan0")
        form.addRow("Wireless interface:", self.iface)

        self.ssid = QLineEdit(backend.config.get("target_ssid", ""))
        form.addRow("Default target SSID:", self.ssid)

        self.bssid = QLineEdit(backend.config.get("target_bssid", ""))
        self.bssid.setPlaceholderText("AA:BB:CC:DD:EE:FF")
        form.addRow("Default target BSSID:", self.bssid)

        self.wordlist = QLineEdit(backend.config.get("wordlist", ""))
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._pick_wordlist)
        row = QWidget()
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.addWidget(self.wordlist)
        row_layout.addWidget(browse)
        form.addRow("Wordlist:", row)

        self.capture_timeout = QSpinBox()
        self.capture_timeout.setRange(10, 600)
        self.capture_timeout.setSuffix(" s")
        self.capture_timeout.setValue(int(backend.config.get("capture_timeout", 120)))
        form.addRow("Handshake capture timeout:", self.capture_timeout)

        self.reaver_timeout = QSpinBox()
        self.reaver_timeout.setRange(30, 3600)
        self.reaver_timeout.setSuffix(" s")
        self.reaver_timeout.setValue(int(backend.config.get("reaver_timeout", 600)))
        form.addRow("Reaver timeout:", self.reaver_timeout)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(buttons)

    def _pick_wordlist(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Choose wordlist", self.wordlist.text() or "/usr/share/wordlists")
        if path:
            self.wordlist.setText(path)

    def accept(self):
        iface = self.iface.text().strip()
        if not iface:
            QMessageBox.warning(self, APP_NAME, "Interface name cannot be empty.")
            return
        self.backend.config.update({
            "interface": iface,
            "target_ssid": self.ssid.text().strip(),
            "target_bssid": self.bssid.text().strip(),
            "wordlist": self.wordlist.text().strip(),
            "capture_timeout": self.capture_timeout.value(),
            "reaver_timeout": self.reaver_timeout.value(),
        })
        self.backend.set_interface(iface)
        self.backend.save_config()
        super().accept()


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.backend = WifiBackend(self)
        self.backend.scanFinished.connect(self.on_scan_finished)
        self.backend.scanFailed.connect(self.on_scan_failed)
        self.backend.progress.connect(self.on_progress)
        self.backend.attackFinished.connect(self.on_attack_finished)
        self.backend.toolStateChanged.connect(self.on_tool_state)
        self.backend.installFinished.connect(self.on_install_finished)

        self.setWindowTitle(APP_NAME)
        self.resize(1180, 760)
        for path in ICON_PATHS:
            if os.path.isfile(path):
                self.setWindowIcon(QIcon(path))
                break

        self._build_ui()
        self._build_menu()
        self._build_toolbar()
        self.setStatusBar(QStatusBar(self))
        self.statusBar().showMessage(f"{APP_NAME} {VERSION}")

        setup_logging()
        self.backend.check_tools()
        self.backend.set_interface(self.backend.config.get("interface", "wlan0"))
        self.refresh_interfaces()
        self.refresh_tools()
        self.refresh_captures()          # show any existing .cap/.pcap files
        self.scan()

    # ------------------------------------------------------------------ UI
    def _build_ui(self):
        central = QWidget()
        root = QVBoxLayout(central)

        # ---- top bar: interface + refresh + helper status ----
        top = QHBoxLayout()
        top.addWidget(QLabel("Interface:"))
        self.iface_combo = QComboBox()
        self.iface_combo.setMinimumWidth(140)
        self.iface_combo.currentTextChanged.connect(self.on_iface_changed)
        top.addWidget(self.iface_combo)
        self.refresh_btn = QPushButton("Scan")
        self.refresh_btn.clicked.connect(self.scan)
        top.addWidget(self.refresh_btn)
        top.addStretch(1)
        self.helper_label = QLabel("helper: …")
        self.sudo_label = QLabel("sudo: …")
        top.addWidget(self.helper_label)
        top.addWidget(self.sudo_label)
        root.addLayout(top)

        # ---- splitter: networks table | tabs ----
        splitter = QSplitter(Qt.Orientation.Horizontal)

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["SSID", "BSSID", "Ch", "Signal", "Security", "WPS", "Mode"])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for col in (1, 2, 3, 4, 5, 6):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        self.table.itemSelectionChanged.connect(self.on_selection_changed)
        self.table.itemDoubleClicked.connect(self.on_double_click)
        splitter.addWidget(self.table)

        # ---- right tabs ----
        tabs = QTabWidget()
        tabs.addTab(self._build_attack_tab(), "Attacks")
        tabs.addTab(self._build_log_tab(), "Log")
        tabs.addTab(self._build_tools_tab(), "Tools")
        splitter.addWidget(tabs)
        splitter.setSizes([720, 460])

        root.addWidget(splitter, 1)
        self.setCentralWidget(central)

    def _build_attack_tab(self):
        page = QWidget()
        v = QVBoxLayout(page)

        # target info
        info_box = QGroupBox("Target")
        form = QFormLayout(info_box)
        self.target_ssid_edit = QLineEdit()
        self.target_ssid_edit.setReadOnly(True)
        self.target_ssid_edit.setPlaceholderText("Select a network from the list")
        form.addRow("SSID:", self.target_ssid_edit)
        self.target_bssid_edit = QLineEdit()
        self.target_bssid_edit.setReadOnly(True)
        form.addRow("BSSID:", self.target_bssid_edit)
        self.target_channel_edit = QLineEdit()
        self.target_channel_edit.setReadOnly(True)
        form.addRow("Channel:", self.target_channel_edit)
        v.addWidget(info_box)

        # actions
        actions_box = QGroupBox("Actions")
        grid = QGridLayout(actions_box)
        self.handshake_btn = QPushButton("Capture handshake")
        self.handshake_btn.clicked.connect(self.capture_handshake)
        self.wps_btn = QPushButton("WPS Pixie Dust")
        self.wps_btn.clicked.connect(self.attack_wps)
        self.reaver_btn = QPushButton("Reaver (PIN)")
        self.reaver_btn.clicked.connect(self.attack_reaver_pin)
        self.deauth_btn = QPushButton("Deauth")
        self.deauth_btn.clicked.connect(self.attack_deauth)
        self.crack_btn = QPushButton("Crack capture")
        self.crack_btn.clicked.connect(self.crack_capture)
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self.stop_attack)
        grid.addWidget(self.handshake_btn, 0, 0)
        grid.addWidget(self.wps_btn, 0, 1)
        grid.addWidget(self.reaver_btn, 1, 0)
        grid.addWidget(self.deauth_btn, 1, 1)
        grid.addWidget(self.crack_btn, 2, 0)
        grid.addWidget(self.stop_btn, 2, 1)
        v.addWidget(actions_box)

        # captures
        cap_box = QGroupBox("Captures")
        cap_layout = QHBoxLayout(cap_box)
        self.capture_list = QListWidget()
        self.capture_list.itemDoubleClicked.connect(self.on_capture_double_click)
        cap_layout.addWidget(self.capture_list, 1)
        btn_col = QVBoxLayout()
        self.open_capture_btn = QPushButton("Open in Wireshark")
        self.open_capture_btn.clicked.connect(self.open_capture)
        self.crack_capture_btn = QPushButton("Crack this capture")
        self.crack_capture_btn.clicked.connect(self.crack_selected_capture)
        btn_col.addWidget(self.open_capture_btn)
        btn_col.addWidget(self.crack_capture_btn)
        btn_col.addStretch(1)
        cap_layout.addLayout(btn_col)
        v.addWidget(cap_box, 1)

        # progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setVisible(False)
        v.addWidget(self.progress_bar)

        return page

    def _build_log_tab(self):
        page = QWidget()
        v = QVBoxLayout(page)
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(QFont("monospace"))
        v.addWidget(self.log_view)
        row = QHBoxLayout()
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.log_view.clear)
        row.addStretch(1)
        row.addWidget(clear_btn)
        v.addLayout(row)
        return page

    def _build_tools_tab(self):
        page = QWidget()
        v = QVBoxLayout(page)
        v.addWidget(QLabel(
            "These tools are required for WiFi analysis. "
            "Missing ones can be installed with your package manager."))
        self.tools_grid = QGridLayout()
        v.addLayout(self.tools_grid)
        v.addStretch(1)
        return page

    # --------------------------------------------------------------- menus
    def _build_menu(self):
        menubar = self.menuBar()
        file_menu = menubar.addMenu("&File")
        file_menu.addAction("Settings…", "Ctrl+,", self.open_settings)
        file_menu.addSeparator()
        quit_action = file_menu.addAction("Quit", "Ctrl+Q", self.close)
        quit_action.setMenuRole(QAction.MenuRole.QuitRole)

        network_menu = menubar.addMenu("&Network")
        network_menu.addAction("Set as target", self.set_target_from_selection)
        network_menu.addAction("Copy BSSID", self.copy_bssid)
        network_menu.addSeparator()
        network_menu.addAction("Install helper", self.install_helper)
        network_menu.addAction("Restore interface", self.restore_interface)

        help_menu = menubar.addMenu("&Help")
        help_menu.addAction("About", self.show_about)

    def _build_toolbar(self):
        tb = QToolBar("Main")
        tb.setMovable(False)
        self.addToolBar(tb)
        style = self.style()
        tb.addAction(style.standardIcon(QStyle.StandardPixmap.SP_BrowserReload),
                     "Scan", self.scan)
        tb.addAction(style.standardIcon(QStyle.StandardPixmap.SP_FileDialogDetailedView),
                     "Settings", self.open_settings)
        tb.addSeparator()
        tb.addAction("Stop", self.stop_attack)

    # ------------------------------------------------------------ helpers
    def log(self, msg):
        self.log_view.append(msg)
        self.log_view.verticalScrollBar().setValue(
            self.log_view.verticalScrollBar().maximum())

    def on_progress(self, msg):
        self.log(msg)
        self.statusBar().showMessage(msg, 5000)

    def on_scan_finished(self, networks):
        self.networks = networks
        self.table.setRowCount(len(networks))
        for row, net in enumerate(networks):
            self._set_row(row, net)
        self.refresh_tools()
        self.statusBar().showMessage(f"Scan complete: {len(networks)} networks", 5000)
        self.log(f"[scan] found {len(networks)} networks")

    def _set_row(self, row, net):
        ssid_item = QTableWidgetItem(net.display_name())
        ssid_item.setData(Qt.ItemDataRole.UserRole, net)
        if net.is_target:
            ssid_item.setForeground(Qt.GlobalColor.darkYellow)
        self.table.setItem(row, 0, ssid_item)
        self.table.setItem(row, 1, QTableWidgetItem(net.bssid))
        self.table.setItem(row, 2, QTableWidgetItem(net.channel))
        self.table.setItem(row, 3, QTableWidgetItem(str(net.signal)))
        self.table.setItem(row, 4, QTableWidgetItem(net.security))
        wps = "yes" if net.wps else ""
        if net.wps_locked is not None:
            wps += " (locked)" if net.wps_locked else " (open)"
        self.table.setItem(row, 5, QTableWidgetItem(wps))
        self.table.setItem(row, 6, QTableWidgetItem(net.mode))

    def on_scan_failed(self, msg):
        self.statusBar().showMessage("Scan failed: " + msg, 8000)
        self.log("[scan] FAILED: " + msg)
        QMessageBox.warning(self, APP_NAME, f"Scan failed:\n{msg}")

    def on_selection_changed(self):
        net = self.selected_network()
        if net is None:
            return
        self.target_ssid_edit.setText(net.display_name())
        self.target_bssid_edit.setText(net.bssid)
        self.target_channel_edit.setText(net.channel)

    def on_double_click(self, item):
        self.set_target_from_selection()

    def selected_network(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return None
        item = self.table.item(rows[0].row(), 0)
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    def set_target_from_selection(self):
        net = self.selected_network()
        if not net:
            QMessageBox.information(self, APP_NAME, "Select a network first.")
            return
        self.backend.set_target(net.ssid, net.bssid)
        self.log(f"[target] set to {net.display_name()} ({net.bssid})")
        self.statusBar().showMessage("Target set: " + net.display_name(), 5000)

    def copy_bssid(self):
        net = self.selected_network()
        if net:
            QApplication.clipboard().setText(net.bssid)

    def refresh_interfaces(self):
        """Populate the interface combo from detected wireless adapters."""
        from wifi_backend import list_interfaces
        ifaces = list_interfaces()
        current = self.backend.iface
        self.iface_combo.blockSignals(True)
        self.iface_combo.clear()
        self.iface_combo.addItems(ifaces)
        if current in ifaces:
            self.iface_combo.setCurrentText(current)
        elif ifaces:
            self.iface_combo.setCurrentIndex(0)
            self.backend.set_interface(ifaces[0])
        else:
            self.iface_combo.setPlaceholderText("no wireless interface")
        self.iface_combo.blockSignals(False)
        if ifaces:
            self.statusBar().showMessage(
                f"Wireless interface: {self.backend.iface}", 5000)
        else:
            self.statusBar().showMessage(
                "No wireless interface detected. Connect a compatible adapter.", 10000)

    def on_iface_changed(self, iface):
        if iface and iface != self.backend.iface:
            self.backend.set_interface(iface)
            self.scan()

    def refresh_tools(self):
        self.backend.check_tools()

    def on_tool_state(self, state):
        tools = {k: v for k, v in state.items() if k in TOOL_PACKAGES}
        missing = [t for t, ok in tools.items() if not ok]
        if missing:
            self.statusBar().showMessage(
                "Missing tools: " + ", ".join(missing), 10000)
        helper_path = state.get("helper_path", "")
        self.helper_label.setText(
            "helper: " + (("✓ " + helper_path) if state.get("helper")
                          else "✗ belum diotorisasi"))
        self.sudo_label.setText("sudo: " + ("✓" if state.get("sudo") else "✗"))
        self._render_tools(state)

    def _render_tools(self, state):
        # clear grid
        while self.tools_grid.count():
            item = self.tools_grid.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        row = 0
        for tool in sorted(TOOL_PACKAGES):
            ok = state.get(tool, False)
            label = QLabel(f"{tool}: {'installed' if ok else 'MISSING'}")
            label.setStyleSheet(
                "color: green;" if ok else "color: red; font-weight: bold;")
            self.tools_grid.addWidget(label, row, 0)
            if not ok:
                btn = QPushButton("Install")
                btn.clicked.connect(lambda _, t=tool: self.install_tool(t))
                self.tools_grid.addWidget(btn, row, 1)
            row += 1

    def install_tool(self, tool):
        self.progress_bar.setVisible(True)
        self.log(f"[install] installing {tool} (requires sudo password)…")
        self.backend.install(tool)

    def on_install_finished(self, ok, msg):
        self.progress_bar.setVisible(False)
        self.log(f"[install] {'OK' if ok else 'FAILED'}: {msg}")
        if ok:
            self.refresh_tools()
        else:
            QMessageBox.warning(self, APP_NAME, f"Install failed:\n{msg}")

    def install_helper(self):
        src = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "wifi-lab-priv")
        if not os.path.isfile(src):
            QMessageBox.information(
                self, APP_NAME,
                "The helper script wifi-lab-priv is not next to this app.\n"
                "Create it manually or copy it here and restart.")
            return
        try:
            subprocess.run(["sudo", "-n", "install", "-m", "755", src,
                            "/usr/local/bin/wifi-lab-priv"], check=True)
            QMessageBox.information(self, APP_NAME, "Helper installed to /usr/local/bin.")
            self.refresh_tools()
        except Exception as exc:
            QMessageBox.warning(self, APP_NAME, f"Could not install helper:\n{exc}")

    def restore_interface(self):
        self.progress_bar.setVisible(True)
        self.backend.restore()

    def stop_attack(self):
        """Stop tool; helper + backend memulihkan interface ke managed mode."""
        if not self.backend.stop():
            self.log("[system] tidak ada proses aktif untuk dihentikan.")
            return
        self.log("[system] Stop diminta — menghentikan tool dan memulihkan interface...")
        self.statusBar().showMessage("Stopping and restoring interface...", 8000)

    def closeEvent(self, event):
        # Jangan tinggalkan adapter dalam monitor mode saat window ditutup.
        self.backend.stop()
        super().closeEvent(event)

    # ------------------------------------------------------------- attacks
    def _require_target(self):
        net = self.selected_network()
        if net is None:
            QMessageBox.information(self, APP_NAME,
                                    "Select a network first (click a row).")
            return None
        return net

    def capture_handshake(self):
        net = self._require_target()
        if not net:
            return
        self.set_target_from_selection()
        self.progress_bar.setVisible(True)
        self.log(f"[handshake] targeting {net.display_name()} on ch {net.channel}")
        self.backend.attack_handshake(net)

    def attack_wps(self):
        net = self._require_target()
        if not net:
            return
        if not net.wps:
            answer = QMessageBox.question(
                self, APP_NAME,
                "This network does not advertise WPS. Try anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if answer != QMessageBox.StandardButton.Yes:
                return
        self.progress_bar.setVisible(True)
        self.log(f"[wps] pixie dust on {net.display_name()}")
        self.backend.attack_wps(net)

    def attack_reaver_pin(self):
        net = self._require_target()
        if not net:
            return
        pin, ok = QInputDialog.getText(
            self, "Reaver PIN",
            "Enter a WPS PIN to test (leave empty for pixie dust):")
        if not ok:
            return
        self.progress_bar.setVisible(True)
        self.log(f"[reaver] PIN attack on {net.display_name()}")
        self.backend.attack_wps(net, pin=pin.strip() or None)

    def attack_deauth(self):
        net = self._require_target()
        if not net:
            return
        count, ok = QInputDialog.getInt(
            self, "Deauth", "Number of deauth frames:", 20, 1, 500)
        if not ok:
            return
        self.progress_bar.setVisible(True)
        self.log(f"[deauth] sending {count} frames to {net.display_name()}")
        self.backend.attack_deauth(net, count=count)

    def crack_capture(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select capture (.cap/.pcap)", CAPTURE_DIR,
            "Capture files (*.cap *.pcap);;All files (*)")
        if not path:
            return
        self.progress_bar.setVisible(True)
        self.log(f"[crack] cracking {path}")
        self.backend.crack_capture(path)

    def crack_selected_capture(self):
        item = self.capture_list.currentItem()
        if not item:
            QMessageBox.information(self, APP_NAME, "Select a capture first.")
            return
        self.progress_bar.setVisible(True)
        self.log(f"[crack] cracking {item.data(Qt.ItemDataRole.UserRole)}")
        self.backend.crack_capture(item.data(Qt.ItemDataRole.UserRole))

    def on_attack_finished(self, ok, msg):
        self.progress_bar.setVisible(False)
        self.log(f"[result] {'OK' if ok else 'FAILED'}: {msg}")
        self.statusBar().showMessage(msg, 10000)
        self.refresh_captures()
        if ok:
            QMessageBox.information(self, APP_NAME, msg)
        elif msg.lower().startswith("dihentikan") or "dikembalikan ke managed" in msg.lower():
            # Stop adalah aksi normal: tidak perlu dialog error.
            return
        else:
            QMessageBox.warning(self, APP_NAME, msg)

    def refresh_captures(self):
        self.capture_list.clear()
        if not os.path.isdir(CAPTURE_DIR):
            return
        for fname in sorted(os.listdir(CAPTURE_DIR)):
            if fname.endswith((".cap", ".pcap")):
                path = os.path.join(CAPTURE_DIR, fname)
                item = QListWidgetItem(os.path.basename(path))
                item.setData(Qt.ItemDataRole.UserRole, path)
                self.capture_list.addItem(item)

    def on_capture_double_click(self, item):
        self.open_capture()

    def open_capture(self):
        item = self.capture_list.currentItem()
        if not item:
            QMessageBox.information(self, APP_NAME, "Select a capture first.")
            return
        path = item.data(Qt.ItemDataRole.UserRole)
        if shutil.which("wireshark"):
            subprocess.Popen(["wireshark", path])
        else:
            QMessageBox.information(
                self, APP_NAME, "Wireshark is not installed. Open the file manually:\n" + path)

    # -------------------------------------------------------------- misc
    def scan(self):
        self.refresh_interfaces()
        if not self.backend.iface:
            self.statusBar().showMessage(
                "No wireless interface. Connect an adapter, then click Scan.", 8000)
            self.log("[scan] aborted: no wireless interface detected")
            return
        self.statusBar().showMessage("Scanning…")
        self.log("[scan] starting…")
        self.backend.scan()

    def open_settings(self):
        dlg = SettingsDialog(self.backend, self)
        if dlg.exec():
            self.refresh_interfaces()
            self.refresh_tools()

    def show_about(self):
        QMessageBox.about(
            self, APP_NAME,
            f"<b>{APP_NAME} {VERSION}</b><br><br>"
            "GUI for WiFi auditing (WPA handshake capture, WPS attacks, "
            "deauth, cracking).<br><br>"
            "Requires a compatible wireless adapter in monitor mode and "
            "the wifi-lab-priv root helper.<br><br>"
            "<i>For authorized testing only.</i>")


def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
