#!/usr/bin/env python3
"""STRYKER — Wi-Fi audit dashboard for Kali Linux.

Safe-by-default scope: passive/standard scanning, adapter capability checks,
analysis of existing capture files, and explicit audit modules that are only
started by the operator. The dashboard binds to localhost only.
"""
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import subprocess, shutil, re, os, sys, threading, time, uuid
import html, ipaddress, json, socket, ssl, urllib.error, urllib.parse, urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from datetime import datetime
from urllib.parse import unquote

app = Flask(__name__)
app.secret_key = os.environ.get("WIFI_AUDIT_SECRET", "change-this-local-secret")
CAPTURE_DIR = Path("captures")
CAPTURE_DIR.mkdir(exist_ok=True)

# ---------------------------------------------------------------------------
# Privilege layer — Flask tetap berjalan sebagai user biasa. Semua tool yang
# butuh root dijalankan lewat helper kecil yang diizinkan di sudoers.
# ---------------------------------------------------------------------------
HELPER_PATH = Path(os.environ.get("WIFI_LAB_HELPER", "/usr/local/sbin/wifi-lab-priv"))
LOCAL_HELPER = Path(__file__).resolve().with_name("privileged_helper.py")
_PRIV_CACHE = {"at": 0.0, "value": None}
_PRIV_LOCK = threading.Lock()
_PRIV_TTL = 5.0


def is_root():
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _helper_prefix():
    """Return (prefix, error). Prefix menjalankan wifi-lab-priv sebagai root."""
    if HELPER_PATH.is_file() and os.access(HELPER_PATH, os.X_OK):
        if is_root():
            return [str(HELPER_PATH)], ""
        return ["sudo", "-n", str(HELPER_PATH)], ""

    # Menjalankan app langsung dengan sudo tapi helper belum dipasang:
    # gunakan salinan lokal dari folder proyek.
    if is_root() and LOCAL_HELPER.is_file():
        return [sys.executable, str(LOCAL_HELPER)], ""

    return None, (
        "Akses root belum disiapkan. Jalankan ./setup_privileges.sh satu kali "
        "(atau gunakan ./run.sh yang akan menawarkan setup otomatis)."
    )


def privilege_status(force=False):
    now = time.time()
    with _PRIV_LOCK:
        cached = _PRIV_CACHE["value"]
        if not force and cached and now - _PRIV_CACHE["at"] < _PRIV_TTL:
            return cached

    prefix, reason = _helper_prefix()
    if prefix is None:
        status = {
            "ready": False,
            "mode": "none",
            "helper": str(HELPER_PATH),
            "message": reason,
        }
    elif is_root():
        status = {
            "ready": True,
            "mode": "root",
            "helper": str(HELPER_PATH),
            "message": "Aplikasi berjalan sebagai root.",
        }
    else:
        rc, out, err = run_cmd(prefix + ["check"], timeout=8)
        if rc == 0:
            status = {
                "ready": True,
                "mode": "sudo",
                "helper": str(HELPER_PATH),
                "message": "Helper root aktif. Modul audit siap dijalankan.",
            }
        else:
            detail = (err or out or "sudo menolak akses helper.").strip().splitlines()
            hint = detail[-1] if detail else "sudo menolak akses helper."
            status = {
                "ready": False,
                "mode": "sudo",
                "helper": str(HELPER_PATH),
                "message": (
                    "Helper root ada tetapi belum diizinkan. Jalankan "
                    f"./setup_privileges.sh. Detail: {hint}"
                ),
            }

    with _PRIV_LOCK:
        _PRIV_CACHE["at"] = time.time()
        _PRIV_CACHE["value"] = status
    return status


def _priv_prefix_or_fallback():
    prefix, _ = _helper_prefix()
    if prefix:
        return prefix
    # Jangan pernah dipakai saat status belum ready; ini hanya pengaman.
    return ["sudo", "-n", str(HELPER_PATH)]


def privileged_command(tool, *args):
    """Perintah tool yang butuh root (tanpa mengubah mode interface)."""
    return _priv_prefix_or_fallback() + ["run", tool, *args]


def monitor_command(iface, channel, tool, *args):
    """Perintah tool yang butuh root + monitor mode otomatis pada channel target."""
    return _priv_prefix_or_fallback() + [
        "monitor-run",
        iface,
        str(channel or "-"),
        tool,
        *args,
    ]


def install_command(package):
    return _priv_prefix_or_fallback() + ["install", package]


def pretty_command(cmd):
    """Tampilkan perintah logis tanpa detail sudo/helper yang membingungkan."""
    parts = [str(part) for part in cmd]
    for index, part in enumerate(parts):
        name = Path(part).name
        if name not in ("wifi-lab-priv", "privileged_helper.py"):
            continue
        rest = parts[index + 1:]
        if rest and rest[0] == "monitor-run":
            rest = rest[3:]  # buang aksi + nama interface + channel
        elif rest and rest[0] == "run":
            rest = rest[1:]
        elif rest and rest[0] == "install":
            return ["apt-get", "install", "-y", *rest[1:]]
        return rest or parts[-1:]
    return parts


def run_cmd(args, timeout=15):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except FileNotFoundError:
        return 127, "", f"Perintah tidak ditemukan: {args[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", "Waktu proses habis."


def has(cmd):
    return shutil.which(cmd) is not None


# ---------------------------------------------------------------------------
# Background job engine — streams process output to the live terminal page.
# ---------------------------------------------------------------------------

JOBS = {}
JOBS_LOCK = threading.Lock()
JOB_TTL_SECONDS = 2 * 60 * 60


class Job:
    def __init__(self, label, commands, target="", timeout=180):
        self.id = uuid.uuid4().hex[:12]
        self.label = label
        self.commands = commands
        self.target = target
        self.timeout = timeout
        self.lines = []
        self.status = "running"  # running | done | failed | stopped | timeout
        self.rc = None
        self.started_at = datetime.now()
        self.finished_at = None
        self.proc = None
        self._lock = threading.Lock()
        self._done = threading.Event()

    @property
    def command_preview(self):
        return " ; ".join(" ".join(pretty_command(part)) for part in self.commands)

    def append(self, text):
        with self._lock:
            self.lines.append(str(text).rstrip("\n"))

    def snapshot(self, after=0):
        with self._lock:
            total = len(self.lines)
            start = max(0, min(int(after), total))
            end = self.finished_at or datetime.now()
            return {
                "id": self.id,
                "label": self.label,
                "target": self.target,
                "command": self.command_preview,
                "lines": list(self.lines[start:]),
                "next": total,
                "status": self.status,
                "rc": self.rc,
                "elapsed": round((end - self.started_at).total_seconds(), 1),
            }

    def summary(self):
        with self._lock:
            end = self.finished_at or datetime.now()
            return {
                "id": self.id,
                "label": self.label,
                "target": self.target,
                "status": self.status,
                "started": self.started_at.strftime("%H:%M:%S"),
                "elapsed": round((end - self.started_at).total_seconds(), 1),
            }

    def finish(self, rc):
        with self._lock:
            if self.status != "running":
                return
            self.rc = rc
            self.status = "done" if rc == 0 else "failed"
            self.finished_at = datetime.now()
        self._done.set()

    def _terminate(self):
        proc = self.proc
        if proc is None:
            return
        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
        except Exception:
            pass

    def stop(self, reason="dihentikan oleh operator"):
        with self._lock:
            if self.status != "running":
                return False
            self.status = "stopped"
            self.finished_at = datetime.now()
            self.lines.append(f"[system] {reason} — proses dihentikan.")
        self._terminate()
        self._done.set()
        return True

    def mark_timeout(self):
        with self._lock:
            if self.status != "running":
                return
            self.status = "timeout"
            self.rc = 124
            self.finished_at = datetime.now()
            self.lines.append(f"[system] batas waktu {self.timeout}s tercapai — proses dihentikan.")
        self._terminate()
        self._done.set()


def _run_job(job):
    rc = 0
    try:
        for index, cmd in enumerate(job.commands, 1):
            if job.status != "running":
                return
            if len(job.commands) > 1:
                job.append(f"[system] langkah {index}/{len(job.commands)}")
            job.append(f"$ {' '.join(pretty_command(cmd))}")
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    errors="replace",
                )
            except FileNotFoundError:
                job.append(f"[error] perintah tidak ditemukan: {cmd[0]}")
                if cmd[0] == "sudo" or Path(cmd[0]).name in ("wifi-lab-priv", "privileged_helper.py"):
                    job.append("[hint] Akses root belum siap. Jalankan ./setup_privileges.sh lalu coba lagi.")
                else:
                    tool = pretty_command(cmd)[0] if cmd else cmd[0]
                    pkg = TOOL_APT_MAP.get(tool, tool)
                    job.append(f"[hint] Pasang dulu: sudo apt-get install -y {pkg} (atau lewat Toolkit di dashboard).")
                rc = 127
                if len(job.commands) > 1:
                    job.append("")
                    continue
                job.finish(rc)
                return

            job.proc = proc
            timer = threading.Timer(job.timeout, job.mark_timeout)
            timer.daemon = True
            timer.start()
            try:
                if proc.stdout is not None:
                    for line in proc.stdout:
                        job.append(line.rstrip("\n"))
                rc = proc.wait()
            finally:
                timer.cancel()
                job.proc = None

            if job.status != "running":
                return

            job.append(f"[exit] kode {rc}")
            if rc != 0 and len(job.commands) > 1:
                job.append("[system] langkah gagal, lanjut ke PIN berikutnya.")
            job.append("")

        job.finish(rc)
    except Exception as exc:
        job.append(f"[error] {exc}")
        job._terminate()
        job.finish(1)


def _prune_jobs():
    cutoff = datetime.now().timestamp() - JOB_TTL_SECONDS
    with JOBS_LOCK:
        stale = [
            job_id
            for job_id, job in JOBS.items()
            if job.status != "running" and job.started_at.timestamp() < cutoff
        ]
        for job_id in stale:
            JOBS.pop(job_id, None)


def start_job(label, commands, target="", timeout=180):
    _prune_jobs()
    job = Job(label, commands, target=target, timeout=timeout)
    with JOBS_LOCK:
        JOBS[job.id] = job
    threading.Thread(target=_run_job, args=(job,), daemon=True).start()
    return job


def launch_job(label, commands, target="", timeout=180):
    job = start_job(label, commands, target=target, timeout=timeout)
    return redirect(url_for("terminal", job_id=job.id))


def failed_job(label, message, target=""):
    """Buat sesi terminal yang langsung menampilkan instruksi, bukan error sudo."""
    job = Job(label, [], target=target)
    for line in (message or "Terjadi kesalahan.").splitlines():
        job.append(line)
    job.finish(126)
    with JOBS_LOCK:
        JOBS[job.id] = job
    return redirect(url_for("terminal", job_id=job.id))


def launch_privileged(label, commands, target="", timeout=180):
    """Jalankan job yang butuh root, atau tampilkan panduan yang jelas."""
    status = privilege_status(force=True)
    if not status["ready"]:
        return failed_job(
            label,
            "[error] Modul ini membutuhkan akses root, tetapi helper belum siap.\n"
            "\n"
            "[fix] Jalankan sekali di terminal proyek:\n"
            "       ./setup_privileges.sh\n"
            "\n"
            "[fix] Atau hentikan server lalu jalankan:\n"
            "       sudo ./run.sh\n"
            "\n"
            f"[info] {status['message']}\n"
            "[info] Setelah setup selesai, muat ulang halaman ini dan klik Run kembali.",
            target=target,
        )
    return launch_job(label, commands, target=target, timeout=timeout)


# ---------------------------------------------------------------------------
# Network discovery helpers
# ---------------------------------------------------------------------------

def interfaces():
    rc, out, err = run_cmd(["iw", "dev"])
    result, current = [], None
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("Interface "):
            current = {"name": s.split(None, 1)[1], "type": "unknown", "phy": ""}
            result.append(current)
        elif current and s.startswith("type "):
            current["type"] = s.split(None, 1)[1]
        elif current and s.startswith("wiphy "):
            current["phy"] = "phy" + s.split(None, 1)[1]
    return result, err if rc else ""


def _band_from_freq(freq):
    try:
        f = int(freq)
    except (TypeError, ValueError):
        return "—"
    if 2400 <= f < 2500:
        return "2.4 GHz"
    if 4900 <= f < 5900:
        return "5 GHz"
    if 5925 <= f < 7125:
        return "6 GHz"
    return "—"


def _signal_class(value):
    if value >= 75:
        return "strong"
    if value >= 50:
        return "good"
    if value >= 25:
        return "fair"
    return "weak"


def _security_meta(security):
    raw = (security or "").strip()
    upper = raw.upper()
    if raw in ("", "--", "—", "-", "NONE", "OPEN"):
        return {"label": "Open", "class": "open", "secure": False}
    if upper == "UNKNOWN":
        return {"label": "Unknown", "class": "unknown", "secure": False}
    if "WEP" in upper:
        return {"label": "WEP", "class": "wep", "secure": True}
    if "WPA3" in upper:
        label = "WPA2/WPA3" if "WPA2" in upper else "WPA3"
        return {"label": label, "class": "wpa3", "secure": True}
    if "WPA2" in upper:
        label = "WPA2 Enterprise" if "802.1X" in upper else "WPA2"
        return {"label": label, "class": "wpa2", "secure": True}
    if "WPA" in upper:
        return {"label": "WPA", "class": "wpa", "secure": True}
    return {"label": raw, "class": "unknown", "secure": True}


def scan_wifi(iface):
    # Passive/standard scan only; does not deauthenticate or inject frames.
    rc, out, err = run_cmd(
        ["nmcli", "-t", "-f", "IN-USE,SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY",
         "device", "wifi", "list", "ifname", iface],
        timeout=25,
    )
    rows = []
    if rc != 0:
        return rows, err or out or "Pemindaian gagal. Periksa NetworkManager dan izin perangkat."
    for line in out.splitlines():
        if not line.strip():
            continue
        # nmcli -t format: IN-USE:SSID:BSSID(6 octets):CHAN:FREQ:SIGNAL:SECURITY
        # nmcli escapes ':' inside values, so we anchor the BSSID from the right.
        parts = line.split(":")
        if len(parts) < 11:
            continue
        inuse = parts[0]
        ssid = ":".join(parts[1:-10]).replace("\\:", ":")
        bssid = _normalize_mac(":".join(parts[-10:-4]))
        chan, freq, signal, security = parts[-4], parts[-3], parts[-2], parts[-1]
        signal_int = int(signal) if signal.isdigit() else 0
        meta = _security_meta(security)
        rows.append({
            "inuse": inuse == "*",
            "ssid": ssid or "(hidden/empty)",
            "hidden": not bool(ssid),
            "bssid": bssid,
            "channel": chan,
            "freq": freq,
            "band": _band_from_freq(freq),
            "signal": signal,
            "signal_int": signal_int,
            "signal_class": _signal_class(signal_int),
            "security": security or "Unknown",
            "security_class": meta["class"],
            "security_label": meta["label"],
            "secure": meta["secure"],
        })
    return rows, ""


# ---------------------------------------------------------------------------
# ISP & router discovery — only runs when the selected interface is actually
# connected to the target network. No login attempts are made: router access
# data is reported as a factory-default reference the operator can verify.
# ---------------------------------------------------------------------------
_OUI_CACHE = {"loaded": False, "map": {}, "source": ""}
_OUI_LOCK = threading.Lock()
_OUI_FILES = (
    "/usr/share/nmap/nmap-mac-prefixes",
    "/usr/share/arp-scan/ieee-oui.txt",
    "/usr/share/ieee-data/oui.txt",
    "/usr/share/wireshark/manuf",
)

ROUTER_BRANDS = (
    ("TP-Link", ("tp-link", "tplink", "archer", "deco", "omada", "mercusys")),
    ("ZTE", ("zte", "zxhn")),
    ("Huawei", ("huawei", "honor", "hg8", "eg8")),
    ("FiberHome", ("fiberhome", "an5506", "hg6")),
    ("Nokia", ("nokia", "alcatel", "ont-", "g-140w")),
    ("Tenda", ("tenda",)),
    ("D-Link", ("d-link", "dlink", "dir-")),
    ("Netgear", ("netgear", "orbi", "nighthawk")),
    ("Asus", ("asus", "rt-", "zenwifi")),
    ("Linksys", ("linksys", "velop")),
    ("Cisco", ("cisco", "scientific atlanta")),
    ("MikroTik", ("mikrotik", "routeros", "routerboard")),
    ("Ubiquiti", ("ubiquiti", "unifi", "edge router", "airrouter")),
    ("Xiaomi", ("xiaomi", "mi router", "redmi")),
    ("TOTOLINK", ("totolink",)),
    ("Ruijie", ("ruijie", "reyee")),
    ("Cudy", ("cudy",)),
    ("Zyxel", ("zyxel",)),
    ("DrayTek", ("draytek", "vigor")),
    ("Arris", ("arris", "touchstone")),
    ("Technicolor", ("technicolor", "thomson")),
    ("Sagemcom", ("sagemcom",)),
    ("Hitron", ("hitron",)),
    ("Sercomm", ("sercomm",)),
    ("Samsung", ("samsung", "smartthings")),
    ("Xiaomi", ("xiaomi",)),
)

DEFAULT_LOGIN_REFERENCES = (
    {"brand": "TP-Link", "keys": ("tp-link", "tplink", "archer", "deco", "omada", "mercusys"),
     "username": "admin", "password": "admin"},
    {"brand": "ZTE", "keys": ("zte", "zxhn"),
     "username": "admin", "password": "admin",
     "alternatives": [("admin", ""), ("user", "user"), ("telecomadmin", "admintelecom")]},
    {"brand": "Huawei", "keys": ("huawei", "honor", "hg8", "eg8"),
     "username": "admin", "password": "admin",
     "alternatives": [("telecomadmin", "admintelecom"), ("root", "admin")]},
    {"brand": "FiberHome", "keys": ("fiberhome", "an5506", "hg6"),
     "username": "admin", "password": "admin",
     "alternatives": [("user", "user"), ("admin", "1234")]},
    {"brand": "Nokia", "keys": ("nokia", "alcatel", "ont-", "g-140w"),
     "username": "admin", "password": "admin",
     "alternatives": [("user", "user"), ("telecomadmin", "admintelecom")]},
    {"brand": "Tenda", "keys": ("tenda",),
     "username": "admin", "password": "admin",
     "alternatives": [("admin", "")]},
    {"brand": "D-Link", "keys": ("d-link", "dlink", "dir-"),
     "username": "admin", "password": "",
     "alternatives": [("admin", "admin"), ("Admin", "admin")]},
    {"brand": "Netgear", "keys": ("netgear", "orbi", "nighthawk"),
     "username": "admin", "password": "password",
     "alternatives": [("admin", "admin")]},
    {"brand": "Asus", "keys": ("asus", "rt-", "zenwifi"),
     "username": "admin", "password": "admin"},
    {"brand": "Linksys", "keys": ("linksys", "velop"),
     "username": "admin", "password": "admin"},
    {"brand": "Cisco", "keys": ("cisco", "scientific atlanta"),
     "username": "admin", "password": "admin",
     "alternatives": [("admin", "password"), ("cisco", "cisco")]},
    {"brand": "MikroTik", "keys": ("mikrotik", "routeros", "routerboard"),
     "username": "admin", "password": "",
     "alternatives": [("admin", "admin")]},
    {"brand": "Ubiquiti", "keys": ("ubiquiti", "unifi", "edge router", "airrouter"),
     "username": "ubnt", "password": "ubnt",
     "alternatives": [("admin", "admin")]},
    {"brand": "Xiaomi", "keys": ("xiaomi", "mi router", "redmi"),
     "username": "admin", "password": "",
     "alternatives": [("admin", "admin")]},
    {"brand": "TOTOLINK", "keys": ("totolink",),
     "username": "admin", "password": "admin"},
    {"brand": "Ruijie", "keys": ("ruijie", "reyee"),
     "username": "admin", "password": "admin"},
    {"brand": "Cudy", "keys": ("cudy",),
     "username": "admin", "password": "admin"},
    {"brand": "Zyxel", "keys": ("zyxel",),
     "username": "admin", "password": "1234",
     "alternatives": [("admin", "admin")]},
    {"brand": "DrayTek", "keys": ("draytek", "vigor"),
     "username": "admin", "password": "admin"},
    {"brand": "Arris", "keys": ("arris", "touchstone"),
     "username": "admin", "password": "password",
     "alternatives": [("admin", "admin")]},
    {"brand": "Technicolor", "keys": ("technicolor", "thomson"),
     "username": "admin", "password": "admin"},
    {"brand": "Sagemcom", "keys": ("sagemcom",),
     "username": "admin", "password": "admin"},
    {"brand": "Hitron", "keys": ("hitron",),
     "username": "admin", "password": "password",
     "alternatives": [("admin", "admin")]},
    {"brand": "Sercomm", "keys": ("sercomm",),
     "username": "admin", "password": "admin"},
    {"brand": "Generic", "keys": (),
     "username": "admin", "password": "admin",
     "alternatives": [("admin", "password"), ("admin", ""), ("user", "user")]},
)


def _run_json(args, timeout=8):
    rc, out, err = run_cmd(args, timeout=timeout)
    if rc != 0 or not out:
        return None
    try:
        return json.loads(out)
    except (ValueError, TypeError):
        return None


def _load_oui():
    """Muat database OUI lokal (nmap/arp-scan/IEEE) sekali saja."""
    with _OUI_LOCK:
        if _OUI_CACHE["loaded"]:
            return _OUI_CACHE["map"]
        mapping = {}
        source = ""
        for path in _OUI_FILES:
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as handle:
                    for line in handle:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split(None, 1)
                        if len(parts) < 2:
                            continue
                        prefix = re.sub(r"[^0-9A-Fa-f]", "", parts[0]).upper()
                        if len(prefix) < 6:
                            continue
                        vendor = parts[1].split("\t")[0].strip()
                        key = prefix[:6]
                        if vendor and "\\" not in vendor:
                            mapping.setdefault(key, vendor)
                source = path
                break
            except OSError:
                continue
        _OUI_CACHE.update({"loaded": True, "map": mapping, "source": source})
        return mapping


def _oui_vendor(mac):
    clean = re.sub(r"[^0-9A-Fa-f]", "", mac or "").upper()
    if len(clean) < 6:
        return ""
    return _load_oui().get(clean[:6], "")


def _ipv4_info(iface):
    data = _run_json(["ip", "-j", "addr", "show", "dev", iface])
    addresses = []
    if isinstance(data, list):
        for entry in data:
            for item in entry.get("addr_info", []) or []:
                if item.get("family") == "inet" and item.get("local"):
                    addresses.append({
                        "address": item["local"],
                        "prefix": item.get("prefixlen"),
                    })
    return addresses


def _default_gateway(iface=None):
    data = _run_json(["ip", "-j", "route", "show", "default"])
    if isinstance(data, list):
        for route in data:
            if route.get("dst") not in (None, "default"):
                continue
            if iface and route.get("dev") != iface:
                continue
            if route.get("gateway"):
                return route["gateway"]
    rc, out, _ = run_cmd(["ip", "route", "show", "default"], timeout=6)
    if rc == 0:
        for line in out.splitlines():
            match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", line)
            if match and (not iface or f"dev {iface}" in line):
                return match.group(1)
    return ""


def _dns_servers(iface):
    rc, out, _ = run_cmd(["nmcli", "-t", "-f", "IP4.DNS", "device", "show", iface], timeout=8)
    servers = []
    if rc == 0:
        for line in out.splitlines():
            if ":" in line:
                value = line.split(":", 1)[1].strip()
                if value and value not in servers:
                    servers.append(value)
    if not servers:
        try:
            with open("/etc/resolv.conf", "r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    if line.startswith("nameserver"):
                        value = line.split()[1]
                        if value not in servers:
                            servers.append(value)
        except OSError:
            pass
    return servers[:4]


def _wifi_link(iface):
    link = {
        "iface": iface,
        "connected": False,
        "ssid": "",
        "bssid": "",
        "freq": "",
        "signal_dbm": None,
        "bitrate": "",
        "mode": "",
    }
    if not _validate_iface(iface):
        return link
    rc, out, _ = run_cmd(["iw", "dev", iface, "link"], timeout=8)
    text = out or ""
    if rc == 0 and text and "Not connected" not in text:
        match = re.search(r"Connected to ([0-9A-Fa-f:]{17})", text)
        if match:
            link["bssid"] = match.group(1).upper()
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("SSID:"):
                link["ssid"] = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("freq:"):
                link["freq"] = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("signal:"):
                value = stripped.split(":", 1)[1].strip().split()[0]
                try:
                    link["signal_dbm"] = int(value)
                except ValueError:
                    pass
            elif stripped.startswith("tx bitrate:"):
                link["bitrate"] = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("rx bitrate:") and not link["bitrate"]:
                link["bitrate"] = stripped.split(":", 1)[1].strip()

    if not link["bssid"]:
        # Fallback NetworkManager agar informasi tetap muncul pada driver tertentu.
        rc, out, _ = run_cmd(
            ["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID", "device", "wifi", "list", "ifname", iface],
            timeout=10,
        )
        if rc == 0:
            for line in out.splitlines():
                parts = line.split(":")
                if len(parts) >= 8 and parts[0] == "yes":
                    link["ssid"] = ":".join(parts[1:-6]).replace("\\:", ":")
                    bssid = _normalize_mac(":".join(parts[-6:]))
                    if _validate_bssid(bssid):
                        link["bssid"] = bssid.upper()
                    break

    link["connected"] = bool(link["bssid"])
    if link["connected"]:
        link["ipv4"] = _ipv4_info(iface)
        link["gateway"] = _default_gateway(iface)
        link["dns"] = _dns_servers(iface)
    return link


def _neighbor_mac(ip):
    if not ip:
        return ""

    def read():
        rc, out, _ = run_cmd(["ip", "neigh", "show", ip], timeout=5)
        if rc == 0:
            match = re.search(r"lladdr ([0-9A-Fa-f:]{17})", out)
            if match:
                return match.group(1).upper()
        return ""

    mac = read()
    if mac:
        return mac
    # Kirim paket UDP kecil agar kernel melakukan ARP/NDP, lalu baca ulang.
    for port in (53, 80):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.4)
            sock.sendto(b"\x00", (ip, port))
        except OSError:
            pass
        finally:
            try:
                sock.close()
            except (OSError, UnboundLocalError):
                pass
        time.sleep(0.25)
        mac = read()
        if mac:
            return mac
    return ""


def _host_is_private(host):
    if not host:
        return False
    try:
        address = ipaddress.ip_address(host)
        return address.is_private or address.is_loopback or address.is_link_local
    except ValueError:
        pass
    try:
        resolved = socket.gethostbyname(host)
        return _host_is_private(resolved)
    except (OSError, socket.gaierror):
        return False


def _safe_lan_url(url):
    try:
        parsed = urllib.parse.urlparse(url)
    except (ValueError, TypeError):
        return ""
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return ""
    if not _host_is_private(parsed.hostname):
        return ""
    return url


def _http_get(url, timeout=3.0, max_bytes=200000, lan_only=False):
    if lan_only and not _safe_lan_url(url):
        raise ValueError("URL tidak diizinkan")
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) STRYKER/1.0",
            "Accept": "text/html,application/xml,application/json;q=0.9,*/*;q=0.8",
            "Connection": "close",
        },
    )
    # HTTPS router admin sering memakai sertifikat self-signed, jadi verifikasi
    # hanya dilonggarkan untuk probe LAN. Lookup ISP tetap memverifikasi TLS.
    context = ssl._create_unverified_context() if lan_only else None
    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
        raw = response.read(max_bytes)
        charset = response.headers.get_content_charset() or "utf-8"
        return {
            "status": getattr(response, "status", 200),
            "url": response.geturl(),
            "headers": {key.lower(): value for key, value in response.headers.items()},
            "text": raw.decode(charset, errors="replace"),
        }


def _http_json(url, timeout=6.0):
    result = _http_get(url, timeout=timeout, max_bytes=120000)
    return json.loads(result["text"])


def _upnp_discover(timeout=2.5):
    target = "239.255.255.250"
    port = 1900
    message = "\r\n".join([
        "M-SEARCH * HTTP/1.1",
        f"HOST: {target}:{port}",
        'MAN: "ssdp:discover"',
        "MX: 1",
        "ST: ssdp:all",
        "", "",
    ]).encode()
    locations = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(0.5)
        sock.sendto(message, (target, port))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, _ = sock.recvfrom(8192)
            except socket.timeout:
                continue
            except OSError:
                break
            text = data.decode("utf-8", errors="replace")
            match = re.search(r"^location:\s*(\S+)", text, re.I | re.M)
            if match:
                location = match.group(1).strip()
                if location not in locations:
                    locations.append(location)
    except OSError:
        pass
    finally:
        try:
            sock.close()
        except (OSError, UnboundLocalError):
            pass

    info = {}
    for location in locations[:2]:
        try:
            if not _safe_lan_url(location):
                continue
            result = _http_get(location, timeout=2.5, max_bytes=80000, lan_only=True)
            root = ET.fromstring(result["text"])
        except (ValueError, OSError, ET.ParseError):
            continue
        values = {}
        for node in root.iter():
            tag = node.tag.rsplit("}", 1)[-1]
            if tag in ("friendlyName", "manufacturer", "manufacturerURL", "modelName",
                       "modelNumber", "modelDescription", "deviceType", "presentationURL",
                       "serialNumber") and (node.text or "").strip():
                values.setdefault(tag, node.text.strip())
        if values:
            # presentationURL relatif terhadap LOCATION
            presentation = values.get("presentationURL", "")
            if presentation and not presentation.lower().startswith(("http://", "https://")):
                values["adminURL"] = urllib.parse.urljoin(location, presentation)
            elif presentation:
                values["adminURL"] = presentation
            info = values
            info["location"] = location
            break
    return info


MODEL_PATTERNS = (
    r"\bZXHN\s+F\d{3,4}[A-Z]?\b",
    r"\b(?:HG|EG|AN|F|G)\d{3,4}[A-Z]?\b",
    r"\bArcher\s+[A-Z0-9]{2,10}\b",
    r"\bTL-[A-Z0-9]{3,12}\b",
    r"\bDIR-\d{3,4}[A-Z]?\b",
    r"\bRT-[A-Z0-9]{2,10}\b",
    r"\bVR-\d{3,4}\b",
)


def _guess_model(text):
    source = (text or "").strip()
    if not source:
        return ""
    for pattern in MODEL_PATTERNS:
        match = re.search(pattern, source, re.I)
        if match:
            return match.group(0).strip()
    return ""


def _probe_router_http(gateway):
    hosts = [gateway] if gateway else []
    candidates = []
    for host in hosts:
        candidates.extend([
            f"http://{host}/",
            f"http://{host}:8080/",
            f"https://{host}/",
            f"http://{host}:8000/",
        ])
    if not candidates:
        return []

    def probe(url):
        try:
            result = _http_get(url, timeout=2.2, max_bytes=120000, lan_only=True)
        except (ValueError, OSError):
            return None
        text = result["text"]
        title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
        title = html.unescape(re.sub(r"\s+", " ", title_match.group(1)).strip())[:160] if title_match else ""
        auth = result["headers"].get("www-authenticate", "")
        generator = ""
        gen_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', text, re.I)
        if gen_match:
            generator = html.unescape(gen_match.group(1))[:80]
        server = result["headers"].get("server", "")[:120]
        lowered = text.lower()
        hints = [brand for brand, keys in ROUTER_BRANDS if any(key in lowered for key in keys)]
        return {
            "url": result["url"],
            "status": result["status"],
            "title": title,
            "server": server,
            "auth": auth[:120],
            "generator": generator,
            "hints": hints[:4],
            "model": _guess_model(title),
            "login_form": bool(re.search(r"type=[\"']?password", text, re.I)),
        }

    probes = []
    with ThreadPoolExecutor(max_workers=min(4, len(candidates))) as pool:
        for result in pool.map(probe, candidates):
            if result:
                probes.append(result)
    probes.sort(key=lambda item: (not (item["login_form"] or item["title"]), item["status"] != 200))
    return probes


def _isp_lookup(timeout=6.0):
    warnings = []
    try:
        data = _http_json("https://ipinfo.io/json", timeout=timeout)
        org = (data.get("org") or "").strip()
        asn = ""
        isp = org
        match = re.match(r"^(AS\d+)\s+(.*)$", org)
        if match:
            asn = match.group(1)
            isp = match.group(2)
        return {
            "source": "ipinfo.io",
            "public_ip": data.get("ip", ""),
            "isp": isp,
            "org": org,
            "asn": asn,
            "city": data.get("city", ""),
            "region": data.get("region", ""),
            "country": data.get("country", ""),
            "loc": data.get("loc", ""),
            "timezone": data.get("timezone", ""),
        }, warnings
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        warnings.append(f"ipinfo.io tidak dapat dihubungi: {exc}")

    try:
        data = _http_json("https://ifconfig.co/json", timeout=timeout)
        return {
            "source": "ifconfig.co",
            "public_ip": data.get("ip", ""),
            "isp": data.get("asn_org", "") or data.get("asn_org", ""),
            "org": data.get("asn_org", ""),
            "asn": f"AS{data['asn']}" if data.get("asn") else "",
            "city": data.get("city", ""),
            "region": data.get("region_name", ""),
            "country": data.get("country_iso", data.get("country", "")),
            "loc": "",
            "timezone": data.get("time_zone", ""),
        }, warnings
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        warnings.append(f"ifconfig.co tidak dapat dihubungi: {exc}")

    return {"error": "Lookup ISP eksternal gagal."}, warnings


def _detect_brand(blob):
    text = (blob or "").lower()
    if not text.strip():
        return ""
    for brand, keys in ROUTER_BRANDS:
        if any(key in text for key in keys):
            return brand
    return ""


def _default_login_reference(brand, model, blob):
    if brand:
        for entry in DEFAULT_LOGIN_REFERENCES:
            if entry["brand"].lower() == brand.lower():
                return entry
    model_text = (model or "").lower()
    if model_text:
        for entry in DEFAULT_LOGIN_REFERENCES:
            if entry["brand"] != "Generic" and any(key in model_text for key in entry["keys"]):
                return entry
    text = (blob or "").lower()
    for entry in DEFAULT_LOGIN_REFERENCES:
        if entry["brand"] != "Generic" and any(key in text for key in entry["keys"]):
            return entry
    return DEFAULT_LOGIN_REFERENCES[-1]


def _credential_block(entry, source_note):
    def pairs(item):
        values = [(item["username"], item["password"])]
        for username, password in item.get("alternatives", []):
            values.append((username, password))
        return [{"username": username, "password": password} for username, password in values]

    return {
        "brand": entry["brand"],
        "username": entry["username"],
        "password": entry["password"],
        "alternatives": pairs(entry)[1:],
        "verified": False,
        "source": source_note,
    }


def network_info_snapshot(iface, bssid, ssid):
    """Kumpulkan info ISP/router. Hanya melakukan lookup bila target terhubung."""
    bssid = (_normalize_mac(bssid) or "").upper()
    result = {
        "ok": True,
        "connected": False,
        "target": {"iface": iface, "ssid": ssid, "bssid": bssid},
        "link": {},
        "isp": {},
        "router": {},
        "login": {},
        "warnings": [],
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    def matches_target(candidate):
        if not candidate.get("connected"):
            return False
        if candidate.get("bssid", "").upper() == bssid:
            return True
        # Roaming/mesh: SSID sama tetapi BSSID berbeda tetap dianggap jaringan target.
        return bool(ssid and candidate.get("ssid") == ssid)

    active_iface = ""
    link = _wifi_link(iface)
    if matches_target(link):
        active_iface = iface
    else:
        # Cari interface lain yang mungkin terhubung ke jaringan target.
        for candidate in interfaces()[0]:
            name = candidate.get("name", "")
            if name == iface or not _validate_iface(name):
                continue
            other = _wifi_link(name)
            if matches_target(other):
                active_iface = name
                link = other
                break

    result["link"] = link
    if not active_iface:
        if link.get("connected"):
            message = (
                f"Interface {iface} sedang terhubung ke {link.get('ssid') or 'jaringan lain'} "
                f"({link.get('bssid')}), bukan ke target {ssid or bssid}. "
                "Sambungkan ke Wi-Fi target terlebih dahulu."
            )
        else:
            message = (
                f"Interface {iface} tidak terhubung ke Wi-Fi mana pun. "
                "Sambungkan ke jaringan target, lalu klik Run info lagi."
            )
        result["message"] = message
        result["warnings"].append(
            "Info ISP, router, dan login hanya bisa dideteksi saat perangkat terhubung ke jaringan target."
        )
        return result

    result["connected"] = True
    result["target"]["iface"] = active_iface
    if link.get("bssid", "").upper() != bssid:
        result["warnings"].append(
            f"Terhubung ke SSID {link.get('ssid')!r} melalui BSSID {link.get('bssid')} "
            f"(target {bssid}). Kemungkinan roaming/mesh; info gateway tetap dari koneksi aktif."
        )
    link["gateway"] = link.get("gateway") or _default_gateway(active_iface)
    gateway = link.get("gateway", "")
    if not gateway:
        result["warnings"].append(
            "Gateway IPv4 tidak terdeteksi. Login router tidak bisa ditentukan; "
            "periksa konfigurasi DHCP atau koneksi IPv6-only."
        )
    gateway_mac = _neighbor_mac(gateway) if gateway else ""
    vendor = _oui_vendor(gateway_mac) if gateway_mac else ""

    try:
        gateway_hostname = socket.gethostbyaddr(gateway)[0] if gateway else ""
    except (OSError, socket.herror, socket.gaierror):
        gateway_hostname = ""

    # Lookup eksternal, UPnP, dan HTTP router berjalan paralel.
    upnp = {}
    probes = []
    isp = {"error": "Lookup tidak dijalankan."}
    isp_warnings = []
    with ThreadPoolExecutor(max_workers=3) as pool:
        future_isp = pool.submit(_isp_lookup)
        future_upnp = pool.submit(_upnp_discover)
        future_http = pool.submit(_probe_router_http, gateway)
        try:
            isp, isp_warnings = future_isp.result(timeout=12)
        except Exception as exc:  # noqa: BLE001 - jangan gagalkan seluruh panel
            isp = {"error": f"Lookup ISP gagal: {exc}"}
        try:
            upnp = future_upnp.result(timeout=8)
        except Exception as exc:  # noqa: BLE001
            isp_warnings.append(f"UPnP discovery gagal: {exc}")
        try:
            probes = future_http.result(timeout=12)
        except Exception as exc:  # noqa: BLE001
            isp_warnings.append(f"HTTP fingerprint gagal: {exc}")

    result["warnings"].extend(isp_warnings)
    result["isp"] = isp

    principal = probes[0] if probes else {}
    upnp_blob = " ".join(str(value) for value in upnp.values()) if upnp else ""
    probe_blob = " ".join(
        f"{item.get('title', '')} {item.get('server', '')} {item.get('generator', '')} "
        f"{' '.join(item.get('hints', []))} {item.get('model', '')}"
        for item in probes
    )
    blob = " ".join([vendor, upnp_blob, probe_blob])
    model = upnp.get("modelName", "") or principal.get("model", "")
    http_identity = " ".join([
        principal.get("title", ""),
        principal.get("server", ""),
        principal.get("generator", ""),
    ])
    # Prioritaskan identitas yang paling kuat: OUI gateway, lalu UPnP, lalu HTTP.
    brand = _detect_brand(vendor) or _detect_brand(upnp_blob) or _detect_brand(http_identity)
    if not brand:
        for hint in principal.get("hints", []) or []:
            brand = hint
            break
    admin_url = upnp.get("adminURL") or principal.get("url") or (f"http://{gateway}/" if gateway else "")
    oui_name = _detect_brand(vendor) or vendor

    result["router"] = {
        "gateway": gateway,
        "gateway_hostname": gateway_hostname,
        "mac": gateway_mac,
        "vendor_oui": oui_name,
        "brand": brand,
        "manufacturer": upnp.get("manufacturer", ""),
        "model": model,
        "model_number": upnp.get("modelNumber", ""),
        "friendly_name": upnp.get("friendlyName", ""),
        "admin_url": admin_url,
        "http": principal,
        "upnp": upnp,
        "evidence": [
            item for item in (
                f"MAC OUI: {oui_name}" if oui_name else "",
                f"UPnP: {upnp.get('manufacturer', '')} {upnp.get('modelName', '')}".strip() if upnp else "",
                f"HTTP title: {principal.get('title', '')}" if principal.get("title") else "",
                f"HTTP server: {principal.get('server', '')}" if principal.get("server") else "",
                f"Model dari halaman login: {principal.get('model', '')}" if principal.get("model") else "",
            ) if item
        ],
    }

    login_entry = _default_login_reference(brand, model, blob)
    result["login"] = {
        "ip": gateway,
        "url": admin_url,
        "hostname": gateway_hostname,
        "credentials": _credential_block(
            login_entry,
            "Referensi kredensial default pabrik — belum diverifikasi dan bisa sudah diubah.",
        ),
        "note": (
            "Kata sandi router tidak dapat dibaca dari luar perangkat. Yang ditampilkan adalah "
            "referensi default pabrik; pada ONT/ISP, kredensial asli biasanya tercetak di stiker "
            "perangkat. Coba hanya pada router yang Anda miliki/berizin."
        ),
    }

    if not vendor and not upnp and not probes:
        result["warnings"].append(
            "Router tidak merespons fingerprint. Panel login memakai gateway default; "
            "beberapa router memblokir probe lokal."
        )
    result["warnings"].append(
        "Lookup ISP mengirim IP publik ke layanan pihak ketiga (ipinfo.io / ifconfig.co). "
        "Gunakan hanya pada jaringan yang Anda berwenang audit."
    )
    return result


@app.route("/api/network-info")
def network_info():
    iface = request.args.get("iface", "").strip()
    bssid = _normalize_mac(request.args.get("bssid", "").strip())
    ssid = request.args.get("ssid", "").strip()[:64]
    if not _validate_iface(iface) or not _validate_bssid(bssid):
        return jsonify({"ok": False, "error": "Parameter interface atau BSSID tidak valid."}), 400
    try:
        return jsonify(network_info_snapshot(iface, bssid, ssid))
    except Exception as exc:  # noqa: BLE001 - API harus selalu mengembalikan JSON
        app.logger.exception("network-info gagal")
        return jsonify({
            "ok": False,
            "error": f"Gagal mengumpulkan info jaringan: {exc}",
        }), 500


TOOL_APT_MAP = {
    "iw": "iw",
    "nmcli": "network-manager",
    "tshark": "wireshark-common",
    "aircrack-ng": "aircrack-ng",
    "reaver": "reaver",
    "bully": "bully",
    "mdk4": "mdk4",
    "hashcat": "hashcat",
    "aireplay-ng": "aircrack-ng",
    "airodump-ng": "aircrack-ng",
}


def installed_tools():
    tools = [
        ("iw", "Info adaptor dan mode Wi-Fi"),
        ("nmcli", "Pemindaian jaringan melalui NetworkManager"),
        ("tshark", "Analisis file capture"),
        ("aircrack-ng", "Pemeriksaan metadata capture yang kompatibel"),
        ("reaver", "WPS audit (pixie dust, pin brute)"),
        ("bully", "WPS audit alternatif"),
        ("mdk4", "Deauth dan stress test"),
        ("hashcat", "PSK brute force"),
        ("aireplay-ng", "Deauth dan inject frame"),
        ("airodump-ng", "Capture handshake dan beacon"),
    ]
    return [
        {"name": name, "description": desc, "installed": has(name), "apt": TOOL_APT_MAP.get(name, name)}
        for name, desc in tools
    ]


def capture_files():
    return sorted(
        p.name
        for p in CAPTURE_DIR.iterdir()
        if p.is_file() and p.suffix.lower() in (".cap", ".pcap", ".pcapng")
    )


def _normalize_mac(mac):
    """Bersihkan dan normalisasi MAC address: hilangkan karakter non-hex non-colon,
    pastikan pemisah adalah titik dua, kembalikan huruf besar."""
    if not mac:
        return mac
    hex_chars = re.findall(r"[0-9A-Fa-f]{2}", mac)
    if len(hex_chars) != 6:
        return mac
    return ":".join(hex_chars).upper()


def _validate_iface(iface):
    return bool(re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", iface))


def _validate_bssid(bssid):
    return bool(re.fullmatch(r"[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}", bssid))


def _target_label(ssid, bssid):
    ssid = (ssid or "").strip()[:64]
    return f"{ssid} · {bssid}" if ssid else bssid


@app.context_processor
def inject_runtime_status():
    return {"privileges": privilege_status()}


@app.route("/")
def index():
    ifaces, err = interfaces()
    tools = installed_tools()
    with JOBS_LOCK:
        recent = sorted(list(JOBS.values()), key=lambda job: job.started_at, reverse=True)[:4]
    return render_template(
        "index.html",
        ifaces=ifaces,
        iface_error=err,
        tools=tools,
        installed_count=sum(1 for t in tools if t["installed"]),
        capture_files=capture_files(),
        recent_jobs=[job.summary() for job in recent],
        now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )


@app.route("/scan", methods=["POST"])
def scan():
    iface = request.form.get("iface", "").strip()
    if not _validate_iface(iface):
        flash("Nama interface tidak valid.", "error")
        return redirect(url_for("index"))
    ifaces, _ = interfaces()
    if iface not in [x["name"] for x in ifaces]:
        flash("Interface tidak ditemukan oleh iw. Sambungkan adaptor yang kompatibel lalu periksa `iw dev`.", "error")
        return redirect(url_for("index"))
    rows, err = scan_wifi(iface)
    return render_template(
        "scan.html",
        rows=rows,
        iface=iface,
        error=err,
        now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )


@app.route("/analyze", methods=["POST"])
def analyze():
    name = request.form.get("capture", "")
    # Only accept a file already placed in captures/, not arbitrary paths.
    if not re.fullmatch(r"[A-Za-z0-9_.-]+\.(?:cap|pcap|pcapng)", name, re.I):
        flash("Nama file capture tidak valid.", "error")
        return redirect(url_for("index"))
    path = (CAPTURE_DIR / name).resolve()
    if path.parent != CAPTURE_DIR.resolve() or not path.is_file():
        flash("File tidak ditemukan. Letakkan file milik Anda di folder captures/.", "error")
        return redirect(url_for("index"))
    result = {
        "file": name,
        "size": path.stat().st_size,
        "frames": "Tidak diketahui",
        "summary": "Analisis metadata; isi paket tidak diubah.",
    }
    if has("capinfos"):
        rc, out, err = run_cmd(["capinfos", str(path)], timeout=20)
        result["details"] = out or err
    elif has("tshark"):
        rc, out, err = run_cmd(["tshark", "-r", str(path), "-q", "-z", "io,phs"], timeout=30)
        result["details"] = out or err
    else:
        result["details"] = "Pasang Wireshark/tshark untuk metadata: sudo apt install wireshark-common"
    if has("tshark"):
        rc, out, err = run_cmd(
            ["tshark", "-r", str(path), "-T", "fields", "-e", "frame.number"], timeout=30
        )
        if rc == 0:
            result["frames"] = str(len([x for x in out.splitlines() if x.strip()]))
    return render_template("analyze.html", result=result)


@app.route("/install-tool/<tool_name>", methods=["POST"])
def install_tool(tool_name):
    if not re.fullmatch(r"[A-Za-z0-9_-]+", tool_name):
        flash("Nama paket tidak valid.", "error")
        return redirect(url_for("index"))
    pkg = TOOL_APT_MAP.get(tool_name, tool_name)
    return launch_privileged(
        f"Install {pkg}",
        [install_command(pkg)],
        target=pkg,
        timeout=300,
    )


@app.route("/network/<iface>/<path:bssid>")
def network_detail(iface, bssid):
    # Werkzeug tidak meng-decode percent-encoding (contoh %3A untuk ':') pada
    # nilai converter <path:>, sehingga decode terlebih dahulu sebelum divalidasi.
    iface = unquote(iface)
    bssid = unquote(bssid)
    bssid = _normalize_mac(bssid)
    if not _validate_iface(iface) or not _validate_bssid(bssid):
        flash("Parameter interface atau BSSID tidak valid.", "error")
        return redirect(url_for("index"))
    rows, err = scan_wifi(iface)
    network = next((r for r in rows if r["bssid"].upper() == bssid.upper()), None)
    if not network:
        flash("Jaringan tidak ditemukan pada hasil scan terakhir. Silakan scan ulang terlebih dahulu.", "error")
        return redirect(url_for("index"))
    tools = installed_tools()
    return render_template(
        "detail.html",
        iface=iface,
        network=network,
        tool_status={t["name"]: t["installed"] for t in tools},
        capture_files=capture_files(),
        now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )


# ---------------------------------------------------------------------------
# Audit modules — every long-running process opens a live terminal session.
# ---------------------------------------------------------------------------

def _form_iface_bssid():
    iface = request.form.get("iface", "").strip()
    bssid = request.form.get("bssid", "").strip()
    ssid = request.form.get("ssid", "").strip()
    channel = request.form.get("channel", "").strip()
    if channel and not re.fullmatch(r"[0-9]{1,4}", channel):
        channel = ""
    if not _validate_iface(iface) or not _validate_bssid(bssid):
        return None, None, None, None, "Parameter interface atau BSSID tidak valid."
    return iface, bssid, channel, _target_label(ssid, bssid), ""


@app.route("/attack/wps/pixie-dust", methods=["POST"])
def attack_wps_pixie():
    iface, bssid, channel, target, err = _form_iface_bssid()
    if err:
        flash(err, "error")
        return redirect(url_for("index"))
    return launch_privileged(
        "WPS Pixie Dust",
        [monitor_command(iface, channel, "reaver", "-i", iface, "-b", bssid, "-K", "1", "-vv")],
        target=target,
        timeout=180,
    )


@app.route("/attack/wps/pin-brute", methods=["POST"])
def attack_wps_pin_brute():
    iface, bssid, channel, target, err = _form_iface_bssid()
    if err:
        flash(err, "error")
        return redirect(url_for("index"))
    return launch_privileged(
        "WPS Pin Brute",
        [monitor_command(iface, channel, "reaver", "-i", iface, "-b", bssid, "-vv")],
        target=target,
        timeout=300,
    )


@app.route("/attack/wps/common-pins", methods=["POST"])
def attack_wps_common_pins():
    iface, bssid, channel, target, err = _form_iface_bssid()
    if err:
        flash(err, "error")
        return redirect(url_for("index"))
    common = ["12345670", "00005678", "12345678", "99985677", "00000000"]
    commands = [
        monitor_command(iface, channel, "reaver", "-i", iface, "-b", bssid, "-p", pin, "-vv")
        for pin in common
    ]
    return launch_privileged("WPS Common Pins", commands, target=target, timeout=45)


@app.route("/attack/wps/custom-pin", methods=["POST"])
def attack_wps_custom_pin():
    iface, bssid, channel, target, err = _form_iface_bssid()
    if err:
        flash(err, "error")
        return redirect(url_for("index"))
    pin = request.form.get("pin", "").strip()
    if not re.fullmatch(r"[0-9]{8}", pin):
        flash("PIN harus 8 digit angka.", "error")
        return redirect(url_for("index"))
    return launch_privileged(
        f"WPS Custom Pin ({pin})",
        [monitor_command(iface, channel, "reaver", "-i", iface, "-b", bssid, "-p", pin, "-vv")],
        target=target,
        timeout=120,
    )


@app.route("/attack/wpa/pmk-capture", methods=["POST"])
def attack_wpa_pmk():
    iface, bssid, channel, target, err = _form_iface_bssid()
    if err:
        flash(err, "error")
        return redirect(url_for("index"))
    return launch_privileged(
        "WPA PMK Capture",
        [monitor_command(iface, channel, "tshark", "-i", iface, "-Y", "wlan.rsna", "-a", "duration:30", "-w", str(CAPTURE_DIR.resolve() / "pmk_capture.pcap"))],
        target=target,
        timeout=60,
    )


@app.route("/attack/wpa/hs-capture", methods=["POST"])
def attack_wpa_hs():
    iface, bssid, channel, target, err = _form_iface_bssid()
    if err:
        flash(err, "error")
        return redirect(url_for("index"))
    airodump_args = ["--bssid", bssid, "-w", str(CAPTURE_DIR.resolve() / "hs_capture")]
    if channel:
        airodump_args = ["--channel", channel, *airodump_args]
    airodump_args.append(iface)
    return launch_privileged(
        "WPA Handshake Capture",
        [monitor_command(iface, channel, "airodump-ng", *airodump_args)],
        target=target,
        timeout=60,
    )


@app.route("/attack/wpa/deauth", methods=["POST"])
def attack_wpa_deauth():
    iface, bssid, channel, target, err = _form_iface_bssid()
    if err:
        flash(err, "error")
        return redirect(url_for("index"))
    return launch_privileged(
        "WPA Deauth",
        [monitor_command(iface, channel, "aireplay-ng", "--deauth", "10", "-a", bssid, iface)],
        target=target,
        timeout=30,
    )


@app.route("/attack/wpa/psk-brute", methods=["POST"])
def attack_wpa_psk_brute():
    iface, bssid, channel, target, err = _form_iface_bssid()
    if err:
        flash(err, "error")
        return redirect(url_for("index"))
    wordlist = request.form.get("wordlist", "").strip()
    capture = request.form.get("capture", "").strip()
    if not wordlist or not capture:
        flash("Masukkan path wordlist dan file capture.", "error")
        return redirect(url_for("index"))
    if not Path(wordlist).is_file():
        flash(f"Wordlist tidak ditemukan: {wordlist}", "error")
        return redirect(url_for("index"))
    if not Path(capture).is_file():
        flash(f"File capture tidak ditemukan: {capture}", "error")
        return redirect(url_for("index"))
    return launch_privileged(
        "WPA PSK Brute",
        [privileged_command("aircrack-ng", "-b", bssid, "-w", wordlist, capture)],
        target=target,
        timeout=1800,
    )


# ---------------------------------------------------------------------------
# Live terminal + polling API
# ---------------------------------------------------------------------------

@app.route("/terminal/<job_id>")
def terminal(job_id):
    job = JOBS.get(job_id)
    if not job:
        flash("Sesi terminal tidak ditemukan atau sudah kedaluwarsa.", "error")
        return redirect(url_for("index"))
    return render_template("terminal.html", job=job)


@app.route("/api/jobs/<job_id>")
def job_api(job_id):
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "not_found"}), 404
    try:
        after = int(request.args.get("after", "0"))
    except (TypeError, ValueError):
        after = 0
    return jsonify(job.snapshot(after))


@app.route("/api/jobs/<job_id>/stop", methods=["POST"])
def job_stop(job_id):
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "not_found"}), 404
    stopped = job.stop()
    return jsonify({"ok": True, "stopped": stopped, "status": job.status})


if __name__ == "__main__":
    status = privilege_status(force=True)
    if not status["ready"]:
        print("[STRYKER] PERINGATAN: modul audit belum mendapat akses root.")
        print(f"[STRYKER] {status['message']}")
        print("[STRYKER] Jalankan ./setup_privileges.sh sekali, lalu restart server.")
    else:
        print(f"[STRYKER] Hak akses root siap ({status['mode']}).")
    # Bind only to localhost; do not expose this admin panel to the network.
    app.run(host="127.0.0.1", port=5055, debug=False)
