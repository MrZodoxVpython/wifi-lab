#!/usr/bin/env python3
"""STRYKER — Wi-Fi audit dashboard for Kali Linux.

Safe-by-default scope: passive/standard scanning, adapter capability checks,
analysis of existing capture files, and explicit audit modules that are only
started by the operator. The dashboard binds to localhost only.
"""
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import subprocess, shutil, re, os, threading, uuid
from pathlib import Path
from datetime import datetime
from urllib.parse import unquote

app = Flask(__name__)
app.secret_key = os.environ.get("WIFI_AUDIT_SECRET", "change-this-local-secret")
CAPTURE_DIR = Path("captures")
CAPTURE_DIR.mkdir(exist_ok=True)


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
        return " ; ".join(" ".join(part) for part in self.commands)

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
            job.append(f"$ {' '.join(cmd)}")
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
    return launch_job(
        f"Install {pkg}",
        [["sudo", "apt-get", "install", "-y", pkg]],
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
    if not _validate_iface(iface) or not _validate_bssid(bssid):
        return None, None, None, "Parameter interface atau BSSID tidak valid."
    return iface, bssid, _target_label(ssid, bssid), ""


@app.route("/attack/wps/pixie-dust", methods=["POST"])
def attack_wps_pixie():
    iface, bssid, target, err = _form_iface_bssid()
    if err:
        flash(err, "error")
        return redirect(url_for("index"))
    return launch_job(
        "WPS Pixie Dust",
        [["reaver", "-i", iface, "-b", bssid, "-K", "1", "-vv"]],
        target=target,
        timeout=180,
    )


@app.route("/attack/wps/pin-brute", methods=["POST"])
def attack_wps_pin_brute():
    iface, bssid, target, err = _form_iface_bssid()
    if err:
        flash(err, "error")
        return redirect(url_for("index"))
    return launch_job(
        "WPS Pin Brute",
        [["reaver", "-i", iface, "-b", bssid, "-vv"]],
        target=target,
        timeout=300,
    )


@app.route("/attack/wps/common-pins", methods=["POST"])
def attack_wps_common_pins():
    iface, bssid, target, err = _form_iface_bssid()
    if err:
        flash(err, "error")
        return redirect(url_for("index"))
    common = ["12345670", "00005678", "12345678", "99985677", "00000000"]
    commands = [["reaver", "-i", iface, "-b", bssid, "-p", pin, "-vv"] for pin in common]
    return launch_job("WPS Common Pins", commands, target=target, timeout=45)


@app.route("/attack/wps/custom-pin", methods=["POST"])
def attack_wps_custom_pin():
    iface, bssid, target, err = _form_iface_bssid()
    if err:
        flash(err, "error")
        return redirect(url_for("index"))
    pin = request.form.get("pin", "").strip()
    if not re.fullmatch(r"[0-9]{8}", pin):
        flash("PIN harus 8 digit angka.", "error")
        return redirect(url_for("index"))
    return launch_job(
        f"WPS Custom Pin ({pin})",
        [["reaver", "-i", iface, "-b", bssid, "-p", pin, "-vv"]],
        target=target,
        timeout=120,
    )


@app.route("/attack/wpa/pmk-capture", methods=["POST"])
def attack_wpa_pmk():
    iface, bssid, target, err = _form_iface_bssid()
    if err:
        flash(err, "error")
        return redirect(url_for("index"))
    return launch_job(
        "WPA PMK Capture",
        [["tshark", "-i", iface, "-Y", "wlan.rsna", "-a", "duration:30", "-w", "/tmp/pmk_capture.pcap"]],
        target=target,
        timeout=60,
    )


@app.route("/attack/wpa/hs-capture", methods=["POST"])
def attack_wpa_hs():
    iface, bssid, target, err = _form_iface_bssid()
    if err:
        flash(err, "error")
        return redirect(url_for("index"))
    return launch_job(
        "WPA Handshake Capture",
        [["airodump-ng", "--bssid", bssid, "-w", "/tmp/hs_capture", iface]],
        target=target,
        timeout=60,
    )


@app.route("/attack/wpa/deauth", methods=["POST"])
def attack_wpa_deauth():
    iface, bssid, target, err = _form_iface_bssid()
    if err:
        flash(err, "error")
        return redirect(url_for("index"))
    return launch_job(
        "WPA Deauth",
        [["aireplay-ng", "--deauth", "10", "-a", bssid, iface]],
        target=target,
        timeout=30,
    )


@app.route("/attack/wpa/psk-brute", methods=["POST"])
def attack_wpa_psk_brute():
    iface, bssid, target, err = _form_iface_bssid()
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
    return launch_job(
        "WPA PSK Brute",
        [["aircrack-ng", "-b", bssid, "-w", wordlist, capture]],
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
    # Bind only to localhost; do not expose this admin panel to the network.
    app.run(host="127.0.0.1", port=5055, debug=False)
