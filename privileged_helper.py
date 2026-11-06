#!/usr/bin/env python3
"""wifi-lab-priv — privileged helper untuk STRYKER Wi-Fi Audit Lab.

Dipasang sebagai root di /usr/local/sbin/wifi-lab-priv dan diizinkan lewat
/etc/sudoers.d/wifi-lab. Helper ini hanya menjalankan tool yang ada di daftar
putih, sehingga Flask tetap berjalan sebagai user biasa.

Perintah yang didukung:
  wifi-lab-priv check
  wifi-lab-priv run TOOL [ARGS...]
  wifi-lab-priv monitor-run IFACE TOOL [ARGS...]
  wifi-lab-priv install PACKAGE
"""
import os
import re
import shutil
import signal
import subprocess
import sys
import time

SEARCH_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")
CHANNEL_RE = re.compile(r"^[0-9]{1,4}$")
PACKAGE_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]{0,63}$")

# Tool yang boleh dijalankan. Jangan tambahkan shell (bash/sh) di sini.
ALLOWED_TOOLS = {
    "iw",
    "ip",
    "nmcli",
    "rfkill",
    "airmon-ng",
    "airodump-ng",
    "aireplay-ng",
    "aircrack-ng",
    "reaver",
    "bully",
    "wash",
    "mdk4",
    "hashcat",
    "tshark",
    "hcxdumptool",
    "hcxpcapngtool",
}

# Tool yang tidak boleh dipakai untuk monitor-run (tidak masuk akal/berisiko).
MONITOR_EXCLUDED = {"iw", "ip", "nmcli", "rfkill", "airmon-ng"}

# Tool konfigurasi jaringan hanya dipakai internal oleh helper, bukan via "run".
RUN_EXCLUDED = {"iw", "ip", "nmcli", "rfkill", "airmon-ng"}

_child = None


def out(message=""):
    print(message, flush=True)


def err(message):
    print(message, file=sys.stderr, flush=True)


def resolve(tool):
    path = shutil.which(tool, path=SEARCH_PATH)
    if not path:
        err(f"[priv] tool tidak ditemukan di PATH sistem: {tool}")
        return None
    return path


def sh(args, optional=False, timeout=20):
    """Jalankan perintah pendukung dan tampilkan output hanya bila perlu."""
    args = list(args)
    if not os.path.isabs(args[0]):
        found = shutil.which(args[0], path=SEARCH_PATH)
        if not found:
            if not optional:
                err(f"[priv] perintah tidak ditemukan: {args[0]}")
            return 127
        args[0] = found
    out(f"[priv] $ {' '.join(args)}")
    try:
        p = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        if not optional:
            err(f"[priv] perintah tidak ditemukan: {args[0]}")
        return 127
    except subprocess.TimeoutExpired:
        if not optional:
            err(f"[priv] batas waktu {timeout}s: {' '.join(args)}")
        return 124

    text = ((p.stdout or "") + (p.stderr or "")).strip()
    if text and (p.returncode != 0 or not optional):
        for line in text.splitlines():
            out(f"[priv] {line}")
    return p.returncode


def restore_managed(iface):
    out(f"[priv] Mengembalikan {iface} ke managed mode...")
    sh(["ip", "link", "set", iface, "down"], optional=True)
    rc = sh(["iw", "dev", iface, "set", "type", "managed"], optional=True)
    sh(["ip", "link", "set", iface, "up"], optional=True)
    sh(["nmcli", "device", "set", iface, "managed", "yes"], optional=True)
    sh(["nmcli", "device", "connect", iface], optional=True)
    if rc == 0:
        out(f"[priv] {iface} kembali ke managed mode.")
    else:
        err(
            f"[priv] PERINGATAN: gagal mengembalikan {iface} ke managed mode.\n"
            f"[priv] Pulihkan manual:\n"
            f"[priv]   sudo ip link set {iface} down\n"
            f"[priv]   sudo iw dev {iface} set type managed\n"
            f"[priv]   sudo ip link set {iface} up\n"
            f"[priv]   sudo nmcli device set {iface} managed yes"
        )


def enter_monitor(iface, channel=None):
    out(f"[priv] Menyiapkan monitor mode pada {iface}...")
    sh(["rfkill", "unblock", "wifi"], optional=True)
    # NetworkManager harus melepas interface sebelum tipe link diubah.
    sh(["nmcli", "device", "disconnect", iface], optional=True)
    sh(["nmcli", "device", "set", iface, "managed", "no"], optional=True)
    time.sleep(0.4)
    sh(["ip", "link", "set", iface, "down"], optional=True)
    rc = sh(["iw", "dev", iface, "set", "type", "monitor"])
    if rc != 0:
        err(
            f"[priv] Gagal mengaktifkan monitor mode pada {iface}.\n"
            "[priv] Pastikan adaptor mendukung monitor mode. Cek dengan: iw list | grep -A8 'Supported interface modes'"
        )
        restore_managed(iface)
        return False
    sh(["ip", "link", "set", iface, "up"], optional=True)

    if channel:
        rc = sh(["iw", "dev", iface, "set", "channel", str(channel)])
        if rc != 0:
            err(f"[priv] Peringatan: gagal menyetel channel {channel}; melanjutkan pada channel saat ini.")
        else:
            out(f"[priv] Channel disetel ke {channel}.")

    # Verifikasi agar tool tidak dijalankan dengan mode yang salah.
    try:
        iw_path = resolve("iw") or "iw"
        p = subprocess.run(
            [iw_path, "dev", iface, "info"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        info = (p.stdout or "") + (p.stderr or "")
    except Exception as exc:  # noqa: BLE001 - tetap coba jalankan tool
        err(f"[priv] Verifikasi mode gagal: {exc}")
        info = ""

    if "type monitor" not in info:
        err(f"[priv] Verifikasi monitor mode gagal untuk {iface}.")
        if info.strip():
            for line in info.strip().splitlines():
                err(f"[priv] {line}")
        restore_managed(iface)
        return False

    out(f"[priv] Monitor mode aktif pada {iface}.")
    return True


def handle_signal(signum, _frame):
    global _child
    out(f"[priv] Menerima sinyal {signum}, menghentikan proses...")
    if _child is not None and _child.poll() is None:
        try:
            _child.send_signal(signal.SIGTERM)
        except Exception:  # noqa: BLE001
            pass


def monitor_run(iface, channel, tool, args):
    global _child

    if not IFACE_RE.fullmatch(iface or ""):
        err(f"[priv] nama interface tidak valid: {iface!r}")
        return 2
    if channel and not CHANNEL_RE.fullmatch(channel):
        err(f"[priv] channel tidak valid: {channel!r}")
        return 2
    if tool not in ALLOWED_TOOLS or tool in MONITOR_EXCLUDED:
        err(f"[priv] tool tidak diizinkan untuk monitor-run: {tool}")
        return 2

    path = resolve(tool)
    if not path:
        return 127

    if os.geteuid() != 0:
        err("[priv] monitor-run harus dijalankan sebagai root (via sudo).")
        return 2

    if not enter_monitor(iface, channel or None):
        return 3

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, handle_signal)

    rc = 1
    try:
        out(f"[priv] $ {tool} {' '.join(args)}".rstrip())
        _child = subprocess.Popen(  # noqa: S603 - argumen list, tanpa shell
            [path, *args],
            stdin=subprocess.DEVNULL,
        )
        rc = _child.wait()
    except FileNotFoundError:
        err(f"[priv] perintah tidak ditemukan: {tool}")
        rc = 127
    finally:
        _child = None
        restore_managed(iface)

    if rc < 0:
        rc = 128 + abs(rc)
    return rc


def main(argv):
    if len(argv) < 2:
        err("usage: wifi-lab-priv {check|run|monitor-run|install} ...")
        return 2

    action = argv[1]

    if action == "check":
        out(f"wifi-lab-priv ok (uid={os.geteuid()})")
        return 0

    if action == "run":
        if len(argv) < 3:
            err("usage: wifi-lab-priv run TOOL [ARGS...]")
            return 2
        tool = argv[2]
        if tool not in ALLOWED_TOOLS or tool in RUN_EXCLUDED:
            err(f"[priv] tool tidak diizinkan: {tool}")
            return 2
        path = resolve(tool)
        if not path:
            return 127
        try:
            os.execv(path, [path, *argv[3:]])
        except OSError as exc:
            err(f"[priv] gagal menjalankan {tool}: {exc}")
            return 126

    if action == "monitor-run":
        if len(argv) < 5:
            err("usage: wifi-lab-priv monitor-run IFACE CHANNEL|- TOOL [ARGS...]")
            return 2
        return monitor_run(argv[2], argv[3], argv[4], argv[5:])

    if action == "install":
        if len(argv) != 3:
            err("usage: wifi-lab-priv install PACKAGE")
            return 2
        package = argv[2]
        if not PACKAGE_RE.fullmatch(package):
            err(f"[priv] nama paket tidak valid: {package!r}")
            return 2
        apt = resolve("apt-get")
        if not apt:
            return 127
        env = dict(os.environ)
        env["DEBIAN_FRONTEND"] = "noninteractive"
        try:
            os.execve(apt, [apt, "install", "-y", package], env)
        except OSError as exc:
            err(f"[priv] gagal menjalankan apt-get: {exc}")
            return 126

    err(f"[priv] aksi tidak dikenal: {action}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
