#!/usr/bin/env python3
"""wifi-lab-priv — privileged helper untuk STRYKER Wi-Fi Audit Lab.

Dipasang sebagai root di /usr/local/sbin/wifi-lab-priv dan diizinkan lewat
/etc/sudoers.d/wifi-lab. Helper ini hanya menjalankan tool yang ada di daftar
putih, sehingga Flask tetap berjalan sebagai user biasa.

Perintah yang didukung:
  wifi-lab-priv check
  wifi-lab-priv scan IFACE
  wifi-lab-priv run TOOL [ARGS...]
  wifi-lab-priv monitor-run IFACE CHANNEL|- TOOL [ARGS...]
  wifi-lab-priv restore IFACE
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


def iface_exists(name):
    return bool(name) and os.path.exists(f"/sys/class/net/{name}")


def monitor_name(iface):
    """Nama interface monitor khusus, maksimal 15 karakter (IFNAMSIZ-1)."""
    return f"{iface}mon"[:15]


def phy_name(iface):
    iw = resolve("iw") or "iw"
    try:
        p = subprocess.run(
            [iw, "dev", iface, "info"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except Exception:  # noqa: BLE001
        return ""
    for line in (p.stdout or "").splitlines():
        text = line.strip()
        if text.startswith("wiphy "):
            return f"phy{text.split(None, 1)[1]}"
    return ""


def delete_iface(name):
    if not iface_exists(name):
        return
    sh(["ip", "link", "set", name, "down"], optional=True)
    sh(["iw", "dev", name, "del"], optional=True)


def set_monitor_channel(mon, channel):
    """Set channel monitor dan coba beberapa metode bila iwlwifi menolak.

    iwlwifi (mis. AC 8265) kadang melaporkan sukses lewat `iw` tetapi firmware
    tetap berada di channel asosiasi terakhir. Dedicated monitor interface
    adalah jalur utama; fungsi ini menambahkan fallback `set freq`/iwconfig.
    """
    ch = str(channel)
    ok = sh(["iw", "dev", mon, "set", "channel", ch], optional=True) == 0
    if not ok:
        # Beberapa driver lebih menerima frekuensi eksplisit.
        try:
            number = int(ch)
        except ValueError:
            number = 0
        freq = 0
        if 1 <= number <= 13:
            freq = 2407 + number * 5
        elif number == 14:
            freq = 2484
        elif 15 <= number <= 200:
            freq = (number + 1000) * 5
        if freq:
            ok = sh(["iw", "dev", mon, "set", "freq", str(freq)], optional=True) == 0
    if not ok:
        ok = sh(["iwconfig", mon, "channel", ch], optional=True) == 0
    if ok:
        out(f"[priv] Channel {ch} disetel pada {mon}.")
    else:
        err(f"[priv] Peringatan: gagal menyetel channel {ch} pada {mon}.")
    return ok


def wait_disconnected(iface, attempts=10):
    """Tunggu sampai station benar-benar lepas dari AP sebelum ganti mode."""
    iw = resolve("iw") or "iw"
    for _ in range(attempts):
        try:
            p = subprocess.run(
                [iw, "dev", iface, "link"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            info = (p.stdout or "") + (p.stderr or "")
        except Exception:  # noqa: BLE001
            info = ""
        if "Not connected" in info or not info.strip():
            return True
        time.sleep(0.3)
    return False


def create_monitor_iface(iface, channel=None):
    """Buat monitor interface terpisah; return namanya atau "" bila gagal."""
    mon = monitor_name(iface)
    delete_iface(mon)

    # Managed interface harus down agar slot channel-nya lepas dari firmware.
    sh(["ip", "link", "set", iface, "down"], optional=True)
    rc = sh(
        ["iw", "dev", iface, "interface", "add", mon, "type", "monitor"],
        optional=True,
    )
    if rc != 0:
        phy = phy_name(iface)
        if phy:
            rc = sh(
                ["iw", "phy", phy, "interface", "add", mon, "type", "monitor"],
                optional=True,
            )
    if rc != 0:
        delete_iface(mon)
        return ""

    sh(["ip", "link", "set", mon, "up"], optional=True)
    if channel:
        set_monitor_channel(mon, channel)
    return mon


def restore_managed(iface):
    # Hapus monitor interface pasangan (mis. wlan0mon) sebelum restore.
    mon = monitor_name(iface)
    if mon != iface:
        delete_iface(mon)

    out(f"[priv] Mengembalikan {iface} ke managed mode...")
    sh(["ip", "link", "set", iface, "down"], optional=True)
    rc = sh(["iw", "dev", iface, "set", "type", "managed"], optional=True)
    sh(["ip", "link", "set", iface, "up"], optional=True)
    sh(["nmcli", "device", "set", iface, "managed", "yes"], optional=True)

    # NetworkManager kadang menyelesaikan aktivasi secara asinkron. Coba
    # reconnect beberapa kali agar interface tidak tertinggal disconnected.
    connected = False
    for attempt in range(1, 7):
        try:
            p = subprocess.run(
                ["nmcli", "-t", "-f", "DEVICE,STATE", "device", "status"],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            state = (p.stdout or "") + (p.stderr or "")
        except Exception:  # noqa: BLE001
            state = ""
        if any(line.startswith(f"{iface}:connected") for line in state.splitlines()):
            connected = True
            break
        out(f"[priv] Menyambungkan ulang {iface} ({attempt}/6)...")
        sh(["nmcli", "device", "connect", iface], optional=True)
        time.sleep(2)

    if rc == 0 and connected:
        out(f"[priv] {iface} kembali ke managed mode dan tersambung.")
        return True
    elif rc == 0:
        out(f"[priv] {iface} kembali ke managed mode.")
        err(
            f"[priv] PERINGATAN: {iface} belum tersambung ke jaringan. "
            f"Pilih jaringan di NetworkManager atau jalankan: nmcli device connect {iface}"
        )
        return False
    else:
        err(
            f"[priv] PERINGATAN: gagal mengembalikan {iface} ke managed mode.\n"
            f"[priv] Pulihkan manual:\n"
            f"[priv]   sudo ip link set {iface} down\n"
            f"[priv]   sudo iw dev {iface} set type managed\n"
            f"[priv]   sudo ip link set {iface} up\n"
            f"[priv]   sudo nmcli device set {iface} managed yes"
        )
        return False


def restore_interface(iface):
    """Pulihkan satu interface dari monitor mode ke managed mode.

    Jika interface masih memakai nama hasil airmon-ng (mis. wlan0mon) dan
    interface aslinya (wlan0) belum ada, coba hentikan airmon-ng terlebih
    dahulu agar nama interface kembali normal.
    """
    if not IFACE_RE.fullmatch(iface or ""):
        err(f"[priv] nama interface tidak valid: {iface!r}")
        return 2
    if os.geteuid() != 0:
        err("[priv] restore harus dijalankan sebagai root (via sudo).")
        return 2

    sh(["rfkill", "unblock", "wifi"], optional=True)
    sh(["rfkill", "unblock", "all"], optional=True)

    target = iface
    base = iface[:-3] if iface.endswith("mon") else iface
    if base != iface and not os.path.exists(f"/sys/class/net/{base}"):
        airmon = shutil.which("airmon-ng", path=SEARCH_PATH)
        if airmon:
            rc = sh([airmon, "stop", iface], optional=True)
            if rc == 0 and os.path.exists(f"/sys/class/net/{base}"):
                target = base
                out(f"[priv] airmon-ng mengembalikan {iface} -> {base}.")

    # airmon-ng kadang berhasil me-rename walau return code-nya bukan 0.
    if not os.path.exists(f"/sys/class/net/{target}") and os.path.exists(
        f"/sys/class/net/{base}"
    ):
        target = base

    if not os.path.exists(f"/sys/class/net/{target}"):
        err(f"[priv] interface tidak ditemukan: {target}")
        return 1

    ok = restore_managed(target)
    return 0 if ok else 1


def scan_interface(iface):
    """Ambil hasil scan nl80211 sebagai root dan cetak hasil mentahnya.

    Memakai `iw dev IFACE scan dump` (cache kernel) dan fallback ke
    `iw dev IFACE scan`. Dipakai aplikasi untuk membaca informasi IE
    (mis. WPS) yang tidak diekspos NetworkManager. Mode interface tidak
    diubah.
    """
    if not IFACE_RE.fullmatch(iface or ""):
        err(f"[priv] nama interface tidak valid: {iface!r}")
        return 2
    if os.geteuid() != 0:
        err("[priv] scan harus dijalankan sebagai root (via sudo).")
        return 2

    iw_path = resolve("iw")
    if not iw_path:
        return 127

    def run_scan(args):
        try:
            return subprocess.run(
                [iw_path, "dev", iface, *args],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except subprocess.TimeoutExpired:
            err(f"[priv] pemindaian iw pada {iface} melebihi 60 detik.")
            return None

    # Utamakan hasil cache kernel: nmcli baru saja melakukan scan, sehingga
    # `scan dump` cepat dan tidak memicu scan kedua yang bisa gagal EBUSY.
    # `-b` menampilkan IE dari probe response dan beacon sekaligus agar WPS
    # tetap terlihat walau AP hanya mencantumkannya di salah satu frame.
    p = run_scan(["scan", "dump", "-b"])
    if p is None:
        return 124
    if p.returncode != 0 or "BSS " not in (p.stdout or ""):
        p = run_scan(["scan", "-b"])
        if p is None:
            return 124

    if p.stdout.strip():
        out(p.stdout.rstrip("\n"))
    if p.stderr.strip():
        err(p.stderr.strip())
    return p.returncode


def iface_info(name):
    iw = resolve("iw") or "iw"
    try:
        p = subprocess.run(
            [iw, "dev", name, "info"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except Exception:  # noqa: BLE001
        return ""
    return (p.stdout or "") + (p.stderr or "")


def info_channel(info):
    match = re.search(r"channel\s+(\d+)", info or "")
    return match.group(1) if match else ""


def enter_monitor(iface, channel=None):
    """Aktifkan monitor mode dan return nama interface yang dipakai.

    iwlwifi AC 8265 tidak selalu benar-benar pindah channel saat interface
    diubah in-place; firmware tetap di channel asosiasi terakhir. Karena itu
    helper memakai monitor interface terpisah (mis. wlan0mon) dan memastikan
    channel-nya disetel sebelum tool dijalankan. Bila pembuatan interface
    gagal, helper fallback ke konversi in-place.
    """
    out(f"[priv] Menyiapkan monitor mode pada {iface}...")
    sh(["rfkill", "unblock", "wifi"], optional=True)
    # NetworkManager harus melepas interface sebelum tipe link diubah.
    sh(["nmcli", "device", "disconnect", iface], optional=True)
    sh(["nmcli", "device", "set", iface, "managed", "no"], optional=True)
    time.sleep(0.5)
    if not wait_disconnected(iface):
        err(
            f"[priv] Peringatan: {iface} masih terlihat terasosiasi; "
            "monitor mode tetap dicoba."
        )
    sh(["iw", "dev", iface, "set", "power_save", "off"], optional=True)

    mon = create_monitor_iface(iface, channel)
    if mon:
        info = iface_info(mon)
        active = info_channel(info)
        if "type monitor" in info and (
            not channel or active == str(channel)
        ):
            out(
                f"[priv] Monitor mode aktif pada {mon}"
                + (f" (channel {channel})." if channel else ".")
            )
            return mon
        err(
            f"[priv] Monitor interface {mon} tidak siap "
            f"(mode/channel tidak sesuai); mencoba konversi in-place."
        )
        if info.strip():
            for line in info.strip().splitlines():
                err(f"[priv] {line}")
        delete_iface(mon)

    # Fallback: konversi interface utama in-place.
    err(
        "[priv] Monitor interface terpisah gagal dibuat; "
        "memakai konversi in-place."
    )
    sh(["ip", "link", "set", iface, "down"], optional=True)
    rc = sh(["iw", "dev", iface, "set", "type", "monitor"])
    if rc != 0:
        err(
            f"[priv] Gagal mengaktifkan monitor mode pada {iface}.\n"
            "[priv] Pastikan adaptor mendukung monitor mode. Cek dengan: "
            "iw list | grep -A8 'Supported interface modes'"
        )
        restore_managed(iface)
        return ""

    if channel:
        # Set saat interface masih down; sebagian driver menerapkan channel
        # pada saat interface di-up.
        set_monitor_channel(iface, channel)
    sh(["ip", "link", "set", iface, "up"], optional=True)
    if channel:
        set_monitor_channel(iface, channel)
        # Jalur wireless-extensions; sebagian firmware iwlwifi hanya menurut
        # lewat ioctl lama ini.
        sh(["iwconfig", iface, "channel", str(channel)], optional=True)

    info = iface_info(iface)
    if "type monitor" not in info:
        err(f"[priv] Verifikasi monitor mode gagal untuk {iface}.")
        if info.strip():
            for line in info.strip().splitlines():
                err(f"[priv] {line}")
        restore_managed(iface)
        return ""

    active = info_channel(info)
    if channel and active and active != str(channel):
        err(
            f"[priv] Peringatan: {iface} melaporkan channel {active}, "
            f"bukan {channel}. Tool tetap dijalankan."
        )
    out(f"[priv] Monitor mode aktif pada {iface} (fallback in-place).")
    return iface


def handle_signal(signum, _frame):
    global _child
    out(f"[priv] Menerima sinyal {signum}, menghentikan proses...")
    if _child is not None and _child.poll() is None:
        try:
            _child.send_signal(signal.SIGTERM)
        except Exception:  # noqa: BLE001
            pass


def map_iface_args(args, base, mon):
    """Ganti argumen interface dasar dengan monitor interface.

    Tool seperti reaver/airodump/wash menerima nama interface sebagai argumen
    terpisah (`-i wlan0`) atau positional (`airodump-ng wlan0`).
    """
    if not mon or mon == base:
        return list(args)
    mapped = []
    for arg in args:
        text = str(arg)
        if text == base:
            mapped.append(mon)
        elif text.startswith(f"--interface={base}"):
            mapped.append(f"--interface={mon}")
        else:
            mapped.append(text)
    return mapped


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

    mon = enter_monitor(iface, channel or None)
    if not mon:
        return 3

    tool_args = map_iface_args(args, iface, mon)

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, handle_signal)

    rc = 1
    try:
        out(f"[priv] $ {tool} {' '.join(tool_args)}".rstrip())
        _child = subprocess.Popen(  # noqa: S603 - argumen list, tanpa shell
            [path, *tool_args],
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
        err("usage: wifi-lab-priv {check|scan|run|monitor-run|restore|install} ...")
        return 2

    action = argv[1]

    if action == "check":
        out(f"wifi-lab-priv ok (uid={os.geteuid()})")
        return 0

    if action == "scan":
        if len(argv) != 3:
            err("usage: wifi-lab-priv scan IFACE")
            return 2
        return scan_interface(argv[2])

    if action == "restore":
        if len(argv) != 3:
            err("usage: wifi-lab-priv restore IFACE")
            return 2
        return restore_interface(argv[2])

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
