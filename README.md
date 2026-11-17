# WiFi Lab

A PyQt6 desktop GUI for WiFi auditing on Linux: WPA/WPA2 handshake capture,
WPS attacks (pixie dust / PIN), targeted deauth, and offline passphrase
cracking.

> **Ethics / authorization:** This tool is for testing **your own network or
> networks you are explicitly authorized to audit**. Capturing handshakes,
> deauthenticating clients, and attempting WPS PINs are intrusive actions.
> Do not use them against networks you do not own or have permission to test.

---

## Features

- **Scan** — list nearby networks with SSID, BSSID, channel, signal, security
  (WPA1/WPA2/WPA3), and WPS status (from `iw` scan IEs).
- **Handshake capture** — runs `airodump-ng` + `aireplay-ng` in monitor mode
  to capture the 4-way handshake for a selected AP.
- **WPS attacks** — `reaver` pixie dust (`-K 1`) or a specific PIN.
- **Deauth** — targeted deauthentication (broadcast or one client).
- **Cracking** — offline `aircrack-ng` against a captured `.cap`/`.pcap` with
  a wordlist (e.g. `rockyou.txt`).
- **Tool manager** — shows which tools are installed and offers to install
  missing ones.
- **Root helper** — all privileged operations go through a small
  `wifi-lab-priv` helper invoked via `sudo`, so the GUI itself never runs as
  root.

---

## Requirements

- **Linux** with a wireless adapter that supports **monitor mode** (e.g. an
  Atheros/Realtek USB dongle; many built-in Intel cards do not).
- **Python 3.10+** and **PyQt6** (`sudo apt install python3-pyqt6`).
- Tools (installed automatically or via the app's Tools tab):
  - `aircrack-ng` suite -> `aircrack-ng` package (`airodump-ng`, `aireplay-ng`,
    `aircrack-ng`, `airmon-ng`)
  - `reaver` -> `reaver` package
  - `iw`, `nmcli` (usually present)
- `sudo` configured to run `wifi-lab-priv` without a password prompt.

---

## Install

```bash
sudo ./install.sh          # installs helper, icon, desktop entry, launcher
wifi-lab                   # launch from the menu or terminal
```

To run straight from the repo without installing:

```bash
./run.sh
```

---

## First run

1. Open **File → Settings** and set your **wireless interface** (e.g. `wlan0`),
   then click **Scan**.
2. Click a network row to select it as the **target** (or use
   **Network → Set as target**).
3. Choose an action:
   - **Capture handshake** — captures the 4-way handshake to
     `~/.local/share/wifi-lab/captures/`.
   - **WPS Pixie Dust / Reaver (PIN)** — run `reaver` against the AP (only if
     it advertises WPS).
   - **Deauth** — knock clients off to force a reconnection (useful before
     handshake capture).
   - **Crack capture** — select a `.cap`/`.pcap` and a wordlist to recover the
     passphrase offline.
4. The **Log** tab shows live tool output; use **Stop** to cancel a running
   attack.

> **Note on monitor mode:** the helper puts your adapter into monitor mode for
> attacks and restores it to managed mode when done. If your adapter does not
> support monitor mode, attacks will fail with a clear message.

---

## Configuration

Stored at `~/.local/share/wifi-lab/config.json`:

| Key               | Meaning                                  | Default |
|-------------------|------------------------------------------|---------|
| `interface`       | wireless interface to use                | `wlan0` |
| `target_ssid`     | default target SSID (highlighted in scan)| `""`    |
| `target_bssid`    | default target BSSID                     | `""`    |
| `wordlist`        | path to wordlist for cracking            | `/usr/share/wordlists/rockyou.txt` |
| `capture_timeout` | seconds to wait for a handshake          | `120`   |
| `reaver_timeout`  | seconds to run reaver before giving up   | `600`   |

---

## How it works

```
+----------------+     sudo     +------------------+     monitor mode
|  WiFi Lab GUI  | -----------> | wifi-lab-priv    | --> airodump-ng
|  (PyQt6, user) |  helper call | (root helper)    | --> aireplay-ng
+----------------+              +------------------+ --> reaver / aircrack-ng
```

- **Scanning** runs as the normal user via `nmcli` + `iw`.
- **Attacks** run as root through `wifi-lab-priv` (whitelisted tools only).
- Capture files land in `~/.local/share/wifi-lab/captures/`.

---

## Troubleshooting

- **Colom WPS kosong** — status WPS dibaca lewat `iw scan` sebagai root. Jika
  helper belum diotorisasi sudo, kolom WPS tetap kosong (lihat label
  `helper:`/`sudo:` di pojok kanan atas). Perbaiki dengan:
  ```bash
  sudo ./install.sh      # pasang helper + atur sudo NOPASSWD otomatis
  ```
  Lalu mulai ulang aplikasi dan klik **Scan**.
- **"sudo: a password is required"** — jalankan `sudo ./install.sh`. Installer
  membuat `/etc/sudoers.d/wifi-lab-gui` untuk user pemanggil. Bila ada helper
  lama di `/usr/local/sbin` (dari setup Flask), aplikasi otomatis memakai jalur
  yang sudah diotorisasi; menjalankan `install.sh` terbaru lebih disarankan.
- **No networks found** — make sure the interface is up and NetworkManager is
  managing it (`nmcli radio wifi on`).
- **Handshake not captured** — the target may be idle (no clients). Run
  **Deauth** first, or verify the channel is correct.
- **Reaver "no beacon"** — the AP may be on a different channel or have WPS
  locked/disabled. Re-scan and confirm WPS shows `yes (open)`.
- **WiFi tertinggal `Soft blocked: yes` setelah klik Stop** — versi lama helper
  mematikan seluruh radio (`nmcli radio wifi off`) dan bisa terbunuh sebelum
  menyalakannya lagi. Perbaikan ada di helper terbaru; pasang ulang dengan
  `sudo ./install.sh`. Untuk memulihkan sesi yang sedang bermasalah:
  ```bash
  sudo rfkill unblock wifi
  sudo nmcli radio wifi on
  ```
  Helper baru tidak pernah mematikan radio; Stop hanya melepas interface,
  menghentikan tool, lalu mengembalikan managed mode + menyambungkan kembali
  profil WiFi yang tadi aktif.

### Passwordless sudo for the helper

`sudo ./install.sh` menulis aturan ini secara otomatis dan memvalidasinya dengan
`visudo`:

```
youruser ALL=(root) NOPASSWD: /usr/local/bin/wifi-lab-priv
```

File: `/etc/sudoers.d/wifi-lab-gui` (mode `0440`).
