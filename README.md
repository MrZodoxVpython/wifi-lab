# Wi-Fi Audit Lab (Kali Linux)

Dashboard lokal bergaya toolkit audit Wi-Fi. Ini adalah implementasi mandiri, bukan salinan identik atau kode resmi StrykerOSS.

## Fitur
- Menampilkan interface Wi-Fi yang dilaporkan `iw`.
- Pemindaian jaringan sekitar melalui `nmcli`/NetworkManager (scan standar).
- Tabel hasil scan dengan pencarian, filter keamanan, dan sorting sinyal.
- Halaman detail per SSID: profil target, status tool, dan modul audit WPS/WPA.
- **Live terminal** untuk setiap proses (WPS, capture, deauth, PSK brute, instalasi tool) dengan stream output, stop, copy, dan download log.
- Status ketersediaan alat audit.
- Analisis metadata file `.cap`, `.pcap`, dan `.pcapng` yang Anda tempatkan di `captures/`.
- Dashboard hanya bind ke `127.0.0.1`.

## Instalasi
```bash
chmod +x install.sh run.sh setup_privileges.sh
./install.sh
```
`install.sh` juga memasang helper root sekali saja. Jika proyek sudah terpasang sebelumnya, jalankan:
```bash
sudo ./setup_privileges.sh
```

## Jalankan
```bash
./run.sh
```
Buka `http://127.0.0.1:5055` pada browser di komputer Kali yang sama.

`run.sh` memeriksa helper root. Jika belum ada, ia menawarkan setup otomatis (meminta password sudo satu kali). Flask tetap berjalan sebagai user biasa; hanya tool audit yang dijalankan sebagai root melalui helper dengan daftar putih.

## Akses root dan monitor mode
Modul setelah halaman detail SSID (`reaver`, `airodump-ng`, `aireplay-ng`, `tshark`, `aircrack-ng`, serta instalasi paket) membutuhkan root. Anda punya dua pilihan:

1. **Cara yang disarankan** — jalankan `./run.sh`; helper root dipasang di `/usr/local/sbin/wifi-lab-priv` dan diizinkan lewat `/etc/sudoers.d/wifi-lab` (NOPASSWD, hanya untuk helper tersebut).
2. **Mode root langsung** — `sudo ./run.sh`. Aplikasi berjalan sebagai root dan langsung dapat menjalankan semua tool.

Saat modul WPS/capture/deauth dijalankan, helper otomatis:
- melepas interface dari NetworkManager (`nmcli device set … managed no`),
- mengubah interface ke monitor mode (`iw dev … set type monitor`),
- menyetel channel target,
- memverifikasi mode tersebut,
- menjalankan tool,
- mengembalikan interface ke managed mode setelah proses selesai/dihentikan.

Hasil handshake/PMK capture ditulis ke folder `captures/` agar langsung bisa dianalisis dari dashboard.

Jika adaptor tidak mendukung monitor mode, terminal menampilkan pesan yang jelas dan interface tetap dipulihkan.

## Persiapan pemindaian
1. Periksa perangkat: `iw dev`
2. Pastikan NetworkManager aktif: `systemctl status NetworkManager`
3. Jika menggunakan adaptor USB, pastikan chipset dan driver Linux mendukungnya.
4. Pilih interface pada dashboard lalu klik **Scan Wi-Fi**.

Pemindaian standar memakai NetworkManager. Modul audit WPS/WPA tersedia di halaman detail SSID dan hanya berjalan setelah konfirmasi eksplisit. Setiap modul membuka terminal live; hentikan proses dengan tombol **Stop** bila diperlukan.

## Live terminal
Semua proses panjang dijalankan di background dan di-stream ke halaman `/terminal/<session>`. Output dapat di-copy atau diunduh sebagai file `.log`. Sesi tetap tersedia selama server berjalan (kedaluwarsa setelah sekitar 2 jam).

## Analisis capture
Salin file capture dari audit yang sah ke folder `captures/`, lalu muat ulang dashboard. Pilih file dan klik **Analyze capture**. Hasilnya adalah metadata/diagnostik dasar, bukan jaminan bahwa suatu handshake lengkap atau password dapat ditemukan.

## Troubleshooting
- **Banner “Modul audit belum aktif”**: jalankan `sudo ./setup_privileges.sh`, lalu restart `./run.sh`.
- **Cek helper root**: `sudo -n /usr/local/sbin/wifi-lab-priv check` harus menampilkan `wifi-lab-priv ok (uid=0)`.
- **Sudo masih minta password**: pastikan file `/etc/sudoers.d/wifi-lab` ada dan user Anda cocok. Periksa dengan `sudo -l`.
- **Monitor mode gagal**: cek dukungan adaptor dengan `iw list | grep -A8 "Supported interface modes"`. Jika adaptor tidak mendukung, modul capture/deauth tidak bisa dipakai.
- **Interface tidak kembali managed**: ikuti perintah pemulihan yang dicetak di terminal, atau `sudo ip link set <iface> down; sudo iw dev <iface> set type managed; sudo ip link set <iface> up; sudo nmcli device set <iface> managed yes`.
- Tidak ada interface: `iw dev` dan `ip link`
- Tidak ada hasil scan: `nmcli radio wifi`, `systemctl restart NetworkManager`
- Adapter tidak mendukung fitur monitor: cek chipset, driver, kernel dan dokumentasi vendor.
- Port sudah dipakai: ubah port di baris `app.run(...)` pada `app.py`.

Gunakan hanya pada jaringan/perangkat milik sendiri atau yang Anda punya izin tertulis untuk mengujinya.
