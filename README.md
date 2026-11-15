# Wi-Fi Audit Lab (Kali Linux)

Dashboard lokal bergaya toolkit audit Wi-Fi. Ini adalah implementasi mandiri, bukan salinan identik atau kode resmi StrykerOSS.

## Fitur
- Menampilkan interface Wi-Fi yang dilaporkan `iw`.
- Pemindaian jaringan sekitar melalui `nmcli`/NetworkManager (scan standar).
- Tabel hasil scan dengan pencarian, filter keamanan, sorting sinyal, dan status WPS (ON/OFF) dari elemen WPS pada beacon.
- Halaman detail per SSID: profil target, status tool, dan modul audit WPS/WPA.
- **Info ISP & Router** di halaman detail: deteksi ISP, model router, alamat login, dan referensi kredensial default — bisa dijalankan tanpa harus terhubung ke Wi-Fi target, dengan label cakupan data yang jelas.
- **Live terminal** untuk setiap proses (WPS, capture, deauth, PSK brute, instalasi tool) dengan stream output, stop, copy, dan download log.
- **Pemulihan Wi-Fi** di dashboard: kembalikan interface yang tertinggal di monitor mode ke managed mode dan sambungkan ulang ke jaringan tersimpan.
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

Host/port bisa diubah lewat environment variable (default tetap localhost):
```bash
WIFI_LAB_HOST=0.0.0.0 WIFI_LAB_PORT=5055 ./run.sh
```
Membuka ke `0.0.0.0` berarti panel yang bisa menjalankan tool root dapat diakses dari jaringan. Batasi dengan firewall dan hanya lakukan di lab tepercaya.

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

Jika Wi-Fi tetap mati karena proses sebelumnya terhenti paksa, buka menu **Pemulihan** di dashboard, pilih interface, lalu klik **Pulihkan Wi-Fi**. Panel ini akan:
- membuka blokir `rfkill`,
- mengembalikan interface monitor ke `managed` (termasuk `wlan0mon` lewat `airmon-ng` bila tersedia),
- mengaktifkan radio Wi-Fi dan menyambungkan kembali NetworkManager ke jaringan tersimpan,
- me-restart NetworkManager bila interface masih belum tersambung.

Setelah memperbarui kode helper, jalankan sekali `sudo ./setup_privileges.sh` agar aksi `restore` tersedia di `/usr/local/sbin/wifi-lab-priv`. Alternatif langsung dari terminal:

```bash
sudo iw dev wlan0mon set type managed   # atau: sudo airmon-ng stop wlan0mon
sudo ip link set wlan0 up
sudo nmcli radio wifi on
sudo nmcli device connect wlan0
```

Script MFP juga menyediakan opsi **r. Pulihkan Wi-Fi (matikan monitor mode)** pada menu `MFP/jalankan-semua.sh`, atau non-interaktif dengan:

```bash
sudo ./MFP/jalankan-semua.sh --restore-wifi
```

Target AP tidak lagi di-hardcode. Saat pertama dijalankan, pilih menu **a. Scan & pilih Router AP**; script memindai AP sekitar (via `iw`, fallback `nmcli`) lalu menampilkan BSSID, SSID, channel, sinyal, dan keamanan. Tinggal masukkan nomor AP. Jika AP tidak muncul, pilih `0` untuk memasukkan BSSID manual.

## Persiapan pemindaian
1. Periksa perangkat: `iw dev`
2. Pastikan NetworkManager aktif: `systemctl status NetworkManager`
3. Jika menggunakan adaptor USB, pastikan chipset dan driver Linux mendukungnya.
4. Pilih interface pada dashboard lalu klik **Scan Wi-Fi**.

Pemindaian standar memakai NetworkManager. Modul audit WPS/WPA tersedia di halaman detail SSID dan hanya berjalan setelah konfirmasi eksplisit. Setiap modul membuka terminal live; hentikan proses dengan tombol **Stop** bila diperlukan.

## Live terminal
Semua proses panjang dijalankan di background dan di-stream ke halaman `/terminal/<session>`. Output dapat di-copy atau diunduh sebagai file `.log`. Sesi selesai disimpan sekitar 7 hari (selama server berjalan).

Job **tidak memiliki batas waktu buatan**. Proses WPS brute, capture, deauth, PSK brute, dan instalasi berjalan sampai tool selesai atau Anda menekan **Stop**. Sebelumnya job dipotong otomatis pada 30–1800 detik; batas itu dihapus karena membuat proses yang normal di terminal terlihat gagal di web.

Output tool dialirkan melalui pseudo-TTY (PTY), jadi reaver/airodump/aircrack langsung menulis baris ke terminal seperti saat dijalankan di shell — tidak lagi menunggu buffer penuh. Capture handshake memakai durasi 60 detik yang berhenti rapi dan **dianggap sukses**, bukan timeout.

Jika tombol Run sebelumnya selalu berakhir TIMEOUT, restart server setelah memperbarui kode (`./run.sh`) agar job engine baru dipakai.

## Analisis capture
Salin file capture dari audit yang sah ke folder `captures/`, lalu muat ulang dashboard. Pilih file dan klik **Analyze capture**. Hasilnya adalah metadata/diagnostik dasar, bukan jaminan bahwa suatu handshake lengkap atau password dapat ditemukan.

## Info ISP & Router
Pada halaman detail SSID, panel **ISP & Router info** menjalankan deteksi tanpa harus terhubung ke jaringan target terlebih dahulu. Jika terhubung ke target, data diambil dari jaringan tersebut; jika terhubung ke jaringan lain atau tidak ada koneksi, panel tetap menampilkan informasi yang tersedia dengan peringatan cakupan. Data yang dikumpulkan:
- ISP, ASN, IP publik, dan lokasi — lookup `ipinfo.io`, fallback ke `ifconfig.co`.
- IP lokal, gateway, DNS, dan MAC gateway.
- Brand/model router dari OUI MAC gateway, UPnP SSDP, serta fingerprint halaman login (judul/server/form).
- URL login admin, IP gateway, dan referensi username/password default pabrik.

Catatan:
- Lookup ISP mengirim IP publik ke layanan pihak ketiga. Jalankan hanya pada jaringan yang Anda berwenang audit.
- Kredensial router adalah **referensi default pabrik**, bukan hasil pembacaan password dari perangkat. Aplikasi tidak melakukan login otomatis atau brute force terhadap halaman admin.
- Pada ONT/router ISP, kredensial asli biasanya tercetak di stiker perangkat.
- Jika belum terhubung ke Wi-Fi target, panel tetap menampilkan brand target dari OUI BSSID dan kredensial default pabrik; IP publik, ISP, gateway, dan login router hanya tersedia jika ada koneksi Wi-Fi aktif (dari jaringan target atau jaringan lain yang sedang digunakan).

## Troubleshooting
- **Kolom WPS menampilkan “— ”**: helper root belum versi terbaru atau scan `iw` gagal. Jalankan `sudo ./setup_privileges.sh` lalu restart `./run.sh` dan scan ulang. Status WPS dibaca dari IE beacon, jadi AP yang tidak mengiklankan WPS akan tampil **OFF**.
- **Banner “Modul audit belum aktif”**: jalankan `sudo ./setup_privileges.sh`, lalu restart `./run.sh`.
- **Menu Pemulihan gagal dengan “aksi tidak dikenal: restore”**: helper root masih versi lama. Jalankan `sudo ./setup_privileges.sh` lalu restart `./run.sh` (`run.sh` juga mendeteksi helper yang lebih lama dari sumbernya).
- **Info ISP menampilkan data dari jaringan lain atau tidak tersedia**: hasil diikuti koneksi Wi-Fi aktif saat ini. Untuk data akurat target, sambungkan ke Wi-Fi target lalu klik **Run info** lagi.
- **Router tidak terdeteksi**: sebagian router memblokir UPnP/probe HTTP lokal. Panel tetap menampilkan gateway dan referensi kredensial generik.
- **Run langsung berhenti / status TIMEOUT**: pastikan server sudah di-restart dengan kode terbaru. Job sekarang tidak punya batas waktu; status TIMEOUT hanya muncul jika `timeout` eksplisit diberikan (saat ini tidak ada modul yang memakainya).
- **Run terlihat menggantung tanpa output**: terminal memakai PTY sehingga output muncul real-time. Jika tool memang tidak menulis apa pun, cek baris `$ …` dan pesan `[priv]` di terminal; tekan **Stop** untuk menghentikan dan memulihkan interface.
- **Tool keluar dengan kode non-zero**: itu adalah hasil tool (mis. reaver tidak menemukan WPS/handshake), bukan kegagalan web. Baca baris terakhir terminal sebelum `[exit]`.
- **Monitor mode gagal di tengah job**: tunggu beberapa detik setelah job selesai; helper mengembalikan managed mode dan menghubungkan ulang Wi-Fi secara otomatis.
- **Cek helper root**: `sudo -n /usr/local/sbin/wifi-lab-priv check` harus menampilkan `wifi-lab-priv ok (uid=0)`.
- **Sudo masih minta password**: pastikan file `/etc/sudoers.d/wifi-lab` ada dan user Anda cocok. Periksa dengan `sudo -l`.
- **Monitor mode gagal**: cek dukungan adaptor dengan `iw list | grep -A8 "Supported interface modes"`. Jika adaptor tidak mendukung, modul capture/deauth tidak bisa dipakai.
- **Interface tidak kembali managed**: ikuti perintah pemulihan yang dicetak di terminal, atau `sudo ip link set <iface> down; sudo iw dev <iface> set type managed; sudo ip link set <iface> up; sudo nmcli device set <iface> managed yes`.
- Tidak ada interface: `iw dev` dan `ip link`
- Tidak ada hasil scan: `nmcli radio wifi`, `systemctl restart NetworkManager`
- Adapter tidak mendukung fitur monitor: cek chipset, driver, kernel dan dokumentasi vendor.
- Port sudah dipakai: ubah port di baris `app.run(...)` pada `app.py`.

Gunakan hanya pada jaringan/perangkat milik sendiri atau yang Anda punya izin tertulis untuk mengujinya.
