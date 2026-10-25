# Wi-Fi Audit Lab (Kali Linux)

Dashboard lokal bergaya toolkit audit Wi-Fi. Ini adalah implementasi mandiri, bukan salinan identik atau kode resmi StrykerOSS.

## Fitur
- Menampilkan interface Wi-Fi yang dilaporkan `iw`.
- Pemindaian jaringan sekitar melalui `nmcli`/NetworkManager (scan standar).
- Status ketersediaan alat audit.
- Analisis metadata file `.cap`, `.pcap`, dan `.pcapng` yang Anda tempatkan di `captures/`.
- Dashboard hanya bind ke `127.0.0.1`.

## Instalasi
```bash
chmod +x install.sh run.sh
./install.sh
```

## Jalankan
```bash
./run.sh
```
Buka `http://127.0.0.1:5055` pada browser di komputer Kali yang sama.

## Persiapan pemindaian
1. Periksa perangkat: `iw dev`
2. Pastikan NetworkManager aktif: `systemctl status NetworkManager`
3. Jika menggunakan adaptor USB, pastikan chipset dan driver Linux mendukungnya.
4. Pilih interface pada dashboard lalu klik **Scan Wi-Fi**.

Pemindaian standar memakai NetworkManager. Tidak memaksa monitor mode, tidak mengirim deauthentication, tidak menginjeksi frame, tidak mencoba PIN WPS, dan tidak melakukan cracking kata sandi.

## Analisis capture
Salin file capture dari audit yang sah ke folder `captures/`, lalu muat ulang dashboard. Pilih file dan klik **Analyze capture**. Hasilnya adalah metadata/diagnostik dasar, bukan jaminan bahwa suatu handshake lengkap atau password dapat ditemukan.

## Troubleshooting
- Tidak ada interface: `iw dev` dan `ip link`
- Tidak ada hasil scan: `nmcli radio wifi`, `systemctl restart NetworkManager`
- Adapter tidak mendukung fitur monitor: cek chipset, driver, kernel dan dokumentasi vendor.
- Port sudah dipakai: ubah port di baris `app.run(...)` pada `app.py`.

Gunakan hanya pada jaringan/perangkat milik sendiri atau yang Anda punya izin tertulis untuk mengujinya.
