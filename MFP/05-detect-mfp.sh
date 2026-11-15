#!/bin/bash
# airodump-ng does not expose MFP flags (its columns are ENC/CIPHER/AUTH).
# Read the RSN Capabilities bits directly with iw (run the scan on the
# managed interface, not the monitor interface, which cannot scan):
# Ganti "CorpWiFi" dengan SSID target Anda.
sudo iw dev wlan0 scan | grep -A 15 "CorpWiFi" | grep -i "pmf|mfp|capabilities"

# Wireshark filter — check RSN capabilities field
# Bit 6 = MFPC (capable), Bit 7 = MFPR (required)
tshark -i wlan0mon -Y "wlan.fc.type_subtype == 0x08" \
  -T fields -e wlan.ssid -e wlan.rsn.capabilities.mfpc -e wlan.rsn.capabilities.mfpr
