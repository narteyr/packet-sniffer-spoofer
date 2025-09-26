#!/usr/bin/python3
from scapy.all import *

''' Spoof packets using Python and scapy

    Author: Tim Pierson, Dartmouth CS60, Fall 2025
        Adapted from Du: Computer and Internet Security 

    run: sudo python3 udp_spoof.py

    NOTE: Will not run without sudo (no rights to interface)!
'''

print("SENDING SPOOFED UDP PACKET.........")
ip = IP(src="1.2.3.4", dst="10.0.2.5") # IP Layer
udp = UDP(sport=8888, dport=9090)       # UDP Layer
data = "Hello UDP!\n"                   # Payload
pkt = ip/udp/data      # Construct the complete packet
pkt.show()
send(pkt,verbose=0)
