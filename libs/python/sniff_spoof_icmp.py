#!/usr/bin/python3
from scapy.all import *
import sys

''' 
  Create the appearance of a non-existent host on 10.0.2.15
  that replies to pings
  Listen for ICMP packets to 10.0.2.15 and reply with fake ICMP reply

	Author: Tim Pierson, Dartmouth CS60, Fall 2025
		Adapted from Du: Computer and Internet Security 
      from https://github.com/kevin-w-du/BookCode/blob/master/Sniffing_Spoofing/Scapy/sniff_spoof_icmp.py

	run: python3 scapy_spoof_sniff.py <interface>
        Use ifconfig to see interface (ens160 in my VM)   
'''



def spoof_pkt(pkt):
  #wait for ICMP requests
  if ICMP in pkt and pkt[ICMP].type == 8:
     #listen for ICMP request packets (type 8) 
     print("Original Packet.........")
     print("Source IP : ", pkt[IP].src)
     print("Destination IP :", pkt[IP].dst)

     #spoof a reply, even if the request wasn't for us
     #must reverse source and destination on reply!
     ip = IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl=pkt[IP].ihl)
     icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
     data = pkt[Raw].load
     newpkt = ip/icmp/data #make new packet

     print("Spoofed Packet.........")
     print("Source IP : ", newpkt[IP].src)
     print("Destination IP :", newpkt[IP].dst)

     send(newpkt,verbose=0) #send reply

if __name__ == "__main__":
  if len(sys.argv) != 2:
    print(f"Usage: sudo python3 {sys.argv[0]} <interface>")
    exit()
  print("Sniffing for ICMP pings addressed to 10.0.2.15")
  sniff(iface=sys.argv[1], filter='icmp and src host 10.0.2.15',prn=spoof_pkt) #icmp and src host 10.0.2.15