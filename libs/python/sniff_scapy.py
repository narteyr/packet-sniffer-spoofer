from scapy.all import *
import sys

''' 
    Sniff 10 packets using Scapy

	Author: Tim Pierson, Dartmouth CS60, Fall 2025
		Adapted from Du: Computer and Internet Security 

	run: python3 scapy_sniff.py <interface>
        Use ifconfig to see interface (ens160 in my VM)

        Generate traffic on network to see if work, try ping 8.8.8.8
'''

def process_packet(pkt):
	global count	
	print('*'*40)
	print("Packet number",count)
	pkt.show()
	count += 1

if __name__ == '__main__':
	if len(sys.argv) != 2:
		print(f"Usage: sudo python3 {sys.argv[0]} <interface>")
		exit()
	count = 0
	pkt = sniff(iface=sys.argv[1], filter='icmp or udp', count=10, prn=process_packet)