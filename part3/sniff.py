from scapy.all import *
import sys


def process_packet(pkt):
  if pkt.haslayer(Raw):
    payload = pkt[Raw].load
    ascii = payload.decode('ascii')
    printable_char = ascii[0]
    if printable_char:
        print("Telnet Keystroke: " + printable_char)

if __name__ == '__main__':
  if len(sys.argv) != 2:
    print("Must take 1 interface argument")
    exit()
  print("Listening for traffic...")
  sniff(iface=sys.argv[1], filter='tcp dst port 23', count=100, prn=process_packet)