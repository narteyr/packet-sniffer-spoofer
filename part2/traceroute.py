from scapy.all import *

if len(sys.argv) < 2:
  print("Requires 2 or more arguments")
  sys.exit(1)

destination = sys.argv[1]
ttl = sys.argv[2]

for ttl in range(1, int(ttl) + 1):

  packet = IP(dst=destination, ttl=ttl) / ICMP()

  response = sr1(packet, timeout=5, verbose=0)

  if not response:
    print("timeout ttl=" + str(ttl))
  else:
    response_ip = response.src
    if response_ip == destination:
      print("destination reached :)")
      break
    else:
      print("reached router: " + str(response_ip))
