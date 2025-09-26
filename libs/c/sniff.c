#include <pcap.h>
#include <stdio.h>

/* Sniff frames using C and PCAP

    Author: Tim Pierson, Dartmouth CS60, Fall 2025
        From Du: Computer and Internet Security 

    compile gcc sniff.c -o sniff -lpcap
    run: sudo ./sniff

    NOTE: Will not run without sudo (no rights to interface)!
    
*/

void got_packet(u_char *args, const struct pcap_pkthdr *header,
        const u_char *packet) {
   printf("Got a packet\n");
}

int main() {
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "udp or icmp";
  bpf_u_int32 net;
  const int MAX_SIZE = 8192;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("enp0s3", MAX_SIZE, 1, 1000, errbuf);
  if (handle == NULL) {
    printf("Error on open\n");
    printf("errbuf %s\n",errbuf);
    return (1);
  }

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);             
  if (pcap_setfilter(handle, &fp) != 0) {
    printf("set filter error");
    return(1);
    }                               

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);                    

  pcap_close(handle);   //Close the handle
  return 0;
}
