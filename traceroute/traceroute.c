/*
*
*
* Purpose: The 'traceroute.c' is used for icmp request at different
* ttl to trace all the hops before its destination
* @author Richmond Kwalah Nartey Tettey, Dartmouth CS60 Fall 2025
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/select.h>
#include <unistd.h>

#define PACKET_SIZE 64
#define ICMP_HDRLEN 8  // bytes: type(1) + code(1) + cksum(2) + id(2) + seq(2)
#define MAX_HOPS 50

// This struct is a great idea to keep socket info organized.
typedef struct {
    int family;
    int socktype;
    int protocol;
    socklen_t addrlen;
    struct sockaddr_storage addr; // sockaddr_storage can hold both IPv4 and IPv6
} SocketAddress;


int main(int argc, char* argv[]) {
    if (argc != 2){
        fprintf(stderr, "usage: %s [<ip address> | <domain name>]\n",argv[0]);
    }

    const char* hostname = argv[1];
    char ip_address[INET6_ADDRSTRLEN];
    SocketAddress resolved_addr;
    resolve_hostname(hostname,ip_address, &resolved_addr);
    printf("Tracerouting %s %s\n", hostname, ip_address);


    if (resolved_addr.family != AF_INET) {
    fprintf(stderr, "IPv6 not supported in this version (ICMPv6 differs). Please use an IPv4 host/address.\n");
    return EXIT_FAILURE;
    }

    int sock = socket(resolved_addr.family, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        perror("socket");
        fprintf(stderr, "Error: Creating a raw socket often requires root privileges.\nTry running with 'sudo'.\n");
        return 1;
    }

    printf("Socket created successfully. Ready to build and send ICMP packet.\n");


    char packet[PACKET_SIZE];

    for(int ttl = 1; ttl < MAX_HOPS; ttl++) {
        if (setsocketopt(sock,IPPROTO_IP, IP_TTL, sizeof(ttl) < 0)){
           perror("setsocket ttl");
           break;
        }
        memset(packet, 0, sizeof(packet));
        struct icmp *icmp_hdr = (struct icmp*)packet;
        
        //payload carries the timestamp
        struct timeval *payload = (struct timeval *)(packet + ICMP_HDRLEN);
        
        // File ICMP header
        icmp_hdr->icmp_type = ICMP_ECHO;
        icmp_hdr->icmp_code = 0;
        icmp_hdr->icmp_id = getpid() & 0xFFFF;
        icmp_hdr->icmp_seq = ttl;

        gettimeofday(payload, NULL);

        //comput checksum over header
        size_t icmp_len = ICMP_HDRLEN + sizeof(struct timeval);
        icmp_hdr->icmp_cksum = 0;
        icmp_hdr->icmp_cksum = calculate_checksum(icmp_hdr, (int)icmp_len);
        
        ssize_t sent = sendto(sock, packet, icmp_len, 0,
                            (struct sockaddr *)&resolved_addr.addr, resolved_addr.addrlen);

        if (sent < 0) {
            perror("sendto");
            close(sock);
            return EXIT_FAILURE;
        }

        char recvbuf[1500];
        struct sockaddr_storage src;
        socklen_t srclen;
        int got_reply = 0;


    }
}





void resolve_hostname(const char *hostname, char *ip_address, SocketAddress *result) {
    struct addrinfo hints, *res, *p;
    int status;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; // Allow IPv4 or IPv6
    hints.ai_socktype = 0;  // don't filter by socktype; we only need an address

    if ((status = getaddrinfo(hostname, NULL, &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        exit(1);
    }

    // Loop through the results and use the first one we can.
    // This is a robust way to handle it. Your loop logic was fine.
    // This simplified version just takes the first result.
    p = res;
    void *addr;
    const char *ipver;

    if (p->ai_family == AF_INET) { // IPv4
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
        addr = &(ipv4->sin_addr);
        ipver = "IPv4";
    } else { // IPv6
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
        addr = &(ipv6->sin6_addr);
        ipver = "IPv6";
    }

    // Convert the IP to a string and store it
    inet_ntop(p->ai_family, addr, ip_address, INET6_ADDRSTRLEN);
    printf("Resolved to %s (%s)\n", ip_address, ipver);

    // Now that the pointer `result` is valid, we can safely write to it.
    result->family = p->ai_family;
    result->socktype = p->ai_socktype;
    result->protocol = p->ai_protocol;
    result->addrlen = p->ai_addrlen;
    memcpy(&result->addr, p->ai_addr, p->ai_addrlen);

    // Always free the linked list returned by getaddrinfo.
    freeaddrinfo(res);
}

unsigned short calculate_checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) {
        sum += *buf++;
    }
    if (len == 1) {
        sum += *(unsigned char*)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}