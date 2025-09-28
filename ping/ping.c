/*
*
* Purpose: The 'ping.c' is used for making an echo
* request and recieving response from target address
* The functionalities are designed for the ping
* tool command
* @author Richmond Kwalah Nartey Tettey, Dartmouth CS60 Fall 2025
* date: 09.27.2025
*
* Usage: ./ping [<ipv4 address> | <domain name> ]
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>

#define PACKET_SIZE 64

// This struct is a great idea to keep socket info organized.
typedef struct {
    int family;
    int socktype;
    int protocol;
    socklen_t addrlen;
    struct sockaddr_storage addr; // sockaddr_storage can hold both IPv4 and IPv6
} SocketAddress;


void resolve_hostname(const char *hostname, char *ip_address, SocketAddress *result);

int main(int argc, char *argv[]) {
    // We expect two arguments: The program name and one input. This is correct.
    if (argc != 2) {
        fprintf(stderr, "usage: %s [<ipv4 address> | <domain name> ]\n", argv[0]);
        return EXIT_FAILURE;
    }
    const char *hostname = argv[1];
    char ip_address[INET6_ADDRSTRLEN];

    SocketAddress resolved_addr;

    resolve_hostname(hostname, ip_address, &resolved_addr);

    printf("Pinging %s [%s]\n", hostname, ip_address);

    int sock = socket(resolved_addr.family, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) {
        perror("socket");
        fprintf(stderr, "Error: Creating a raw socket often requires root privileges.\nTry running with 'sudo'.\n");
        return 1;
    }

    printf("Socket created successfully. Ready to build and send ICMP packet.\n");

    // --- YOUR NEXT STEPS GO HERE ---
    // 1. Create an ICMP echo request packet.
    // 2. Use sendto() to send it to the destination.
    // 3. Use recvfrom() to wait for the reply.
    // 4. Calculate the time difference.
    // 5. Close the socket.
    int sequence_number = 1;
    char packet[PACKET_SIZE];
    //first part of the buffer is the ICMP header
    struct icmp* icmp_hdr = (struct icmp*) packet;

    //rest of the buffer is for the payload
    struct timeval* payload = (struct timeval*) (packet + sizeof(struct icmp));

    icmp_hdr->icmp_type = 8;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_id = getpid();
    icmp_hdr->icmp_seq = sequence_number;
    icmp_hdr->icmp_cksum = 0;
    gettimeofday(payload, NULL);
    close(sock);
    return 0;
}


void resolve_hostname(const char *hostname, char *ip_address, SocketAddress *result) {
    struct addrinfo hints, *res, *p;
    int status;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC; // Allow IPv4 or IPv6
    hints.ai_socktype = SOCK_RAW;

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