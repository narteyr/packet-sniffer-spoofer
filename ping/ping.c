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

// This struct is a great idea to keep socket info organized.
typedef struct {
    int family;
    int socktype;
    int protocol;
    socklen_t addrlen;
    struct sockaddr_storage addr; // sockaddr_storage can hold both IPv4 and IPv6
} SocketAddress;

unsigned short calculate_checksum(void *b, int len);
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
    for (int sequence_number = 1; sequence_number < 100; sequence_number++) {
        memset(packet, 0, sizeof(packet));

        // ICMP header is at the start of the buffer
        struct icmp *icmp_hdr = (struct icmp *)packet;

        // Payload will carry the send timestamp
        struct timeval *payload = (struct timeval *)(packet + ICMP_HDRLEN);

        // Fill ICMP header
        icmp_hdr->icmp_type = ICMP_ECHO;   // 8
        icmp_hdr->icmp_code = 0;
        icmp_hdr->icmp_id   = getpid() & 0xFFFF;
        icmp_hdr->icmp_seq  = sequence_number;

        // Put the send time in the payload BEFORE computing checksum
        gettimeofday(payload, NULL);

        // Compute checksum over header + payload actually used
        size_t icmp_len = ICMP_HDRLEN + sizeof(struct timeval);
        icmp_hdr->icmp_cksum = 0;
        icmp_hdr->icmp_cksum = calculate_checksum(icmp_hdr, (int)icmp_len);

        // Send packet to resolved address
        ssize_t sent = sendto(sock, packet, icmp_len, 0,
                            (struct sockaddr *)&resolved_addr.addr, resolved_addr.addrlen);
        if (sent < 0) {
            perror("sendto");
            close(sock);
            return EXIT_FAILURE;
        }

        // Wait for the matching echo reply for this sequence (or timeout)
        char recvbuf[1500];
        struct sockaddr_storage src;
        socklen_t srclen;
        int got_reply = 0;

        for (;;) {
            fd_set rfds; FD_ZERO(&rfds); FD_SET(sock, &rfds);
            struct timeval tv; tv.tv_sec = 1; tv.tv_usec = 0;  // 1s per-echo timeout

            int r = select(sock + 1, &rfds, NULL, NULL, &tv);
            if (r < 0) {
                perror("select");
                close(sock);
                return EXIT_FAILURE;
            }
            if (r == 0) {
                // timed out waiting for this sequence
                printf("Request timeout for icmp_seq=%d\n", sequence_number);
                break;
            }

            srclen = sizeof(src);
            ssize_t n = recvfrom(sock, recvbuf, sizeof(recvbuf), 0,
                                 (struct sockaddr *)&src, &srclen);
            if (n < 0) {
                perror("recvfrom");
                close(sock);
                return EXIT_FAILURE;
            }

            // Parse IP header to locate ICMP inside the received packet
            struct ip *ip_hdr = (struct ip *)recvbuf;
            int iphdr_len = ip_hdr->ip_hl << 2;  // ip_hl is in 32-bit words
            if (iphdr_len < (int)sizeof(struct ip) || iphdr_len > (int)n) {
                // malformed; ignore and keep waiting
                continue;
            }

            struct icmp *icmp_reply = (struct icmp *)(recvbuf + iphdr_len);

            if (icmp_reply->icmp_type == ICMP_ECHOREPLY &&
                icmp_reply->icmp_id == (getpid() & 0xFFFF)) {

                // If it's for a different seq (late/early), ignore and keep waiting
                if (icmp_reply->icmp_seq != sequence_number) {
                    continue;
                }

                struct timeval now;
                gettimeofday(&now, NULL);

                // Echoed payload holds the original send timestamp
                struct timeval *sent_time = (struct timeval *)((char *)icmp_reply + ICMP_HDRLEN);
                double rtt_ms = (now.tv_sec - sent_time->tv_sec) * 1000.0
                              + (now.tv_usec - sent_time->tv_usec) / 1000.0;

                char src_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &((struct sockaddr_in *)&src)->sin_addr, src_ip, sizeof(src_ip));
                int reply_ttl = ip_hdr->ip_ttl;
                printf("Reply from %s: icmp_seq=%d ttl=%d time=%.3f ms\n",
                       src_ip, icmp_reply->icmp_seq, reply_ttl, rtt_ms);

                got_reply = 1;
                break;
            }
        }
        
        sleep(1);
    }
    close(sock);
    return 0;
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