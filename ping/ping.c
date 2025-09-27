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
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>

typedef struct {
    int family;
    int socktype;
    int protocol; // 0 ir IPPROTO_TCP
    socklen_t addrlen;
    struct sockaddr_storage addr;
} SocketAddress;


void resolve_hostname(const char * hostname, char* ip_address, SocketAddress* result);

int main(int argc, char *argv[]) {
    // if argc is not 2, then throw usage error, break
    //We expect two arguments: The program name: argv[0] and one input
    if (argc != 2) {
        fprintf(stderr, "usage: %s [<ipv4 address> | <domain name> ]\n", argv[0]);
        return EXIT_FAILURE;
    }
    const char* hostname = argv[1];
    char ip_address[INET6_ADDRSTRLEN];
    SocketAddress* resolved_addr;
    resolve_hostname(hostname, ip_address, resolved_addr);    
    printf("final ip address: %s\n", ip_address);

    int sock = socket(resolved_addr->family, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) { perror("socket"); return 1;}


    struct sockaddr_in addr;
    addr.sin_family = resolved_addr->family;
    


    return 0;
}


void resolve_hostname(const char* hostname, char* ip_address, SocketAddress* result) {
    
    struct addrinfo hints, *res, *p;
    int status;
    const char *ipver;
    char ipstr[INET6_ADDRSTRLEN];
    memset(&hints, 0, sizeof(hints)); // set empty struct
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    if ((status = getaddrinfo(hostname, NULL, &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfor error: %s\n", gai_strerror(status));
        exit(1);
    }

    if (res == NULL) {
        fprintf(stderr, "Could not find any address for %s\n", hostname);
        freeaddrinfo(res);
        exit(1);
    }

    result->family = res->ai_family;
    result->socktype = res->ai_socktype;
    result->protocol = res->ai_protocol;
    result->addrlen = res-> ai_addrlen;
    memcpy(&result->addr, res->ai_addr, res->ai_addrlen);

    printf("IP address for %s:\n\n", hostname);
    void *addr;
    for (p = res; p != NULL; p = p->ai_next){
        if (p->ai_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
            ipver = "IPv4";
            break;
        } else { //IPV6
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
            ipver = "IPv6";
        }
    } 

    //Convert the IP to a string and print it
    inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
    strcpy(ip_address, ipstr);
    printf(" %s: %s\n", ipver, ipstr);
    freeaddrinfo(res);
}