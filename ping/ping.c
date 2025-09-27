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


void resolveHostName(const char * hostname, const void * addr);

int main(int argc, char *argv[]) {
    // if argc is not 2, then throw usage error, break
    //We expect two arguments: The program name: argv[0] and one input
    if (argc != 2) {
        fprintf(stderr, "usage: %s [<ipv4 address> | <domain name> ]\n", argv[0]);
        return EXIT_FAILURE;
    }
    const char* hostname = argv[1];
    const void* addr;
    resolveHostName(hostname, addr);
    return 0;
}


void resolveHostName(const char* hostname, const void* addr) {
    
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
    printf("IP address for %s:\n\n", hostname);
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
    printf(" %s: %s\n", ipver, ipstr);
    freeaddrinfo(res);
}