#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <errno.h>


/* Receive UDP packets using C

    Author: Tim Pierson, Dartmouth CS60, Fall 2025
        Adapted from Du: Computer and Internet Security 

    compile gcc receive_udp.c -o receive_udp
    run: ./receive_upd
    
    send data from netcat in another terminal
    nc -u 127.0.0.1 9090

*/

const int MAX_SIZE = 1500;
const int port = 9090;

int main() {
    struct sockaddr_in server;
    struct sockaddr_in client;
    unsigned int clientlen;
    char buf[MAX_SIZE];
    char ip[INET_ADDRSTRLEN];
    

    // Create the socket
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); 
    memset((char *) &server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(port);

    if (bind(sock, (struct sockaddr *) &server, sizeof(server)) < 0) {
        printf ("Binding error!");
        return(EXIT_FAILURE);
    }

    // Getting captured packets
    while (1) {
        bzero(buf,MAX_SIZE);
        recvfrom(sock, buf, MAX_SIZE-1, 0, (struct sockaddr *) &client, &clientlen);
        //get ip address
        inet_ntop(AF_INET, &(client.sin_addr), ip, INET_ADDRSTRLEN);
        printf("%s:%i %s\n",ip, client.sin_port,buf);
        
    }

    close(sock);
    return(EXIT_SUCCESS);
}
