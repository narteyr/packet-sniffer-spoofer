
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>

/* Send a UDP packet using C

	Author: Tim Pierson, Dartmouth CS60, Fall 2025
		From Du: Computer and Internet Security 

	compile gcc send_udp.c -o send_udp
	run: ./send_upd
	
	set up netcat to listen for packet before sending
	nc -luv 9090

*/

int main() {
	struct sockaddr_in dest_info;
	char *dest_addr = "127.0.0.1";
	int port = 9090;
	char *data = "Hello World (in C!)\n";

	//Create network socket
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	//Provide needed data
	memset((char *) &dest_info,0,sizeof(dest_info));
	dest_info.sin_family = AF_INET;
	dest_info.sin_addr.s_addr = inet_addr(dest_addr);
	dest_info.sin_port = htons(port);

	//send packet and close
	sendto(sock, data, strlen(data), 0, (struct sockaddr *) &dest_info, sizeof(dest_info));
	close(sock); 
}