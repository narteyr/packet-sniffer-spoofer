#!/usr/bin/python3

''' 
    Receive UDP packets using Python

	Author: Tim Pierson, Dartmouth CS60, Fall 2025
		Adapted from Du: Computer and Internet Security 

	run: python3 receive_upd.py
	
	send data from netcat in another terminal or computer (replace IP address)
	nc -u 127.0.0.1 9090
	then type messages
'''

import socket

MAX_SIZE = 1500 #max message size in bytes
ip_addr = "0.0.0.0" #0.0.0.0 means bind to all interfaces
port = 9090  #listen on this port

if __name__ == '__main__':
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.bind((ip_addr,port))

	while (True):
		msg, (ip, port) = sock.recvfrom(MAX_SIZE)
		print(f"{ip}:{port} {msg.decode('utf-8')}")
