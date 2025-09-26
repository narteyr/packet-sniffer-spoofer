import socket

'''
Send UDP packet containing data to dest_addr on port 

Can listen for this packet with
    nc -luv 9090 
    (l = listen, u = udp, v = verbose)
    (9090 = port)

@author Tim Pierson, Dartmouth CS60, Fall 2025
    Adapted (or copied) from "Internet Security" by Wenliang Du
'''

dest_addr = "127.0.0.1"
port = 9090
msg = b'Hello world!' 

if __name__ == '__main__':
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(msg,(dest_addr,port))
    sock.close()
