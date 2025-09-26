import socket

''' 
    Demonstrate setting a time out

	Author: Tim Pierson, Dartmouth CS60, Fall 2025
		

	run: python3 settimeout.py
        should time out after 5 seconds if no response from server
'''

if __name__ == '__main__':

    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Set a timeout of 5 seconds for the socket operations
    sock.settimeout(5) 

    # Example usage (sending and receiving data with timeout)
    serverAddressPort = ("127.0.0.1", 9090)
    bytesToSend = str.encode("Hello UDP Server")

    try:
        sock.sendto(bytesToSend, serverAddressPort)
        msgFromServer, address = sock.recvfrom(1024)
        print(f"Message from server: {msgFromServer.decode()}")
    except socket.timeout:
        print("Socket operation timed out.")
    except socket.error as e:
        print(f"Socket error: {e}")
    finally:
        sock.close()