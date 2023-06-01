import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 2222))


# the key range (0 - 0xff) cause it use "bl" register in operation 
s.send(b"\xa2")
print(s.recv(1024))