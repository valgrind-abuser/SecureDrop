
import socket

server_ip = 'localhost'
server_port = 8080

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((server_ip, server_port))

email = input("Enter your email to login/connect > ")
s.sendall(email.encode("utf-8"))

buff = s.recv(1024)
print(buff.decode("utf-8"))

s.close()
