import socket

connected_users = {}

# set up socket object for ipv4 and tcp stream
serverSocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
serverSocket.bind(('localhost', 8080))
serverSocket.listen(10) # max 10 connections

while True:
    connection, address = serverSocket.accept()
    buff = connection.recv(64)
    if len(buff) > 0:
        print(buff)
    
    