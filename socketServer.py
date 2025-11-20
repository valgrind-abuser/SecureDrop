
import socket
import threading

connected_users = {} # email → (ip, port)

def handle_client(connection, address):
    try:
        buff = connection.recv(1024) # Larger buffer
        if buff:
            try:
                email = buff.decode("utf-8").strip()
                if email:
                    connected_users[email] = address
                    print(f"User '{email}' connected from {address}")
                    # Echo to confirm server got it
                    connection.sendall(f"Welcome, {email}!".encode("utf-8"))
            except Exception as e:
                print("Error decoding:", e)
        # Optionally: keep connection open, add more commands here
    except Exception as e:
        print(f"Client error: {e}")
    finally:
        connection.close()

def main():
    # Set up TCP socket server
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.bind(('localhost', 8080))
    serverSocket.listen(10)
    print("[Server] Listening on localhost:8080 ...")
    
    while True:
        connection, address = serverSocket.accept()
        # Handle each client in a new thread (so you can connect multiple clients)
        threading.Thread(target=handle_client, args=(connection, address), daemon=True).start()
        # You can print the current connected users
        print("Active users:", list(connected_users.keys()))

if __name__ == "__main__":
    main()
    
    
