

import socket
import threading
import getpass

SERVER_IP = "127.0.0.1"
PORT = 34567

# Create a TCP socket using IPv4 addressing.
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the server at (IP, port).
client_socket.connect((SERVER_IP, PORT))

print("[CLIENT] Connected to server.")


stop = False  # When True, both loops should end.

def receive_messages():
    global stop
    while not stop:
        try:
            data = client_socket.recv(1024)
            if not data:
                break


            msg = data.decode()
            print(f"\n[SERVER] {msg}")
        except OSError:
            break
        if msg.strip().lower() == "terminate":
            print("[CLIENT] Server ended the chat.")
            stop = True
            break

# Start receiver thread so client can receive while also typing messages.
threading.Thread(target=receive_messages, daemon=True).start()

print("[CLIENT] Type messages. Type 'terminate' to end. Type 'identifier' to enter/create the user account. Type 'message' to write message. Type 'online users list' to view all online users")

# Main thread is used for sending messages typed by the client user.
while not stop:
    text = input("[CLIENT] ")
    client_socket.sendall(text.encode())
    if text.strip().lower() == "terminate":
        stop = True
        break
    elif text.strip().lower() == "identifier":
        identifier = input("ENTER [CLIENT] IDENTIFIER ")
        client_socket.sendall(identifier.encode())
        password = getpass.getpass('[CLIENT] ENTER IDENTIFIER PASSWORD: ')
        client_socket.sendall(password.encode())
    elif text.strip().lower() == "message":
        identifier = input("ENTER [RECIPIENT] IDENTIFIER ")
        client_socket.sendall(identifier.encode())
        message = input("ENTER MESSAGE ")
        client_socket.sendall(message.encode())
    elif text.strip().lower() == "online users list":
        stop = False
        continue





client_socket.close()                       # Close the socket.
print("[CLIENT] Chat ended.")               # Confirm shutdown.
