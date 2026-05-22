import socket
import threading
import getpass
import struct
import hashlib
import time
import warnings
import os
import gc
from pgpy import PGPKey, PGPMessage, PGPUID
from pgpy.constants import PubKeyAlgorithm, KeyFlags, SymmetricKeyAlgorithm, HashAlgorithm

SERVER_IP = "127.0.0.1"
PORT = 34567

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEYS_DIR = os.path.join(BASE_DIR, "trusted_keys")

warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=UserWarning)


client_private_key = None
client_public_key_pem = None

clients_public_keys = {}

keys_received_event = threading.Event()
waiting_for_recipient = None



def recv_exact(sock, num_bytes):
    buf = b''
    while len(buf) < num_bytes:
        chunk = sock.recv(num_bytes - len(buf))
        if not chunk:
            return False
        buf += chunk
    return buf

def recv_msg(sock):
    length = recv_exact(sock, 4)
    if not length:
        return False
    data_length = struct.unpack("!I", length)[0]
    data = recv_exact(sock, data_length)
    if not data:
        return False
    return data.decode()

def secure_send(sock, data):
    encode_data = data.encode()
    header = struct.pack("!I", len(encode_data))
    sock.sendall(header+encode_data)



stop = False  # When True, both loops should end.


def save_public_key_to_disk(client_name, pgp_key_object):
    if not os.path.exists(KEYS_DIR):
        os.makedirs(KEYS_DIR)
    file_path = os.path.join(KEYS_DIR, f"{client_name}.asc")
    with open(file_path, "w") as f:
        f.write(str(pgp_key_object))

def load_public_key_from_disk():
    global clients_public_keys
    if os.path.exists(KEYS_DIR):
        for filename in os.listdir(KEYS_DIR):
            if filename.endswith(".asc"):
                client_name = filename[:-4]
                file_path = os.path.join(KEYS_DIR, filename)
                try:
                    with open(file_path, "r") as f:
                        key_data = f.read()
                        key_object, _ = PGPKey.from_blob(key_data)
                        clients_public_keys[client_name] = key_object
                except Exception as e:
                    print(f"[SYSTEM] Failed to load public key from {file_path}: {e}")

def receive_messages():
    global stop
    while not stop:
        try:
            msg = recv_msg(client_socket)
            if not msg:
                break
            if msg.startswith("PUBKEY_EXCHANGE:"):
                _, client_name, key_data = msg.split(":", 2)
                client_pub, _ = PGPKey.from_blob(key_data)
                if client_name in clients_public_keys:
                    existing_client_public_key = clients_public_keys[client_name]
                    if existing_client_public_key.fingerprint != client_pub.fingerprint:
                        print(f"\n [CLIENT] Critical ERROR, Public KEY is resend as a new value by the server for {client_name} ")
                        if waiting_for_recipient==client_name:
                            keys_received_event.set()
                        continue

                clients_public_keys[client_name] = client_pub
                save_public_key_to_disk(client_name, client_pub)

                print(f"\n[SYSTEM] Received trusted public key for: {client_name}")
                print("[CLIENT] Press Enter to finish sending your message...")

                if waiting_for_recipient == client_name:
                    keys_received_event.set()

            elif msg.startswith("MSG_FROM:"):
                _, sender_name, pgp_blob = msg.split(":", 2)
                try:
                    signedPackage = PGPMessage.from_blob(pgp_blob)


                    if sender_name not in clients_public_keys:
                        print(f"[SYSTEM] New sender {sender_name} detected, requesting PGP public key...")
                        secure_send(client_socket, f"GET_KEY:{sender_name}")


                    signature_verified = False

                    if sender_name in clients_public_keys:
                        try:
                            clients_public_keys[sender_name].verify(signedPackage)
                            signature_verified = True
                        except Exception:
                            signature_verified = False
                    inner_encrypted_msg = PGPMessage.from_blob(signedPackage.message)
                    decrypted = client_private_key.decrypt(inner_encrypted_msg)

                    if signature_verified:
                        print(f"\n[SYSTEM] Received trusted private message from: <{sender_name}> -> {decrypted.message}")
                    else:
                        print(f"[SYSTEM WARNING] Received new message but Signature Unverified. {sender_name} -> {decrypted.message}")
                except Exception as e:
                    print(f"\n[SYSTEM] Failed to decrypt message due to error: {e}")
            else:
                print(f"\n[SERVER] {msg}")

                if msg.strip().lower() == "terminate":
                    print("[CLIENT] Server ended the chat.")
                    stop = True
                    break
        except OSError:
            break

load_public_key_from_disk()
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((SERVER_IP, PORT))
print("[CLIENT] Connected to server.")
# Start receiver thread so client can receive while also typing messages.
threading.Thread(target=receive_messages, daemon=True).start()

print("[CLIENT] Type messages. Type 'terminate' to end. Type 'identifier' to enter/create the user account. Type 'message' to write message. Type 'online users list' to view all online users")

# Main thread is used for sending messages typed by the client user.
while not stop:

    if client_private_key is None:
        text = input("[CLIENT] ")
        if not text.strip():
            continue
        if text.lower() != "message":
            secure_send(client_socket, text)

        if text.strip().lower() == "terminate":
            stop = True
            break

        elif text.strip().lower() == "identifier":
            identifier = input("ENTER [CLIENT] IDENTIFIER ")
            secure_send(client_socket, identifier)

            password = getpass.getpass('[CLIENT] ENTER IDENTIFIER PASSWORD: ')
            salt = f"secure_hash_salt_{identifier}"
            password_hash = hashlib.sha512((password + salt).encode()).hexdigest()
            secure_send(client_socket, password_hash)

            private_key_file = os.path.join(BASE_DIR, f"{identifier}_private.asc")
            if os.path.exists(private_key_file):
                print(f"[CLIENT] Loading existing PGP key from disk")
                try:
                    loaded_key, _ = PGPKey.from_file(private_key_file)
                    client_private_key = loaded_key
                    client_public_key_pem = str(client_private_key.pubkey)
                except Exception as e:
                    print(f"[CLIENT] Failed to unlock key from disk, Wrong password. Error: {e}")
                    client_private_key = None
                    continue
            else:
                print("[CLIENT] GENERATING PGP KEY PAIR.")
                uid = PGPUID.new(identifier, email=f'{identifier}@secure.chat.local')
                client_private_key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 3072)
                client_private_key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications})
                client_private_key.protect(password, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
                with open(private_key_file, "w") as f:
                    f.write(str(client_private_key))

                client_public_key_pem = str(client_private_key.pubkey)
                print(f"[CLIENT] PGP Key Generated and stored encrypted on your local disk Successfully.")
            secure_send(client_socket, f"CLIENT_KEY:{client_public_key_pem}")
            print(f"[SYSTEM] PGP Key bound to '{identifier}' and shared with server.")

    elif client_private_key.is_protected:
        print(f"[CLIENT] Activating Secure session with unlocked key")
        with client_private_key.unlock(password):
            del password
            gc.collect()
            while not stop:
                text = input("[CLIENT] ")
                if not text.strip():
                    continue
                if text.lower() != "message":
                    secure_send(client_socket, text)

                if text.strip().lower() == "terminate":
                    stop = True
                    break
                elif text.strip().lower() == "message":

                    recipient = input("ENTER [RECIPIENT] IDENTIFIER ")

                    if recipient not in clients_public_keys:
                        print(f"[ERROR]  KEY for '{recipient}' is not received yet. Sending querry to the server.")
                        waiting_for_recipient = recipient
                        keys_received_event.clear()
                        secure_send(client_socket, f"GET_KEY:{recipient}")
                        print(f"[SYSTEM] System waiting for the key from the server. Up to 5 seconds.")
                        key_received = keys_received_event.wait(5.0)
                        waiting_for_recipient = None

                        if not key_received or recipient not in clients_public_keys:
                            print(
                                f"[ERROR] Cannot receive message, key for '{recipient}' is not received yet. User might be offline.")
                            continue

                    message = input("ENTER MESSAGE ")

                    pgp_message = PGPMessage.new(message)
                    recipient_key = clients_public_keys[recipient]
                    encrypted_msg = recipient_key.encrypt(pgp_message)
                    encrypted_str = str(encrypted_msg)

                    signedPackage = PGPMessage.new(encrypted_str)
                    signedPackage |= client_private_key.sign(signedPackage)

                    secure_send(client_socket, "message")
                    secure_send(client_socket, recipient)
                    secure_send(client_socket, str(signedPackage))
                    print(f"[SYSTEM] PGP Message sent successfully.")
                elif text.strip().lower() == "online users list":
                    continue


client_socket.close()
print("[CLIENT] Chat ended.")
