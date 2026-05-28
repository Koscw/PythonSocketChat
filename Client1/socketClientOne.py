import socket
import threading
import getpass
import struct
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
os.system("")

BG_GREEN = "\033[42m"
BG_BLUE = "\033[44m"
RESET = "\033[0m"

warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=UserWarning)


client_private_key = None
client_public_key_pem = None
clients_public_keys = {}

keys_received_event = threading.Event()
waiting_for_recipient = None

auth_event = threading.Event()
auth_status = None
challenge_token = None
password = None

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
    time.sleep(0.05)



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
    global stop, auth_status, challenge_token, client_private_key, client_public_key_pem, password
    while not stop:
        try:
            msg = recv_msg(client_socket)
            if not msg:
                break
            if msg.startswith("[PGP AUTH CHALLENGE]"):
                _, challenge_token = msg.split("[PGP AUTH CHALLENGE] ", 1)
                challenge_token = challenge_token.strip()
                auth_status = "CHALLENGE"
                auth_event.set()
            elif msg == "NEW_ACCOUNT_REQUEST":
                auth_status = "NEW_ACCOUNT"
                auth_event.set()
            elif msg.startswith("PUBKEY_EXCHANGE:"):
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

                if waiting_for_recipient == client_name:
                    keys_received_event.set()

            elif msg.startswith("MSG_FROM:"):
                _, sender_name, pgp_blob = msg.split(":", 2)
                try:
                    signedPackage = PGPMessage.from_blob(pgp_blob)
                    with client_private_key.unlock(password):
                        decryptedPackage = client_private_key.decrypt(signedPackage)


                    if sender_name not in clients_public_keys:
                        print(f"[SYSTEM] New sender {sender_name} detected, requesting PGP public key...")
                        secure_send(client_socket, f"GET_KEY:{sender_name}")


                    signature_verified = False

                    if sender_name in clients_public_keys:
                        try:
                            clients_public_keys[sender_name].verify(decryptedPackage)
                            signature_verified = True
                        except Exception:
                            signature_verified = False

                    if signature_verified:
                        print(f"{BG_GREEN}\n[SYSTEM] Received trusted private message from: <{sender_name}> -> {decryptedPackage.message} {RESET}")
                    else:
                        print(f"{BG_BLUE}[SYSTEM WARNING] Received new message but Signature Unverified. {sender_name} -> {decryptedPackage.message} {RESET}")
                except Exception as e:
                    print(f"\n[SYSTEM] Failed to decrypt message due to error: {e}")
            elif msg == "identifier confirmed" or msg == "[SERVER] Identifier Confirmed":
                auth_status="SUCCESS"
                auth_event.set()
            elif msg == "Wrong Password":
                auth_status="FAILED"
                auth_event.set()
                stop = True
                break
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
        if text.lower() not in ["message","online users list", "identifier"]:
            secure_send(client_socket, text)

        if text.strip().lower() == "terminate":
            stop = True
            break

        elif text.strip().lower() == "identifier":


            identifier = input("ENTER [CLIENT] IDENTIFIER ").strip()
            if not identifier:
                continue
            password = getpass.getpass('[CLIENT] ENTER IDENTIFIER PASSWORD: ')





            secure_send(client_socket, "identifier")
            secure_send(client_socket, identifier)

            private_key_file = os.path.join(BASE_DIR, f"{identifier}_private.asc")

            if os.path.exists(private_key_file):
                print(f"[CLIENT] Loading existing PGP key from disk")
                try:
                    loaded_key, _ = PGPKey.from_file(private_key_file)
                    client_private_key = loaded_key
                    client_public_key_pem = str(client_private_key.pubkey)
                    is_new_account = False
                except Exception as e:
                    print(f"[CLIENT] Failed to unlock key from disk, Wrong password. Error: {e}")
                    client_private_key = None
                    password = None
                    gc.collect()
                    continue
            else:
                print(f"[CLIENT] Local PGP key not found. Generating new key...")
                is_new_account = True
            print(f"[SYSTEM] Waiting for server response...")
            auth_event.wait(5.0)

            if auth_status == "CHALLENGE":

                if is_new_account:
                    print(f"[ERROR] Server has a key, but you don't have it locally. Authentification denied.")
                    client_private_key = None
                    continue
                try:
                    challenge_msg = challenge_token.encode()
                    with client_private_key.unlock(password):
                        signature = client_private_key.sign(challenge_msg)

                    auth_event.clear()
                    secure_send(client_socket, str(signature))
                    auth_event.wait(5.0)
                except Exception as e:
                    print(f"[ERROR] Failed to sign challenge message: {e}")
                    auth_status = "FAILED"
                    secure_send(client_socket, "AUTH_CANCEL")
                    continue
            elif auth_status == "NEW_ACCOUNT":
                if not is_new_account:
                    print(f"[SYSTEM] You have local key. Server doesn't know you, registering ...")
                else:
                    print("[CLIENT] GENERATING PGP KEY PAIR.")
                    uid = PGPUID.new(identifier, email=f'{identifier}@secure.chat.local')
                    client_private_key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 3072)
                    client_private_key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications})
                    client_private_key.protect(password, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
                    with open(private_key_file, "w") as f:
                        f.write(str(client_private_key))
                    client_private_key.unlock(password)
                    client_public_key_pem = str(client_private_key.pubkey)
                    print(f"[CLIENT] PGP Key Generated and stored encrypted on your local disk Successfully.")
                auth_event.clear()
                secure_send(client_socket, f"CLIENT_KEY:{client_public_key_pem}")
                auth_event.wait(5.0)


            if auth_status == "SUCCESS":
                print(f"[SYSTEM] Authentication successful. Secure session activated.")



                while not stop and auth_status == "SUCCESS":
                    text = input("[CLIENT] ").strip()
                    if not text:
                        continue
                    if text.lower() not in ["message","online users list"]:
                        secure_send(client_socket, text)

                    if text.lower() == "terminate":
                        stop = True
                        break
                    elif text.lower() == "message":

                        recipient = input("ENTER [RECIPIENT] IDENTIFIER ")

                        if recipient not in clients_public_keys:
                            print(f"[ERROR]  KEY for '{recipient}' is not received yet. Sending querry to the server.")
                            waiting_for_recipient = recipient
                            keys_received_event.clear()
                            secure_send(client_socket, f"GET_KEY:{recipient}")
                            print(f"[SYSTEM] System waiting for the key from the server. Up to 5 seconds.")
                            key_received = keys_received_event.wait(4.0)


                            if not key_received or recipient not in clients_public_keys:
                                print(f"[ERROR] Cannot receive message, key for '{recipient}' is not received yet. User might be offline.")
                                continue

                        message = input("ENTER MESSAGE ")
                        if not message.strip():
                            continue
                        try:
                            pgp_message = PGPMessage.new(message)
                            with client_private_key.unlock(password):
                                pgp_message |= client_private_key.sign(pgp_message)



                            recipient_key = clients_public_keys[recipient]
                            encrypted_package = recipient_key.encrypt(pgp_message)


                            secure_send(client_socket, "message")
                            time.sleep(0.05)
                            secure_send(client_socket, recipient)
                            time.sleep(0.05)
                            secure_send(client_socket, str(encrypted_package))
                            print(f"[SYSTEM] PGP Message sent successfully.")
                        except Exception as e:
                            print(f"[ERROR] Encryption error {e}")
                    elif text.strip().lower() == "online users list":
                        secure_send(client_socket, "online users list")
            else:
                print(f"[SYSTEM] Authentication failed on server side.")
                client_private_key = None
                client_public_key_pem = None
                password = None
                auth_status = None
                challenge_token = None
                gc.collect()
                continue



client_socket.close()
password = None
del password
gc.collect()
print("[CLIENT] Chat ended.")
