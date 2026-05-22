import socket
import threading
import struct

threading.stack_size(1024*1024)

pgp_keys_database = {}

db_lock = threading.Lock()

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
    try:
        sock.sendall(header+encode_data)
        return True
    except (OSError, BrokenPipeError):
        return False

nestedList = [[('0.0.0.0', 00000), 'ALL REGISTERED USERS->', None, None]]
logList = [[('0.0.0.0', 00000), 'ALL ONLINE USERS->', None, None]]

def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    connected = True
    while connected:
        try:
            # Receive message from client
            msg = recv_msg(conn)
            if not msg:
                break

            print(f"[{addr}] Command: {msg[:30]}")

            if msg.lower() == "terminate":  #If terminate message is received from user
                with db_lock:
                    delFromLogList(addr, logList)
                    printLogList(logList)
                secure_send(conn, "terminate")
                connected = False
            elif msg.lower() == "identifier": #If identifier message is received from user
                newIdentifier = recv_msg(conn)
                newIdentifierPassword = recv_msg(conn)

                if newIdentifier and newIdentifierPassword:
                    with db_lock:
                        success = bindAddressToIdentifier(addr, newIdentifier, nestedList, conn, newIdentifierPassword, logList)

                    if not success:
                        continue
                    with db_lock:
                        printNestedList(nestedList)
                        printLogList(logList)

                key_packet = recv_msg(conn)
                if key_packet and key_packet.startswith("CLIENT_KEY:"):
                    _, pem_key = key_packet.split(":",1)
                    with db_lock:
                        pgp_keys_database[newIdentifier] = pem_key
                    print(f"[SYSTEM] Successfully stored PGP Public Key for {newIdentifier}")


            elif msg.lower() == "message": #If 'message' message is received from user
                try:
                    recipientName = recv_msg(conn)
                    with db_lock:
                        senderName = getNameByConnAddress(conn, nestedList)
                        nameCheck = verifyRecipientInLogBase(recipientName, logList)
                        target_key = pgp_keys_database.get(recipientName) if nameCheck else None
                    if not nameCheck:
                        secure_send(conn, f"{recipientName} is not registered or not online.")
                        continue

                    #serverAnswer = f"[{addr}] {recipientName} is registered."
                    #conn.send(serverAnswer.encode())
                    print(f"[{addr}] {recipientName} is registered.")
                    if target_key:
                        exchange_payload = f"PUBKEY_EXCHANGE:{recipientName}:{target_key}"
                        secure_send(conn, exchange_payload)
                    else:
                        secure_send(conn, f"[SERVER ERROR] {recipientName} hasn't uploaded PGP key]")
                        continue
                    recipientMessage = recv_msg(conn)
                    if recipientMessage == "CANCEL_MESSAGE" or not recipientMessage:
                        continue
                    adjustedMessage = f"MSG_FROM:{senderName}:{recipientMessage}"
                    with db_lock:
                        writeMessage(recipientName, adjustedMessage, nestedList, logList )

                    secure_send(conn, f"{recipientName} received your message")
                    continue
                except Exception as e:
                    print(f"Error in message part: {e}")
            elif msg.lower().startswith("get_key:"):
                _, target_user = msg.split(":",1)
                with db_lock:
                    has_key = target_user in pgp_keys_database
                    target_key = pgp_keys_database.get(target_user)
                if has_key:
                    secure_send(conn, f"PUBKEY_EXCHANGE:{target_user}:{target_key}")
                else:
                    secure_send(conn, f"[SERVER] Key for {target_user} is not found.")
                continue
            elif msg.lower() == "online users list": #If 'online users list' message is received from user
                with db_lock:
                    usersList = f"{returnAvailableUsersList(logList)}"
                    printLogList(logList)
                secure_send(conn,usersList)
                continue

        except (ConnectionResetError, OSError):
            break
    with db_lock:
        delFromLogList(addr, logList)
    conn.close()
    print(f"[DISCONNECT] {addr} disconnected.")

def bindAddressToIdentifier(addr, identifier, nestedList, conn, newIdentifierPassword, logList):
    is_registered = False
    for elements in nestedList[:]:
        if  len(elements)>=4 and elements[1]==identifier:
            is_registered = True
            if elements[3] == newIdentifierPassword:
                elements[2] = conn
                elements[0] = addr
                for online_elements in logList[:]:
                    if len(online_elements)>=4 and online_elements[1] == identifier:
                        logList.remove(online_elements)
            else:
                secure_send(conn, "Wrong Password")
                return False


    newIdentifier = [addr, identifier, conn, newIdentifierPassword]
    if not is_registered:
        nestedList.append(newIdentifier)
    logList.append(newIdentifier)
    secure_send(conn,"identifier confirmed")
    return True

def verifyRecipientInDataBase(recipientIdentifier, nestedList):
    output = False
    for rows in nestedList:
        if len(rows)>1 and rows[1] == recipientIdentifier:
            output = True
    return output

def verifyRecipientInLogBase(recipientIdentifier, logList):
    output = False
    for rows in logList:
        if len(rows)>1 and rows[1] == recipientIdentifier:
            output = True
    return output
def getNameByConnAddress(currentConn, nestedList):
    for rows in nestedList:
        if len(rows)>2 and rows[2] == currentConn:
            return rows[1]
    return "Unknown"
def writeMessage(recipientName, msg, nestedList, logList):
    for rows in nestedList:
        if len(rows)>2 and rows[1] == recipientName:
            target_conn = rows[2]
            target_addr = rows[0]
            try:
                secure_send(target_conn, msg)
                return True
            except (BrokenPipeError, OSError, ConnectionResetError):
                print(f"Error connecting to {recipientName} Deleting from log database.")
                delFromLogList(target_addr,logList)
                return False
    return False




def delFromLogList(addr,logList):
    for rows in logList[:]:
        if rows[0] == addr:
            logList.remove(rows)


def delFromNestedList(addr,nestedList):
    for rows in nestedList[:]:
        if rows[0] == addr:
            nestedList.remove(rows)


def printNestedList(nestedList):
    for rows in nestedList:
        #print(rows)
        print(rows[:2])

def printLogList(logList):
    for rows in logList:
        print(rows)
def returnAvailableUsersList(logList):
    availableUsers = []
    for rows in logList:
        if len(rows)>=4 and rows[1] != "ALL ONLINE USERS->" :
            availableUsers.append(rows[1])
    return availableUsers

# 2. SERVER CONFIGURATION
PORT = 34567
SERVER = "0.0.0.0"

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

try:
    server.bind((SERVER, PORT))
except socket.error as e:
    print(f"[ERROR] Binding failed: {e}")
    exit()


server.listen()
print(f"[LISTENING] Server is starting on {SERVER}:{PORT}")

while True:
    conn, addr = server.accept()

    thread = threading.Thread(target=handle_client, args=(conn, addr))
    thread.start()

    print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")
    printNestedList(nestedList)