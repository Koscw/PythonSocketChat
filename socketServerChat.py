import socket
import threading
import struct
import json

threading.stack_size(1024*1024)



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

pgp_keys_database = {}
nestedList = [[('0.0.0.0', 00000), 'ALL REGISTERED USERS->', None, None]]
logList = [[('0.0.0.0', 00000), 'ALL ONLINE USERS->', None, None]]

def serialize(pgp_keys_database, nestedList):
    with db_lock:

        adjusted_nestedList = []
        for rows in nestedList:
            if len(rows) >= 4:
                adjusted_nestedList.append([[["0.0.0.0"],0],rows[1],None,rows[3]])
            else:
                adjusted_nestedList.append(rows)

        try:
            with open('pgp_keys_database.json', 'w') as keys_file:
                json.dump(pgp_keys_database, keys_file, ensure_ascii=False, indent=4)

            with open('nestedList.json', 'w') as db_file:
                json.dump(adjusted_nestedList, db_file, ensure_ascii=False, indent=4)

        except IOError as e:
            print(f"[SERVER] Failed to write to file, exception: {e}")



def deserialize():
    global pgp_keys_database, nestedList
    with db_lock:
        try:
            with open('pgp_keys_database.json', 'r') as keys_file:
                keys_file.seek(0)
                pgp_keys_database = json.load(keys_file)

            with open('nestedList.json', 'r') as db_file:
                db_file.seek(0)
                nestedList = json.load(db_file)


            adjusted_nestedList = []
            for rows in nestedList:
                if len(rows) >= 4 and isinstance(rows[0], list):
                    adjusted_nestedList.append([tuple(rows[0]),rows[1],rows[2],rows[3]])
                else:
                    adjusted_nestedList.append(rows)
            nestedList = adjusted_nestedList
            print(f"[SERVER] Successfully read from file.")
            return pgp_keys_database, nestedList
        except FileNotFoundError as e:
            print(f"[SERVER] File not found. Create new one. Exception: {e} ")
            return pgp_keys_database, nestedList

def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    connected = True
    while connected:
        try:
            with db_lock:
                my_name = getNameByConnAddress(conn, nestedList)
                current_db_conn = None
                for rows in nestedList:
                    if len(rows) >= 4 and rows[1]==my_name:
                        current_db_conn = rows[2]
            if my_name != "Unknown" and current_db_conn!=conn:
                print(f"[SERVER] Phantom thread for {my_name} is detected. Killing it now ")
                break


            # Receive message from client
            msg = recv_msg(conn)
            if not msg:
                break

            print(f"[{addr}] Command: {msg[:30]}")

            if msg.lower() == "terminate":  #If terminate message is received from user
                with db_lock:
                    delFromLogListByConn(conn, logList)
                    clearConnNestedList(conn, nestedList)
                    printLogList(logList)
                secure_send(conn, "terminate")
                try:
                    serialize(pgp_keys_database, nestedList)
                except IOError:
                    print("[SERVER] Failed to save to the file.")
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                    conn.close()
                except:
                    pass
                print(f"[SERVER] Disconnected {addr} connection closed.")
                return
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
                if key_packet and key_packet.startswith("CLIENT_KEY"):
                    _, pem_key = key_packet.split(":",1)
                    with db_lock:
                        pgp_keys_database[newIdentifier] = pem_key
                    print(f"[SYSTEM] Successfully stored/updated PGP key for {newIdentifier}.")
                else:
                    print(f"[SYSTEM] Failed to store/update PGP key for {newIdentifier}.")
                with db_lock:
                    my_name = getNameByConnAddress(conn, nestedList)
                    current_db_conn = None
                    for rows in nestedList:
                        if len(rows) >= 4 and rows[1] == my_name:
                            current_db_conn = rows[2]
                if my_name != "Unknown" and current_db_conn != conn:
                    print(f"[SERVER] Phantom thread for {my_name} is detected. Killing it now ")
                    break
                continue

            elif msg.lower() == "message": #If 'message' message is received from user
                try:
                    recipientName = recv_msg(conn)
                    with db_lock:
                        senderName = getNameByConnAddress(conn, nestedList)
                        nameCheck = verifyRecipientInLogBase(recipientName, logList)

                    if not nameCheck:
                        secure_send(conn, f"{recipientName} is not registered or not online.")
                        continue

                    #serverAnswer = f"[{addr}] {recipientName} is registered."
                    #conn.send(serverAnswer.encode())
                    print(f"[{addr}] {recipientName} is registered.")

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
        my_name = getNameByConnAddress(conn, nestedList)
        current_db_conn = None
        for rows in nestedList:
            if len(rows) >= 4 and rows[1] == my_name:
                current_db_conn = rows[2]
    if my_name != "Unknown" and current_db_conn != conn:
        print(f"[SERVER] Old thread for {my_name}  is terminated.")
        conn.close()
        return

    with db_lock:
        delFromLogListByConn(conn, logList)
        clearConnNestedList(conn, nestedList)
        try:
            serialize(pgp_keys_database, nestedList)
        except IOError:
            print("[SERVER] Failed to save to the file.")
    conn.close()
    print(f"[DISCONNECT] {addr} disconnected.")
    return

def bindAddressToIdentifier(addr, identifier, nestedList, conn, newIdentifierPassword, logList):
    for elements in nestedList[:]:
        if  len(elements)>=4 and elements[1]==identifier:
            if elements[3] == newIdentifierPassword:
                old_connection = elements[2]
                if old_connection and old_connection!=conn:
                    try:
                        secure_send(old_connection, "terminate")
                        old_connection.shutdown(socket.SHUT_RDWR)
                        old_connection.close()
                    except Exception as e:
                        pass

                for onlineElements in logList[:]:
                    if len(onlineElements) >= 4 and onlineElements[1] == identifier:
                        logList.remove(onlineElements)

                elements[2] = conn
                elements[0] = addr



                logList.append(elements)
                secure_send(conn, "identifier confirmed")
                return True
            else:
                secure_send(conn, "Wrong Password")
                return False


    newIdentifier = [addr, identifier, conn, newIdentifierPassword]
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
    for rows in logList:
        if len(rows)>2 and rows[1] == recipientName:
            target_conn = rows[2]
            target_addr = rows[0]
            try:
                secure_send(target_conn, msg)
                return True
            except (BrokenPipeError, OSError, ConnectionResetError):
                print(f"Error connecting to {recipientName} Deleting from log database.")
                delFromLogListByConn(target_conn,logList)
                return False
    return False




def delFromLogListByConn(conn,logList):
    for rows in logList[:]:
        if len(rows)>=3 and rows[2] == conn:
            logList.remove(rows)


def clearConnNestedList(conn,nestedList):
    for rows in nestedList:
        if len(rows)>=3 and rows[2] == conn:
            rows[2] = None


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

try:
    deserialize()
    print("[SERVER] Successfully loaded from the file.")
except Exception as e:
    print(f"[SERVER] Failed to load from the file. Exception: {e}")


while True:
    conn, addr = server.accept()
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

    thread = threading.Thread(target=handle_client, args=(conn, addr))
    thread.start()

    print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")
    printNestedList(nestedList)