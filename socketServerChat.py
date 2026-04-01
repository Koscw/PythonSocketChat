import socket
import threading

nestedList = [[('0.0.0.0', 00000), 'ALL REGISTERED USERS->']]
logList = [[('0.0.0.0', 00000), 'ALL ONLINE USERS->']]

def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    connected = True
    while connected:
        try:
            # Receive message from client
            msg = conn.recv(1024).decode('utf-8')
            if not msg:
                break

            print(f"[{addr}] {msg}")

            if msg.lower() == "terminate":  #If terminate message is received from user
                delFromLogList(addr, logList)
                printLogList(logList)
                connected = False
            elif msg.lower() == "identifier": #If identifier message is received from user
                newIdentifier = conn.recv(1024).decode('utf-8')
                newIdentifierPassword = conn.recv(1024).decode('utf-8')
                bindAddressToIdentifier(addr, newIdentifier, nestedList, conn, newIdentifierPassword, logList)
                printNestedList(nestedList)
                printLogList(logList)
                serverAnswer = "identifier confirmed"
                conn.send(serverAnswer.encode())
            elif msg.lower() == "message": #If 'message' message is received from user
                try:
                    recipientName = conn.recv(1024).decode('utf-8')
                    nameCheck = verifyRecipientInLogBase(recipientName, logList)
                    if not nameCheck:
                        serverAnswer = f"{recipientName} is not registered or not online."
                        conn.send(serverAnswer.encode())
                        continue


                    #serverAnswer = f"[{addr}] {recipientName} is registered."
                    #conn.send(serverAnswer.encode())
                    print(f"[{addr}] {recipientName} is registered.")
                    recipientMessage = conn.recv(1024).decode('utf-8')
                    senderName = getNameByConnAddress(conn, nestedList)
                    adjustedRecipientMessage ="New message from <"+ senderName + "> : " + recipientMessage
                    writeMessage(recipientName, adjustedRecipientMessage, nestedList )
                    confirmation_message = f"{recipientName} received your message"
                    conn.send(confirmation_message.encode())
                    continue
                except Exception as e:
                    print(f"Error: {e}")
            elif msg.lower() == "online users list": #If 'online users list' message is received from user
                usersList = f"{returnAvailableUsersList(logList)}"
                printLogList(logList)
                conn.send(usersList.encode())
                continue













        except ConnectionResetError:
            break

    conn.close()
    print(f"[DISCONNECT] {addr} disconnected.")

def bindAddressToIdentifier(addr, identifier, nestedList, conn, newIdentifierPassword, logList):

    for elements in nestedList:
        if verifyRecipientInDataBase(identifier, nestedList):
            if elements[1] == identifier and elements[3] == newIdentifierPassword and verifyRecipientInLogBase(identifier, logList):
                nestedList.remove(elements)
                logList.remove(elements)
            elif elements[1] == identifier and elements[3] == newIdentifierPassword and verifyRecipientInLogBase(identifier, logList) == False:
                nestedList.remove(elements)
            elif elements[1] == identifier and elements[3] != newIdentifierPassword:
                msg = 'Wrong password'
                conn.send(msg.encode())
                return False


    newIdentifier = [addr, identifier, conn, newIdentifierPassword]
    nestedList.append(newIdentifier)
    logList.append(newIdentifier)

def verifyRecipientInDataBase(recipientIdentifier, nestedList):
    output = False
    for rows in nestedList:
        if rows[1] == recipientIdentifier:
            output = True
    return output

def verifyRecipientInLogBase(recipientIdentifier, logList):
    output = False
    for rows in logList:
        if rows[1] == recipientIdentifier:
            output = True
    return output
def getNameByConnAddress(currentConn, nestedList):
    name = "Unknown"
    for rows in nestedList:
        if len(rows)>2 and rows[2] == currentConn:
            name = rows[1]
            return name
    return name
def writeMessage(recipientName, msg, nestedList):
    for rows in nestedList:
        if rows[1] == recipientName:
            target_conn = rows[2]
            target_addr = rows[0]
            try:
                target_conn.send(msg.encode())
                return True
            except (BrokenPipeError, OSError, ConnectionResetError):
                print(f"Error connecting to {recipientName} Deleting from log database.")
                delFromLogList(target_addr,logList)
                return False
    return False




def delFromLogList(addr,logList):
    cntr = 0
    for rows in logList:
        if rows[0] == addr:
            del logList[cntr]
            cntr += 1
            continue
        else:
            cntr += 1
            continue

def delFromNestedList(addr,nestedList):
    cntr = 0
    for rows in nestedList:
        if rows[0] == addr:
            del nestedList[cntr]
            break
        else:
            cntr += 1

def printNestedList(nestedList):
    for rows in nestedList:
        print(rows)

def printLogList(logList):
    for rows in logList:
        print(rows)
def returnAvailableUsersList(logList):
    availableUsers = []
    for rows in logList:
        availableUsers.append(rows[1])
    return availableUsers
# 2. SERVER CONFIGURATION
PORT = 34567
SERVER = "0.0.0.0"  # Listens on all available interfaces

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# This line prevents "Address already in use" errors:
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

try:
    server.bind((SERVER, PORT))
except socket.error as e:
    print(f"[ERROR] Binding failed: {e}")
    exit()


server.listen()
print(f"[LISTENING] Server is starting on {SERVER}:{PORT}")

while True:
    # Accept new connection
    conn, addr = server.accept()

    # Create a new thread for each client
    # target=handle_client refers to the function defined above
    thread = threading.Thread(target=handle_client, args=(conn, addr))
    thread.start()

    print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")
    printNestedList(nestedList)