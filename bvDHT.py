import hashlib
from socket import *
import threading
from sys import argv, exit
from time import sleep

class DHTNode:
    def __init__(self):
        """
        Initializes the DHTNode with networking, hash identity,
        local address, and an empty hashmap and finger table.
        """
        self.clientSock = socket(AF_INET, SOCK_STREAM)
        self.clientSock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.clientSock.bind(('', 0))
        self.clientSock.listen(32)

        self.PORT = self.clientSock.getsockname()[1]

        self.hashmap = {}
        self.localFingerTable = {}
        self.fingerTableLock = threading.Lock()

        self.localAddr = f"{self.getLocalIPAddress()}:{self.PORT}"
        self.selfKey = self.getHashIndex(self.localAddr)
        self.fingers = self.computeFingerTargets(fingers=4)

        print(f"DHT Node joined on {self.localAddr}")

    #######################################################################################
    ################################ HELPER FUNCTIONS #####################################
    ####################################################################################### 

    def getLocalIPAddress(self):
        """
        Gets the local IP address of the current device.
        """
        s = socket(AF_INET, SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]


    def recvall(self, conn, msgLength):
        """
        Receives a specified number of bytes from a connection.
        """
        msg = b''
        while len(msg) < msgLength:
            retVal = conn.recv(msgLength - len(msg))
            msg += retVal
            if len(retVal) == 0:
                break    
        return msg


    def getLine(self, conn):
        """
        Reads a line from the socket until a newline character is found.
        """
        msg = b''
        while True:
            ch = conn.recv(1)
            msg += ch
            if ch == b'\n' or len(ch) == 0:
                break
        return msg.decode().strip()


    def hashGenerator(self, inputValue):
        """
        Converts any input into a SHA-1 hash and returns it as an integer.
        """
        inputStr = str(inputValue)
        inputBytes = inputStr.encode()
        return int.from_bytes(hashlib.sha1(inputBytes).digest(), byteorder="big")

    # Takes in a tuple 
    def getHashIndex(self, address):
        """
        Hashes a given IP:Port address into the DHT space.
        """
        ip, port = address.split(":")
        addr = (ip, int(port))
        b_addrStr = ("%s:%d" % addr).encode()
        return int.from_bytes(hashlib.sha1(b_addrStr).digest(), byteorder="big")


    def computeFingerTargets(self, fingers):
        """
        Calculates target positions in the DHT ring for finger table entries.
        """
        SIZE = 2 ** 160
        GAP = SIZE // (fingers + 1) # Diviide the DHT into 5 (four fingers + me) equal chunks

        finger_targets = []
        for i in range(1, fingers + 1):
            target = (int(self.selfKey) + i * GAP) % SIZE 
            finger_targets.append(target)

        return finger_targets

    def findClosest(self, hashKey):
        """
        Finds the closest preceding node to the given hashKey in the finger table.
        """
        with self.fingerTableLock:
            localFingerTableArray = list(self.localFingerTable.values())

        # Sort the finger table to find the closest peer that owns the closest finger to the hashkey
        localFingerTableArray.sort()

        # If the hashKey is exactly the same as something you have in your local finger table, this would probably never happen though
        for tablekey in localFingerTableArray:
            if hashKey == tablekey[0]:
                return tablekey[1]

        for i in range(len(localFingerTableArray)):
            if hashKey < localFingerTableArray[i][0]:
                # If it's the first element, wrap around and return the last one
                if i == 0:
                    return localFingerTableArray[-1][1]
                else:
                    return localFingerTableArray[i-1][1]
            
        # If no element is found, wrap around and return the last one
        return localFingerTableArray[-1][1]


    def Debbugging(self):
        """
        Outputs the contents of the local finger table and hashmap for visual inspection.
        """
        print("\n======================================================== Local Finger Table ===============================================================")

        print(f"{"spot in the DHT":<50} → {"owner's hashkey":<50} @ {"owner's address"}\n")
        with self.fingerTableLock:
            for key, value in self.localFingerTable.items():
                hashKey, addr = value
                print(f"{key:<50} → {hashKey:<50} @ {addr}")

        print("\n===================================================== HashMap Contents ==================================================================")
        if not self.hashmap:
            print("(empty)")
        else:
            for k, v in self.hashmap.items():
                print(f"{k} → {v}")

    def InBetween(self, target, start, end):
        """
        Determines if target is in the range (start, end) in a circular keyspace.
        """
        if start <= end:
            return start < target < end 
        else:
            return target > start or target < end
        
    def SendingValueData(self, peerConn, valueData):
        """
        Sends string or byte data over the socket to a peer.
        """
        if isinstance(valueData, str):
            peerConn.sendall(valueData.encode())
        else:
            peerConn.sendall(valueData)
    
    def ResolvePeerOrFallback(self, hashKey):
        """
        Attempts to locate the peer responsible for a given hashKey.
        Falls back to the current node if resolution fails.
        """
        try:
            peerAddress = self.Locate(hashKey)
            return (self.getHashIndex(peerAddress), peerAddress)
        except Exception:
            return (self.selfKey, self.localAddr)

    ###################################################################################
    ############################## CONNECT PROTOCOL ###################################
    ###################################################################################

    def CreateNewDHT(self):
        """
        Initializes a new DHT by making the current node its own successor and predecessor.
        Sets all finger table entries to the node itself, forming a single-node ring.
        """
        selfEntry = (int(self.selfKey), self.localAddr)

        with self.fingerTableLock:
            self.localFingerTable = {
                "me": selfEntry, 
                "next": selfEntry, 
                "prev": selfEntry
            }

        # Again each finger point to our self initially
        for finger in self.fingers:
            self.localFingerTable[finger] = selfEntry

    def Connect(self, ip, port):
        """
        Connects the current node to an existing DHT network.
        Finds the node responsible for the current node's hash key and transfers relevant entries.
        """
        peerAddress = f"{ip}:{port}"
        peerHashKey = int(self.getHashIndex(peerAddress))

        with self.fingerTableLock:
            for finger in self.fingers:
                self.localFingerTable[finger] = (peerHashKey, peerAddress)

        # Send the LOCATE proctocol to find out the owner.
        finalOwnerAddress = self.Locate(self.selfKey) # you found who owns your space
        print(f"[CONNECT] finalOwnerAddress: {finalOwnerAddress}")

        print(f"[CONNECT] Attempting to connect to {finalOwnerAddress}")
        finalOwnerIP, finalOwnerPort = finalOwnerAddress.split(":")
        finalOwnerConn = socket(AF_INET, SOCK_STREAM)
        
        try:
            finalOwnerConn.connect((finalOwnerIP, int(finalOwnerPort)))

            finalOwnerConn.send(("CONNECT\n").encode())
            finalOwnerConn.send((str(self.selfKey) + '\n').encode())

            ack = self.getLine(finalOwnerConn)

            if ack == '0':
                print("[CONNECT] Bail you received no response")
                return 
            
            numEntries = self.getLine(finalOwnerConn)

            for _ in range(int(numEntries)):
                hashKey = int(self.getLine(finalOwnerConn))
                lengthValueData = int(self.getLine(finalOwnerConn))
                valueData = self.recvall(finalOwnerConn, lengthValueData)
                self.hashmap[hashKey] = valueData
            
            nextPeerAddress = self.getLine(finalOwnerConn)
            print(f"[CONNECT] Peer’s next is {nextPeerAddress}")
            self.UpdatePrev(self.localAddr, nextPeerAddress)

            with self.fingerTableLock:
                self.localFingerTable['me'] = (self.selfKey, self.localAddr)
                self.localFingerTable['next'] = (self.getHashIndex(nextPeerAddress), nextPeerAddress)
                self.localFingerTable['prev'] = (self.getHashIndex(finalOwnerAddress), finalOwnerAddress)

            finalOwnerConn.send((self.localAddr + '\n').encode())
        
        except Exception as e:
            print(f"[CONNECT] Error: {e}")
            return

        finally:
            finalOwnerConn.close()

    def HandleConnect(self, peerConn):
        """
        Handles the CONNECT request from a new peer.
        Verifies if this node is responsible for the peer's hashed key.
        Transfers key-value entries and responds with the current next node.
        """
        try:
            peerHashedKey = self.getLine(peerConn)
            print(f"[HANDLE CONNECT] Receiving peerHashedKey: {peerHashedKey}")

            if self.selfKey == self.localFingerTable['next'][0] or self.InBetween(int(peerHashedKey), self.selfKey, self.localFingerTable['next'][0]):
                peerConn.send(("1\n").encode())
            
            else:
                print("Sending a negative acknowledgement.")
                print("Did not receive the hashedkey.") 
                peerConn.send(("0\n").encode())
                return
            
            peerConn.send((str(len(self.hashmap)) + '\n').encode())

            for hashKey, valueData in self.hashmap.items():
                peerConn.send((str(hashKey) + "\n").encode())
                peerConn.send((str(len(valueData)) + "\n").encode())
                self.SendingValueData(peerConn, valueData)

            with self.fingerTableLock:
                nextPeerHash, nextPeerAddress = self.localFingerTable['next']

            peerConn.send((nextPeerAddress + "\n").encode())

            peerAddress = self.getLine(peerConn)
            print(f"[HANDLE CONNECT] Receiving selfPeerAddress: {peerAddress}")

            with self.fingerTableLock:
                self.localFingerTable['next'] = (self.getHashIndex(peerAddress), peerAddress)

        except Exception as e:
            peerConn.send(("0\n").encode())
            print(f"[HANDLE CONNECT] Error: {e}")


    ###################################################################################
    ################################ GET PROTOCOL #####################################
    ###################################################################################

    def Get(self, keyToGet):
        """
        Sends a GET request to the peer who owns the specified key.
        If the key exists, receives and prints the associated value.
        """
        # Send the LOCATE proctocol to find out the owner.
        finalOwnerAddress = self.Locate(keyToGet)

        peerIP, peerPort = finalOwnerAddress.split(":")
        peerConn = socket(AF_INET, SOCK_STREAM)

        try:
            peerConn.connect((peerIP, int(peerPort)))

            peerConn.send(("GET\n").encode())

            peerConn.send((str(keyToGet) + '\n').encode())

            # This is the acknowledgement from the server
            ownsSpace = self.getLine(peerConn)  # It will be either a 0 or 1. If 0 bail out.

            if ownsSpace == '0':
                print("Owner of hash space not found")
                return
            
            lenValueData = int(self.getLine(peerConn))

            valueData = self.recvall(peerConn, lenValueData)

            if valueData:
                print(f"valueData : {valueData.decode()}")
            
            else:
                print("The Key you are looking for does not exist or does not have a corresponding value to it")

        except Exception as e:
            print(f"Error: {e}")
            return

        finally:
            peerConn.close()

    def HandleGet(self, peerConn):
        """
        Handles an incoming GET request from another peer.
        If this node owns the key and it exists, it sends back the value.
        """
        try:
            keyToGet = int(self.getLine(peerConn)) 
            
            # First do a local locate to find the closest funtion
            closestPeerAddress = self.findClosest(keyToGet)

            # Do I own this key space
            if self.localAddr == closestPeerAddress:
                peerConn.send(("1\n").encode())

                if keyToGet in self.hashmap:
                    valueData = self.hashmap[keyToGet]
                    peerConn.send((str(len(valueData)) + "\n").encode())
                    self.SendingValueData(peerConn, valueData)
                    return
                
                else:
                    peerConn.send(("0\n").encode())
                    return
            
            peerConn.send(("0\n").encode())

        except Exception as e:
            peerConn.send(("0\n").encode())
            print(f"Error: {e}")

    ###################################################################################
    ############################## INSERT PROTOCOL ####################################
    ###################################################################################

    def Insert(self, keyToInsert, valueData):
        """
        Sends an INSERT request to the node responsible for the given key.
        If the node owns the keyspace, the value will be inserted.
        """
        finalOwnerAddress = self.Locate(keyToInsert)

        peerIP, peerPort = finalOwnerAddress.split(":")
        peerConn = socket(AF_INET, SOCK_STREAM)

        try:
            peerConn.connect((peerIP, int(peerPort)))

            peerConn.send(("INSERT\n").encode())

            peerConn.send((str(keyToInsert) + "\n").encode())

            ownsSpace = self.getLine(peerConn)  # It will be either a 0 or 1. If 0 bail out.

            if ownsSpace == '0':
                print("Owner of hash space not found")
                peerConn.close()
                return

            peerConn.send((str(len(valueData)) + "\n").encode())
            self.SendingValueData(peerConn, valueData)

            insertAck = int(self.getLine(peerConn).strip())
            
            if (insertAck == 0):
                print("Insert failed")
            else:
                print("Insert successful")

        except Exception as e:
            print(f"Error: {e}")
            return

        finally:
            peerConn.close()
            return

    def HandleInsert(self, peerConn):
        """
        Handles an incoming INSERT request from another peer.
        If this node owns the keyspace, it stores the value in the hashmap.
        """
        try:
            keyToInsert = int(self.getLine(peerConn)) 
            
            # First do a local locate to find the closest funtion
            closestPeerAddress = self.findClosest(keyToInsert)

            # Do I own this key space
            if self.localAddr == closestPeerAddress:
                peerConn.send(("1\n").encode())

                lenValueData = int(self.getLine(peerConn))
                valueData = self.recvall(peerConn, lenValueData)

                self.hashmap[keyToInsert] = valueData

                peerConn.send(("1\n").encode()) # send successfull insert ack
                return
            
            else:
                peerConn.send(("0\n").encode())

        except Exception as e:
            peerConn.send(("0\n").encode())
            print(f"Error: {e}")


    ###################################################################################
    ############################## REMOVE PROTOCOL ####################################
    ###################################################################################

    def Remove(self, keyToRemove):
        """
        Sends a REMOVE request to the node responsible for the given key.
        If the node owns the keyspace, the key is removed from its hashmap.
        """
        finalOwnerAddress = self.Locate(keyToRemove)

        peerIP, peerPort = finalOwnerAddress.split(":")
        peerConn = socket(AF_INET, SOCK_STREAM)
        
        try:
            peerConn.connect((peerIP, int(peerPort)))

            peerConn.send(("REMOVE\n").encode()) 
            peerConn.send((str(keyToRemove) + "\n").encode())

            ownsSpace = self.getLine(peerConn)
            if ownsSpace == "0":
                print("Owner of hash space not found")
                peerConn.close()
                return
            
            removeAck = self.getLine(peerConn)
            if removeAck == "1":
                print("Key removed Successfully or key didn't exist.")
            else:
                print("Remove Failed!")

        except Exception as e:
            print(f"Error: {e}")
            return

        finally:
            peerConn.close()
            return

    def HandleRemove(self, peerConn):
        """
        Handles an incoming REMOVE request from another peer.
        If this node owns the keyspace, the key is removed from its hashmap.
        """
        try:
            keyToRemove = int(self.getLine(peerConn))

            # First do a local locate to find the closest funtion
            closestPeerAddress = self.findClosest(keyToRemove)

            # Do I own this key space
            if self.localAddr == closestPeerAddress:
                peerConn.send(("1\n").encode())
                self.hashmap.pop(keyToRemove, None)
                peerConn.send(("1\n").encode()) # Send a remove ack after removing or if the key didn't exist
                return 
            
            peerConn.send(("0\n").encode())

        except Exception as e:
            peerConn.send(("0\n").encode())
            print(f"Error: {e}")
            return

    #######################################################################################
    ################################# CONTAINS PROTOCOL ###################################
    #######################################################################################

    def Contains(self, keyToLookFor):
        """
        Sends a CONTAINS request to the node responsible for the given key.
        Returns whether the key exists in the distributed hash table (DHT).
        """
        finalOwnerAddress = self.Locate(keyToLookFor)

        peerIP, peerPort = finalOwnerAddress.split(":")
        peerConn = socket(AF_INET, SOCK_STREAM)

        try:
            peerConn.connect((peerIP, int(peerPort)))


            peerConn.send(("CONTAINS\n").encode())

            peerConn.send((str(keyToLookFor) + '\n').encode())

            ownsSpace = self.getLine(peerConn)  # It will be either a 0 or 1. If 0 bail out.

            if ownsSpace == '0':
                print("No owner found hashed space")
                peerConn.close()
                return False
            
            hasEntry = self.getLine(peerConn)
            if hasEntry == '1':
                print("True")
                return True

            else:
                print("False")
                return False

        except Exception as e:
            print(f"Error: {e}")
            return False

        finally:
            peerConn.close()

    def HandleContains(self, peerConn):
        """
        Handles an incoming CONTAINS request from another peer.
        Checks if the requested key exists in this node's hashmap.
        """
        try:
            keyToLookFor = int(self.getLine(peerConn))

            # First do a local locate to find the closest funtion
            closestPeerAddress = self.findClosest(keyToLookFor)

            # Do I own this key space
            if self.localAddr == closestPeerAddress:
                peerConn.send(("1\n").encode())

                if keyToLookFor in self.hashmap:
                    peerConn.send(("1\n").encode())
                    return
                else:
                    peerConn.send(("0\n").encode())
                    return

            peerConn.send(("0\n").encode())

        except Exception as e:
            peerConn.send(("0\n").encode())
            print(f"Error: {e}")
            return


    #######################################################################################
    ################################# LOCATE PROTOCOL #####################################
    #######################################################################################

    def Locate(self, keyToLookFor):
        """
        Determines the address of the peer responsible for a specific hash key in the DHT.
        If the current node owns the key, it returns its own address.
        Otherwise, it contacts the closest known peer and follows redirections until the owner is found.
        """
        found = False

        closestPeerAddress = self.findClosest(keyToLookFor)

        # Return yourself if since you own the keyToLookFor
        if self.localAddr == closestPeerAddress:
            found = True
            return self.localAddr

        # Otherwise ask the closest person to key if they own the key
        while not found:
            peerIP, peerPort = closestPeerAddress.split(":") 
            peerConn = socket(AF_INET, SOCK_STREAM)

            try:
                peerConn.connect((peerIP, int(peerPort)))
                peerConn.send(("LOCATE\n").encode())
                peerConn.send((str(keyToLookFor) + '\n').encode())

                peerAddress = self.getLine(peerConn)

                if peerAddress == closestPeerAddress:
                    found = True
                    return peerAddress

                closestPeerAddress = peerAddress

            except Exception as e:
                return self.Locate(keyToLookFor)

            finally:
                peerConn.close()

        return peerAddress


    def HandleLocate(self, peerConn):
        """
        Handles an incoming LOCATE request from another peer.
        Determines and responds with the closest known peer to the requested key.
        """
        try:
            keyToLookFor = int(self.getLine(peerConn))

            closestPeerAddress = self.findClosest(keyToLookFor)

            # Return yourself if since you own the keyToLookFor
            if self.localAddr == closestPeerAddress:
                peerConn.send((self.localAddr + '\n').encode())
                return

            # Otherwise, send back the closest peer to the keyToLookFor
            peerConn.send((closestPeerAddress + '\n').encode())

        except Exception as e:
            print(f"[LOCATE] Error: {e}")


    #######################################################################################
    ############################## DISCONNECT PROTOCOL ####################################
    #######################################################################################

    def Disconnect(self):
        """
        Gracefully disconnects the current node from the DHT ring.
        Transfers all key-value entries to the previous node and updates the previous
        node's pointer to skip over the disconnecting node by connecting it to the next node.

        After a successful transfer, the node terminates itself.
        """
        with self.fingerTableLock:
            prevPeerAddress = self.localFingerTable["prev"][1]
            nextPeerAddress = self.localFingerTable["next"][1]

        prevIP, prevPort = prevPeerAddress.split(":")
        prevConn = socket(AF_INET, SOCK_STREAM)
        prevConn.connect((prevIP, int(prevPort)))

        try:
            prevConn.send(("DISCONNECT\n").encode())
            prevConn.send((nextPeerAddress + "\n").encode())

            prevConn.send((str(len(self.hashmap)) + "\n").encode())
            print("Hii")

            for hashKey, valueData in self.hashmap.items():
                prevConn.send((str(hashKey) + "\n").encode())
                prevConn.send((str(len(valueData)) + "\n").encode())
                self.SendingValueData(prevConn, valueData)

            ack = self.getLine(prevConn)

            if ack == "0":
                print("Ownership was not transfered")
            
            else:
                print("Ownership was officially transfered!")
        
        except Exception as e:
            print(f"Error: {e}")
            return

        finally:
            prevConn.close()
        
        exit(0)

    def HandleDisconnect(self, prevConn):
        """
        Handles a DISCONNECT request from a departing peer.
        Receives all key-value entries and updates the 'prev' pointer to maintain ring continuity.
        """
        try:
            nextPeerAddress = self.getLine(prevConn)

            numEntries = int(self.getLine(prevConn))

            for _ in range(numEntries):
                hashKey = int(self.getLine(prevConn))
                lengthValueData = int(self.getLine(prevConn))
                valueData = self.recvall(prevConn, int(lengthValueData))
                self.hashmap[hashKey] = valueData

            self.UpdatePrev(self.localAddr, nextPeerAddress)

            prevConn.send(("1\n").encode())

        except Exception as e:
            prevConn.send(("0\n").encode())
            print(f"Error: {e}")
            return

    #######################################################################################
    ############################## UPDATE PREV PROTOCOL ###################################
    #######################################################################################

    def UpdatePrev(self, localAddr, nextPeerAddress):
        """
        Sends a request to the next peer to update its 'prev' pointer to this node's address.
        This ensures the DHT ring remains correctly linked after a node joins or disconnects.
        """
        nextPeerIP, nextPeerPort = nextPeerAddress.split(":")
        nextConn = socket(AF_INET, SOCK_STREAM)

        try:
            nextConn.connect((nextPeerIP, int(nextPeerPort)))
            nextConn.send(("UPDATE_PREV\n").encode())
            nextConn.send((localAddr + '\n').encode())

            ack = self.getLine(nextConn)

            if ack == '0':
                print("Update prev failed!")
                return

        except Exception as e:
            print(f"[UPDATE_PREV] Error: {e}")
            return

        finally:
            nextConn.close()
        
    def HandleUpdatePrev(self, nextConn):
        """
        Handles an UPDATE_PREV request from another peer.
        Updates this node's 'prev' pointer to the new previous node specified in the request.
        """
        try:
            selfPeerAddress = self.getLine(nextConn)

            selfHashKey = self.getHashIndex(selfPeerAddress)

            with self.fingerTableLock:
                self.localFingerTable["prev"] = (selfHashKey, selfPeerAddress)

            nextConn.send(("1\n").encode())

        except Exception as e:
            nextConn.send(("0\n").encode())
            print(f"[HANDLE UPDATE_PREV] Error: {e}")

    #######################################################################################
    ############################ FINGER TABLE FUNCTIONS ###################################
    #######################################################################################

    def VerifyPeer(self, peerAddress):
        """
        Attempts to verify whether a given peer is alive by opening a connection 
        and sending a simple TEST command.
        """
        if not peerAddress:
            return False 
        
        try:
            ip, port = peerAddress.split(":")
            testSock = socket(AF_INET, SOCK_STREAM)
            testSock.settimeout(1)
            testSock.connect((ip, int(port)))
            testSock.send(("TEST\n").encode())
            testSock.close()
            return True
        except:
            return False
        

    def UpdateFingerTable(self):
        """
        Periodically checks and updates the local finger table by:
            - Verifying that 'prev' and 'next' peers are still alive.
            - Recomputing the finger entries by locating the current owner of each finger key.
            - Replacing dead or unreachable peers with the current node's own address.
        This function helps maintain DHT consistency in a dynamic peer environment.
        """
        nextPeerHashKey, nextPeerAddress = self.localFingerTable['next']
        prevPeerHashKey, prevPeerAddress = self.localFingerTable['prev']

        if not self.VerifyPeer(prevPeerAddress):
            self.localFingerTable['prev'] = self.ResolvePeerOrFallback(prevPeerHashKey)

        if not self.VerifyPeer(nextPeerAddress):
            self.localFingerTable['next'] = self.ResolvePeerOrFallback(nextPeerHashKey)

        for finger in self.fingers:
            self.localFingerTable[finger] = self.ResolvePeerOrFallback(finger)
        
    #######################################################################################
    ############################ THREADING HELPER FUNCTIONS ###############################
    #######################################################################################

    def Listener(self, peerConn):
        """
        Handles incoming requests from a connected peer. Reads the command type and 
        dispatches it to the corresponding handler function.
        """
        try:
            conn, addr = peerConn # Socket  ,  (IP, Port)
            ip = addr[0]
            port = addr[1]

            incomingCommand = self.getLine(conn).strip()

            match incomingCommand:
                case "CONNECT":
                    self.HandleConnect(conn)
                case "LOCATE":
                    self.HandleLocate(conn)
                case "DISCONNECT":
                    self.HandleDisconnect(conn)
                case "GET":
                    self.HandleGet(conn)
                case "INSERT":
                    self.HandleInsert(conn)
                case "REMOVE":
                    self.HandleRemove(conn)
                case "CONTAINS":
                    self.HandleContains(conn)
                case "UPDATE_PREV":
                    self.HandleUpdatePrev(conn)
                case "TEST":
                    pass # Do nothing, it's just a test
                case _:
                    print(f"[LISTENER] Unknown command: {incomingCommand}")
        
        except Exception as e:
            self.HandleDisconnect(conn)
        finally:
            conn.close()

    def ConnectionHandler(self):
        """
        Continuously listens for new incoming peer connections and spawns a new thread 
        to handle each connection using the Listener method.
        """
        while True:
            try:
                conn = self.clientSock.accept()
                threading.Thread(target=self.Listener, args=(conn,), daemon=True).start()

            except Exception as e:
                print(f"Error: {e}")
                continue

    def UpdateFingerTableHandler(self):
        """
        Periodically updates the local finger table every 15 seconds to keep the routing 
        information fresh and accurate in a dynamic network.
        """
        while True:
            sleep(15)
            self.UpdateFingerTable()

#######################################################################################
###################################### MAIN CODE ######################################
#######################################################################################

if __name__ == "__main__":
    node = DHTNode()

    if len(argv) == 1:
        node.CreateNewDHT()
    elif len(argv) != 3:
        print("Invalid passing parameters")
    else:
        node.Connect(argv[1], argv[2])
        node.UpdateFingerTable()

    print(f"{node.getLocalIPAddress()} : {node.PORT}")

    # Thread to update the finger table after 15 seconds
    threading.Thread(target=node.UpdateFingerTableHandler, daemon=True).start()

    # Start the connection handler thread
    threading.Thread(target=node.ConnectionHandler, daemon=True).start()

    #node.clientSock.settimeout(3) # Set a timeout so that if no peer connects, you node still works locally

    try:
        while True:
            try:
                rawInput = input("").strip()
                parts = rawInput.split()
                command = parts[0].upper()

                match command:
                    case "DEBUG":
                        node.Debbugging()
                    case "GET":
                        if len(parts) >= 2:
                            key = parts[1]
                            node.Get(node.hashGenerator(key))
                    case "INSERT":
                        if len(parts) >= 3:
                            key = parts[1]
                            value = parts[2]
                            node.Insert(node.hashGenerator(key), value)
                    case "REMOVE":
                        if len(parts) >= 2:
                            key = parts[1]
                            node.Remove(node.hashGenerator(key))
                    case "CONTAINS":
                        if len(parts) >= 2:
                            key = parts[1]
                            node.Contains(node.hashGenerator(key))
                    case "LOCATE":
                        if len(parts) >= 2:
                            key = parts[1]
                            node.Locate(node.hashGenerator(key))
                    case "DISCONNECT":
                        node.Disconnect()
                    case _:
                        print("Unknown or malformed command.")

            except Exception as e:
                print(f"Error: {e}")

    except Exception as e:
        node.Disconnect()
        print(f"Error: {e}")
    finally:
        node.clientSock.close()