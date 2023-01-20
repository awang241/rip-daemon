from queue import Queue
from select import select
from threading import Timer
import socket
import struct
import sys


#Globals
EXPECTED_NUM_ARGS = 2
AUTO_PERIOD = 30
TIMEOUT_PERIOD = 180
GARBAGE_PERIOD = 120
MAX_PACKET_SIZE = 504
LOCALHOST = "127.0.0.1"    
RECV_ADDR = (LOCALHOST, 6000)

AUTO_UPDATE = "automatic update"
TRIG_UPDATE = "triggered update"
GARBAGE = "garbage removal"
TIMEOUT = "timeout"
RESPONSE = "response"

FLAG_SOCK = socket.socket()
REQ_QUEUE = Queue()

class Link:
    """
    Class for holding link data for better readibility. Values set to -1 to indicate no existing data.
    """
    def __init__(self):
        self.port = -1 #the port this link is on
        self.metric = -1 #the cost of the link
        self.routerID = -1 #the ID of the router on the otherside

    def __str__(self):
        return "(Link: Port = {0}, Metric = {1}, Router ID = {2})".format(self.port, self.metric, self.routerID)
    
class TableEntry:
    def __init__(self, routerId, nextHop, metric):
        self.routerId = routerId
        self.nextHop = nextHop
        self.metric = metric
        self.flag = True
        self.timeout = None
        self.setTimeout()
        self.garbage = Timer(GARBAGE_PERIOD, queueRequest, [(self, GARBAGE)])
  
    def setTimeout(self):
        self.timeout = Timer(TIMEOUT_PERIOD, queueRequest, [(self, TIMEOUT)])
        self.timeout.start()
        
    def resetTimeout(self):
        self.timeout.cancel()
        self.setTimeout()
        
    def setGarbage(self):
        self.metric = 16
        self.flag = True
        self.garbage = Timer(GARBAGE_PERIOD, queueRequest, [(self, GARBAGE)])
        self.garbage.start()
        
    def resetGarbage(self):
        self.garbage.cancel()
        

class RipResponse:
    """Class for modeling RIP response packets. Also provides methods for 
    validation and conversion to and from raw bytes."""
    HEADER_LENGTH = 4
    ENTRY_LENGTH = 20
    COMMAND = 2
    VERSION = 2
    
    def __init__(self, version=VERSION, command=COMMAND, sourceId=0, entries={}, packet=None):
        """Constructor for RIP response. The packet argument must be the bytes of an actual RIP 
        response packet. If it isn't provided, the response will be created from the other arguments
        instead"""
        if packet == None:
            self.command = command
            self.version = version
            self.sourceId = sourceId
            self.entries = entries
        elif isinstance(packet, bytes):
            self.entries = {}
            if self.isValidPacketLength(packet):
                header = packet[0:self.HEADER_LENGTH]
                self.command = struct.unpack('>B', header[0:1])[0]
                self.version = struct.unpack('>B', header[1:2])[0]
                self.sourceId = struct.unpack('>H', header[2:])[0]
                for byteIndex in range(self.HEADER_LENGTH, len(packet), self.ENTRY_LENGTH):
                    rows = struct.unpack('>IIIII', packet[byteIndex:byteIndex + self.ENTRY_LENGTH])
                    routerId = rows[1]
                    metric = rows[4]
                    self.entries[routerId] = metric
        else:
            raise Exception("Invalid packet format for RIP response")
                
    def isValidPacketLength(self, packet):
        """Returns true if the packet is a valid length. RIP packets must be 
        (length of header + length of entries * number of entries) bytes long. 
        The packet must also be under the maximum possible length for RIP."""
        return (len(packet) % self.ENTRY_LENGTH == self.HEADER_LENGTH and 
                len(packet) <= self.MAX_PACKET_SIZE)
    
    def toBytes(self):
        """Returns this RIP response as a bytes object for use in sockets."""
        packet = bytes()
        header = struct.pack(">BBH", self.command, self.version, self.sourceId)
        packet += header
        for routerId, metric in self.entries.items():
            packet += struct.pack(">HHIIII", 2, 0, routerId, 0, 0, metric)
        return packet
    
    def isValid(self, neighbourIds):
        """Returns true if the header fields are valid."""
        return (
            self.sourceId in neighbourIds and
            self.command == self.COMMAND and
            self.version == self.VERSION
        )



def readConfig(filePath):
    routerID = -1 #initially set to this value to check if a routerID actually comes up
    routerID_list = [] #list to keep track of duplicate routerID
    inputPorts = [] #input ports 
    outputLinks = [] #output connections
    periodic_update_time = 30 #default update time if not set
    
    file = open(filePath, 'r')
    text = file.readlines()
    file.close()
    
    for index, line in enumerate(text):
        line = line.strip()
        
        if len(line) == 0:
            continue #empty line
        
        elif line.startswith('#'): 
            continue #comment line
        
        elif line.startswith("router-id"):
            routerID = int(line.split(' ')[1])
            if routerID < 1 or routerID > 64000: #check between 1 and 64000 inclusive
                raise ValueError("Router ID not valid")
            routerID_list.append(routerID) #append to list for later dupe checks
                
        elif line.startswith("input-ports"):
            line = line.strip("input-ports ")
            interfaces = line.split(',')
            
            for interface in interfaces:
                interface = interface.strip()
                if int(interface) < 1024 or int(interface) > 64000:
                    raise ValueError("Input Port not Valid")
                if not (interface in inputPorts) and not (interface in [output.port for output in outputLinks]):
                        inputPorts.append(interface)
                else:
                    raise ValueError("Port {} already in use".format(interface))
                    
        elif line.startswith("outputs"):
            line = line.strip("outputs ")
            line = line.split(',')
            
            for output in line:
                link = Link() #link object to indicate link (need this to be imported)
                output = output.split('-') #split the parts of each output
                portNum = int(output[0])
                if portNum < 1024 or portNum > 64000:
                    raise ValueError("Output not Valid")
                if not (portNum in [output.port for output in outputLinks]) and not (portNum in inputPorts):
                    link.port = portNum
                else:                
                    raise ValueError("Port {} already in use".format(portNum))
                
                link.metric = int(output[1])
                if link.metric < 0 or link.metric > 15:
                    raise ValueError("Invalid Metric Link")
                
                otherRouterID = int(output[2])
                if otherRouterID < 1 or otherRouterID > 64000:
                    raise ValueError("Router ID not valid")
                if not (otherRouterID in routerID_list):
                    routerID_list.append(otherRouterID)
                    link.routerID = otherRouterID
                else:
                    raise ValueError("Router ID {} is duplicated".format(output[2]))
                outputLinks.append(link)
                
        elif line.startswith("periodic-update-time"):
            periodic_update_time = int(line.split(' ')[1]) #maybe add check for this if too long/too short
            if periodic_update_time < 4 or periodic_update_time > 1800:
                raise ValueError("Periodic Update Time Invalid")
        
        else: #line starts with something not valid
            raise SyntaxError("Syntax error in file on line {0}".format(index + 1))
        
    if routerID == -1 or len(inputPorts) == 0 or len(outputLinks) == 0:
        raise ValueError("Router ID, Input Ports and Outputs must all be included in the file")
    
    return (routerID, inputPorts, outputLinks, periodic_update_time) #return information from file if everything valid


def createSockets(ports):
    sockets = {}
    for port in ports:
        currentSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        currentSocket.bind((LOCALHOST, int(port)))
        sockets[port] = currentSocket
    configSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    configSocket.bind(RECV_ADDR)
    configSocket.listen()
    timer = Timer(1, connectFlagSocket)
    timer.start()
    recvSocket, addr = configSocket.accept()
    return (sockets, recvSocket, addr)


def connectFlagSocket():
    FLAG_SOCK.connect(RECV_ADDR)


def automaticUpdate(period, init=False):
    if not init:
        queueRequest(None, AUTO_UPDATE)
    timer = Timer(period, automaticUpdate, [period])
    timer.start()   
    

def createResponses(sourceId, destId, routingTable, updateType):
    version = 2
    command = 2
    index = 0
    responses = []
    tableEntries = list(routingTable.values())
    while index < len(tableEntries):
        packetEntries = {}
        while len(packetEntries) < 25 and index < len(tableEntries): 
            tableEntry = tableEntries[index]
            if tableEntry.nextHop != destId and (updateType != TRIG_UPDATE or tableEntry.flag):
                packetEntries[tableEntry.routerId] = tableEntry.metric
            index += 1
        responses.append(RipResponse(version, command, sourceId, packetEntries))
    return responses
    
    
    
def sendUpdates(linkAddresses, socket, routingTable, updateType, routerId):
    responseMap = {}
    for destId in linkAddresses.keys():
        responses = createResponses(routerId, destId, routingTable, updateType)
        responseMap[destId] = []
        for response in responses:
            if len(response.entries) > 0:
                responseMap[destId].append(response)
    if updateType == TRIG_UPDATE:
        for entry in routingTable.values():
            entry.flag = False
    for destId, address in linkAddresses.items():
        for response in responseMap[destId]:
            socket.sendto(response.toBytes(), address)
    
    
def processPacket(packet, neighbourIds, routingTable):
    """Processes an incoming RIP response packet and updates the routing table
    accordingly."""
    if not packet.isValid(neighbourIds):
        return None
    
    for routerId, metric in packet.entries.items():
        if routerId >= 1 and routerId <= 64000 and metric <= 16 and metric >= 1:
            metric = min(16, metric + routingTable[packet.sourceId].metric)
            if routerId not in routingTable and metric < 16: #Undiscovered non-infinite route, so add to routing table
                routingTable[routerId] = TableEntry(routerId, metric, packet.sourceId, True)
                queueRequest(None, TRIG_UPDATE)
            elif routerId in routingTable: #Existing entry in routing table
                entry = routingTable[routerId]
                if entry.nextHop == packet.sourceId:
                    entry.resetTimeout()
                
                if ((entry.nextHop == packet.sourceId and entry.metric != metric) or entry.metric > metric):
                    entry.resetGarbage()
                    entry.metric = metric
                    entry.nextHop = packet.sourceId
                    entry.flag = True
                    queueRequest(None, TRIG_UPDATE)
                    if metric == 16:
                        entry.setGarbage()
                        
                    
                
def queueRequest(obj, reqType):
    REQ_QUEUE.put((obj, reqType))
    FLAG_SOCK.send(bytes(1))
################################################################################

if len(sys.argv) != 1:#EXPECTED_NUM_ARGV:
    print("Usage: rip.py [config_filepath]")
    sys.exit()
else:
    routerId, inputPorts, links, timeVal = readConfig("config.txt")#sys.argv[1])
    sockets, alarmSocket, recvAddr = createSockets(inputPorts)

    socketList = list(sockets.values())
    socketList.append(alarmSocket)
    linkAddresses = {}
    routingTable = {}
    for link in links:
        linkAddresses[link.routerID] = (LOCALHOST, link.port)
        routingTable[link.routerID] = TableEntry(link.routerID, link.routerID, link.metric)
    automaticUpdate(5, True)
    print(socketList)
    while True:
        print("waiting for reqs")
        (receivedSockets, _, _) = select(socketList, [], [])
        for socket in receivedSockets:
            if socket != alarmSocket:
                print(socket.getsockname())
                print(socket.recvfrom(1))
                print(alarmSocket.getsockname())
                res = RipResponse(packet=socket.recv(MAX_PACKET_SIZE))
                queueRequest(res, RESPONSE)
        if alarmSocket in receivedSockets:
            alarmSocket.recv(4096)
        while not REQ_QUEUE.empty():
            body, reqType = REQ_QUEUE.get(False)
            socketList[0]
            if reqType == AUTO_UPDATE or reqType == TRIG_UPDATE:
                sendUpdates(linkAddresses, socketList[0], routingTable, reqType, routerId)
            elif reqType == TIMEOUT:
                body.setGarbage()
            elif reqType == GARBAGE:
                del routingTable[body.routerId]
            elif reqType == RESPONSE: 
                processPacket(body, linkAddresses.keys(), routingTable)

    