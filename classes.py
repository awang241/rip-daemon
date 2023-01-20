import struct

class RipResponse:
    """Class for modeling RIP response packets. Also provides methods for 
    validation and conversion to and from raw bytes."""
    HEADER_LENGTH = 4
    ENTRY_LENGTH = 20
    MAX_PACKET_LENGTH = 504
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
                len(packet) <= self.MAX_PACKET_LENGTH)
    
    def toBytes(self):
        """Returns this RIP response as a bytes object for use in sockets."""
        packet = bytes()
        header = struct.pack(">BBH", self.command, self.version, self.sourceId)
        packet += header
        for routerId, metric in self.entries.items():
            packet += struct.pack(">HHIIII", 2, 0, routerId, 0, 0, metric)
        return packet
    
    def isValid(self, neighbourIds):
        """Returns true if all packet fields are valid."""
        validEntries = len(self.entries) > 0
        index = 0
        entryList = list(self.entries.items())
        while validEntries and index < len(entryList):
            entryId, metric = entryList[index]
            if metric < 1 or metric > 15:
                validEntries = false
            index += 1
        return (
            self.sourceId in neighbourIds and
            self.command == self.COMMAND and
            self.version == self.VERSION and
            validEntries
        )

testEntries = {1:1, 2:1, 4:6}
testRes = RipResponse(entries=testEntries)