import struct

class Ticket:
    def __init__(self,clientID,serverID,ticketIV,version,code,payload_size,payload):
        self.clientID= clientID
        self.serverID= serverID
        self.ticketIV= ticketIV
        self.version=version
        self.code=code
        self.payload_size=payload_size
        self.payload=payload

    def pack(self):
        packed_data = struct.pack(f"!16s !16s !16s B H I {len(self.payload)}s",
                                  self.clientID.encode('utf-8'),
                                  self.version,
                                  self.code,
                                  self.payload_size,
                                  self.payload.encode('utf-8'))
        return packed_data

        
