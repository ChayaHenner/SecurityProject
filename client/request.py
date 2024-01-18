import struct
client_request = {
    1025: "RegisterClient",
    1027: "RegisterServer",
    1027: "GetServerList",
    1027: "GetSymmetricKey",
}

class Request:
    def __init__(self,clientID,version,code,payload_size,payload):
        self.clientID= clientID
        self.version=version
        self.code=code
        self.payload_size=payload_size
        self.payload=payload

    def pack(self):
        packed_data = struct.pack(f"!16s B H I {len(self.payload)}s",
                                  self.clientID.encode('utf-8'),
                                  self.version,
                                  self.code,
                                  self.payload_size,
                                  self.payload.encode('utf-8'))
        return packed_data

        
