import struct
client_request = {
    1024: "RegisterClient",
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
        if self.code==1024:
            x=255
            y=255
        elif self.code==1027 :
            x=16
            y=8
        packed_data = struct.pack(f"16s B H I {x}s {y}s",
                                  self.clientID.encode('utf-8'),
                                  self.version,
                                  self.code,
                                  self.payload_size,
                                  self.payload[0].encode('utf-8'),
                                  self.payload[1].encode('utf-8')
                                  )
    
        return packed_data

        
