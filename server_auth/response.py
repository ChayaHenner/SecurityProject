import struct
server_response = {
    1600: "RegisterSuccess",
    1601: "RegisterFail",
    1602: "ServerList",
    1603: "SendSymmetricKey",
}

class Response:
    def __init__(self,version,code,payload_size,payload):
        self.version=version
        self.code=code
        self.payload_size=payload_size
        self.payload=payload

    def pack(self):
        packed_data = struct.pack(f" B H I {len(self.payload)}s",
                                  self.version,
                                  self.code,
                                  self.payload_size,
                                  self.payload.encode('utf-8'))
        return packed_data
    

        
