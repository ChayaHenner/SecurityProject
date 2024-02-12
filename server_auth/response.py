import socket
import struct
import logging 
from enum import Enum
class ResponsePayloadCodes(Enum):
    RegistrationSuccess = 1600
    RegistrationFailed = 1601
    SendingSymmetricKey = 1603


SERVER_VERSION = 24 
SUCCESS_SIZE = 16


class Response:
    def __init__(self, code):
        self.version = SERVER_VERSION
        self.code = code
        self.payload_size = 0#according to code
        self.payload = b''
        
    def pack(self, x):
        packed_data = struct.pack(f"B H I {x}s",
                                  self.version,
                                  self.code,
                                  self.payload_size,
                                  self.payload
                                  )
        return packed_data
    
    def print_packed_data(packed_data,x):
        version, code, payload_size, payload = struct.unpack_from(f"B H I {x}s", packed_data)
        print(f"Version: {version}")
        print(f"Code: {code}")
        print(f"Payload Size: {payload_size}")
        print(f"Payload: {payload.decode('utf-8')}")

    # def update_payload(self, payload_size):
    #     self.payload_size = payload_size


class ResponseRegistrationSuccess(Response):
    def __init__(self, client_id, client_socket):
        super().__init__(ResponsePayloadCodes.RegistrationSuccess.value)
        
        logging.info("in regist success")

        self.payload_size= SUCCESS_SIZE
        self.payload = client_id
        self.client_socket = client_socket
        
        packed_data = self.pack(self.payload_size)
        self.client_socket.send(packed_data)
        print("Packed Data:")
        self.print_packed_data(packed_data)
        
        
        
class ResponseRegistrationFailed(Response):
    def __init__(self, client_socket):
        super().__init__(ResponsePayloadCodes.RegistrationFailed.value)
        
        logging.info("in regist failed")
        
        self.client_socket = client_socket
        packed_data = self.pack(self.payload_size)
        self.client_socket.send(packed_data)
        print("Packed Data:")
        self.print_packed_data(packed_data)  # Print the packed data
        logging.info("regist failed done!")

class ResponseSendingSymmetricKey(Response):
    def __init__(self):
        super().__init__(ResponsePayloadCodes.SendingSymmetricKey.value)
# import struct
# server_response = {
#     1600: "RegisterSuccess",
#     1601: "RegisterFail",
#     1602: "ServerList",
#     1603: "SendSymmetricKey",
# }

# class Response:
#     def __init__(self,version,code,payload_size,payload):
#         self.version=version
#         self.code=code
#         self.payload_size=payload_size
#         self.payload=payload

#     def pack(self):
#         packed_data = struct.pack(f" B H I {len(self.payload)}s",
#                                   self.version,
#                                   self.code,
#                                   self.payload_size,
#                                   self.payload.encode('utf-8'))
#         return packed_data
    

        
