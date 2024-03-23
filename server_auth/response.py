import socket
import struct
import logging 
from enum import Enum
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from uuid import UUID

from datetime import datetime, timedelta
from Crypto.Random import get_random_bytes
class ResponsePayloadCodes(Enum):
    RegistrationSuccess = 1600
    RegistrationFailed = 1601
    SendingSymmetricKey = 1603


SERVER_VERSION = 24 
SUCCESS_SIZE = 16
SEND_KEY_SIZE = 169

class Response:
    def __init__(self, code):
        self.version = SERVER_VERSION
        self.code = code
        self.payload_size = 0#according to code
        self.payload = b''
    
    import struct

    def pack(self, x):
        
        if isinstance(self.payload, UUID):
        # Convert UUID payload to bytes (UUIDs are 16 bytes)
            payload_bytes = self.payload.bytes
        
        packed_data = struct.pack(f"B H I {x}s", self.version, self.code, self.payload_size, payload_bytes)
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
    def __init__(self, client_socket,client_id, client_nonce,client_key,server_id,msg_server_key):
        super().__init__(ResponsePayloadCodes.SendingSymmetricKey.value)
        
        logging.info("in SendingSymmetricKey")
        
        self.client_socket = client_socket
        self.payload_size= SEND_KEY_SIZE
        AES_key=get_random_bytes(32)

        
        client_id=client_id
        encrypted_key= create_encrypt_key(client_nonce,client_key,AES_key)
        ticket=create_ticket(client_id,server_id,msg_server_key,AES_key)
        
        packed_data = struct.pack('16s56s97s', client_id, encrypted_key, ticket)
        self.client_socket.send(packed_data)
        
        
        
def create_encrypt_key(client_nonce,client_key,AES_key):
    
    random_IV = get_random_bytes(16)
    
    encrypted_nonce= encrypt_message(random_IV,client_key,client_nonce)
    logging.info("encrypted_nonce=" + encrypted_nonce)
    encrypted_key= encrypt_message(random_IV,client_key,AES_key)    
    encrypted_key_pack =encrypted_key_pack(random_IV, encrypted_nonce, encrypted_key)
    return encrypted_key_pack


 
def encrypted_key_pack(IV, Nonce, AES_key):
    # pack_objects(obj1, obj2, obj3):
 
    if not (len(IV) == 16 and len(Nonce) == 8 and len(AES_key) == 32):
        raise ValueError("Invalid input sizes. Ensure IV is 16 bytes, Nonce is 8 bytes, and AES_key is 32 bytes.")
    
    # The format string '16s8s32s' indicates three sequences of bytes of lengths 16, 8, and 32.
    # 's' stands for 'string' which is used for bytes objects in Python struct.
    packed_data = struct.pack('16s8s32s', IV, Nonce, AES_key)
    return packed_data


def encrypt_message(iv, key, message):

    # Ensure the inputs are in the correct format
    if not isinstance(message, bytes):
        message = message.encode()  # Convert str to bytes if necessary
    
    if not isinstance(iv, bytes) or not isinstance(key, bytes):
        raise TypeError("IV and key must be bytes.")

    # Create a new AES cipher instance
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Encrypt the message
    # The 'pad' method will pad the message to be a multiple of AES.block_size
    encrypted_message = cipher.encrypt(pad(message, AES.block_size))
    return encrypted_message

def create_ticket(client_id,server_id,msg_server_key,AES_key):
    logging.info("ticket")
    Version=24
    client_id=client_id
    server_id= server_id
    creation_time=datetime.now()
    ticket_IV=get_random_bytes(16)
    AES_key= encrypt_message(ticket_IV,msg_server_key,AES_key)
    two_weeks_later = datetime.now() + timedelta(weeks=2)
    expiration_time=encrypt_message(ticket_IV,msg_server_key,two_weeks_later)
    packed_data = struct.pack('1s16s16s8s16s32s8s', Version, client_id, server_id,creation_time,ticket_IV,AES_key,expiration_time)
    return packed_data
    



      
        


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
    

        
