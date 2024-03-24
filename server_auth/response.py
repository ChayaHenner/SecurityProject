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
        else:
            payload_bytes = self.payload
        
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
        #print("Packed Data:")
        #self.print_packed_data(packed_data)
        logging.info("regist success done!")

        
        
        
class ResponseRegistrationFailed(Response):
    def __init__(self, client_socket):
        super().__init__(ResponsePayloadCodes.RegistrationFailed.value)
        
        logging.info("in regist failed")
        
        self.client_socket = client_socket
        packed_data = self.pack(self.payload_size)
        self.client_socket.send(packed_data)
        #print("Packed Data:")
        #self.print_packed_data(packed_data)  # Print the packed data
        logging.info("regist failed done!")

class ResponseSendingSymmetricKey(Response):
    def __init__(self, client_socket,client_id, client_nonce,client_key,server_id,msg_server_key):
        super().__init__(ResponsePayloadCodes.SendingSymmetricKey.value)
        
        logging.info("in SendingSymmetricKey")
        
        self.client_socket = client_socket      
        self.payload_size= SEND_KEY_SIZE       
        client_key=client_key.encode()
        AES_key=get_random_bytes(32)
        client_nonce= client_nonce.encode()
        
        client_id=client_id
        logging.info("working till here")
        logging.info(client_nonce)
        logging.info(client_key)
        logging.info(AES_key)
        encrypted_key_package= get_encryp(client_nonce,client_key,AES_key)
        logging.info("encrypted_key created")
  
        ticket=create_ticket(client_id,server_id,msg_server_key,AES_key)
        logging.info("ticket created")

        packed_data = struct.pack('16s56s97s', client_id, encrypted_key_package, ticket)
        logging.info("pack created")

        #self.client_socket.send(packed_data)
        
def get_encryp(massage,key,AES_key):
    random_IV = get_random_bytes(16)
    encrypted_nonce= encrypt_message(random_IV,key,massage)
    encrypted_key= encrypt_message(random_IV,key,AES_key) 
    encrypted_k_pack =encrypted_key_pack(random_IV, encrypted_nonce, encrypted_key)
    return encrypted_k_pack       
        
def create_encrypted_key(massage,key,AES_key):
    logging.INFO("in encrypted key")
    logging.INFO(massage)
    logging.INFO(key) 
    logging.INFO(AES_key) 
    random_IV = get_random_bytes(16)
    
    encrypted_nonce= encrypt_message(random_IV,key,massage)
    logging.info("encrypted_nonce=" + encrypted_nonce)
    encrypted_key= encrypt_message(random_IV,key,AES_key)    
    encrypted_k_pack =encrypted_key_pack(random_IV, encrypted_nonce, encrypted_key)
    return encrypted_k_pack


 
def encrypted_key_pack(IV, Nonce, AES_key):
    packed_data = struct.pack('16s8s32s', IV, Nonce, AES_key)
    return packed_data


def encrypt_message(iv, key, message):
    if isinstance(message, datetime):
        massage_bytes = message.isoformat().encode()
    # Ensure the inputs are in the correct format
    elif not isinstance(message, bytes):
        massage_bytes = message.encode()  # Convert str to bytes if necessary
    else:
        massage_bytes=message
    if not isinstance(iv, bytes) or not isinstance(key, bytes):
        raise TypeError("IV and key must be bytes.")

    # Create a new AES cipher instance
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Encrypt the message
    # The 'pad' method will pad the message to be a multiple of AES.block_size
    encrypt_message = cipher.encrypt(pad(massage_bytes, AES.block_size))
    return encrypt_message

def create_ticket(client_id,server_id,msg_server_key,AES_key):
    logging.info("ticket")
    Version=24
    Version=Version.to_bytes(1, 'big')
    client_id_bytes=client_id.encode()
    server_id_bytes= server_id.encode()
    
    creation_time=datetime.now()

    ticket_IV=get_random_bytes(16)
    msg_server_key_bytes=msg_server_key.encode()[:16]
    AES_key= encrypt_message(ticket_IV,msg_server_key_bytes,AES_key)
    logging.info("ttt")
    two_weeks_from_now = creation_time + timedelta(weeks=2)
    creation_time = creation_time.isoformat().encode()
    expiration_time=encrypt_message(ticket_IV,msg_server_key_bytes,two_weeks_from_now)
    logging.info("time")
    packed_data = struct.pack('1s16s16s8s16s32s8s', Version, client_id_bytes, server_id_bytes,creation_time,ticket_IV,AES_key,expiration_time)
    return packed_data
    



      
        




        
