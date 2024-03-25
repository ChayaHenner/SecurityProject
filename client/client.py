import socket
import logging
import json
import struct
import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
from request import Request
import secrets
class Client:
    def __init__(self):
        self.get_info()
        self.connect_to_auth_server()
        self.read_me_file()

        #self.send_register_request()
        #regist_response = self.receive_register_response()
        self.send_symmetrickey_request()
        key_respone= self.receive_and_process_key_response()
        self.connect_to_msg_server()
   
    def get_info(self):
        file_path = "srv.info.txt"
        try:
            with open(file_path, 'r') as file:
                lines = file.readlines()
                self.auth_server_address, self.auth_server_port = lines[0].strip().split(':')
                self.auth_server_port=int(self.auth_server_port)
                self.msg_server_address, self.msg_server_port = lines[1].strip().split(':')
                self.msg_server_port=int(self.msg_server_port)

        except FileNotFoundError:
            logging.error(f"Error: {file_path} not found.")
        except Exception as e:
            logging.error(f"An error occurred while reading client info: {e}")

    def connect_to_auth_server(self):
        try:
            self.serverAuth_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # logging.info(self.auth_server_port , self.auth_server_address)
            self.serverAuth_socket.connect((self.auth_server_address, self.auth_server_port))
            # client_socket.connect((self.auth_server_address, self.auth_server_port))
            # request = Request("1234567890123456", 2, 1025, 10, "payload")
            # packed_data = request.pack()
            # client_socket.send(packed_data)

        except Exception as e:
            logging.error(f"Error connecting to the server: {e}")
    
    def send_register_request(self):
        try:
            self.read_me_file()            
            request = Request('not matter whats here', 24, 1024, 510,[ self.client_name ,self.client_password ] )
            packed_data = request.pack()
            self.serverAuth_socket.send(packed_data)

        except Exception as e:
            logging.error(f"Error connecting to the server: {e}")

    def send_symmetrickey_request(self):
        try:
            nonce = secrets.token_bytes(8).hex()
            request = Request("4a0fbcea-05a8-4628-9b52-d55fa35c8763", 24, 1027, 24,[ '123195f2-e740-40a2-8c8b-daa624f35123' ,nonce ] )
            packed_data = request.pack()
            self.serverAuth_socket.send(packed_data)

        except Exception as e:
            logging.error(f"Error connecting to the server: {e}")
    
    def read_me_file(self):
        file_path = "me.info.txt"
        try:
            with open(file_path, 'r') as file:
                self.client_name = file.readline().strip()
                self.client_password = file.readline().strip()
        except FileNotFoundError:
                logging.error(f"Error: {file_path} not found.")
        except ValueError:
            logging.error(f"Error: Unable to parse port number from {file_path}. Make sure the file contains a valid integer.")
        except Exception as e:
            logging.error(f"An error occurred: {e}")




    def receive_register_response(self):
        # Header format: version (1 byte), code (2 bytes), payload size (4 bytes)
        header_format = 'B H I'
        header_size = struct.calcsize(header_format)  # Calculate size of the header

        # Receive the header first
        header_data = self.serverAuth_socket.recv(header_size)
        if len(header_data) != header_size:
            raise ValueError("Received incomplete response header from server.")

        # Unpack the header
        version, code, payload_size = struct.unpack(header_format, header_data)

        # Now receive the payload based on the payload size indicated by the header
        payload_data = self.serverAuth_socket.recv(payload_size) if payload_size > 0 else b''

        # Process the response based on the code
        if code == 1600:  # Registration Success
            if len(payload_data) != 16:
                raise ValueError("Invalid client ID length received from server.")
            client_id = payload_data
            print("Registration successful. Client ID:", client_id.hex())
            return {'version': version, 'code': code, 'client_id': client_id}
        elif code == 1601:  # Registration Failed
            print("Registration failed. No payload expected.")
            return {'version': version, 'code': code}
        else:
            print("Received unknown response code from server.")
            return {'version': version, 'code': code}

    # Existing class contents...

    def decrypt_with_aes(self, encrypted_data, key, iv):
        if len(encrypted_data) % 16 != 0:
                raise ValueError("The encrypted AES key is not a multiple of the block size (16 bytes).")

        # Convert the key from string to bytes if it's not already bytes
        if isinstance(key, str):
            key = key.encode('utf-8')
        decryptor = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        ).decryptor()

        # Decrypt the data
        padded_plaintext = decryptor.update(encrypted_data) + decryptor.finalize()

        # Unpad the plaintext
        #unpadder = padding.PKCS7(128).unpadder()  # 128 is the block size for AES
        #plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return padded_plaintext
    
    
    def receive_and_process_key_response(self):
        header_format = 'B H I'
        header_size = struct.calcsize(header_format)
        self.client_password=self.passwordHash(self.client_password)[0:32]
        self.client_password = self.client_password.encode()

        # Receive the header
        header_data = self.serverAuth_socket.recv(header_size)
        version, code, payload_size = struct.unpack(header_format, header_data)

        # Check if code is 1603 for symmetric key response
        if code == 1603:
            # Receive the payload
            payload_data = self.serverAuth_socket.recv(payload_size)

            # Unpack the payload
            client_id, encrypted_key_package, ticket = struct.unpack('16s{}s{}s'.format(16+8+32, payload_size-16-56), payload_data)
            
            # Unpack the encrypted key package
            encrypted_key_iv, nonce, encrypted_aes_key = struct.unpack('16s8s32s', encrypted_key_package)

            # Assuming you have the client's private RSA key
            # For AES, you don't typically "decrypt" the key itself if it's what you sent; you use it directly.
            # However, assuming these are actually RSA encrypted and need to be decrypted:
            print(len(nonce))  
            print(len(encrypted_aes_key))  
            print(len(self.client_password ))  
            print(len(encrypted_key_iv )) 
            
            
            #decrypted_nonce = self.decrypt_with_aes(nonce, self.client_password, encrypted_key_iv)
            decrypted_aes_key = self.decrypt_with_aes(encrypted_aes_key, self.client_password, encrypted_key_iv)
            print("succses unpack' key ")
            # You can now use decrypted_aes_key for further AES operations and store the ticket for future use
            # Note: In real-world applications, ensure you are safely managing and storing cryptographic keys and materials.

            return {
                'client_id': client_id,
                #'decrypted_nonce': decrypted_nonce,
                'decrypted_aes_key': decrypted_aes_key,
                'ticket': ticket  # Stored as-is for now
            }

        else:
            print("Unexpected response code:", code)
            return None

    def passwordHash(self,password):
            encoded_data = password.encode('utf-8')
            # Calculate the SHA256 hash
            sha256_hash = hashlib.sha256()
            sha256_hash.update(encoded_data)
            return sha256_hash.hexdigest()
        
    def connect_to_msg_server(self):
        try:
            self.msgServer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.msgServer_socket.connect((self.msg_server_address, self.msg_server_port))

        except Exception as e:
            logging.error(f"Error connecting to the server: {e}")