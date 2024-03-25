import socket
import logging
import json
import struct
import hashlib
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
from request import Request
import secrets
class Client:
    def __init__(self):
        self.client_id="4a0fbcea-05a8-4628-9b52-d55fa35c8763"
        self.msg_server_id='123195f2-e740-40a2-8c8b-daa624f35123'
        self.get_info()
        self.connect_to_auth_server()
        self.read_me_file()
        self.connect_to_msg_server()

        #self.send_register_request()
        #regist_response = self.receive_register_response()
        
        self.send_symmetrickey_request()
        self.key_respone= self.receive_and_process_key_response()
        
        #self.send_ticket_to_msg_server()
        #self.get_answer()

        #self.send_msg_to_msg_server()
        #self.get_answer()


   
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
                request = Request(self.client_id, 24, 1027, 24,[ self.msg_server_id ,nonce ] )
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
                self.client_id = payload_data
                print("Registration successful. Client ID:", self.client_id.hex())
                return {'version': version, 'code': code, 'client_id': self.client_id}
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
                
    def send_ticket_to_msg_server(self):
                logging.info("sending ticket")
                client_id_bytes=self.client_id.encode()
                version=24
                version_bytes=version.to_bytes(1, 'big')
                code= 1028
                code_bytes=code.to_bytes(2, 'big')
                payload_size=154
                payload_size_bytes= payload_size.to_bytes(1, 'big')
                ticket=self.key_respone['ticket']
                
                msg_server_key=self.key_respone['decrypted_aes_key']
                authenticator= self.pack_authenticator(version_bytes, msg_server_key, client_id_bytes, self.msg_server_id)

                packed_send_ticket = struct.pack(
                        '16s1s2s4s97s57s',
                        client_id_bytes,
                        version_bytes,
                        code_bytes,
                        payload_size_bytes,
                        ticket,
                        authenticator,
                    )
                self.msgServer_socket.send(packed_send_ticket)
                logging.info("send ticket")
                
    def pack_authenticator(self,version_bytes, msg_server_key, client_id, msg_server_id):
                # Generate the IV for the authenticator
                authenticator_IV = get_random_bytes(16)

                # Encrypt various components with the message server key
                # Note: Assuming 'encrypt_message' function returns byte data
                authenticator_version = self.encrypt_message(authenticator_IV,msg_server_key, version_bytes)
                authenticator_client_id = self.encrypt_message(authenticator_IV, msg_server_key, client_id)
                authenticator_msg_server_id = self.encrypt_message(authenticator_IV, msg_server_key, msg_server_id)
                creation_time_bytes = int(datetime.now().timestamp()).to_bytes(8, 'big')  # Convert current time to 8-byte format
                authenticator_creation_time = self.encrypt_message(authenticator_IV, msg_server_key, creation_time_bytes)

                # Pack all elements into a single binary structure
                packed_authenticator = struct.pack(
                    '16s1s16s16s8s',
                    authenticator_IV,
                    authenticator_version[:1],  # Slice first byte if more than one byte
                    authenticator_client_id,
                    authenticator_msg_server_id,
                    authenticator_creation_time
                )

                return packed_authenticator

                
    def send_msg_to_msg_server(self):
                client_id_bytes=self.client_id.encode()
                version=24
                version_bytes=version.to_bytes(1, 'big')
                code= 1029
                code_bytes=code.to_bytes(2, 'big')
                
                massage= "bring them home now"
                massage_bytes= massage.encode()
                massage_IV = get_random_bytes(16)
                msg_server_key=self.key_respone['decrypted_aes_key']
                encrypt_msg=self.encrypt_message(massage_IV,msg_server_key, massage_bytes)
                message_size=(len(encrypt_msg)) 
                
                payload_size=20+message_size
                payload_size_bytes= payload_size.to_bytes(1, 'big')
                
                packed_send_msg = struct.pack(
                        '16s1s2s4s4s16s{message_size}s',
                        client_id_bytes,
                        version_bytes,
                        code_bytes,
                        payload_size_bytes,
                        message_size,
                        massage_IV,
                        encrypt_msg,
                    )
                self.msgServer_socket.send(packed_send_msg)
                logging.info("sending massage")
            
    def get_answer(self):
                rec_code=self.msgServer_socket.recv(2)
                if rec_code==1604:
                    print("The msg_server received the symmetric key")
                elif rec_code==1605:
                    print("The msg_server received the massage")
                elif rec_code==1609:
                    print("There is a error in the msg_server")
                
                
    def encrypt_message(self,iv, key, message):
                # Convert message to bytes if it's a datetime object or a string
                
                if isinstance(message, str):
                    message_bytes = message.encode()  # Convert string to bytes if necessary
                elif isinstance(message, bytes):
                    message_bytes = message
                else:
                    raise TypeError("Message must be a datetime, str, or bytes object.")

                # Ensure the IV and key are bytes
                if not (isinstance(iv, bytes) and isinstance(key, bytes)):
                    raise TypeError("IV and key must be bytes.")

                # Create a new AES cipher instance
                cipher = AES.new(key, AES.MODE_CBC, iv)

                # Encrypt the message with padding
                encrypted_message = cipher.encrypt(pad(message_bytes, AES.block_size))
                return encrypted_message