import threading
from threading import Thread
import logging 
import struct
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.NOTSET)

class msgServerThread(Thread):
        def __init__(self, client_socket, auth_server_key):
            self.auth_server_key=auth_server_key
            super().__init__(name='client_socket', daemon=True)
            self.client_socket = client_socket
            logging.info("Server Thread ID " + str(threading.current_thread().ident))

        def run(self):
              try:
                    self.handle_request()
              except Exception as err:
                        logging.error(err)
        def handle_request(self):
            # logging.info("handle request")  
            try:
                self.request = self.client_socket.recv(2042)
                #logging.info(self.request)  
                self.unpack_request()
                self.proccess_request()
            except Exception as error:
                self.close_connection(error)
        


        def unpack_data(self,pack):
            # Unpack the initial parts of the package
            client_id, version, code, payload_size = struct.unpack('16sBHI', pack[:23])
            payload = pack[23:23 + payload_size]

            # Process according to code
            if code == 1028:  # symmetric_key
                # Unpack the payload for symmetric_key
                auth_IV, auth_version, auth_client_id, auth_server_id, creation_time = struct.unpack('16sB16s16sQ', payload[:57])
                ticket_version, ticket_client_id, ticket_server_id, ticket_creation_time, ticket_IV, AES_key, expiration_time = struct.unpack('B16s16sQ16s32sQ', payload[57:])

                
                

                
                request_data= {
                    'client_id': client_id,
                    'version': version,
                    'code': code,
                    'payload_size': payload_size,
                    'Authenticator': {
                        'IV': auth_IV,
                        'version': auth_version,
                        'client_id': auth_client_id,
                        'server_id': auth_server_id,
                        'creation_time': creation_time
                    },
                    'Ticket': {
                    'version': ticket_version,
                    'client_id': ticket_client_id,
                    'server_id': ticket_server_id,
                    'creation_time': ticket_creation_time,
                    'IV': ticket_IV,
                    'AES_key': AES_key,
                    'expiration_time': expiration_time
                    }
                }
                self.handele_ticket(request_data)

            elif code == 1029:  # print_ask
                # Unpack the payload for print_ask
                message_size, = struct.unpack('I', payload[:4])
                message_IV, message_content = struct.unpack(f'16s{message_size}s', payload[4:])

                request_data=  {
                    'client_id': client_id,
                    'version': version,
                    'code': code,
                    'payload_size': payload_size,
                    'Message': {
                        'size': message_size,
                        'IV': message_IV,
                        'content': message_content
                    }
                }
                self.hendel_prints(request_data)

            else:
                print("Unexpected response code:", code)
                
        def handele_ticket(self,request_data):
            logging.info("handele_ticket")
            self.client_id=request_data['client_id']
            self.ticket_IV=request_data['Ticket']['IV']
            self.client_AES_key= self.decrypt_with_aes(request_data['Ticket']['AES_key'], self.auth_server_key, self.ticket_IV)
            self.expiration_time=self.decrypt_with_aes(request_data['Ticket']['expiration_time'], self.auth_server_key, self.ticket_IV)
            self.expiration_datetime = datetime.fromtimestamp(self.expiration_time)
            if self.expiration_time < datetime.now():
                print("The expiration time has passed.")
                self.client_socket.close()
            client_info={
                'client_id':self.client_id,
                'client_AES_key': self.client_AES_key
            }
            self.clients.append(client_info)
            self.send_succses_semmetrik_key()
            
            
        def hendel_prints(self,request_data):
            logging.info("hendel_prints")
            self.client_key=self.search_for_client(request_data['client_id'])
            massage = self.decrypt_with_aes(request_data['Message']['content'], self.client_key, request_data['Message']['IV'])
            logging.info(massage.decode('utf-8'))
            self.send_succses_printing()
            

            
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
        
        def search_for_client(self,client_id):
            for client in self.clients:
                if client['client_id'][:16] == client_id[:16]:
                    logging.info("faond client")                 
                    return client['client_AES_key']
            raise Exception("Request failed: invalid code request.")
