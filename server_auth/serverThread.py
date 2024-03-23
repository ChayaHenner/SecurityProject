import threading
from threading import Thread
import logging 
import struct
import uuid
from datetime import datetime
import os
from response import Response ,ResponseRegistrationSuccess ,ResponseRegistrationFailed,ResponseSendingSymmetricKey
import hashlib
#from Crypto.Hash import SHA256

logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.NOTSET)

class ServerThread(Thread):
        def __init__(self, client_socket,clients,msg_server_key):
            super().__init__(name='client_socket', daemon=True)
            self.client_socket = client_socket
            self.clients = clients
            self.msg_server_key=msg_server_key
            logging.info("Server Thread ID " + str(threading.current_thread().ident))

        def run(self):
              try:
                # while True:#need to always run?
                    self.handle_request()
              except Exception as err:
                        logging.error(err)
        
        def send(self, package: bytes):
            self.client_socket.send(package)

        def handle_request(self):
            # logging.info("handle request")  
            try:
                self.request = self.client_socket.recv(2042)
                logging.info(self.request)  
                self.unpack_request()
                self.proccess_request()
            except Exception as error:
                self.close_connection(error)
                
        def unpack_request(self):
            logging.info("unpack request")
            
            #unpacked_data = struct.unpack("!16s B H I 255s 255s", self.request)
            unpacked_data = struct.unpack("!16s B H I 16s 8s", self.request)

            self.request_info = {
            'clientID': unpacked_data[0].decode('utf-8').rstrip('\x00'),
            'version': unpacked_data[1],
            'code': unpacked_data[2],
            'payload_size': unpacked_data[3],
            'payload_0': unpacked_data[4].decode('utf-8').rstrip('\x00'),
            'payload_1': unpacked_data[5].decode('utf-8').rstrip('\x00')
            }
            logging.info(self.request_info['clientID'])
            logging.info(self.request_info['version'])
            logging.info(self.request_info['code'])
            logging.info(self.request_info['payload_size'])            
            logging.info(self.request_info['payload_0'])
            logging.info(self.request_info['payload_1'])

        def proccess_request(self):
            try:
                 match self.request_info['code']:
                        case 1024:
                           self.register_client()
                        case 1027:
                           self.send_ticket()
                        case _:
                            raise Exception("Request failed: invalid code request.")

            except Exception as error:
                self.close_connection(error)

        def close_connection(self,error):
            logging.error(error)
            logging.info("Client connection is down, du to a fatal error or a protocol error")
            self.client_socket.close()

        def register_client(self):
             logging.info("register client")
             exists=self.check_client_exist()
             if not exists:
                self.create_uuid()
                self.save_client()
                self.response_register_client_success()
             else:
                self.response_register_client_failed()
       
        def send_ticket(self):
            logging.info("send ticket")
            self.req_client=self.search_for_client()          
            self.Response_sending_symmetric_key()
            #self.create_encrypt_AES()
            #self.create_ticket()
            #self.response_send_ticket()
        
        def check_client_exist(self):
            for client in self.clients:
                if client['Name'] == self.request_info['payload_0']:
                    return True
            return False
        
        def search_for_client(self):
            for client in self.clients:
                if client['ID'][:16] == self.request_info['clientID'][:16]:
                    logging.info("faond client")           
                    logging.info(client['ID'][:16])           
                    logging.info(client['PasswordHash'])           
                    return client
            raise Exception("Request failed: invalid code request.")

            
        
        def create_uuid(self):
            self.uuid=uuid.uuid4()
            logging.info(self.uuid)
        
        def save_client(self):
                logging.info("save client")
                client_info = {
                        'ID': self.uuid,
                        'Name': self.request_info['payload_0'],
                        'PasswordHash':self.request_info['payload_1'], 
                        'LastSeen': datetime.now()
                }

                client_info['PasswordHash']=self.passwordHash(client_info['PasswordHash'])[0:32]
                logging.info(client_info['PasswordHash'])
                self.clients.append(client_info)
                try:
                    with open('clients.txt', 'a') as file:
                        file.write(f"{self.uuid}:{client_info['Name']}:{client_info['PasswordHash']}:{client_info['LastSeen']}\n")
                    print(f"Client '{self.uuid}' saved to 'clients'.")
                except Exception as e:
                    print(f"Error saving client to file 'clients': {e}")

        def passwordHash(self,password):
            encoded_data = password.encode('utf-8')
            # Calculate the SHA256 hash
            sha256_hash = hashlib.sha256()
            sha256_hash.update(encoded_data)
            return sha256_hash.hexdigest()

        def response_register_client_success(self):
             logging.info("aaa")
             ResponseRegistrationSuccess(self.uuid, self.client_socket)
              
        def response_register_client_failed(self):
            logging.info("bbb")
            ResponseRegistrationFailed(self.client_socket)
        
        def Response_sending_symmetric_key(self):
            logging.info("ccc")
            ResponseSendingSymmetricKey(self.client_socket,self.req_client['ID'],self.request_info['payload_1'],self.req_client['PasswordHash'],self.request_info['payload_0'],self.msg_server_key)
            

            

            
