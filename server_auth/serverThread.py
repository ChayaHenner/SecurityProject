import threading
from threading import Thread
import logging 
import struct
import uuid
from datetime import datetime

logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.NOTSET)

class ServerThread(Thread):
        def __init__(self, client_socket,clients):
            super().__init__(name='client_socket', daemon=True)
            self.client_socket = client_socket
            self.clients = clients
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
            unpacked_data = struct.unpack("!16s B H I 255s 255s", self.request)
            self.request_info = {
            'clientID': unpacked_data[0].decode('utf-8').rstrip('\x00'),
            'version': unpacked_data[1],
            'code': unpacked_data[2],
            'payload_size': unpacked_data[3],
            'payload_0': unpacked_data[4].decode('utf-8').rstrip('\x00'),
            'payload_1': unpacked_data[5].decode('utf-8').rstrip('\x00')
            }
            # logging.info(clientID, version, code, payload_size, payload_0, payload_1)  

            # return clientID, version, code, payload_size, payload_0, payload_1

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
             else:
                raise Exception("client already exists")
       
        def send_ticket(self):
             logging.info("send ticket")
        
        def check_client_exist(self):
            for client in self.clients:
                if client['ID'] == self.request_info['clientID']:
                    return True
            return False

        
        def create_uuid(self):
            self.uuid=uuid.uuid4()
            logging.info(self.uuid)
        
        def save_client(self):
                logging.info("save client")
                client_info = {
                        'ID': self.request_info['clientID'],
                        'Name': self.request_info['payload_0'],
                        'PasswordHash':self.request_info['payload_1'], #to do sha-256
                        'LastSeen': datetime.now()
                }
                self.clients.append(client_info)

                try:
                    with open('clients.txt', 'a') as file:
                        file.write(f"{client_info['ID']}:{client_info['Name']}:{client_info['PasswordHash']}:{client_info['LastSeen']}\n")
                    print(f"Client '{client_info['ID']}' saved to 'clients'.")
                except Exception as e:
                    print(f"Error saving client to file 'clients': {e}")

