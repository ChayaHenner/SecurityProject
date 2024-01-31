import threading
from threading import Thread
import logging 
import struct

logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.NOTSET)

class ServerThread(Thread):
        def __init__(self, client_socket):
            super().__init__(name='client_socket', daemon=True)
            self.client_socket = client_socket
            logging.info("Server Thread ID " + str(threading.current_thread().ident))

        def run(self):
              try:
                while True:#need to always run
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
            self.clientID = unpacked_data[0].decode('utf-8').rstrip('\x00')
            self.version = unpacked_data[1]
            self.code = unpacked_data[2]
            self.payload_size = unpacked_data[3]
            self.payload_0 = unpacked_data[4].decode('utf-8').rstrip('\x00')
            self.payload_1 = unpacked_data[5].decode('utf-8').rstrip('\x00')
            # logging.info(clientID, version, code, payload_size, payload_0, payload_1)  

            # return clientID, version, code, payload_size, payload_0, payload_1

        def proccess_request(self):
            try:
                 match self.code:
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