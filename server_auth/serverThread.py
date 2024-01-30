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
                # while True:
                self.handle_request()
              except Exception as err:
                        logging.error(err)
        
        def send(self, package: bytes):
            self.client_socket.send(package)

        def handle_request(self):
            logging.info("handle request")  
            self.request = self.client_socket.recv(2042)
            logging.info(self.request)  
            self.unpack_request()

        def unpack_request(self):
            logging.info("unpack request")  
            unpacked_data = struct.unpack("!16s B H I 255s 255s", self.request)
            clientID = unpacked_data[0].decode('utf-8').rstrip('\x00')
            version = unpacked_data[1]
            code = unpacked_data[2]
            payload_size = unpacked_data[3]
            payload_0 = unpacked_data[4].decode('utf-8').rstrip('\x00')
            payload_1 = unpacked_data[5].decode('utf-8').rstrip('\x00')
            # logging.info(clientID, version, code, payload_size, payload_0, payload_1)  



            return clientID, version, code, payload_size, payload_0, payload_1

            #read_header unpack header and payload ,send errors if not good header
            #according to code send to appropriate request                                         
