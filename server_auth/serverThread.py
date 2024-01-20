import threading
from threading import Thread
import logging 
logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.NOTSET)

class ServerThread(Thread):
        def __init__(self, client_socket):
            super().__init__(name='client_socket', daemon=True)
            self.client_socket = client_socket

            logging.info("Server Thread ID " + str(threading.current_thread().ident))

        def run(self):
              try:
                    while True:
                          self.handle_request()
              except Exception as err:
                        logging.error(err)
                        #close connection 
        
        def handle_request(self):
            logging.info("handle request")  
            #read_header unpack header and payload ,send errors if not good header
            #according to code send to appropriate request                                         
