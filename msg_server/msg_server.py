import logging
import socket
import struct
from msgServerThread import msgServerThread
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
class msg_server:
    def __init__(self):
        logging.info("connecting to msg server")
        self.port = 1267 
        self.get_auth_server_info()
        self.create_socket()
        
    def get_auth_server_info(self):
        file_path = "msg.info.txt"
        try:
            with open(file_path, 'r') as file:
                lines = file.readlines()
                self.auth_server_address, self.auth_server_port = lines[0].strip().split(':')
                self.auth_server_port=int(self.auth_server_port)
                self.auth_server_name = lines[1]
                self.auth_server_code = lines[2]
                self.auth_server_key = lines[3]
        except Exception as e:
            logging.error(f"Error reader msg server info: {e}")
    
    def create_socket(self):
        try:
            self.msg_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.msg_server_socket.bind(('localhost', self.port))
            print(f"Socket created and bound to port {self.port}")
            self.msg_server_socket.listen(1)

            while True:
                client_socket, client_address = self.msg_server_socket.accept()
                logging.info(f"New client on {client_address}.")
                msgServerThread(client_socket,self.auth_server_key).start()
        except Exception as e:
            logging.error(f"Error creating socket: {e}")

