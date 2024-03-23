import socket
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
from request import Request
import secrets
class Client:
    def __init__(self):
        self.get_info()
        self.connect_to_auth_server()
        self.read_me_file()

        #self.send_register_request()
        self.send_symmetrickey_request()
   
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
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # logging.info(self.auth_server_port , self.auth_server_address)
            self.client_socket.connect(("127.0.0.1", 8080))
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
            self.client_socket.send(packed_data)

        except Exception as e:
            logging.error(f"Error connecting to the server: {e}")

    def send_symmetrickey_request(self):
        try:
            nonce = secrets.token_bytes(8).hex()
            request = Request("fb080d6b-cc1f-4d44-ae3e-2bde227f712c", 24, 1027, 24,[ '123195f2-e740-40a2-8c8b-daa624f35123' ,nonce ] )
            packed_data = request.pack()
            self.client_socket.send(packed_data)

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

