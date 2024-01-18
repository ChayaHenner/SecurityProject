import socket
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
from request import Request

class Client:
    def __init__(self):
        self.get_info()
        self.connect_to_server()
   
    def get_info(self):
        file_path = "me.info.txt"
        try:
            with open(file_path, 'r') as file:
                lines = file.readlines()
                self.server_address, self.server_port = lines[0].strip().split(':')
                self.server_port=int(self.server_port)
                self.client_name = lines[1].strip()
                self.id = lines[2].strip()
        except FileNotFoundError:
            logging.error(f"Error: {file_path} not found.")
        except Exception as e:
            logging.error(f"An error occurred while reading client info: {e}")

    def connect_to_server(self):
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((self.server_address, self.server_port))
            # client_socket.send(self.client_name.encode('utf-8'))
            # client_socket.close()
            client_id = "1234567890123456"  # 16 characters
            version = 2  # 1 byte
            code = 1025  # 2 bytes
            payload_size = 10  # 4 bytes
            payload = "sari"  # Variable size

            request_instance = Request(client_id, version, code, payload_size, payload)
            packed_data = request_instance.pack()
            client_socket.send(packed_data)

        except Exception as e:
            logging.error(f"Error connecting to the server: {e}")

