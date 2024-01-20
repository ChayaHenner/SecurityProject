import logging
import staticVar
import socket
import struct
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
from serverThread import ServerThread
class Server:
    def __init__(self):
        logging.info("connecting to auth server")
        self.port = staticVar.DEFAULT_PORT 
        self.get_port()
        self.create_socket()
        
    def get_port(self):
        file_path = "port.info.txt"
        try:
            with open(file_path, 'r') as file:
                self.port = int(file.read().strip())
        except FileNotFoundError:
                logging.error(f"Error: {file_path} not found.")
        except ValueError:
            logging.error(f"Error: Unable to parse port number from {file_path}. Make sure the file contains a valid integer.")
        except Exception as e:
            logging.error(f"An error occurred: {e}")
    
    def create_socket(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind(('localhost', self.port))
            print(f"Socket created and bound to port {self.port}")
            self.server_socket.listen(1)

            while True:
                client_socket, client_address = self.server_socket.accept()
                ServerThread(client_socket).start()
                # request = client_socket.recv(1024)
                # # name = client_socket.recv(1024).decode('utf-8')
                # logging.info(f"got request: {request} from {client_address}")
                # unpacked_data = struct.unpack(f"!16s B H I {len(request) - struct.calcsize('!16s B H I ')}s", request)
                # clientID, version, code, payload_size, payload = unpacked_data
                # logging.info(f"got request:client id {clientID.decode('utf-8')} version {version} code {code } payload {payload.decode('utf-8')} payload_size {payload_size}")


        except Exception as e:
            logging.error(f"Error creating socket: {e}")
