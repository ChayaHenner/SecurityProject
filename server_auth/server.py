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
        self.get_msg_server_info()
        self.read_client_info()
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
    
    def get_msg_server_info(self):
        file_path = "msg.info.txt"
        try:
            with open(file_path, 'r') as file:
                lines = file.readlines()
                self.msg_server_address, self.msg_server_port = lines[0].strip().split(':')
                self.msg_server_port=int(self.msg_server_port)
                self.msg_server_name = lines[1]
                self.msg_server_code = lines[2]
                self.msg_server_key = lines[3]
        except Exception as e:
            logging.error(f"Error reader msg server info: {e}")
    
    def read_client_info(self):
        self.clients = []
#do we need to do with pack?
        try:
            with open("clients.txt", 'r') as file:
                for line in file:
                    fields = line.strip().split(':')
                    client_info = {
                            'ID': fields[0],
                            'Name': fields[1],
                            'PasswordHash': fields[2],
                            'LastSeen': ':'.join(fields[3:]) 
                        }
                    self.clients.append(client_info)
                print(self.clients)
        except FileNotFoundError:
            print(f"File clients not found.")
        except Exception as e:
            print(f"Error reading file clients: {e}")



    
    def create_socket(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind(('localhost', self.port))
            print(f"Socket created and bound to port {self.port}")
            self.server_socket.listen(1)

            while True:
                client_socket, client_address = self.server_socket.accept()
                logging.info(f"New client on {client_address}.")
                ServerThread(client_socket,self.clients).start()
                # request = client_socket.recv(1024)
                # # name = client_socket.recv(1024).decode('utf-8')
                # logging.info(f"got request: {request} from {client_address}")
                # unpacked_data = struct.unpack(f"!16s B H I {len(request) - struct.calcsize('!16s B H I ')}s", request)
                # clientID, version, code, payload_size, payload = unpacked_data
                # logging.info(f"got request:client id {clientID.decode('utf-8')} version {version} code {code } payload {payload.decode('utf-8')} payload_size {payload_size}")


        except Exception as e:
            logging.error(f"Error creating socket: {e}")
