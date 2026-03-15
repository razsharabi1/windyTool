import socket

class ServerBase:
    def __init__(self, host='localhost', port=12345):
        self.host = host
        self.port = port
        self.server_socket = None

    def start_server(self):
        """Start the server and listen for incoming connections."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Server started on {self.host}:{self.port}")

    def accept_connections(self):
        """Accept incoming connections and handle them."""
        while True:
            client_socket, addr = self.server_socket.accept()
            print(f"Connection accepted from {addr}")
            # Handle the client connection in a separate thread or process
            # For simplicity, we will just close the connection here
            client_socket.close()





def main():
    server = ServerBase()
    server.start_server()
    server.accept_connections()

if __name__ == "__main__":
    main()