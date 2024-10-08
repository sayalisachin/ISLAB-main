#Implement a centralized service for managing and distributing keys using the Diffie-Hellman key exchange algorithm. Allow multiple users to securely share keys through the service.
#server
import socket
import threading
from Crypto.Util import number
from Crypto.Hash import SHA256

class KeyDistributionService:
    def __init__(self):
        # Public parameters for Diffie-Hellman
        self.p = number.getPrime(2048)  # A large prime number
        self.g = 2  # A primitive root mod p

        self.user_keys = {}  # Dictionary to store user keys

    def handle_client(self, client_socket):
        # Get the username from the client
        username = client_socket.recv(1024).decode()
        print(f"{username} connected.")

        # Generate a private key for the user
        private_key = number.getRandomRange(1, self.p - 1)
        public_key = pow(self.g, private_key, self.p)

        # Send public key to client
        client_socket.send(str(public_key).encode())

        # Receive the client's public key
        client_public_key = int(client_socket.recv(1024).decode())

        # Calculate the shared secret
        shared_secret = pow(client_public_key, private_key, self.p)
        
        # Store the shared secret for the user
        self.user_keys[username] = shared_secret

        print(f"Shared key for {username}: {shared_secret}")
        client_socket.close()

    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('localhost', 65432))
        server_socket.listen(5)
        print("Key Distribution Service is running...")

        while True:
            client_socket, addr = server_socket.accept()
            thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            thread.start()

if __name__ == "__main__":
    kds = KeyDistributionService()
    kds.start_server()

#client
import socket
from Crypto.Util import number

def diffie_hellman_client(username):
    # Connect to the Key Distribution Service
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 65432))

    # Send the username to the KDS
    client_socket.send(username.encode())

    # Receive the server's public key
    server_public_key = int(client_socket.recv(1024).decode())
    
    # Generate a private key for the client
    private_key = number.getRandomRange(1, 2048)
    public_key = pow(2, private_key, server_public_key)

    # Send the client's public key to the server
    client_socket.send(str(public_key).encode())

    # Receive the shared secret key from the server
    # This part would normally involve further communication to share encrypted messages
    client_socket.close()

if __name__ == "__main__":
    username = input("Enter your username: ")
    diffie_hellman_client(username)


#python key_distribution.py
#python client.py
