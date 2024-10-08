#An e-commerce platform wants to secure payment transactions. Create a solution that uses TLS for secure communication between the client and server, RSA for key exchange, and AES for encrypting sensitive payment information.
#server
import socket
import ssl
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

class SecurePaymentServer:
    def __init__(self, host='localhost', port=65432):
        self.host = host
        self.port = port
        self.server_cert = 'server.crt'
        self.server_key = 'server.key'
        self.rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    def start_server(self):
        # Create a TLS context
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=self.server_cert, keyfile=self.server_key)

        # Create a socket and bind it to the host and port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            sock.bind((self.host, self.port))
            sock.listen(5)
            print("Server is listening...")

            with context.wrap_socket(sock, server_side=True) as secure_sock:
                while True:
                    conn, addr = secure_sock.accept()
                    print(f"Connection from {addr}")
                    self.handle_client(conn)

    def handle_client(self, conn):
        with conn:
            # Receive the encrypted AES key
            encrypted_aes_key = conn.recv(256)

            # Decrypt the AES key using the server's RSA private key
            aes_key = self.rsa_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            
            # Receive the encrypted payment data
            iv = conn.recv(16)  # AES block size for IV
            encrypted_payment_data = conn.recv(1024)

            # Decrypt the payment data
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_payment_data = decryptor.update(encrypted_payment_data) + decryptor.finalize()

            print(f"Received payment data: {decrypted_payment_data.decode('utf-8')}")

if __name__ == "__main__":
    server = SecurePaymentServer()
    server.start_server()

#client
import socket
import ssl
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

class SecurePaymentClient:
    def __init__(self, host='localhost', port=65432):
        self.host = host
        self.port = port

    def generate_aes_key(self):
        return os.urandom(32)  # AES-256

    def encrypt_payment_data(self, aes_key, payment_data):
        iv = os.urandom(16)  # AES block size
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Ensure payment data length is a multiple of block size
        pad_length = 16 - len(payment_data) % 16
        padded_payment_data = payment_data + (pad_length.to_bytes(1, 'big') * pad_length)

        encrypted_payment_data = encryptor.update(padded_payment_data.encode('utf-8')) + encryptor.finalize()
        return iv, encrypted_payment_data

    def start_client(self):
        # Create RSA key pair
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        public_key = rsa_key.public_key()

        # Connect to the server
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            with ssl.wrap_socket(sock) as secure_sock:
                secure_sock.connect((self.host, self.port))
                
                # Generate AES key and encrypt it using the server's public key
                aes_key = self.generate_aes_key()
                encrypted_aes_key = public_key.encrypt(
                    aes_key,
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )
                secure_sock.send(encrypted_aes_key)

                # Prepare payment data
                payment_data = "User1234: $100.00"  # Example payment data
                iv, encrypted_payment_data = self.encrypt_payment_data(aes_key, payment_data)

                # Send the IV and the encrypted payment data
                secure_sock.send(iv)
                secure_sock.send(encrypted_payment_data)

if __name__ == "__main__":
    client = SecurePaymentClient()
    client.start_client()
