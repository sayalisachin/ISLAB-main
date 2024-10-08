#Create a Python program that securely transfers a file between two parties using RSA for key exchange and AES for file encryption.
#server
import socket
import os
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64

# Function to decrypt AES-encrypted files
def decrypt_file(encrypted_file_path, decrypted_file_path, aes_key):
    with open(encrypted_file_path, 'rb') as f:
        iv = f.read(16)  # Read the IV
        encrypted_data = f.read()  # Read the remaining encrypted data

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

    with open(decrypted_file_path, 'wb') as f:
        f.write(decrypted_data)

# Set up the server
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen(1)
print("Server listening on port 12345...")

# Generate RSA keys
private_key = RSA.generate(2048)
public_key = private_key.publickey()

while True:
    client_socket, addr = server_socket.accept()
    print(f"Connection from {addr} has been established!")

    # Send public RSA key to the client
    client_socket.send(public_key.export_key())

    # Receive encrypted file metadata
    file_metadata = client_socket.recv(1024).decode()
    file_info = json.loads(file_metadata)

    # Decrypt the AES key with the RSA private key
    encrypted_aes_key = base64.b64decode(file_info['aes_key'])
    aes_key = private_key.decrypt(encrypted_aes_key)

    # Receive the encrypted file
    with open("encrypted_file.enc", 'wb') as f:
        while True:
            data = client_socket.recv(4096)
            if not data:
                break
            f.write(data)

    # Decrypt the received file
    decrypt_file("encrypted_file.enc", "decrypted_file.txt", aes_key)
    print(f"File received and decrypted as 'decrypted_file.txt'")

    client_socket.close()

#client
import socket
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# Function to encrypt files with AES
def encrypt_file(file_path, aes_key):
    cipher = AES.new(aes_key, AES.MODE_CBC)
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    padded_plaintext = plaintext + (b'\x00' * (AES.block_size - len(plaintext) % AES.block_size))  # Padding
    ciphertext = cipher.encrypt(padded_plaintext)

    return cipher.iv + ciphertext  # Prepend IV to the ciphertext

# Set up the client
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 12345))

# Receive the public RSA key from the server
public_key = RSA.import_key(client_socket.recv(2048))

# Generate a random AES key
aes_key = get_random_bytes(16)  # 128-bit key

# Encrypt the AES key with the server's RSA public key
encrypted_aes_key = public_key.encrypt(aes_key, 32)[0]
encrypted_aes_key_b64 = base64.b64encode(encrypted_aes_key).decode()

# Specify the file to send
file_path = 'file_to_send.txt'  # Change this to the file you want to send
encrypted_file = encrypt_file(file_path, aes_key)

# Send the encrypted AES key and file metadata
file_info = {
    'aes_key': encrypted_aes_key_b64,
    'file_name': file_path
}
client_socket.send(json.dumps(file_info).encode())

# Send the encrypted file
client_socket.send(encrypted_file)

client_socket.close()
