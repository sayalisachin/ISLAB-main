#Implement a secure messaging system where RSA is used for key exchange, and AES is used for encrypting the actual messages. Demonstrate the process with a client-server model.

#server.py
import socket
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64

# Function to decrypt AES-encrypted messages using a given key
def decrypt_aes(encrypted_msg, aes_key):
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=encrypted_msg[:16])  # Using the first 16 bytes as IV
    decrypted = unpad(cipher.decrypt(encrypted_msg[16:]), AES.block_size)
    return decrypted.decode()

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

    # Receive AES-encrypted message from the client
    encrypted_message_json = client_socket.recv(4096).decode()
    encrypted_message = json.loads(encrypted_message_json)

    # Decrypt the AES key with the RSA private key
    encrypted_aes_key = base64.b64decode(encrypted_message['aes_key'])
    aes_key = private_key.decrypt(encrypted_aes_key)

    # Decrypt the actual message
    encrypted_msg = base64.b64decode(encrypted_message['message'])
    decrypted_msg = decrypt_aes(encrypted_msg, aes_key)

    print(f"Received message: {decrypted_msg}")

    client_socket.close()

#client
import socket
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# Function to encrypt messages with AES
def encrypt_aes(message, aes_key):
    cipher = AES.new(aes_key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(message)
    iv = cipher.iv
    return iv + ct_bytes  # Prepend IV to the ciphertext

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

# Prepare the message to send
message = b'This is a secret message.'
padded_message = message + b'\x00' * (16 - len(message) % 16)  # Padding to make it a multiple of 16 bytes
encrypted_msg = encrypt_aes(padded_message, aes_key)
encrypted_msg_b64 = base64.b64encode(encrypted_msg).decode()

# Send the encrypted AES key and the encrypted message as JSON
data = json.dumps({
    'aes_key': encrypted_aes_key_b64,
    'message': encrypted_msg_b64
})
client_socket.send(data.encode())

client_socket.close()
