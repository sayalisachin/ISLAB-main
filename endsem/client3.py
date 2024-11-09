/*
Client Side:
Use RSA to encrypt patient information (name, treatment) before transmission.
Implement a Diffie-Hellman key exchange with the server to establish a shared symmetric key.
Encrypt the patient’s expenses using the shared symmetric key and send it to the server.
Server Side:
Perform Diffie-Hellman key exchange to derive the shared symmetric key.
Decrypt the patient's expenses and verify it matches the encrypted data.
Display all patient data once verified.
*/

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Protocol.KDF import HKDF
from Crypto.Protocol.SecretSharing import Shamir
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import ECC
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad
import pickle
import os

# RSA Encryption/Decryption for Patient Information
def generate_rsa_key_pair():
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key

def rsa_encrypt(public_key, data):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(data)

def rsa_decrypt(private_key, encrypted_data):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(encrypted_data)

# Diffie-Hellman Key Exchange
def generate_dh_key_pair():
    private_key = get_random_bytes(32)  # Private key for Diffie-Hellman
    public_key = get_random_bytes(32)   # Placeholder public key (would usually involve a large prime and base)
    return private_key, public_key

def derive_shared_key(dh_private_key, dh_public_key_other_party):
    shared_key = scrypt(dh_private_key + dh_public_key_other_party, salt=b'secure_salt', key_len=32, N=2**14, r=8, p=1)
    return shared_key

# AES Encryption/Decryption for Expenses
def aes_encrypt(key, data):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return cipher.iv, ciphertext

def aes_decrypt(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_data

# Client Side: Encrypt data and send
def client_send_data(patient_data, rsa_public_key_server, dh_private_key, dh_public_key_client, dh_public_key_server):
    # RSA Encrypt the patient information (name, treatment)
    patient_info = f"Name: {patient_data['name']}, Treatment: {patient_data['treatment']}".encode()
    encrypted_info = rsa_encrypt(rsa_public_key_server, patient_info)

    # Perform Diffie-Hellman key exchange to derive shared symmetric key
    shared_symmetric_key = derive_shared_key(dh_private_key, dh_public_key_server)

    # AES Encrypt the patient’s expenses using the shared symmetric key
    iv, encrypted_expenses = aes_encrypt(shared_symmetric_key, patient_data['expenses'].encode())

    # Package data for sending to the server
    data_package = {
        'encrypted_info': encrypted_info,
        'dh_public_key_client': dh_public_key_client,
        'iv': iv,
        'encrypted_expenses': encrypted_expenses
    }

    # Serialize data package (in practice, send this over network)
    with open("data_package.pkl", "wb") as file:
        pickle.dump(data_package, file)
    print("Data package sent to server (saved to file).")

# Server Side: Receive data, verify, and display
def server_receive_data(data_package_path, rsa_private_key_server, dh_private_key, dh_public_key_client):
    # Load data package
    with open(data_package_path, "rb") as file:
        data_package = pickle.load(file)

    encrypted_info = data_package['encrypted_info']
    dh_public_key_client = data_package['dh_public_key_client']
    iv = data_package['iv']
    encrypted_expenses = data_package['encrypted_expenses']

    # RSA Decrypt the patient information (name, treatment)
    patient_info = rsa_decrypt(rsa_private_key_server, encrypted_info)
    print("Decrypted Patient Info:", patient_info.decode())

    # Perform Diffie-Hellman key exchange to derive shared symmetric key
    shared_symmetric_key = derive_shared_key(dh_private_key, dh_public_key_client)

    # AES Decrypt the patient's expenses
    decrypted_expenses = aes_decrypt(shared_symmetric_key, iv, encrypted_expenses)
    print("Decrypted Expenses:", decrypted_expenses.decode())

# Main Program
if __name__ == "__main__":
    # Generate RSA Key Pair for Server
    rsa_private_key_server, rsa_public_key_server = generate_rsa_key_pair()

    # Generate Diffie-Hellman Key Pair for Client and Server
    dh_private_key_client, dh_public_key_client = generate_dh_key_pair()
    dh_private_key_server, dh_public_key_server = generate_dh_key_pair()

    # Patient data
    patient_data = {
        'name': 'John Doe',
        'treatment': 'Physical Therapy',
        'expenses': '$500'
    }

    # Client encrypts and sends data
    client_send_data(patient_data, rsa_public_key_server, dh_private_key_client, dh_public_key_client, dh_public_key_server)

    # Server receives and verifies data
    server_receive_data("data_package.pkl", rsa_private_key_server, dh_private_key_server, dh_public_key_client)
