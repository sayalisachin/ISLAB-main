# Install necessary libraries
# pip install pycryptodome phe

from Crypto.Cipher import AES
from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Hash import MD5
from phe import paillier  # Paillier library for homomorphic encryption
import pickle

# AES Encryption/Decryption
def generate_aes_key():
    return get_random_bytes(16)  # 16 bytes for AES-128

def aes_encrypt(key, data):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce, ciphertext, tag

def aes_decrypt(key, nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_data

# MD5 Hashing
def compute_md5_hash(data):
    return MD5.new(data).digest()

# ElGamal Signing (with placeholder verification for demo)
def generate_elgamal_key():
    key = ElGamal.generate(2048, get_random_bytes)
    return key

def elgamal_sign(private_key, data_hash):
    signature = private_key.sign(data_hash, get_random_bytes(32))
    return signature

def elgamal_verify(public_key, data_hash, signature):
    return public_key.verify(data_hash, signature)

# Paillier Homomorphic Encryption
def paillier_encrypt(public_key, value):
    return public_key.encrypt(value)

def paillier_decrypt(private_key, encrypted_value):
    return private_key.decrypt(encrypted_value)

def paillier_homomorphic_add(public_key, encrypted_value1, encrypted_value2):
    return encrypted_value1 + encrypted_value2

# Client Side
def client_send_data(data, elgamal_private_key, aes_key, paillier_public_key):
    # AES encrypt the data
    nonce, ciphertext, tag = aes_encrypt(aes_key, data)

    # Generate MD5 hash of the ciphertext for signing
    data_hash = compute_md5_hash(ciphertext)

    # ElGamal sign the hash
    signature = elgamal_sign(elgamal_private_key, data_hash)

    # Homomorphic Encryption example
    encrypted_value1 = paillier_encrypt(paillier_public_key, 10)  # Encrypted value of 10
    encrypted_value2 = paillier_encrypt(paillier_public_key, 20)  # Encrypted value of 20
    homomorphic_sum = paillier_homomorphic_add(paillier_public_key, encrypted_value1, encrypted_value2)

    # Package data for sending to the server
    data_package = {
        'nonce': nonce,
        'ciphertext': ciphertext,
        'tag': tag,
        'signature': signature,
        'homomorphic_sum': homomorphic_sum,
    }

    # Serialize data package (in practice, send this over network)
    with open("data_package.pkl", "wb") as file:
        pickle.dump(data_package, file)
    print("Data package sent to server (saved to file).")

# Server Side
def server_receive_data(data_package_path, elgamal_public_key, aes_key, paillier_private_key):
    # Load data package
    with open(data_package_path, "rb") as file:
        data_package = pickle.load(file)

    nonce = data_package['nonce']
    ciphertext = data_package['ciphertext']
    tag = data_package['tag']
    signature = data_package['signature']
    homomorphic_sum = data_package['homomorphic_sum']

    # Verify ElGamal signature
    data_hash = compute_md5_hash(ciphertext)
    if elgamal_verify(elgamal_public_key, data_hash, signature):
        print("Signature verified successfully.")
        
        # AES Decrypt the data
        decrypted_data = aes_decrypt(aes_key, nonce, ciphertext, tag)
        print("Decrypted Data:", decrypted_data.decode())

        # Paillier Decryption of the Homomorphic Sum
        decrypted_sum = paillier_decrypt(paillier_private_key, homomorphic_sum)
        print("Decrypted Homomorphic Sum (10 + 20):", decrypted_sum)
    else:
        print("Signature verification failed.")

# Main Program
if __name__ == "__main__":
    # Generate AES Key
    aes_key = generate_aes_key()

    # Generate ElGamal Key Pair
    elgamal_key = generate_elgamal_key()
    elgamal_private_key = elgamal_key
    elgamal_public_key = elgamal_key.publickey()

    # Generate Paillier Key Pair
    paillier_public_key, paillier_private_key = paillier.generate_paillier_keypair()

    # Client encrypts and sends data
    data = b"Patient data for secure transmission"
    client_send_data(data, elgamal_private_key, aes_key, paillier_public_key)

    # Server receives and verifies data
    server_receive_data("data_package.pkl", elgamal_public_key, aes_key, paillier_private_key)
/*
The code includes:

AES Encryption/Decryption for data confidentiality.
ElGamal Signing and Verification for data integrity and authenticity.
MD5 Hashing for creating a hash of the data.
Paillier Homomorphic Encryption for performing homomorphic addition on encrypted data.
*/