/*
AES Encryption/Decryption for data confidentiality.
ElGamal Signing and Verification for data integrity and authenticity.
MD5 Hashing for creating a hash of the data.
Paillier Homomorphic Encryption for performing homomorphic multiplication on encrypted data.
allow search query function.

take user input

pip install pycryptodome phe

*/

from Crypto.Cipher import AES
from Crypto.Hash import MD5
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from phe import paillier
import os

# Generate RSA key for ElGamal-like signing (simulate ElGamal using RSA)
private_key = RSA.generate(2048)
public_key = private_key.publickey()

# Paillier keys for homomorphic encryption
paillier_public_key, paillier_private_key = paillier.generate_paillier_keypair()

# AES key (256-bit)
aes_key = os.urandom(32)

# AES encryption/decryption
def aes_encrypt(data):
    cipher = AES.new(aes_key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return nonce, ciphertext, tag

def aes_decrypt(nonce, ciphertext, tag):
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

# MD5 Hashing
def hash_data(data):
    hasher = MD5.new()
    hasher.update(data.encode())
    return hasher.hexdigest()

# Simulated ElGamal signing (using RSA)
def sign_data(data):
    hash_data = MD5.new(data.encode())
    return pkcs1_15.new(private_key).sign(hash_data)

def verify_signature(data, signature):
    hash_data = MD5.new(data.encode())
    try:
        pkcs1_15.new(public_key).verify(hash_data, signature)
        return True
    except (ValueError, TypeError):
        return False

# Paillier encryption for homomorphic addition
def paillier_encrypt(number):
    return paillier_public_key.encrypt(number)

def paillier_decrypt(encrypted_number):
    return paillier_private_key.decrypt(encrypted_number)

# Homomorphic addition using Paillier encryption
def paillier_homomorphic_addition(encrypted_number1, encrypted_number2):
    return encrypted_number1 + encrypted_number2

# Simulate data entry and processing
def main():
    # User input for patient data
    patient_name = input("Enter patient's name: ")
    patient_treatment = input("Enter patient's treatment: ")
    patient_expenses = int(input("Enter patient's expenses: "))
    
    # Encrypting and hashing data
    nonce, encrypted_treatment, tag = aes_encrypt(patient_treatment)
    hashed_name = hash_data(patient_name)

    # Simulate digital signing
    signature = sign_data(patient_name)

    # Paillier encryption for expenses
    encrypted_expenses = paillier_encrypt(patient_expenses)
    
    # Display data
    print("\n--- Data Summary ---")
    print(f"Encrypted Treatment (AES): {encrypted_treatment}")
    print(f"Hashed Name (MD5): {hashed_name}")
    print(f"Signed Name (Simulated ElGamal via RSA): {signature}")
    print(f"Encrypted Expenses (Paillier): {encrypted_expenses}")

    # Verify signature and decrypt data as a search functionality
    query_name = input("\nEnter patient name for search verification: ")
    if verify_signature(query_name, signature):
        print("Signature verified. Patient data is authentic.")
        # Decrypt if authenticated
        decrypted_treatment = aes_decrypt(nonce, encrypted_treatment, tag)
        decrypted_expenses = paillier_decrypt(encrypted_expenses)
        print("\n--- Patient Data ---")
        print(f"Name: {query_name}")
        print(f"Treatment: {decrypted_treatment}")
        print(f"Expenses: {decrypted_expenses}")
    else:
        print("Signature verification failed. Data may be tampered with.")

if __name__ == "__main__":
    main()
