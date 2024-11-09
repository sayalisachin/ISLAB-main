/*
Client Side:
Implement a function to encrypt patient data (name, age, diagnosis, and expenses) using AES-256.
Calculate the SHA-256 hash of the encrypted data and generate an HMAC using HMAC-SHA256 with a shared secret key.
Send the encrypted data and HMAC to the server.
Server Side:
Decrypt the received data and verify its integrity using the HMAC.
Display the patient details if the verification succeeds.
*/

pip install pycryptodome


from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto.Random import get_random_bytes
import pickle

# Shared secret key for HMAC (must be securely shared between client and server)
SHARED_SECRET_KEY = get_random_bytes(32)  # 32 bytes for HMAC-SHA256

# AES-256 Encryption/Decryption with padding
def pad(data):
    # Pads data to be a multiple of 16 bytes (AES block size)
    padding_length = 16 - (len(data) % 16)
    return data + bytes([padding_length]) * padding_length

def unpad(data):
    # Removes padding from decrypted data
    padding_length = data[-1]
    return data[:-padding_length]

def generate_aes_key():
    return get_random_bytes(32)  # 32 bytes for AES-256

def aes_encrypt(key, data):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce, ciphertext, tag

def aes_decrypt(key, nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_data

# HMAC-SHA256 Generation and Verification
def generate_hmac(shared_secret, data):
    hmac = HMAC.new(shared_secret, digestmod=SHA256)
    hmac.update(data)
    return hmac.digest()

def verify_hmac(shared_secret, data, received_hmac):
    hmac = HMAC.new(shared_secret, digestmod=SHA256)
    hmac.update(data)
    try:
        hmac.verify(received_hmac)
        return True
    except ValueError:
        return False

# Client Side: Encrypt, HMAC, and send data
def client_send_data(patient_data, aes_key, shared_secret_key):
    # Convert patient data to bytes
    data = f"Name: {patient_data['name']}, Age: {patient_data['age']}, Diagnosis: {patient_data['diagnosis']}, Expenses: {patient_data['expenses']}".encode()
    
    # AES Encrypt the patient data
    nonce, ciphertext, tag = aes_encrypt(aes_key, pad(data))

    # Generate HMAC-SHA256 for integrity check
    hmac = generate_hmac(shared_secret_key, ciphertext)

    # Package data for sending to the server
    data_package = {
        'nonce': nonce,
        'ciphertext': ciphertext,
        'tag': tag,
        'hmac': hmac
    }
    
    # Serialize data package (in practice, send this over network)
    with open("data_package.pkl", "wb") as file:
        pickle.dump(data_package, file)
    print("Data package sent to server (saved to file).")

# Server Side: Decrypt, verify HMAC, and display data
def server_receive_data(data_package_path, aes_key, shared_secret_key):
    # Load data package
    with open(data_package_path, "rb") as file:
        data_package = pickle.load(file)

    nonce = data_package['nonce']
    ciphertext = data_package['ciphertext']
    tag = data_package['tag']
    received_hmac = data_package['hmac']

    # Verify HMAC-SHA256 for integrity check
    if verify_hmac(shared_secret_key, ciphertext, received_hmac):
        print("HMAC verification succeeded.")
        
        # Decrypt the data
        decrypted_data = unpad(aes_decrypt(aes_key, nonce, ciphertext, tag))
        
        # Display patient data
        print("Decrypted Patient Data:", decrypted_data.decode())
    else:
        print("HMAC verification failed. Data integrity compromised.")

# Main Program
if __name__ == "__main__":
    # Generate AES Key for encryption/decryption
    aes_key = generate_aes_key()

    # Patient data
    patient_data = {
        'name': 'John Doe',
        'age': 35,
        'diagnosis': 'Flu',
        'expenses': '$200'
    }

    # Client encrypts and sends data
    client_send_data(patient_data, aes_key, SHARED_SECRET_KEY)

    # Server receives and verifies data
    server_receive_data("data_package.pkl", aes_key, SHARED_SECRET_KEY)
