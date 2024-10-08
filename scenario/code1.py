from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from sympy import mod_inverse

# Step 1: Nurse generates RSA key pairs
nurse_key = RSA.generate(2048)
nurse_public_key = nurse_key.publickey()

# Step 2: Doctor generates RSA key pairs
doctor_key = RSA.generate(2048)
doctor_public_key = doctor_key.publickey()

# Step 3: Radiologist (using Rabin algorithm - simplified)
def rabin_encrypt(m, n):
    return (m * m) % n

def rabin_decrypt(c, p, q):
    n = p * q
    mp = pow(c, (p + 1) // 4, p)
    mq = pow(c, (q + 1) // 4, q)
    inv_q = mod_inverse(q, p)
    inv_p = mod_inverse(p, q)
    
    x = (inv_q * q * mp + inv_p * p * mq) % n
    return x

radiologist_p = 61  # Example prime number for Rabin
radiologist_q = 53  # Another prime number
radiologist_n = radiologist_p * radiologist_q  # Public key (n)

# Step 4: Nurse encrypts and signs a message
message = b"Patient data: Scan results..."
cipher_rsa = PKCS1_OAEP.new(doctor_public_key)
encrypted_message = cipher_rsa.encrypt(message)

# Generate a message digest (hash) and sign it
digest = SHA256.new(message)
signature = pkcs1_15.new(nurse_key).sign(digest)

# Step 5: Doctor decrypts the message and verifies the signature
cipher_rsa = PKCS1_OAEP.new(doctor_key)
decrypted_message = cipher_rsa.decrypt(encrypted_message)

# Verify the signature
try:
    pkcs1_15.new(nurse_public_key).verify(digest, signature)
    print("The signature is valid.")
except (ValueError, TypeError):
    print("The signature is invalid.")

# Step 6: Doctor sends a request to the radiologist using Rabin encryption
request = b"Please review scan results."
m = int.from_bytes(request, byteorder='big')
rabin_encrypted_request = rabin_encrypt(m, radiologist_n)
print(f"Rabin Encrypted request: {rabin_encrypted_request}")

# Radiologist decrypts the request
rabin_decrypted_request = rabin_decrypt(rabin_encrypted_request, radiologist_p, radiologist_q)
decrypted_request_bytes = rabin_decrypted_request.to_bytes((rabin_decrypted_request.bit_length() + 7) // 8, byteorder='big')
print(f"Rabin Decrypted request: {decrypted_request_bytes.decode()}")

#Nurse encrypts the message and generates a digital signature using RSA.
#Doctor decrypts the message using RSA and verifies the digital signature.
#Doctor sends a request to the radiologist, encrypted using Rabin en
#pip install pycryptodome cryptography