# Implement a digital signature scheme where a message is signed by multiple parties in sequence. Verify the integrity and authenticity of the message using each party’s public key.
import os
import time
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

class DigitalSignature:
    def __init__(self):
        # Generate RSA key pair for the signer
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def sign(self, message):
        # Create a timestamp
        timestamp = time.time()
        # Combine message and timestamp
        message_with_timestamp = json.dumps({'message': message, 'timestamp': timestamp}).encode()
        
        # Sign the message with the private key
        signature = self.private_key.sign(
            message_with_timestamp,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature, timestamp

    def verify(self, message, signature, timestamp):
        # Combine message and timestamp for verification
        message_with_timestamp = json.dumps({'message': message, 'timestamp': timestamp}).encode()
        
        # Verify the signature with the public key
        try:
            self.public_key.verify(
                signature,
                message_with_timestamp,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print("Verification failed:", e)
            return False

# Example Usage
if __name__ == "__main__":
    signer1 = DigitalSignature()
    signer2 = DigitalSignature()

    message = "This is a confidential message."
    
    # Sign by multiple parties
    signature1, timestamp1 = signer1.sign(message)
    print(f"Signer 1 signature: {signature1.hex()}")
    
    signature2, timestamp2 = signer2.sign(message)
    print(f"Signer 2 signature: {signature2.hex()}")
    
    # Verification
    if signer1.verify(message, signature1, timestamp1):
        print("Signer 1's signature verified.")
    else:
        print("Signer 1's signature verification failed.")
    
    if signer2.verify(message, signature2, timestamp2):
        print("Signer 2's signature verified.")
    else:
        print("Signer 2's signature verification failed.")

