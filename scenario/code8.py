#Develop a digital notary service where documents are hashed using SHA-256 and signed to prove their existence at a specific time. Include verification mechanisms to validate the signed documents.
import os
import time
import json
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

class DigitalNotaryService:
    def __init__(self):
        # Generate RSA key pair for the notary
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def hash_document(self, document):
        """Hash the document using SHA-256."""
        document_hash = hashlib.sha256(document.encode()).hexdigest()
        return document_hash

    def sign_document(self, document):
        """Sign the document hash with the private key."""
        document_hash = self.hash_document(document)
        timestamp = time.time()
        
        # Create a JSON object with the document hash and timestamp
        data_to_sign = json.dumps({'hash': document_hash, 'timestamp': timestamp}).encode()
        
        # Sign the data
        signature = self.private_key.sign(
            data_to_sign,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return document_hash, signature, timestamp

    def verify_document(self, document, signature):
        """Verify the document's signature."""
        document_hash = self.hash_document(document)
        timestamp = time.time()  # Current time for validation

        # Create the JSON object for verification
        data_to_verify = json.dumps({'hash': document_hash, 'timestamp': timestamp}).encode()

        try:
            # Verify the signature
            self.public_key.verify(
                signature,
                data_to_verify,
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
    notary_service = DigitalNotaryService()

    # Document to be notarized
    document = "This is a confidential document."

    # Sign the document
    document_hash, signature, timestamp = notary_service.sign_document(document)
    print(f"Document hash: {document_hash}")
    print(f"Signature: {signature.hex()}")
    print(f"Timestamp: {timestamp}")

    # Verification
    is_verified = notary_service.verify_document(document, signature)
    if is_verified:
        print("The document is verified and valid.")
    else:
        print("The document verification failed.")
