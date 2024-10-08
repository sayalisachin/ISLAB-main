"""DigiRights  Inc.  is  a  leading  provider  of  digital  content,  including  e-books, 
movies,  and  music.  The  company  has  implemented  a  secure  digital  rights 
management  (DRM)  system  using  the  ElGamal  cryptosystem  to  protect  its 
valuable digital assets. Implement a Python-based centralized key management 
and access control service that can: 
• Key Generation: Generate a master public-private key pair using the ElGamal 
cryptosystem. The key size should be configurable (e.g., 2048 bits). 
• Content Encryption: Provide an API for content creators to upload their digital 
content and have it encrypted using the master public key. 
• Key  Distribution:  Manage  the  distribution  of  the  master  private  key  to 
authorized customers, allowing them to decrypt the content. 
• Access Control: Implement flexible access control mechanisms, such as: 
o Granting limited-time access to customers for specific content 
o Revoking access to customers for specific content 
o Allowing content creators to manage access to their own content 
• Key Revocation: Implement a process to revoke the master private key in case 
of a security breach or other emergency. 
• Key  Renewal:  Automatically  renew  the  master  public-private  key  pair  at 
regular intervals (e.g., every 24 months) to maintain the security of the DRM 
system. 
• Secure Storage: Securely store the master private key, ensuring that it is not 
accessible to unauthorized parties. 
• Auditing  and  Logging:  Maintain  detailed  logs  of  all  key  management  and 
access control operations to enable auditing and troubleshooting
"""

from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Random.random import randint
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from datetime import datetime, timedelta
import os
import pickle
import logging

# Logging setup
logging.basicConfig(level=logging.INFO, filename='drm_audit.log', filemode='a',
                    format='%(asctime)s - %(message)s')

class KeyManagementService:
    def __init__(self, key_size=2048, renewal_period_months=24):
        self.key_size = key_size
        self.renewal_period = timedelta(days=renewal_period_months * 30)
        self.master_key = None
        self.last_renewed = None
        self.access_control_list = {}
        self.generate_master_key()

    def generate_master_key(self):
        """Generates a master public-private key pair using ElGamal cryptosystem."""
        self.master_key = ElGamal.generate(self.key_size, get_random_bytes)
        self.last_renewed = datetime.now()
        logging.info(f"Master key generated. Public key: {self.master_key.publickey().export_key().hex()}")

    def renew_master_key(self):
        """Automatically renew the master key after a specified time interval."""
        if datetime.now() - self.last_renewed >= self.renewal_period:
            self.generate_master_key()
            logging.info("Master key renewed.")

    def revoke_master_key(self):
        """Revoke the master private key."""
        self.master_key = None
        logging.info("Master key revoked due to security breach.")

    def store_private_key_securely(self):
        """Store the private key securely (e.g., in an encrypted file)."""
        with open("private_key.pem", "wb") as key_file:
            encrypted_private_key = self.master_key.export_key(passphrase="secure_passphrase", pkcs=8)
            key_file.write(encrypted_private_key)
        logging.info("Master private key securely stored.")

    def load_private_key(self):
        """Load private key securely."""
        with open("private_key.pem", "rb") as key_file:
            encrypted_private_key = key_file.read()
            self.master_key = ElGamal.import_key(encrypted_private_key, passphrase="secure_passphrase")
        logging.info("Master private key loaded from secure storage.")

    def encrypt_content(self, content):
        """Encrypt content using the master public key."""
        hashed_content = SHA256.new(content.encode()).digest()
        k = randint(1, self.master_key.p - 2)
        ciphertext = self.master_key.encrypt(hashed_content, k)
        logging.info("Content encrypted using master public key.")
        return ciphertext

    def decrypt_content(self, encrypted_content, private_key):
        """Decrypt content using the master private key."""
        decrypted_hash = private_key.decrypt(encrypted_content)
        logging.info("Content decrypted using the private key.")
        return decrypted_hash

    def grant_access(self, customer_id, content_id, expiry_time=None):
        """Grant access to the content with optional expiry time."""
        self.access_control_list[(customer_id, content_id)] = expiry_time
        logging.info(f"Access granted to customer {customer_id} for content {content_id}.")

    def revoke_access(self, customer_id, content_id):
        """Revoke access for a customer to specific content."""
        if (customer_id, content_id) in self.access_control_list:
            del self.access_control_list[(customer_id, content_id)]
            logging.info(f"Access revoked for customer {customer_id} to content {content_id}.")

    def check_access(self, customer_id, content_id):
        """Check if the customer has access to the content."""
        if (customer_id, content_id) in self.access_control_list:
            expiry_time = self.access_control_list[(customer_id, content_id)]
            if expiry_time is None or expiry_time > datetime.now():
                logging.info(f"Access granted for customer {customer_id} to content {content_id}.")
                return True
        logging.info(f"Access denied for customer {customer_id} to content {content_id}.")
        return False


class ContentManagementService:
    def __init__(self, key_management_service):
        self.key_management_service = key_management_service
        self.content_store = {}

    def upload_content(self, content_creator_id, content):
        """Upload content and encrypt it using the master public key."""
        encrypted_content = self.key_management_service.encrypt_content(content)
        content_id = len(self.content_store) + 1
        self.content_store[content_id] = (content_creator_id, encrypted_content)
        logging.info(f"Content uploaded and encrypted by creator {content_creator_id}.")
        return content_id

    def download_content(self, customer_id, content_id):
        """Download and decrypt content if access is granted."""
        if self.key_management_service.check_access(customer_id, content_id):
            encrypted_content = self.content_store[content_id][1]
            decrypted_content = self.key_management_service.decrypt_content(encrypted_content,
                                                                            self.key_management_service.master_key)
            return decrypted_content
        else:
            logging.warning(f"Customer {customer_id} is not authorized to download content {content_id}.")
            return None


def main():
    # Create key management and content management services
    key_management_service = KeyManagementService(key_size=2048)
    content_management_service = ContentManagementService(key_management_service)

    # Content creator uploads content
    content_creator_id = "creator_001"
    content = "This is the valuable digital content that needs DRM protection."
    content_id = content_management_service.upload_content(content_creator_id, content)

    # Grant access to a customer
    customer_id = "customer_001"
    key_management_service.grant_access(customer_id, content_id, expiry_time=datetime.now() + timedelta(days=7))

    # Customer attempts to download the content
    downloaded_content = content_management_service.download_content(customer_id, content_id)
    if downloaded_content:
        print(f"Customer {customer_id} downloaded content: {downloaded_content}")

    # Revoke access and attempt download again
    key_management_service.revoke_access(customer_id, content_id)
    downloaded_content = content_management_service.download_content(customer_id, content_id)
    if downloaded_content is None:
        print(f"Customer {customer_id} is no longer authorized to download content {content_id}.")

if __name__ == "__main__":
    main()

# pip install pycryptodome
