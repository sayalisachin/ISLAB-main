#Control using RSA: Implement an access control system where different users have access to different resources based on their attributes. Use RSA encryption to manage and verify the access policies.
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import json

class AccessControl:
    def __init__(self):
        # Generate RSA keys for the service
        self.service_key = RSA.generate(2048)
        self.service_public_key = self.service_key.publickey()
        self.access_policies = {}

    def define_policy(self, resource, attributes):
        # Define access policies for resources
        self.access_policies[resource] = attributes

    def encrypt_message(self, message):
        cipher = PKCS1_OAEP.new(self.service_public_key)
        return cipher.encrypt(message.encode())

    def decrypt_message(self, encrypted_message):
        cipher = PKCS1_OAEP.new(self.service_key)
        return cipher.decrypt(encrypted_message).decode()

    def verify_access(self, user_attributes, resource):
        # Check if the user has access to the resource
        required_attributes = self.access_policies.get(resource, [])
        return all(attr in user_attributes for attr in required_attributes)

# Example Usage
if __name__ == "__main__":
    access_control = AccessControl()

    # Define access policies
    access_control.define_policy("resource_1", ["role_admin", "role_user"])
    access_control.define_policy("resource_2", ["role_user"])

    # User's attributes
    user_attributes = ["role_user"]

    # Check access
    resource_to_access = "resource_1"
    if access_control.verify_access(user_attributes, resource_to_access):
        print(f"Access granted to {resource_to_access}.")
    else:
        print(f"Access denied to {resource_to_access}.")

    # Encrypt a message
    message = "This is a secret message."
    encrypted_message = access_control.encrypt_message(message)
    print(f"Encrypted message: {encrypted_message.hex()}")

    # Decrypt the message
    decrypted_message = access_control.decrypt_message(encrypted_message)
    print(f"Decrypted message: {decrypted_message}")

#python access_control.py
