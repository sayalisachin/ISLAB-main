"""
Multi-User SSE System
This implementation allows multiple users to upload documents and search for keywords securely.
"""
from cryptography.fernet import Fernet
import json

class MultiUserSSE:
    def __init__(self):
        self.user_keys = {}
        self.index = {}

    def generate_user_key(self, username):
        key = Fernet.generate_key()
        self.user_keys[username] = Fernet(key)
        print(f"Key generated for user: {username}")

    def encrypt_document(self, username, doc_id, document):
        if username not in self.user_keys:
            print("User not found. Please generate a key first.")
            return
        encrypted_doc = self.user_keys[username].encrypt(document.encode())
        if username not in self.index:
            self.index[username] = {}
        self.index[username][doc_id] = encrypted_doc
        print(f"Document {doc_id} encrypted and stored for user {username}.")

    def decrypt_document(self, username, doc_id):
        if username in self.index and doc_id in self.index[username]:
            decrypted_doc = self.user_keys[username].decrypt(self.index[username][doc_id]).decode()
            return decrypted_doc
        else:
            return "Document not found."

    def search(self, username, keyword):
        if username not in self.index:
            return []
        results = []
        for doc_id, encrypted_doc in self.index[username].items():
            decrypted_doc = self.user_keys[username].decrypt(encrypted_doc).decode()
            if keyword in decrypted_doc:
                results.append(doc_id)
        return results

def main():
    sse = MultiUserSSE()
    
    while True:
        action = input("Choose action (generate_key, encrypt, decrypt, search, exit): ").strip().lower()
        if action == 'exit':
            break
        elif action == 'generate_key':
            username = input("Enter username: ")
            sse.generate_user_key(username)
        elif action == 'encrypt':
            username = input("Enter username: ")
            doc_id = input("Enter document ID: ")
            document = input("Enter document text: ")
            sse.encrypt_document(username, doc_id, document)
        elif action == 'decrypt':
            username = input("Enter username: ")
            doc_id = input("Enter document ID to decrypt: ")
            print(sse.decrypt_document(username, doc_id))
        elif action == 'search':
            username = input("Enter username: ")
            keyword = input("Enter keyword to search: ")
            results = sse.search(username, keyword)
            print(f"Documents containing '{keyword}': {results}")
        else:
            print("Invalid action.")

if __name__ == "__main__":
    main()
