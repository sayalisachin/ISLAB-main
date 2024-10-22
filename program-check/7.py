"""
Encrypted Document Sharing System
This implementation allows users to share documents securely.
"""
class DocumentSharingSSE:
    def __init__(self):
        self.user_keys = {}
        self.index = {}
        self.shared_docs = {}

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

    def share_document(self, owner, doc_id, shared_with):
        if owner in self.index and doc_id in self.index[owner]:
            encrypted_doc = self.index[owner][doc_id]
            if shared_with not in self.shared_docs:
                self.shared_docs[shared_with] = {}
            self.shared_docs[shared_with][doc_id] = encrypted_doc
            print(f"Document {doc_id} shared with {shared_with}.")

    def decrypt_document(self, username, doc_id):
        if username in self.index and doc_id in self.index[username]:
            decrypted_doc = self.user_keys[username].decrypt(self.index[username][doc_id]).decode()
            return decrypted_doc
        elif username in self.shared_docs and doc_id in self.shared_docs[username]:
            owner = [k for k, v in self.index.items() if doc_id in v][0]
            decrypted_doc = self.user_keys[owner].decrypt(self.shared_docs[username][doc_id]).decode()
            return decrypted_doc
        else:
            return "Document not found."

    def search(self, username, keyword):
        results = []
        if username in self.index:
            for doc_id, encrypted_doc in self.index[username].items():
                decrypted_doc = self.user_keys[username].decrypt(encrypted_doc).decode()
                if keyword in decrypted_doc:
                    results.append(doc_id)
        if username in self.shared_docs:
            for doc_id, encrypted_doc in self.shared_docs[username].items():
                owner = [k for k, v in self.index.items() if doc_id in v][0]
                decrypted_doc = self.user_keys[owner].decrypt(encrypted_doc).decode()
                if keyword in decrypted_doc:
                    results.append(doc_id)
        return results

def main():
    sse = DocumentSharingSSE()

    while True:
        action = input("Choose action (generate_key, encrypt, share, decrypt, search, exit): ").strip().lower()
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
        elif action == 'share':
            owner = input("Enter document owner's username: ")
            doc_id = input("Enter document ID to share: ")
            shared_with = input("Enter username to share with: ")
            sse.share_document(owner, doc_id, shared_with)
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
