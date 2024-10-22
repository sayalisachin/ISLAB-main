"""
SSE with Access Control
This implementation extends the previous SSE system to include access control features."""

class AccessControlSSE:
    def __init__(self):
        self.user_keys = {}
        self.index = {}
        self.permissions = {}

    def generate_user_key(self, username):
        key = Fernet.generate_key()
        self.user_keys[username] = Fernet(key)
        print(f"Key generated for user: {username}")

    def set_permission(self, username, doc_id, can_access):
        if username not in self.permissions:
            self.permissions[username] = {}
        self.permissions[username][doc_id] = can_access

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
            if self.permissions.get(username, {}).get(doc_id, False):
                decrypted_doc = self.user_keys[username].decrypt(self.index[username][doc_id]).decode()
                return decrypted_doc
            else:
                return "Access denied."
        else:
            return "Document not found."

    def search(self, username, keyword):
        if username not in self.index:
            return []
        results = []
        for doc_id, encrypted_doc in self.index[username].items():
            if self.permissions.get(username, {}).get(doc_id, False):
                decrypted_doc = self.user_keys[username].decrypt(encrypted_doc).decode()
                if keyword in decrypted_doc:
                    results.append(doc_id)
        return results

def main():
    sse = AccessControlSSE()

    while True:
        action = input("Choose action (generate_key, set_permission, encrypt, decrypt, search, exit): ").strip().lower()
        if action == 'exit':
            break
        elif action == 'generate_key':
            username = input("Enter username: ")
            sse.generate_user_key(username)
        elif action == 'set_permission':
            username = input("Enter username: ")
            doc_id = input("Enter document ID: ")
            can_access = input("Can user access? (yes/no): ").strip().lower() == 'yes'
            sse.set_permission(username, doc_id, can_access)
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
