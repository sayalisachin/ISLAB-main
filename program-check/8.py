"""
Query Auditing in SSE
This implementation adds logging for all search queries and access attempts."""
class AuditingSSE:
    def __init__(self):
        self.user_keys = {}
        self.index = {}
        self.audit_log = []

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

    def log_access(self, username, action, doc_id):
        self.audit_log.append({"username": username, "action": action, "doc_id": doc_id})

    def decrypt_document(self, username, doc_id):
        if username in self.index and doc_id in self.index[username]:
            decrypted_doc = self.user_keys[username].decrypt(self.index[username][doc_id]).decode()
            self.log_access(username, 'decrypt', doc_id)
            return decrypted_doc
        else:
            self.log_access(username, 'decrypt_failed', doc_id)
            return "Document not found."

    def search(self, username, keyword):
        results = []
        for user, docs in self.index.items():
            for doc_id, encrypted_doc in docs.items():
                decrypted_doc = self.user_keys[user].decrypt(encrypted_doc).decode()
                if keyword in decrypted_doc:
                    results.append(doc_id)
                    self.log_access(username, 'search', doc_id)
        return results

    def view_audit_log(self):
        for entry in self.audit_log:
            print(entry)

def main():
    sse = AuditingSSE()

    while True:
        action = input("Choose action (generate_key, encrypt, decrypt, search, audit, exit): ").strip().lower()
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
        elif action == 'audit':
            sse.view_audit_log()
        else:
            print("Invalid action.")

if __name__ == "__main__":
    main()
