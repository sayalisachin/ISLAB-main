"""Real world SSE"""
class HealthcareSSE:
    def __init__(self):
        self.user_keys = {}
        self.index = {}
        self.audit_log = []

    def generate_user_key(self, username):
        key = Fernet.generate_key()
        self.user_keys[username] = Fernet(key)
        print(f"Key generated for user: {username}")

    def encrypt_record(self, username, record_id, record):
        if username not in self.user_keys:
            print("User not found. Please generate a key first.")
            return
        encrypted_record = self.user_keys[username].encrypt(record.encode())
        if username not in self.index:
            self.index[username] = {}
        self.index[username][record_id] = encrypted_record
        print(f"Record {record_id} encrypted and stored for user {username}.")

    def log_access(self, username, action, record_id):
        self.audit_log.append({"username": username, "action": action, "record_id": record_id})

    def decrypt_record(self, username, record_id):
        if username in self.index and record_id in self.index[username]:
            decrypted_record = self.user_keys[username].decrypt(self.index[username][record_id]).decode()
            self.log_access(username, 'decrypt', record_id)
            return decrypted_record
        else:
            self.log_access(username, 'decrypt_failed', record_id)
            return "Record not found."

    def search(self, username, keyword):
        results = []
        for user, records in self.index.items():
            for record_id, encrypted_record in records.items():
                decrypted_record = self.user_keys[user].decrypt(encrypted_record).decode()
                if keyword in decrypted_record:
                    results.append(record_id)
                    self.log_access(username, 'search', record_id)
        return results

    def view_audit_log(self):
        for entry in self.audit_log:
            print(entry)

def main():
    sse = HealthcareSSE()

    while True:
        action = input("Choose action (generate_key, encrypt, decrypt, search, audit, exit): ").strip().lower()
        if action == 'exit':
            break
        elif action == 'generate_key':
            username = input("Enter username: ")
            sse.generate_user_key(username)
        elif action == 'encrypt':
            username = input("Enter username: ")
            record_id = input("Enter record ID: ")
            record = input("Enter patient record text: ")
            sse.encrypt_record(username, record_id, record)
        elif action == 'decrypt':
            username = input("Enter username: ")
            record_id = input("Enter record ID to decrypt: ")
            print(sse.decrypt_record(username, record_id))
        elif action == 'search':
            username = input("Enter username: ")
            keyword = input("Enter keyword to search: ")
            results = sse.search(username, keyword)
            print(f"Records containing '{keyword}': {results}")
        elif action == 'audit':
            sse.view_audit_log()
        else:
            print("Invalid action.")

if __name__ == "__main__":
    main()
