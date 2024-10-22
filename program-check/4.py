"""
Implement a secure application that uses the Paillier encryption scheme. This application should include the following functionalities:

Key Generation: Generate public and private keys for the Paillier encryption scheme.
User Input: Allow users to insert integers into an encrypted database, update existing entries, delete entries, and retrieve values in an encrypted format.
Voting System: Implement a secure voting system where users can cast votes (e.g., "yes" or "no"). The votes should be encrypted, and the system should allow tallying of votes while maintaining privacy.
Search Functionality: Enable an encrypted search feature that allows users to query documents indexed by words, returning the IDs of documents that contain the queried word.
Performance Benchmarking: Measure and display the time taken for encryption, decryption, addition, and search operations.
"""
import random
import sympy
import time

class Paillier:
    def __init__(self, bit_length=512):
        self.p = sympy.randprime(2**(bit_length-1), 2**bit_length)
        self.q = sympy.randprime(2**(bit_length-1), 2**bit_length)
        self.n = self.p * self.q
        self.n_squared = self.n ** 2
        self.lambda_ = sympy.lcm(self.p - 1, self.q - 1)
        self.g = self.n + 1
        self.mu = pow(self.g, self.lambda_, self.n_squared) - 1 // self.n

    def encrypt(self, m):
        r = random.randint(1, self.n - 1)
        c = (pow(self.g, m, self.n_squared) * pow(r, self.n, self.n_squared)) % self.n_squared
        return c

    def decrypt(self, c):
        L = (pow(c, self.lambda_, self.n_squared) - 1) // self.n
        m = (L * self.mu) % self.n
        return m

    def add_encrypted(self, c1, c2):
        return (c1 * c2) % self.n_squared

class EncryptedDatabase:
    def __init__(self):
        self.paillier = Paillier()
        self.database = {}

    def insert(self, key, value):
        encrypted_value = self.paillier.encrypt(value)
        self.database[key] = encrypted_value
        print(f"Inserted {value} as {encrypted_value}.")

    def retrieve(self, key):
        if key in self.database:
            encrypted_value = self.database[key]
            decrypted_value = self.paillier.decrypt(encrypted_value)
            print(f"Retrieved: {decrypted_value} (Encrypted: {encrypted_value})")
        else:
            print("Key not found.")

    def update(self, key, new_value):
        if key in self.database:
            encrypted_value = self.paillier.encrypt(new_value)
            self.database[key] = encrypted_value
            print(f"Updated key {key} to {new_value} (Encrypted: {encrypted_value}).")
        else:
            print("Key not found.")

    def delete(self, key):
        if key in self.database:
            del self.database[key]
            print(f"Deleted key {key}.")
        else:
            print("Key not found.")

class SecureVoting:
    def __init__(self):
        self.paillier = Paillier()
        self.votes = []

    def cast_vote(self, vote):
        encrypted_vote = self.paillier.encrypt(vote)
        self.votes.append(encrypted_vote)
        print(f"Vote {vote} cast as {encrypted_vote}.")

    def tally_votes(self):
        encrypted_sum = 1
        for vote in self.votes:
            encrypted_sum = self.paillier.add_encrypted(encrypted_sum, vote)
        return self.paillier.decrypt(encrypted_sum)

class EncryptedSearch:
    def __init__(self):
        self.paillier = Paillier()
        self.index = {}

    def index_document(self, doc_id, words):
        for word in words:
            if word not in self.index:
                self.index[word] = []
            self.index[word].append(doc_id)
        print(f"Document {doc_id} indexed with words: {words}")

    def search(self, query):
        if query in self.index:
            doc_ids = self.index[query]
            print(f"Documents containing '{query}': {doc_ids}")
        else:
            print(f"No documents found for '{query}'.")

def benchmark_operations():
    paillier = Paillier()
    numbers = [random.randint(1, 100) for _ in range(100)]

    # Measure encryption time
    start_time = time.time()
    encrypted_numbers = [paillier.encrypt(num) for num in numbers]
    encryption_time = time.time() - start_time

    # Measure addition time
    start_time = time.time()
    encrypted_sum = encrypted_numbers[0]
    for enc_num in encrypted_numbers[1:]:
        encrypted_sum = paillier.add_encrypted(encrypted_sum, enc_num)
    addition_time = time.time() - start_time

    # Measure decryption time
    start_time = time.time()
    decrypted_sum = paillier.decrypt(encrypted_sum)
    decryption_time = time.time() - start_time

    print(f"Encryption time: {encryption_time:.6f}s")
    print(f"Addition time: {addition_time:.6f}s")
    print(f"Decryption time: {decryption_time:.6f}s")
    print(f"Decrypted sum: {decrypted_sum} (Expected: {sum(numbers)})")

def main():
    db = EncryptedDatabase()
    voting_system = SecureVoting()
    search_system = EncryptedSearch()

    while True:
        action = input("\nChoose action (insert, retrieve, update, delete, vote, index, search, benchmark, exit): ").strip().lower()
        if action == 'exit':
            break
        elif action == 'insert':
            key = input("Enter key: ")
            value = int(input("Enter value to encrypt: "))
            db.insert(key, value)
        elif action == 'retrieve':
            key = input("Enter key to retrieve: ")
            db.retrieve(key)
        elif action == 'update':
            key = input("Enter key to update: ")
            new_value = int(input("Enter new value to encrypt: "))
            db.update(key, new_value)
        elif action == 'delete':
            key = input("Enter key to delete: ")
            db.delete(key)
        elif action == 'vote':
            vote = input("Enter your vote (yes/no): ").strip().lower()
            if vote in ['yes', 'no']:
                voting_system.cast_vote(vote)
            else:
                print("Invalid vote.")
        elif action == 'index':
            doc_id = input("Enter document ID: ")
            words = input("Enter words (space-separated): ").split()
            search_system.index_document(doc_id, words)
        elif action == 'search':
            query = input("Enter word to search: ")
            search_system.search(query)
        elif action == 'benchmark':
            benchmark_operations()
        else:
            print("Invalid action.")

if __name__ == "__main__":
    main()
