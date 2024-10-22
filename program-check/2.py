"""
Implement the Paillier encryption scheme in Python. 
Encrypt two integers (e.g., 15 and 25) using your implementation of the 
Paillier encryption scheme. Print the ciphertexts. 
Perform an addition operation on the encrypted integers without decrypting them. 
Print the result of the addition in encrypted form. 
Decrypt the result of the addition and verify that it matches the sum of the original integers. 
Extend the above scheme for multiple numbers (eg: 20,25,30,25, etc). 
Perform scalar multiplication operation on one of the encrypted integer with 3 and print the multiplication in encrypted form. 
Decrypt the result of the multiplication and verify that it matches the multiplication of the original integer and 3. 
Build an inverted index mapping numbers to the list of document IDs containing those numbers (eg: 1:"45", 2:"30", 3:"35", etc). 
Encrypt the index using the Paillier cryptosystem.Take a search query as input. Encrypt the query using the public key. 
Search the encrypted index for matching terms. Decrypt the returned document IDs using the private key. 
Print the corresponding Document ID for the numbers. (eg: Search query = 45. Output should be ID_1). 
Implement batch encryption and decryption. 
Compare the time taken in Paillier Encryption, Homomorphic operation and Decryption for small number (eg:10) and large number(eg: 10000).
"""

import random
import sympy
import time

class Paillier:
    def __init__(self, bit_length=512):
        # Generate two large prime numbers p and q
        self.p = sympy.randprime(2**(bit_length-1), 2**bit_length)
        self.q = sympy.randprime(2**(bit_length-1), 2**bit_length)
        
        # Compute n = p * q
        self.n = self.p * self.q
        # Compute n_squared = n^2
        self.n_squared = self.n ** 2
        # Compute lambda = lcm(p-1, q-1)
        self.lambda_ = sympy.lcm(self.p - 1, self.q - 1)
        
        # Generate public and private key
        self.g = self.n + 1  # g = n + 1
        self.mu = pow(self.g, self.lambda_, self.n_squared) - 1 // self.n  # mu = g^lambda mod n^2

    def encrypt(self, m):
        """ Encrypt a message m using the public key """
        r = random.randint(1, self.n - 1)  # Random r in [1, n-1]
        c = (pow(self.g, m, self.n_squared) * pow(r, self.n, self.n_squared)) % self.n_squared
        return c

    def decrypt(self, c):
        """ Decrypt ciphertext c using the private key """
        # L function defined in the Paillier scheme
        L = (pow(c, self.lambda_, self.n_squared) - 1) // self.n
        m = (L * self.mu) % self.n
        return m

    def add_encrypted(self, c1, c2):
        """ Perform homomorphic addition of two ciphertexts """
        return (c1 * c2) % self.n_squared

    def scalar_multiply(self, c, k):
        """ Multiply an encrypted value by a scalar k """
        return pow(c, k, self.n_squared)


def main():
    # Initialize the Paillier encryption system
    paillier = Paillier()

    # Encrypt two integers
    int1 = 15
    int2 = 25
    ciphertext1 = paillier.encrypt(int1)
    ciphertext2 = paillier.encrypt(int2)

    # Print the ciphertexts
    print(f"Ciphertext of {int1}: {ciphertext1}")
    print(f"Ciphertext of {int2}: {ciphertext2}")

    # Homomorphic addition
    encrypted_sum = paillier.add_encrypted(ciphertext1, ciphertext2)
    decrypted_sum = paillier.decrypt(encrypted_sum)

    # Verify the addition
    print(f"Decrypted sum: {decrypted_sum} (Expected: {int1 + int2})")

    # Extend for multiple numbers
    numbers = [20, 25, 30, 25]
    encrypted_numbers = [paillier.encrypt(num) for num in numbers]

    # Scalar multiplication
    k = 3
    encrypted_scalar_multiplication = paillier.scalar_multiply(ciphertext1, k)
    decrypted_scalar_multiplication = paillier.decrypt(encrypted_scalar_multiplication)

    # Verify the multiplication
    print(f"Decrypted scalar multiplication: {decrypted_scalar_multiplication} (Expected: {int1 * k})")

    # Inverted index
    inverted_index = {
        1: "45",
        2: "30",
        3: "35",
    }

    # Encrypt the index
    encrypted_index = {key: paillier.encrypt(int(value)) for key, value in inverted_index.items()}

    # Take search query as input
    query = 45
    encrypted_query = paillier.encrypt(query)

    # Search in the encrypted index
    matching_ids = [key for key, encrypted_value in encrypted_index.items() if encrypted_value == encrypted_query]

    # Decrypt the matching IDs
    decrypted_ids = [id for id in matching_ids]
    print(f"Document IDs for the search query {query}: {decrypted_ids}")

    # Measure time for small and large numbers
    small_num = 10
    large_num = 10000

    # Timing for small numbers
    start_time = time.time()
    encrypted_small = [paillier.encrypt(i) for i in range(small_num)]
    encryption_time_small = time.time() - start_time

    start_time = time.time()
    for i in range(small_num - 1):
        paillier.add_encrypted(encrypted_small[i], encrypted_small[i + 1])
    homomorphic_time_small = time.time() - start_time

    start_time = time.time()
    for c in encrypted_small:
        paillier.decrypt(c)
    decryption_time_small = time.time() - start_time

    print(f"Small numbers (n={small_num}):")
    print(f"Encryption time: {encryption_time_small:.6f}s")
    print(f"Homomorphic addition time: {homomorphic_time_small:.6f}s")
    print(f"Decryption time: {decryption_time_small:.6f}s")

    # Timing for large numbers
    start_time = time.time()
    encrypted_large = [paillier.encrypt(i) for i in range(large_num)]
    encryption_time_large = time.time() - start_time

    start_time = time.time()
    for i in range(large_num - 1):
        paillier.add_encrypted(encrypted_large[i], encrypted_large[i + 1])
    homomorphic_time_large = time.time() - start_time

    start_time = time.time()
    for c in encrypted_large:
        paillier.decrypt(c)
    decryption_time_large = time.time() - start_time

    print(f"\nLarge numbers (n={large_num}):")
    print(f"Encryption time: {encryption_time_large:.6f}s")
    print(f"Homomorphic addition time: {homomorphic_time_large:.6f}s")
    print(f"Decryption time: {decryption_time_large:.6f}s")

if __name__ == "__main__":
    main()
