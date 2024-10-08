import random
import math


class Paillier:
    def __init__(self, bits=8):
        self.p = self.generate_prime(bits)
        self.q = self.generate_prime(bits)
        self.n = self.p * self.q
        self.n2 = self.n * self.n
        self.g = self.n + 1
        self.lambda_n = (self.p - 1) * (self.q - 1) // math.gcd(self.p - 1, self.q - 1)

    def generate_prime(self, bits):
        """Generate a small prime number for testing."""
        while True:
            num = random.getrandbits(bits)
            if self.is_prime(num):
                return num

    def is_prime(self, n):
        """Check if n is a prime number using a simple method."""
        if n <= 1:
            return False
        for i in range(2, int(math.sqrt(n)) + 1):
            if n % i == 0:
                return False
        return True

    def encrypt(self, m):
        """Encrypt a message m."""
        r = random.randint(1, self.n - 1)
        ciphertext = (pow(self.g, m, self.n2) * pow(r, self.n, self.n2)) % self.n2
        return ciphertext

    def decrypt(self, c):
        """Decrypt the ciphertext c."""
        u = (pow(c, self.lambda_n, self.n2) - 1) // self.n
        l = mod_inverse(u, self.n)
        return (l % self.n)


def mod_inverse(a, p):
    """Compute the modular inverse of a modulo p."""
    return pow(a, p - 2, p)


# Example usage
if __name__ == "__main__":
    paillier = Paillier(bits=8)  # Reduced bit size for faster execution

    # Simulate data sharing
    data1 = 10  # Data from Party 1
    data2 = 20  # Data from Party 2

    # Encrypt data
    encrypted_data1 = paillier.encrypt(data1)
    encrypted_data2 = paillier.encrypt(data2)

    # Combine encrypted data (adding them without decryption)
    combined_encrypted = (encrypted_data1 + encrypted_data2) % paillier.n2

    # Decrypt the combined data
    decrypted_combined = paillier.decrypt(combined_encrypted)

    # Verify the combined result
    assert decrypted_combined == (data1 + data2), "Secure data sharing failed"
    print(f"Combined encrypted data: {combined_encrypted}")
    print(f"Decrypted combined data matches the sum: {decrypted_combined}")

