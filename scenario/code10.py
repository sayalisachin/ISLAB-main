#A company wants to ensure the integrity of files shared over the internet. Design a system that uses cryptographic hash functions to create file digests, allowing users to verify that files have not been tampered with during transmission.
import hashlib
import os

class FileIntegritySystem:
    def __init__(self):
        pass

    def hash_file(self, file_path):
        """Create a SHA-256 hash of the specified file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            # Read and update hash string value in blocks of 4K
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def transmit_file(self, file_path):
        """Simulate transmitting a file along with its hash."""
        file_hash = self.hash_file(file_path)
        print(f"Transmitting file: {file_path}")
        print(f"File hash: {file_hash}")
        return file_hash

    def verify_file(self, received_file_path, transmitted_hash):
        """Verify the integrity of the received file."""
        print(f"Verifying file: {received_file_path}")
        computed_hash = self.hash_file(received_file_path)
        print(f"Computed hash: {computed_hash}")
        if computed_hash == transmitted_hash:
            print("File integrity verified. The file has not been tampered with.")
            return True
        else:
            print("File integrity verification failed. The file may have been tampered with.")
            return False

# Example Usage
if __name__ == "__main__":
    integrity_system = FileIntegritySystem()

    # Step 1: Hash and transmit the file
    file_to_send = "example_file.txt"  # Ensure this file exists for testing
    transmitted_hash = integrity_system.transmit_file(file_to_send)

    # Step 2: Simulate receiving the file
    received_file = "example_file.txt"  # This is the file we received
    integrity_system.verify_file(received_file, transmitted_hash)
