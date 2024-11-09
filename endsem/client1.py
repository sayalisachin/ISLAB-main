#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/md5.h>
#include <openssl/bn.h>

#define RSA_KEY_SIZE 2048
#define FILENAME "patient_data.txt"

// Function prototypes
void generate_RSA_keys(RSA **rsa);
void encrypt_with_RSA(RSA *rsa, const char *data, unsigned char **encrypted, int *len);
void compute_MD5(const char *data, unsigned char *hash);
void sign_with_ElGamal(const unsigned char *hash, unsigned char *signature);
void send_to_server(const unsigned char *data, const unsigned char *signature);

// Main client function
int main() {
    RSA *rsa = NULL;
    unsigned char *encrypted = NULL;
    int encrypted_len;
    unsigned char hash[MD5_DIGEST_LENGTH];
    unsigned char signature[256];

    // Generate RSA key pair
    generate_RSA_keys(&rsa);

    // Read patient details from file
    FILE *file = fopen(FILENAME, "r");
    if (file == NULL) {
        fprintf(stderr, "Could not open file %s\n", FILENAME);
        return 1;
    }
    char buffer[1024];
    fread(buffer, 1, sizeof(buffer), file);
    fclose(file);

    // Encrypt patient data with RSA
    encrypt_with_RSA(rsa, buffer, &encrypted, &encrypted_len);

    // Compute MD5 hash of the encrypted data
    compute_MD5((const char *)encrypted, hash);

    // Sign hash using ElGamal
    sign_with_ElGamal(hash, signature);

    // Send data and signature to server
    send_to_server(encrypted, signature);

    // Cleanup
    RSA_free(rsa);
    free(encrypted);
    return 0;
}

// Generates RSA key pair
void generate_RSA_keys(RSA **rsa) {
    *rsa = RSA_generate_key(RSA_KEY_SIZE, RSA_F4, NULL, NULL);
}

// Encrypt data using RSA public key
void encrypt_with_RSA(RSA *rsa, const char *data, unsigned char **encrypted, int *len) {
    *encrypted = (unsigned char *)malloc(RSA_size(rsa));
    *len = RSA_public_encrypt(strlen(data), (unsigned char *)data, *encrypted, rsa, RSA_PKCS1_OAEP_PADDING);
}

// Computes MD5 hash of data
void compute_MD5(const char *data, unsigned char *hash) {
    MD5((unsigned char *)data, strlen(data), hash);
}

// Sign hash with a placeholder ElGamal function (ElGamal details would need implementation)
void sign_with_ElGamal(const unsigned char *hash, unsigned char *signature) {
    // Dummy signature function (replace with actual ElGamal implementation)
    strcpy((char *)signature, "elgamal_signature_placeholder");
}

// Placeholder for sending data to server
void send_to_server(const unsigned char *data, const unsigned char *signature) {
    printf("Data and signature sent to server.\n");
}

/*
Client Side:

Generates an RSA key pair.
Reads patient data from a file and encrypts it with RSA.
Computes an MD5 hash of the encrypted data.
Signs the hash with a placeholder ElGamal signature function.
Sends the encrypted data and signature to the server.
Server Side:

Provides a menu-driven interface to retrieve patient data by doctor name.
Verifies the signature (simplified here, replace with actual ElGamal signature verification if needed).
*/

# Install necessary libraries
# pip install pycryptodome

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import MD5
import pickle  # For serialization of data

# Generate an RSA key pair
def generate_rsa_key_pair():
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key

# Encrypt patient data using RSA
def encrypt_data(public_key, data):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_data = cipher.encrypt(data)
    return encrypted_data

# Compute an MD5 hash of the encrypted data
def compute_md5_hash(data):
    md5_hash = MD5.new(data)
    return md5_hash

# Placeholder ElGamal signature function (replace with actual implementation)
def elgamal_sign(data_hash):
    # This is a placeholder signature (actual ElGamal requires a specific key and signing process)
    return b'signed_data_placeholder'

# Client Side Code
def client_send_data(file_path, public_key):
    # Read patient data from file
    with open(file_path, "rb") as file:
        patient_data = file.read()

    # Encrypt data
    encrypted_data = encrypt_data(public_key, patient_data)

    # Generate hash and sign
    data_hash = compute_md5_hash(encrypted_data).digest()
    signature = elgamal_sign(data_hash)

    # Prepare data package to send to server
    data_package = {
        'encrypted_data': encrypted_data,
        'signature': signature
    }
    
    # Serialize data package (in practice, you would send this over a network)
    with open("data_package.pkl", "wb") as file:
        pickle.dump(data_package, file)
    print("Data package sent to server (saved to file).")

# Server Side Code
def retrieve_patient_data(data_package_path, private_key):
    # Load data package
    with open(data_package_path, "rb") as file:
        data_package = pickle.load(file)
    
    encrypted_data = data_package['encrypted_data']
    signature = data_package['signature']

    # Decrypt patient data
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_data = cipher.decrypt(encrypted_data)

    # Verify the placeholder signature (simplified)
    # In a real ElGamal, this would require a proper verification function
    expected_signature = elgamal_sign(compute_md5_hash(encrypted_data).digest())
    if signature == expected_signature:
        print("Signature verified successfully.")
        print("Decrypted Patient Data:", decrypted_data.decode())
    else:
        print("Signature verification failed.")

# Main Program
if __name__ == "__main__":
    # Step 1: Generate RSA keys
    private_key, public_key = generate_rsa_key_pair()

    # Step 2: Client sends encrypted data to server
    client_send_data("patient_data.txt", public_key)

    # Step 3: Server retrieves and verifies data by doctor name (dummy for example)
    retrieve_patient_data("data_package.pkl", private_key)
