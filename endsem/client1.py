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