/*
Client Side:
Implement a function to encrypt patient data (name, age, diagnosis, and expenses) using AES-256.
Calculate the SHA-256 hash of the encrypted data and generate an HMAC using HMAC-SHA256 with a shared secret key.
Send the encrypted data and HMAC to the server.
Server Side:
Decrypt the received data and verify its integrity using the HMAC.
Display the patient details if the verification succeeds.
*/

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>

#define SECRET_KEY "secret_key_12345" // Secret key for HMAC
#define DATA_FILE "patient_data.txt"

// Function prototypes
void encrypt_AES(const char *data, unsigned char *encrypted);
void compute_HMAC_SHA256(const char *data, unsigned char *hmac_out);

// Main function
int main() {
    FILE *file = fopen(DATA_FILE, "r");
    if (!file) {
        perror("File open error");
        return 1;
    }

    char data[1024];
    fread(data, sizeof(char), sizeof(data), file);
    fclose(file);

    unsigned char encrypted[1024];
    encrypt_AES(data, encrypted);

    unsigned char hmac[EVP_MAX_MD_SIZE];
    compute_HMAC_SHA256((const char *)encrypted, hmac);

    // Send `encrypted` and `hmac` to server

    return 0;
}

// Encrypts data using AES
void encrypt_AES(const char *data, unsigned char *encrypted) {
    unsigned char key[32] = "this_is_a_32_byte_key__";
    unsigned char iv[16] = "initial_vector__";

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    int len;
    EVP_EncryptUpdate(ctx, encrypted, &len, (unsigned char *)data, strlen(data));
    EVP_EncryptFinal_ex(ctx, encrypted + len, &len);

    EVP_CIPHER_CTX_free(ctx);
}

// Computes HMAC using SHA256
void compute_HMAC_SHA256(const char *data, unsigned char *hmac_out) {
    unsigned int len;
    HMAC(EVP_sha256(), SECRET_KEY, strlen(SECRET_KEY), (unsigned char *)data, strlen(data), hmac_out, &len);
}
