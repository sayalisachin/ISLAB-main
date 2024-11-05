/*
Client Side:
Use RSA to encrypt patient information (name, treatment) before transmission.
Implement a Diffie-Hellman key exchange with the server to establish a shared symmetric key.
Encrypt the patient’s expenses using the shared symmetric key and send it to the server.
Server Side:
Perform Diffie-Hellman key exchange to derive the shared symmetric key.
Decrypt the patient's expenses and verify it matches the encrypted data.
Display all patient data once verified.
*/

#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/dh.h>

void rsa_encrypt(const char *data, unsigned char *encrypted, RSA *rsa_key);
void diffie_hellman_key_exchange();

int main() {
    // RSA encryption of patient data
    RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    char patient_data[] = "Patient Info";
    unsigned char encrypted[256];
    rsa_encrypt(patient_data, encrypted, rsa);

    // Perform Diffie-Hellman Key Exchange
    diffie_hellman_key_exchange();

    // Send encrypted data and DH shared key to server
    return 0;
}

void rsa_encrypt(const char *data, unsigned char *encrypted, RSA *rsa_key) {
    RSA_public_encrypt(strlen(data), (unsigned char *)data, encrypted, rsa_key, RSA_PKCS1_OAEP_PADDING);
}

void diffie_hellman_key_exchange() {
    DH *dh = DH_new();
    DH_generate_parameters_ex(dh, 2048, DH_GENERATOR_2, NULL);
    DH_generate_key(dh);
    // Send public part of DH to server, derive shared key
}
