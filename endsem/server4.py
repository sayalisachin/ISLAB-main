#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>

void verify_signature(char *role, char *data, unsigned char *signature);

int main() {
    char role[10];
    char data[256];
    unsigned char signature[256];

    // Receive `role`, `data`, and `signature` from client
    verify_signature(role, data, signature);

    return 0;
}

void verify_signature(char *role, char *data, unsigned char *signature) {
    RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    if (RSA_verify(NID_sha256, (unsigned char *)data, strlen(data), signature, 256, rsa)) {
        if (strcmp(role, "Doctor") == 0) {
            printf("Access Granted: Full Patient Data\n");
        } else if (strcmp(role, "Nurse") == 0) {
            printf("Access Granted: Limited Patient Data\n");
        } else {
            printf("Invalid Role\n");
        }
    } else {
        printf("Signature Verification Failed\n");
    }
}
