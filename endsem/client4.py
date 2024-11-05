/*
Client Side:
Allow users to log in as a "Doctor" or "Nurse."
Based on the role, digitally sign a request for patient data using RSA.
Encrypt sensitive details (e.g., treatment, expenses) if the user is a doctor, leaving out sensitive fields for nurses.
Send the request with the digital signature to the server.
Server Side:
Verify the digital signature and check the role of the requester.
If verified and role is "Doctor," return full patient details; if "Nurse," return limited details.
*/
#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

void sign_request(char *role, char *data, unsigned char *signature);

int main() {
    char role[10];
    char data[] = "Patient details request";
    unsigned char signature[256];

    printf("Enter role (Doctor/Nurse): ");
    scanf("%s", role);

    sign_request(role, data, signature);
    // Send `role`, `data`, and `signature` to server

    return 0;
}

void sign_request(char *role, char *data, unsigned char *signature) {
    RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    RSA_sign(NID_sha256, (unsigned char *)data, strlen(data), signature, NULL, rsa);
}
