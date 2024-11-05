#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define SECRET_KEY "secret_key_12345"

void verify_HMAC_SHA256(const char *data, const unsigned char *received_hmac);

// Main function
int main() {
    unsigned char received_data[1024]; // Placeholder for received data
    unsigned char received_hmac[EVP_MAX_MD_SIZE]; // Placeholder for received HMAC

    // Decrypt and verify HMAC on received data
    verify_HMAC_SHA256((const char *)received_data, received_hmac);

    return 0;
}

// Verify HMAC-SHA256 integrity
void verify_HMAC_SHA256(const char *data, const unsigned char *received_hmac) {
    unsigned char computed_hmac[EVP_MAX_MD_SIZE];
    unsigned int len;
    HMAC(EVP_sha256(), SECRET_KEY, strlen(SECRET_KEY), (unsigned char *)data, strlen(data), computed_hmac, &len);

    if (memcmp(received_hmac, computed_hmac, len) == 0) {
        printf("Integrity Verified!\n");
    } else {
        printf("Integrity Verification Failed!\n");
    }
}
