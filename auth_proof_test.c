#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <openssl/sha.h>

#define AUTH_PROOF_HEX_LEN 64

static void bytes_to_hex(const unsigned char *bytes, size_t bytes_len, char *hex_out, size_t hex_out_size) {
    static const char lut[] = "0123456789abcdef";
    size_t required = (bytes_len * 2) + 1;

    if (hex_out_size < required) {
        if (hex_out_size > 0) {
            hex_out[0] = '\0';
        }
        return;
    }

    for (size_t i = 0; i < bytes_len; ++i) {
        hex_out[i * 2] = lut[(bytes[i] >> 4) & 0x0F];
        hex_out[(i * 2) + 1] = lut[bytes[i] & 0x0F];
    }
    hex_out[bytes_len * 2] = '\0';
}

static int compute_proof_hex(const char *nonce_hex, const char *password, char *proof_hex, size_t proof_hex_size) {
    char material[256];
    unsigned char digest[SHA256_DIGEST_LENGTH];
    int written = snprintf(material, sizeof(material), "%s:%s", nonce_hex, password);

    if (written < 0 || written >= (int)sizeof(material)) {
        return -1;
    }

    SHA256((const unsigned char *)material, strlen(material), digest);
    bytes_to_hex(digest, sizeof(digest), proof_hex, proof_hex_size);
    return 0;
}

static void test_same_nonce_same_password_same_digest(void) {
    const char *nonce = "00112233445566778899aabbccddeeff";
    const char *password = "strong-password";
    char p1[AUTH_PROOF_HEX_LEN + 1];
    char p2[AUTH_PROOF_HEX_LEN + 1];

    assert(compute_proof_hex(nonce, password, p1, sizeof(p1)) == 0);
    assert(compute_proof_hex(nonce, password, p2, sizeof(p2)) == 0);
    assert(strlen(p1) == AUTH_PROOF_HEX_LEN);
    assert(strcmp(p1, p2) == 0);
}

static void test_different_nonce_different_digest(void) {
    const char *nonce1 = "00112233445566778899aabbccddeeff";
    const char *nonce2 = "ffeeddccbbaa99887766554433221100";
    const char *password = "strong-password";
    char p1[AUTH_PROOF_HEX_LEN + 1];
    char p2[AUTH_PROOF_HEX_LEN + 1];

    assert(compute_proof_hex(nonce1, password, p1, sizeof(p1)) == 0);
    assert(compute_proof_hex(nonce2, password, p2, sizeof(p2)) == 0);
    assert(strcmp(p1, p2) != 0);
}

int main(void) {
    test_same_nonce_same_password_same_digest();
    test_different_nonce_different_digest();

    printf("auth_proof_test: all tests passed\n");
    return 0;
}
