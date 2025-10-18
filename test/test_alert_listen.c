#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include "../client/alert_listen.h"

// Mock socket functions
int socket(int domain, int type, int protocol) { return 0; }
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) { return 0; }
ssize_t send(int sockfd, const void *buf, size_t len, int flags) { return len; }

static int recv_call_count = 0;

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
    const char *response = "ALERT|RWTPQzuhzBw=|1760522852|1760522852|1763114915|ZW5jcnlwdGVk|ZW5jcnlwdGVkX2tleQ==|aXY=|dGFn";
    uint32_t len_net = htonl(strlen(response));

    recv_call_count++;

    if (recv_call_count == 1) {
        // First call: return message length (4 bytes)
        if (len == sizeof(uint32_t)) {
            memcpy(buf, &len_net, sizeof(uint32_t));
            return sizeof(uint32_t);
        }
    } else if (recv_call_count == 2) {
        // Second call: return actual message
        memcpy(buf, response, strlen(response));
        return strlen(response);
    } else {
        // Third+ call: simulate connection closed (return 0)
        return 0;
    }

    // Fallback (should not happen)
    return -1;
}


int close(int fd) { return 0; }
int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) { return 0; }

// Mock file and encryption functions
FILE *fopen(const char *path, const char *mode) {
    static FILE *mock_fp = NULL;
    if (strstr(path, ".key") || strstr(path, ".pub")) {
        mock_fp = tmpfile();
        return mock_fp;
    }
    return NULL;
}
unsigned char *base64_decode(const char *base64, size_t *out_len) {
    *out_len = 10;
    return (unsigned char *)strdup("decoded");
}
char *decrypt_message(const unsigned char *encrypted, size_t encrypted_len,
                     const unsigned char *encrypted_key, size_t encrypted_key_len,
                     const unsigned char *iv, size_t iv_len, const unsigned char *tag,
                     char **plaintext, const char *priv_file, int verbose) {
    *plaintext = strdup("test message");
    return 0;
}
unsigned char *compute_pubkey_hash(EVP_PKEY *pubkey, size_t *hash_len, int verbose) {
    static unsigned char hash[] = {1, 2, 3, 4};
    *hash_len = 4;
    return hash;
}
char *base64_encode(const unsigned char *data, size_t data_len) {
    return strdup("mock_base64");
}
int encrypt_message(const char *plaintext, unsigned char **encrypted, size_t *encrypted_len,
                    unsigned char **encrypted_key, size_t *encrypted_key_len,
                    unsigned char **iv, size_t *iv_len, unsigned char **tag, size_t *tag_len,
                    const char *pubkey_file, int verbose) {
    *encrypted = (unsigned char *)strdup("encrypted");
    *encrypted_len = 9;
    *encrypted_key = (unsigned char *)strdup("key");
    *encrypted_key_len = 3;
    *iv = (unsigned char *)strdup("iv");
    *iv_len = 2;
    *tag = (unsigned char *)strdup("tag");
    *tag_len = 3;
    return 0;
}
void ERR_print_errors_fp(FILE *fp) {}

// Test parse_response
START_TEST(test_parse_response_valid) {
    Config config = {0};
    const char *response = "ALERT|RWTPQzuhzBw=|1697650800|1697650800|1697737200|ZW5jcnlwdGVk|ZW5jcnlwdGVkX2tleQ==|aXY=|dGFn";
    parse_response(response, "RWTPQzuhzBw=", 0, 0, &config);
    // Check output via redirected stdout (requires additional setup for capturing)
}
END_TEST

// Test listen_alerts
START_TEST(test_listen_alerts_single) {
    char *argv[] = {"listen", "single", "RWTPQzuhzBw="};
    int result = listen_alerts(3, argv, 0, 0);
    ck_assert_int_eq(result, 0);
}
END_TEST

Suite *alert_listen_suite(void) {
    Suite *s = suite_create("Alert Listen");
    TCase *tc_core = tcase_create("Core");
    tcase_add_test(tc_core, test_parse_response_valid);
    tcase_add_test(tc_core, test_listen_alerts_single);
    suite_add_tcase(s, tc_core);
    return s;
}

int main(void) {
    Suite *s = alert_listen_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    int failures = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (failures == 0) ? 0 : 1;
}
