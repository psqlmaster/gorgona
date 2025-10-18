#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <unistd.h>
#include "../client/alert_send.h"
#include "../client/alert_listen.h"
#include "../client/config.h"

// Mock dependencies from encrypt.c
unsigned char *compute_pubkey_hash(EVP_PKEY *pubkey, size_t *hash_len, int verbose) {
    fprintf(stderr, "DEBUG: compute_pubkey_hash called\n");
    unsigned char *hash = malloc(8); // Match PUBKEY_HASH_LEN from encrypt.h
    if (!hash) {
        fprintf(stderr, "DEBUG: compute_pubkey_hash malloc failed\n");
        return NULL;
    }
    for (int i = 0; i < 8; i++) {
        hash[i] = (unsigned char)(i + 1); // Fill with dummy values
    }
    *hash_len = 8;
    fprintf(stderr, "DEBUG: compute_pubkey_hash returning hash=%p, hash_len=%zu\n", hash, *hash_len);
    return hash;
}

char *base64_encode(const unsigned char *data, size_t data_len) {
    fprintf(stderr, "DEBUG: base64_encode called with data_len=%zu\n", data_len);
    char *result = strdup("mock_base64");
    fprintf(stderr, "DEBUG: base64_encode returning %s\n", result);
    return result;
}

unsigned char *base64_decode(const char *data, size_t *out_len) {
    fprintf(stderr, "DEBUG: base64_decode called with data=%s\n", data);
    *out_len = 4;
    unsigned char *decoded = malloc(4);
    if (!decoded) {
        fprintf(stderr, "DEBUG: base64_decode malloc failed\n");
        return NULL;
    }
    memcpy(decoded, "test", 4);
    fprintf(stderr, "DEBUG: base64_decode returning decoded=%p, out_len=%zu\n", decoded, *out_len);
    return decoded;
}

int encrypt_message(const char *plaintext, unsigned char **encrypted, size_t *encrypted_len,
                    unsigned char **encrypted_key, size_t *encrypted_key_len,
                    unsigned char **iv, size_t *iv_len, unsigned char **tag, size_t *tag_len,
                    const char *pubkey_file, int verbose) {
    fprintf(stderr, "DEBUG: encrypt_message called with plaintext=%s, pubkey_file=%s\n", plaintext, pubkey_file);
    size_t plaintext_len = strlen(plaintext);
    *encrypted = (unsigned char *)strdup("encrypted_data");
    *encrypted_len = plaintext_len; // Match plaintext length
    *encrypted_key = (unsigned char *)strdup("encrypted_key");
    *encrypted_key_len = 256; // RSA-2048 key size
    *iv = (unsigned char *)strdup("iv");
    *iv_len = 12; // Match expected IV length for GCM (as per send_alert)
    *tag = (unsigned char *)strdup("tag");
    *tag_len = 16; // Match GCM_TAG_LEN from encrypt.h
    fprintf(stderr, "DEBUG: encrypt_message returning encrypted_len=%zu, encrypted_key_len=%zu, iv_len=%zu, tag_len=%zu\n",
            *encrypted_len, *encrypted_key_len, *iv_len, *tag_len);
    fprintf(stderr, "DEBUG: encrypt_message returning success\n");
    return 0;
}

int decrypt_message(const unsigned char *encrypted, size_t encrypted_len,
                    const unsigned char *encrypted_key, size_t encrypted_key_len,
                    const unsigned char *iv, size_t iv_len,
                    const unsigned char *tag, size_t tag_len,
                    char **plaintext, size_t *plaintext_len,
                    const char *privkey_file, int verbose) {
    fprintf(stderr, "DEBUG: decrypt_message called\n");
    *plaintext = strdup("decrypted");
    *plaintext_len = 9;
    fprintf(stderr, "DEBUG: decrypt_message returning success\n");
    return 0;
}

// Mock socket functions
int socket(int domain, int type, int protocol) {
    fprintf(stderr, "DEBUG: socket called\n");
    return 0;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    fprintf(stderr, "DEBUG: connect called\n");
    return 0;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    fprintf(stderr, "DEBUG: send called with len=%zu\n", len);
    return len;
}

ssize_t read(int sockfd, void *buf, size_t len) {
    fprintf(stderr, "DEBUG: read called with len=%zu\n", len);
    if (len == sizeof(uint32_t)) {
        uint32_t resp_len = htonl(7);
        memcpy(buf, &resp_len, sizeof(uint32_t));
        fprintf(stderr, "DEBUG: read returning resp_len=%u\n", ntohl(resp_len));
        return sizeof(uint32_t);
    }
    if (len >= 7) {
        strcpy(buf, "SUCCESS");
        fprintf(stderr, "DEBUG: read returning SUCCESS\n");
        return 7;
    }
    fprintf(stderr, "DEBUG: read returning 0\n");
    return 0;
}

int close(int fd) {
    fprintf(stderr, "DEBUG: close called\n");
    return 0;
}

int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
    fprintf(stderr, "DEBUG: setsockopt called\n");
    return 0;
}

// Mock fopen for pubkey file
FILE *fopen(const char *path, const char *mode) {
    fprintf(stderr, "DEBUG: fopen called with path=%s, mode=%s\n", path, mode);
    static FILE *mock_fp = NULL;
    if (strstr(path, ".pub")) {
        mock_fp = tmpfile();
        if (mock_fp) {
            fprintf(mock_fp, "-----BEGIN PUBLIC KEY-----\nMOCK\n-----END PUBLIC KEY-----\n");
            rewind(mock_fp);
            fprintf(stderr, "DEBUG: fopen returning mock_fp=%p\n", mock_fp);
        }
        return mock_fp;
    }
    fprintf(stderr, "DEBUG: fopen returning NULL\n");
    return NULL;
}

EVP_PKEY *PEM_read_PUBKEY(FILE *fp, EVP_PKEY **x, pem_password_cb *cb, void *u) {
    fprintf(stderr, "DEBUG: PEM_read_PUBKEY called\n");
    return (EVP_PKEY *)1; // Mock non-NULL pointer
}

void EVP_PKEY_free(EVP_PKEY *pkey) {
    fprintf(stderr, "DEBUG: EVP_PKEY_free called\n");
    // Do nothing in mock
}

void ERR_print_errors_fp(FILE *fp) {
    fprintf(stderr, "DEBUG: ERR_print_errors_fp called\n");
    fprintf(fp, "Mock OpenSSL error\n");
}

// Mock read_config
void read_config(Config *config, int verbose) {
    fprintf(stderr, "DEBUG: read_config called\n");
    strncpy(config->server_ip, "127.0.0.1", sizeof(config->server_ip));
    config->server_ip[sizeof(config->server_ip) - 1] = '\0'; // Ensure null-termination
    config->server_port = 7777;
    config->exec_count = 0; // Initialize exec_count
    fprintf(stderr, "DEBUG: read_config set server_ip=%s, server_port=%d\n", config->server_ip, config->server_port);
}

START_TEST(test_send_alert) {
    char *argv[] = {"send", "2025-09-28 21:44:00", "2025-12-30 12:00:00", "test_message", "BTW9V5jVztY=.pub"};
    int argc = 5;
    fprintf(stderr, "DEBUG: test_send_alert started\n");
    int result = send_alert(argc, argv, 0);
    fprintf(stderr, "DEBUG: test_send_alert result=%d\n", result);
    ck_assert_int_eq(result, 0);
}
END_TEST

START_TEST(test_send_alert_invalid_time) {
    char *argv[] = {"send", "invalid", "2025-12-30 12:00:00", "test_message", "BTW9V5jVztY=.pub"};
    int argc = 5;
    fprintf(stderr, "DEBUG: test_send_alert_invalid_time started\n");
    int result = send_alert(argc, argv, 0);
    fprintf(stderr, "DEBUG: test_send_alert_invalid_time result=%d\n", result);
    ck_assert_int_eq(result, 1);
}
END_TEST

START_TEST(test_send_alert_missing_args) {
    char *argv[] = {"send", "2025-09-28 21:44:00"};
    int argc = 2;
    fprintf(stderr, "DEBUG: test_send_alert_missing_args started\n");
    int result = send_alert(argc, argv, 0);
    fprintf(stderr, "DEBUG: test_send_alert_missing_args result=%d\n", result);
    ck_assert_int_eq(result, 1);
}
END_TEST

START_TEST(test_send_alert_stdin_message) {
    FILE *temp_stdin = tmpfile();
    fprintf(temp_stdin, "test_message");
    rewind(temp_stdin);
    int original_stdin = dup(STDIN_FILENO);
    dup2(fileno(temp_stdin), STDIN_FILENO);

    char *argv[] = {"send", "2025-09-28 21:44:00", "2025-12-30 12:00:00", "-", "BTW9V5jVztY=.pub"};
    int argc = 5;
    fprintf(stderr, "DEBUG: test_send_alert_stdin_message started\n");
    int result = send_alert(argc, argv, 0);
    fprintf(stderr, "DEBUG: test_send_alert_stdin_message result=%d\n", result);
    ck_assert_int_eq(result, 0);

    dup2(original_stdin, STDIN_FILENO);
    close(original_stdin);
    fclose(temp_stdin);
}
END_TEST

Suite *alert_send_suite(void) {
    Suite *s = suite_create("Alert Send");
    TCase *tc_core = tcase_create("Core");
    tcase_add_test(tc_core, test_send_alert);
    tcase_add_test(tc_core, test_send_alert_invalid_time);
    tcase_add_test(tc_core, test_send_alert_missing_args);
    tcase_add_test(tc_core, test_send_alert_stdin_message);
    suite_add_tcase(s, tc_core);
    return s;
}

int main(void) {
    Suite *s = alert_send_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    int failures = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (failures == 0) ? 0 : 1;
}
