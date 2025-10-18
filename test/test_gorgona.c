#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include "../client/alert_send.h"
#include "../client/alert_listen.h"
#include "../client/config.h"

// Mock socket functions
int socket(int domain, int type, int protocol) { return 0; }
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) { return 0; }
ssize_t send(int sockfd, const void *buf, size_t len, int flags) { return len; }
ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
    const char *response = "ALERT|RWTPQzuhzBw=|1697650800|1697650800|1697737200|ZW5jcnlwdGVk|ZW5jcnlwdGVkX2tleQ==|aXY=|dGFn";
    uint32_t len_net = htonl(strlen(response));
    if (len == sizeof(uint32_t)) {
        memcpy(buf, &len_net, sizeof(uint32_t));
        return sizeof(uint32_t);
    }
    memcpy(buf, response, strlen(response));
    return strlen(response);
}
int close(int fd) { return 0; }
int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) { return 0; }

// Mock file functions
FILE *fopen(const char *path, const char *mode) {
    static FILE *mock_fp = NULL;
    if (strstr(path, ".pub") || strstr(path, ".key")) {
        mock_fp = tmpfile();
        return mock_fp;
    }
    return NULL;
}

// Mock encryption functions
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
unsigned char *base64_decode(const char *base64, size_t *out_len) {
    *out_len = 10;
    return (unsigned char *)strdup("decoded");
}
char *decrypt_message(const unsigned char *encrypted, size_t encrypted_len,
                     const unsigned char *encrypted_key, size_t encrypted_key_len,
                     const unsigned char *iv, size_t iv_len, const char *tag,
                     char **plaintext, const char *priv_file, int verbose) {
    *plaintext = strdup("test message");
    return 0;
}
void ERR_print_errors_fp(FILE *fp) {}

// Mock config and alert functions
void read_config(Config *config, int verbose) {
    strcpy(config->server_ip, "64.188.70.158");
    config->server_port = 5555;
    config->exec_count = 0;
}
int read_port_config(void) {
    return 5555;
}
time_t parse_datetime(const char *datetime) {
    return 1697650800;
}
char *read_from_stdin(size_t *len) {
    *len = 13;
    return strdup("test message\n");
}
int send_alert(int argc, char *argv[], int verbose) {
    return 0;
}
int listen_alerts(int argc, char *argv[], int verbose, int execute) {
    return 0;
}
void trim_string(char *str) {
    if (!str) return;
    size_t len = strlen(str);
    while (len > 0 && (str[len - 1] == '\n' || str[len - 1] == ' ')) {
        str[len - 1] = '\0';
        len--;
    }
}
void time_to_utc_string(time_t t, char *buf, size_t bufsize) {
    snprintf(buf, bufsize, "2025-10-18 12:00:00");
}
int has_private_key(const char *pubkey_hash_b64, int verbose) {
    return 1;
}
void parse_response(const char *response, const char *expected_pubkey_hash_b64, int verbose, int execute, Config *config) {
    printf("Parsed message: test message\n");
}

// Mock print_help
void print_help(const char *program_name) {
    printf("Usage: %s [send|listen] [...]\n", program_name);
}

// Test print_help
START_TEST(test_print_help) {
    FILE *temp = tmpfile();
    FILE *original_stdout = stdout;
    stdout = temp;

    print_help("gorgona");
    rewind(temp);
    
    char buffer[1024] = {0};
    size_t len = fread(buffer, 1, sizeof(buffer) - 1, temp);
    buffer[len] = '\0';
    
    ck_assert_str_eq(buffer, "Usage: gorgona [send|listen] [...]\n");
    
    stdout = original_stdout;
    fclose(temp);
}
END_TEST

Suite *gorgona_suite(void) {
    Suite *s = suite_create("Gorgona");
    TCase *tc_core = tcase_create("Core");
    tcase_add_test(tc_core, test_print_help);
    suite_add_tcase(s, tc_core);
    return s;
}

int main(void) {
    Suite *s = gorgona_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    int failures = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (failures == 0) ? 0 : 1;
}
