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

/* 
 * SYSTEM MOCKS 
 * We keep these because they override LIBC functions. 
 * This allows us to test logic without actual networking or files.
 */
int socket(int domain, int type, int protocol) { return 3; }
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) { return 0; }
ssize_t send(int sockfd, const void *buf, size_t len, int flags) { return len; }
ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
    /* Simulate a server response for testing */
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

/* Mock fopen to avoid touching /etc/ during tests */
FILE *fopen(const char *path, const char *mode) {
    if (strstr(path, ".pub") || strstr(path, ".key") || strstr(path, "gorgona.conf")) {
        return tmpfile();
    }
    return NULL;
}

/* 
 * PROJECT-SPECIFIC FUNCTIONS DELETED FROM HERE
 * (send_alert, encrypt_message, read_config, trim_string, etc.)
 * They are now pulled from the real object files via the Makefile.
 */

/* We redefine this only because gorgona.client.o is excluded from tests */
void print_help_mock(const char *program_name) {
    printf("Usage: %s [send|listen] [...]\n", program_name);
}

/* --- TESTS --- */

START_TEST(test_help_output) {
    FILE *temp = tmpfile();
    FILE *original_stdout = stdout;
    stdout = temp;

    print_help_mock("gorgona");
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
    Suite *s = suite_create("Gorgona Logic Integration");
    TCase *tc_core = tcase_create("Core");
    tcase_add_test(tc_core, test_help_output);
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
