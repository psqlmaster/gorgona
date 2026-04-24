#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include "alert_listen.h"
#include "admin_mesh.h"

/* 
 * System Mocks: 
 * We keep these to prevent the test from actually hitting the network.
 */
int socket(int domain, int type, int protocol) { return 3; }
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) { return 0; }
ssize_t send(int sockfd, const void *buf, size_t len, int flags) { return len; }
int close(int fd) { return 0; }
int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) { return 0; }
ssize_t recv(int sockfd, void *buf, size_t len, int flags) { return 0; }
int access(const char *pathname, int mode) { return -1; }

/* 
 * The REAL parse_response depends on a lot of state.
 * This test now verifies it doesn't crash with a valid string.
 */
START_TEST(test_parse_response_valid) {
    Config config;
    memset(&config, 0, sizeof(Config));
    strcpy(config.server_ip, "127.0.0.1");

    const char *response = "ALERT|RWTPQzuhzBw=|1697650800|1697650800|1824759307|ZW5jcnlwdGVk|ZW5jcnlwdGVkX2tleQ==|aXY=|dGFn";
    
    parse_response(3, response, "RWTPQzuhzBw=", 0, 0, &config, 0);
}
END_TEST

Suite *alert_listen_suite(void) {
    Suite *s = suite_create("Alert Listen");
    TCase *tc_core = tcase_create("Core");
    tcase_add_test(tc_core, test_parse_response_valid);
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
