#include <check.h>
#include <string.h>
#include <stdio.h>
#include "config.h"

/* Control mock behavior: 0 = valid config, 1 = missing file, 2 = empty file */
static int mock_config_mode = 0;

/* Mock fopen to provide a controlled config file */
FILE *fopen(const char *path, const char *mode) {
    static FILE *mock_fp = NULL;
    if (strcmp(path, "/etc/gorgona/gorgona.conf") == 0) {
        if (mock_config_mode == 1) { /* Simulate missing file */
            return NULL;
        }
        mock_fp = tmpfile();
        if (mock_fp) {
            if (mock_config_mode == 0) { /* Simulate valid config */
                fprintf(mock_fp, "[server]\nip=192.168.1.200\nport=7777\n[exec_commands]\ndf=/home/su/repository/c/gorgona/test/df.sh\n");
                rewind(mock_fp);
            }
            /* For empty config (mode 2), leave file empty */
            return mock_fp;
        }
    }
    return NULL;
}

START_TEST(test_read_config_valid) {
    mock_config_mode = 0; /* Set to valid config */
    Config config;
    memset(&config, 0, sizeof(Config)); /* Initialize config struct */
    read_config(&config, 0);
    ck_assert_str_eq(config.server_ip, "192.168.1.200");
    ck_assert_int_eq(config.server_port, 7777);
    ck_assert_int_eq(config.exec_count, 1);
    ck_assert_str_eq(config.exec_commands[0].key, "df");
    ck_assert_str_eq(config.exec_commands[0].value, "/home/su/repository/c/gorgona/test/df.sh");
}
END_TEST

START_TEST(test_read_config_missing) {
    mock_config_mode = 1; /* Set to missing file */
    Config config;
    memset(&config, 0, sizeof(Config)); /* Initialize config struct */
    read_config(&config, 0); /* Should use defaults */
    ck_assert_str_eq(config.server_ip, "192.168.1.200");
    ck_assert_int_eq(config.server_port, 7777); /* Expect default port */
    ck_assert_int_eq(config.exec_count, 0);
}
END_TEST

START_TEST(test_read_config_empty) {
    mock_config_mode = 2; /* Set to empty file */
    Config config;
    memset(&config, 0, sizeof(Config)); /* Initialize config struct */
    read_config(&config, 0); /* Should use defaults */
    ck_assert_str_eq(config.server_ip, "192.168.1.200");
    ck_assert_int_eq(config.server_port, 7777); /* Expect default port */
    ck_assert_int_eq(config.exec_count, 0);
}
END_TEST

Suite *config_suite(void) {
    Suite *s = suite_create("Config");
    TCase *tc_core = tcase_create("Core");
    tcase_add_test(tc_core, test_read_config_valid);
    tcase_add_test(tc_core, test_read_config_missing);
    tcase_add_test(tc_core, test_read_config_empty);
    suite_add_tcase(s, tc_core);
    return s;
}

int main(void) {
    Suite *s = config_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    int failures = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (failures == 0) ? 0 : 1;
}
