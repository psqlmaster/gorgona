#include <check.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "config.h"
#include "common.h"

/* Control mock behavior: 0 = valid config, 1 = missing file, 2 = empty file */
static int mock_config_mode = 0;

/*
 * Mock fopen: we can keep this because it overrides the libc function
 * to provide controlled input to the REAL read_config function.
 */
FILE *fopen(const char *path, const char *mode) {
    if (strcmp(path, "/etc/gorgona/gorgona.conf") == 0) {
        if (mock_config_mode == 1) return NULL;
        FILE *mock_fp = tmpfile();
        if (mock_fp) {
            if (mock_config_mode == 0) {
                fprintf(mock_fp, "[server]\n"
                                 "ip=192.168.1.200\n"
                                 "port=7777\n"
                                 "[exec_commands]\n"
                                 "df=/home/su/repository/c/gorgona/test/df.sh\n");
                rewind(mock_fp);
            }
            return mock_fp;
        }
    }
    /* For other files (like keys), we return NULL or real files if needed */
    return NULL;
}

START_TEST(test_read_config_valid) {
    mock_config_mode = 0;
    Config config;
    memset(&config, 0, sizeof(Config));
    /* ✅ НОВАЯ СИГНАТУРА: config_path, config, verbose */
    read_config("/etc/gorgona/gorgona.conf", &config, 0);
    ck_assert_str_eq(config.server_ip, "192.168.1.200");
    ck_assert_int_eq(config.server_port, 7777);
    ck_assert_int_eq(config.exec_count, 1);
    ck_assert_str_eq(config.exec_commands[0].key, "df");
}
END_TEST

START_TEST(test_read_config_missing) {
    mock_config_mode = 1;
    Config config;
    memset(&config, 0, sizeof(Config));
    /* ✅ НОВАЯ СИГНАТУРА: config_path, config, verbose */
    read_config("/etc/gorgona/gorgona.conf", &config, 0);
    /* Should fall back to defaults defined in config.c */
    ck_assert_str_eq(config.server_ip, DEFAULT_SERVER_IP);
}
END_TEST

/* ===== Key argument normalization tests ===== */

static char keys_dir[PATH_MAX];
static char saved_conf_dir[256];

/* fopen is mocked above, so plain open() is used to create the fixtures */
static void touch_file(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) close(fd);
}

static void keys_setup(void) {
    snprintf(keys_dir, sizeof(keys_dir), "/tmp/gorgona_keys_XXXXXX");
    ck_assert_ptr_nonnull(mkdtemp(keys_dir));

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/RWTPQzuhzBw=.pub", keys_dir);
    touch_file(path);
    snprintf(path, sizeof(path), "%s/RWTPQzuhzBw=.key", keys_dir);
    touch_file(path);

    snprintf(saved_conf_dir, sizeof(saved_conf_dir), "%s", gorgona_conf_dir);
    snprintf(gorgona_conf_dir, sizeof(gorgona_conf_dir), "%s", keys_dir);
}

static void keys_teardown(void) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/RWTPQzuhzBw=.pub", keys_dir);
    unlink(path);
    snprintf(path, sizeof(path), "%s/RWTPQzuhzBw=.key", keys_dir);
    unlink(path);
    rmdir(keys_dir);
    snprintf(gorgona_conf_dir, sizeof(gorgona_conf_dir), "%s", saved_conf_dir);
}

START_TEST(test_key_arg_to_hash) {
    static const struct { const char *in; const char *want; } cases[] = {
        { "RWTPQzuhzBw=",                  "RWTPQzuhzBw=" },
        { "RWTPQzuhzBw=.pub",              "RWTPQzuhzBw=" },
        { "RWTPQzuhzBw=.key",              "RWTPQzuhzBw=" },
        { "/etc/gorgona/RWTPQzuhzBw=.pub", "RWTPQzuhzBw=" },
        { "/etc/gorgona/RWTPQzuhzBw=.key", "RWTPQzuhzBw=" },
        { "",                              "" },
    };
    char out[128];
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        key_arg_to_hash(cases[i].in, out, sizeof(out));
        ck_assert_str_eq(out, cases[i].want);
    }
}
END_TEST

START_TEST(test_key_arg_resolve_public_forms) {
    char out[PATH_MAX], want[PATH_MAX];
    snprintf(want, sizeof(want), "%s/RWTPQzuhzBw=.pub", keys_dir);

    const char *forms[] = { "RWTPQzuhzBw=", "RWTPQzuhzBw=.pub", want };
    for (size_t i = 0; i < sizeof(forms) / sizeof(forms[0]); i++) {
        ck_assert_int_eq(key_arg_resolve(forms[i], "pub", out, sizeof(out)), 0);
        ck_assert_str_eq(out, want);
    }
}
END_TEST

/* A private key argument must never be used as a public one */
START_TEST(test_key_arg_resolve_public_from_private_arg) {
    char out[PATH_MAX], want[PATH_MAX], priv[PATH_MAX];
    snprintf(want, sizeof(want), "%s/RWTPQzuhzBw=.pub", keys_dir);
    snprintf(priv, sizeof(priv), "%s/RWTPQzuhzBw=.key", keys_dir);

    ck_assert_int_eq(key_arg_resolve("RWTPQzuhzBw=.key", "pub", out, sizeof(out)), 0);
    ck_assert_str_eq(out, want);

    ck_assert_int_eq(key_arg_resolve(priv, "pub", out, sizeof(out)), 0);
    ck_assert_str_eq(out, want);
}
END_TEST

START_TEST(test_key_arg_resolve_private_forms) {
    char out[PATH_MAX], want[PATH_MAX], pub[PATH_MAX];
    snprintf(want, sizeof(want), "%s/RWTPQzuhzBw=.key", keys_dir);
    snprintf(pub, sizeof(pub), "%s/RWTPQzuhzBw=.pub", keys_dir);

    const char *forms[] = { "RWTPQzuhzBw=", "RWTPQzuhzBw=.key", want };
    for (size_t i = 0; i < sizeof(forms) / sizeof(forms[0]); i++) {
        ck_assert_int_eq(key_arg_resolve(forms[i], "key", out, sizeof(out)), 0);
        ck_assert_str_eq(out, want);
    }

    ck_assert_int_eq(key_arg_resolve(pub, "key", out, sizeof(out)), 0);
    ck_assert_str_eq(out, want);
}
END_TEST

/* On failure the canonical path is returned for a readable error message */
START_TEST(test_key_arg_resolve_missing) {
    char out[PATH_MAX], want[PATH_MAX];
    snprintf(want, sizeof(want), "%s/ABSENT=.pub", keys_dir);

    ck_assert_int_eq(key_arg_resolve("ABSENT=", "pub", out, sizeof(out)), -1);
    ck_assert_str_eq(out, want);

    ck_assert_int_eq(key_arg_resolve(NULL, "pub", out, sizeof(out)), -1);
}
END_TEST

Suite *config_suite(void) {
    Suite *s = suite_create("Config");
    TCase *tc_core = tcase_create("Core");
    tcase_add_test(tc_core, test_read_config_valid);
    tcase_add_test(tc_core, test_read_config_missing);
    suite_add_tcase(s, tc_core);

    TCase *tc_keys = tcase_create("KeyArgs");
    tcase_add_checked_fixture(tc_keys, keys_setup, keys_teardown);
    tcase_add_test(tc_keys, test_key_arg_to_hash);
    tcase_add_test(tc_keys, test_key_arg_resolve_public_forms);
    tcase_add_test(tc_keys, test_key_arg_resolve_public_from_private_arg);
    tcase_add_test(tc_keys, test_key_arg_resolve_private_forms);
    tcase_add_test(tc_keys, test_key_arg_resolve_missing);
    suite_add_tcase(s, tc_keys);
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
