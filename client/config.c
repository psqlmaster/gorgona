/*
BSD 3-Clause License
Copyright (c) 2025, Alexander Shcheglov
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <errno.h>
#include "config.h"
#include "common.h"

extern char client_log_level[32];
char config_file_path[512] = DEFAULT_CONFIG_FILE;

/* ===== Sync rules (linked list) ===== */
sync_config_t *sync_rules_head = NULL;

sync_config_t *get_or_create_sync_rule(const char *pubkey)
{
    if (!pubkey || !*pubkey)
        return NULL;
    /* Look for an existing rule */
    for (sync_config_t *r = sync_rules_head; r; r = r->next) {
        if (strcmp(r->pubkey, pubkey) == 0)
            return r;
    }
    /* Create a new rule */
    sync_config_t *rule = calloc(1, sizeof(sync_config_t));
    if (!rule)
        return NULL;
    strncpy(rule->pubkey, pubkey, sizeof(rule->pubkey) - 1);
    rule->pubkey[sizeof(rule->pubkey) - 1] = '\0';
    /* Default values */
    strncpy(rule->direction, "rw", sizeof(rule->direction) - 1);
    rule->max_file_size = 0;          /* The global limit is applied later */
    rule->next = NULL;
    /* Insert at the head of the list */
    rule->next = sync_rules_head;
    sync_rules_head = rule;
    return rule;
}

void apply_global_max_file_size(size_t global_limit)
{
    for (sync_config_t *r = sync_rules_head; r; r = r->next) {
        if (r->max_file_size == 0)
            r->max_file_size = global_limit;
    }
}

/* Convenience lookup (already declared in the header) */
const sync_config_t *config_get_sync_rule(const char *pubkey)
{
    if (!pubkey || !*pubkey)
        return NULL;
    for (const sync_config_t *r = sync_rules_head; r; r = r->next) {
        if (strcmp(r->pubkey, pubkey) == 0)
            return r;
    }
    return NULL;
}
/* Helper function to trim leading and trailing whitespace */
static char *trim_spaces(char *str) {
    if (!str) return NULL;
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return str;
}

/* ===== Key argument normalization =====
 * Accepted forms: "HASH", "HASH.pub", "HASH.key", "/etc/gorgona/HASH.pub".
 */

static int str_ends_with(const char *s, const char *suffix) {
    size_t ls = strlen(s), lf = strlen(suffix);
    return lf <= ls && strcmp(s + ls - lf, suffix) == 0;
}

void key_arg_to_hash(const char *arg, char *out, size_t outlen) {
    if (!out || outlen == 0) return;
    out[0] = '\0';
    if (!arg || !*arg) return;

    const char *base = strrchr(arg, '/');
    base = base ? base + 1 : arg;
    snprintf(out, outlen, "%s", base);

    if (str_ends_with(out, ".pub") || str_ends_with(out, ".key"))
        out[strlen(out) - 4] = '\0';
}

/* A path is accepted as is only if it is not marked with the extension of
   another key type (for example .key where a public key is required). */
static int path_ext_compatible(const char *path, const char *ext) {
    char dot_ext[8];
    snprintf(dot_ext, sizeof(dot_ext), ".%s", ext ? ext : "pub");
    if (str_ends_with(path, ".pub") || str_ends_with(path, ".key"))
        return str_ends_with(path, dot_ext);
    return 1;   /* no extension given, try to open it */
}

static int regular_file_exists(const char *path) {
    struct stat st;
    return path && *path && stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

int key_arg_resolve(const char *arg, const char *ext, char *out, size_t outlen) {
    char hash[256];
    char cand[3][PATH_MAX];
    int n = 0;

    if (!arg || !*arg || !out || outlen == 0) return -1;
    if (!ext || !*ext) ext = "pub";
    key_arg_to_hash(arg, hash, sizeof(hash));

    /* An explicit path was given, try it as is */
    if (strchr(arg, '/') && path_ext_compatible(arg, ext)) {
        snprintf(cand[n++], PATH_MAX, "%s", arg);
    }
    /* The name relative to conf_dir (HASH, HASH.pub, HASH.key) */
    if (path_ext_compatible(arg, ext))
        snprintf(cand[n++], PATH_MAX, "%s/%s", gorgona_conf_dir, arg);
    /* Canonical path <conf_dir>/<hash>.<ext> */
    snprintf(cand[n++], PATH_MAX, "%s/%s.%s", gorgona_conf_dir, hash, ext);

    for (int i = 0; i < n; i++) {
        if (regular_file_exists(cand[i])) {
            snprintf(out, outlen, "%s", cand[i]);
            return 0;
        }
    }

    /* Nothing found, return the canonical path for the error message */
    snprintf(out, outlen, "%s", cand[n - 1]);
    return -1;
}

void read_config(const char *config_path, Config *config, int verbose) {
    /* Initialize defaults */
    memset(config->sync_psk, 0, sizeof(config->sync_psk));
    if (strlen(DEFAULT_SERVER_IP) > 0) {
        strncpy(config->server_ip, DEFAULT_SERVER_IP, sizeof(config->server_ip) - 1);
    } else {
        config->server_ip[0] = '\0';
    }
    config->server_port = DEFAULT_SERVER_PORT;
    config->exec_count = 0;

    strncpy(gorgona_data_dir, DEFAULT_DATA_DIR, sizeof(gorgona_data_dir) - 1);
    gorgona_data_dir[sizeof(gorgona_data_dir) - 1] = '\0';
    strncpy(gorgona_conf_dir, DEFAULT_CONF_DIR, sizeof(gorgona_conf_dir) - 1);
    gorgona_conf_dir[sizeof(gorgona_conf_dir) - 1] = '\0';
    gorgona_log_file[0] = '\0';   /* Empty = use data_dir or /dev/null */

    /* Global sync file size limit (10 MiB by default) */
    long global_max_file_size = 10485760;

    FILE *conf_fp = fopen(config_path, "r");
    if (!conf_fp) {
        if (verbose) fprintf(stderr, "Warning: Config file %s not found. Using defaults.\n", config_path);
        return;
    }

    int in_server_section = 0;
    int in_exec_section   = 0;
    int in_sync_section   = 0;          /* [sync] or [sync:KEY] */
    int is_global_sync    = 0;          /* Exactly [sync], without a key */

    char current_required_key[256] = "";
    char current_sync_key[256]     = "";   /* Pubkey for [sync:KEY] */

    char line[512];
    while (fgets(line, sizeof(line), conf_fp)) {
        char *comment_ptr = strchr(line, '#');
        if (comment_ptr) *comment_ptr = '\0';

        char *trimmed = trim_spaces(line);
        if (*trimmed == '\0') continue;

        /* === Section header handling === */
        if (trimmed[0] == '[') {
            char *end = strchr(trimmed, ']');
            if (end) {
                *end = '\0';
                char *sec = trim_spaces(trimmed + 1);

                /* Reset all section flags */
                in_server_section = 0;
                in_exec_section   = 0;
                in_sync_section   = 0;
                is_global_sync    = 0;
                current_required_key[0] = '\0';
                current_sync_key[0]     = '\0';

                if (strncmp(sec, "exec_commands", 13) == 0) {
                    in_exec_section = 1;
                    char *colon = strchr(sec, ':');
                    if (colon) {
                        strncpy(current_required_key, trim_spaces(colon + 1),
                                sizeof(current_required_key) - 1);
                        current_required_key[sizeof(current_required_key) - 1] = '\0';
                    }
                }
                else if (strcmp(sec, "server") == 0) {
                    in_server_section = 1;
                }
                else if (strcmp(sec, "sync") == 0) {
                    /* Global [sync] section */
                    in_sync_section = 1;
                    is_global_sync  = 1;
                }
                else if (strncmp(sec, "sync:", 5) == 0) {
                    /* [sync:<pubkey>] section */
                    in_sync_section = 1;
                    is_global_sync  = 0;
                    strncpy(current_sync_key, trim_spaces(sec + 5),
                            sizeof(current_sync_key) - 1);
                    current_sync_key[sizeof(current_sync_key) - 1] = '\0';
                }
                /* Otherwise an unknown section, all flags are already reset */
                continue;
            }
        }

        /* === Handling of key = value pairs === */
        char *delimiter = strchr(trimmed, '=');
        if (!delimiter) continue;

        *delimiter = '\0';
        char *key   = trim_spaces(trimmed);
        char *value = trim_spaces(delimiter + 1);

        if (in_server_section) {
            if (strcmp(key, "ip") == 0) {
                strncpy(config->server_ip, value, sizeof(config->server_ip) - 1);
                config->server_ip[sizeof(config->server_ip) - 1] = '\0';
            }
            else if (strcmp(key, "port") == 0) {
                config->server_port = atoi(value);
            }
            else if (strcmp(key, "sync_psk") == 0) {
                strncpy(config->sync_psk, value, sizeof(config->sync_psk) - 1);
                config->sync_psk[sizeof(config->sync_psk) - 1] = '\0';
            }
            else if (strcmp(key, "data_dir") == 0) {
                strncpy(gorgona_data_dir, value, sizeof(gorgona_data_dir) - 1);
                gorgona_data_dir[sizeof(gorgona_data_dir) - 1] = '\0';
            }
            else if (strcmp(key, "conf_dir") == 0) {
                strncpy(gorgona_conf_dir, value, sizeof(gorgona_conf_dir) - 1);
                gorgona_conf_dir[sizeof(gorgona_conf_dir) - 1] = '\0';
            }
            else if (strcmp(key, "log_file") == 0) {
                strncpy(gorgona_log_file, value, sizeof(gorgona_log_file) - 1);
                gorgona_log_file[sizeof(gorgona_log_file) - 1] = '\0';
            }
            else if (strcmp(key, "log_level") == 0) {
                strncpy(client_log_level, value, sizeof(client_log_level) - 1);
                client_log_level[sizeof(client_log_level) - 1] = '\0';
            }
        }
        else if (in_exec_section) {
            if (strcmp(key, "key") == 0) {
                strncpy(current_required_key, value, sizeof(current_required_key) - 1);
                current_required_key[sizeof(current_required_key) - 1] = '\0';
                continue;
            }
            if (config->exec_count < MAX_EXEC_COMMANDS) {
                ExecCommand *cmd = &config->exec_commands[config->exec_count];
                cmd->time_limit = 0;

                char *limit_ptr = strstr(value, "time_limit =");
                if (limit_ptr) {
                    cmd->time_limit = atoi(limit_ptr + 12);
                    *limit_ptr = '\0';
                }

                char *cleaned_path = trim_spaces(value);
                strncpy(cmd->key, key, sizeof(cmd->key) - 1);
                cmd->key[sizeof(cmd->key) - 1] = '\0';
                strncpy(cmd->value, cleaned_path, sizeof(cmd->value) - 1);
                cmd->value[sizeof(cmd->value) - 1] = '\0';
                strncpy(cmd->required_key, current_required_key, sizeof(cmd->required_key) - 1);
                cmd->required_key[sizeof(cmd->required_key) - 1] = '\0';

                config->exec_count++;
            }
        }
        else if (in_sync_section) {
            if (is_global_sync) {
                /* Global [sync] section */
                if (strcmp(key, "max_file_size") == 0) {
                    global_max_file_size = atol(value);
                    if (global_max_file_size <= 0)
                        global_max_file_size = 10485760;  /* Guard against invalid values */
                }
                /* Other global sync parameters can be added here */
            }
            else {
                /* [sync:<pubkey>] section */
                if (current_sync_key[0] == '\0')
                    continue;   /* Just in case */

                sync_config_t *rule = get_or_create_sync_rule(current_sync_key);
                if (!rule)
                    continue;   /* Rule could not be created */

                if (strcmp(key, "dir") == 0) {
                    strncpy(rule->dir, value, sizeof(rule->dir) - 1);
                    rule->dir[sizeof(rule->dir) - 1] = '\0';
                }
                else if (strcmp(key, "direction") == 0) {
                    strncpy(rule->direction, value, sizeof(rule->direction) - 1);
                    rule->direction[sizeof(rule->direction) - 1] = '\0';
                }
                else if (strcmp(key, "on_change") == 0) {
                    strncpy(rule->on_change, value, sizeof(rule->on_change) - 1);
                    rule->on_change[sizeof(rule->on_change) - 1] = '\0';
                }
                else if (strcmp(key, "max_size") == 0 || strcmp(key, "max_file_size") == 0) {
                    rule->max_file_size = (size_t)atol(value);
                }
            }
        }
    }
    fclose(conf_fp);

    /* After parsing: if a rule has no max_file_size set, fall back to the global one */
    /* (get_or_create_sync_rule / the rule list are expected to be available) */
    apply_global_max_file_size((size_t)global_max_file_size); 

    if (verbose && config->server_ip[0] != '\0') {
        printf("Config: Node IP set to %s:%d\n", config->server_ip, config->server_port);
    }
}

int connect_with_timeout(const char *ip, int port, int timeout_ms) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    int res = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (res < 0 && errno != EINPROGRESS) { close(sock); return -1; }
    struct timeval tv = { .tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000 };
    fd_set fdset; FD_ZERO(&fdset); FD_SET(sock, &fdset);
    res = select(sock + 1, NULL, &fdset, NULL, &tv);
    if (res > 0) {
        int so_error; socklen_t len = sizeof(so_error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error == 0) {
            fcntl(sock, F_SETFL, flags);
            int nodelay = 1;
            setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&nodelay, sizeof(int));
            return sock;
        }
    }
    close(sock); return -1;
}

/* STICKY_NODE_PATH now uses gorgona_data_dir */
void save_sticky_node(const char *ip, int port) {
    char sticky_path[512];
    snprintf(sticky_path, sizeof(sticky_path), "%s/sticky_node", gorgona_data_dir);
    int fd = open(sticky_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd >= 0) {
        char buf[64];
        int len = snprintf(buf, sizeof(buf), "%s:%d", ip, port);
        if (len > 0) write(fd, buf, (size_t)len);
        close(fd);
        chmod(sticky_path, 0666);
    }
}

void invalidate_sticky_node() {
    char sticky_path[512];
    snprintf(sticky_path, sizeof(sticky_path), "%s/sticky_node", gorgona_data_dir);
    unlink(sticky_path);
}
