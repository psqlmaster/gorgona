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
    /* Ищем существующее */
    for (sync_config_t *r = sync_rules_head; r; r = r->next) {
        if (strcmp(r->pubkey, pubkey) == 0)
            return r;
    }
    /* Создаём новое */
    sync_config_t *rule = calloc(1, sizeof(sync_config_t));
    if (!rule)
        return NULL;
    strncpy(rule->pubkey, pubkey, sizeof(rule->pubkey) - 1);
    rule->pubkey[sizeof(rule->pubkey) - 1] = '\0';
    /* значения по умолчанию */
    strncpy(rule->direction, "rw", sizeof(rule->direction) - 1);
    rule->max_file_size = 0;          /* 0 → потом подставится глобальный */
    rule->next = NULL;
    /* вставляем в начало списка */
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

/* Удобный поиск (уже был объявлен в заголовке) */
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

void read_config(const char *config_path, Config *config, int verbose) {
    /* 1. Initialize defaults */
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
    gorgona_log_file[0] = '\0';   /* пусто = использовать data_dir или /dev/null */

    /* Глобальный лимит размера файла для sync (по умолчанию 10 МБ) */
    long global_max_file_size = 10485760;

    FILE *conf_fp = fopen(config_path, "r");
    if (!conf_fp) {
        if (verbose) fprintf(stderr, "Warning: Config file %s not found. Using defaults.\n", config_path);
        return;
    }

    int in_server_section = 0;
    int in_exec_section   = 0;
    int in_sync_section   = 0;          /* 1 = [sync] или [sync:KEY] */
    int is_global_sync    = 0;          /* 1 = именно [sync] без ключа */

    char current_required_key[256] = "";
    char current_sync_key[256]     = "";   /* pubkey для [sync:KEY] */

    char line[512];
    while (fgets(line, sizeof(line), conf_fp)) {
        char *comment_ptr = strchr(line, '#');
        if (comment_ptr) *comment_ptr = '\0';

        char *trimmed = trim_spaces(line);
        if (*trimmed == '\0') continue;

        /* === Обработка заголовка секции === */
        if (trimmed[0] == '[') {
            char *end = strchr(trimmed, ']');
            if (end) {
                *end = '\0';
                char *sec = trim_spaces(trimmed + 1);

                /* Сброс всех флагов секций */
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
                    /* Глобальная секция [sync] */
                    in_sync_section = 1;
                    is_global_sync  = 1;
                }
                else if (strncmp(sec, "sync:", 5) == 0) {
                    /* Секция [sync:<pubkey>] */
                    in_sync_section = 1;
                    is_global_sync  = 0;
                    strncpy(current_sync_key, trim_spaces(sec + 5),
                            sizeof(current_sync_key) - 1);
                    current_sync_key[sizeof(current_sync_key) - 1] = '\0';
                }
                /* иначе — неизвестная секция, все флаги уже сброшены */
                continue;
            }
        }

        /* === Обработка пар key = value === */
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
                /* Глобальная секция [sync] */
                if (strcmp(key, "max_file_size") == 0) {
                    global_max_file_size = atol(value);
                    if (global_max_file_size <= 0)
                        global_max_file_size = 10485760;  /* защита */
                }
                /* здесь можно добавить другие глобальные параметры sync */
            }
            else {
                /* Секция [sync:<pubkey>] */
                if (current_sync_key[0] == '\0')
                    continue;   /* на всякий случай */

                sync_config_t *rule = get_or_create_sync_rule(current_sync_key);
                if (!rule)
                    continue;   /* нет свободных слотов */

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

    /* После парсинга: если у правила не задан max_file_size — берём глобальный */
    /* (предполагается, что get_or_create_sync_rule / список правил доступны) */
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

/* ✅ STICKY_NODE_PATH теперь использует gorgona_data_dir */
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
