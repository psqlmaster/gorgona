/*
BSD 3-Clause License
Copyright (c) 2025, Alexander Shcheglov
All rights reserved.
*/
#ifndef GORGONA_CLIENT_CONFIG_H
#define GORGONA_CLIENT_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <limits.h>

#define DEFAULT_SERVER_IP ""
#define DEFAULT_SERVER_PORT 7777
#define MAX_EXEC_COMMANDS 100
#define DEFAULT_CONFIG_FILE "/etc/gorgona/gorgona.conf"

extern char config_file_path[512];

typedef struct {
    char key[256];
    char value[1024];
    char required_key[256];
    int time_limit;
} ExecCommand;

typedef struct {
    char server_ip[256];
    int server_port;
    ExecCommand exec_commands[MAX_EXEC_COMMANDS];
    int exec_count;
    char sync_psk[64];
} Config;

typedef struct sync_config {
    char pubkey[128];
    char dir[PATH_MAX];
    char direction[8];      /* "ro", "wo", "rw" */
    char on_change[256];
    size_t max_file_size;
    struct sync_config *next;
} sync_config_t;

/* Глобальный список правил синхронизации */
extern sync_config_t *sync_rules_head;

/* Создать или найти правило по pubkey.
 * Возвращает указатель на правило или NULL при ошибке выделения памяти. */
sync_config_t *get_or_create_sync_rule(const char *pubkey);

/* Применить глобальный лимит max_file_size ко всем правилам,
 * у которых он ещё не задан (равен 0). */
void apply_global_max_file_size(size_t global_limit);

/* Существующий прототип оставляем */
const sync_config_t *config_get_sync_rule(const char *pubkey);

void read_config(const char *config_path, Config *config, int verbose);

int connect_with_timeout(const char *ip, int port, int timeout_ms);
int try_sticky_node(int verbose);
void save_sticky_node(const char *ip, int port);
void invalidate_sticky_node();

#endif
