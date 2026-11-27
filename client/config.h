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

/* Global list of sync rules */
extern sync_config_t *sync_rules_head;

/* Finds a rule by pubkey or creates it,
 * returns the rule or NULL on allocation failure. */
sync_config_t *get_or_create_sync_rule(const char *pubkey);

/* Applies the global max_file_size limit to the rules
 * that do not have it set yet (zero). */
void apply_global_max_file_size(size_t global_limit);

const sync_config_t *config_get_sync_rule(const char *pubkey);

void read_config(const char *config_path, Config *config, int verbose);

/* Reduces a key argument (HASH, HASH.pub, HASH.key or a full path)
 * to the bare public key hash. */
void key_arg_to_hash(const char *arg, char *out, size_t outlen);

/* Resolves a key argument to an existing "pub" or "key" file path,
 * returns 0 on success, -1 with the canonical path in out otherwise. */
int key_arg_resolve(const char *arg, const char *ext, char *out, size_t outlen);

int connect_with_timeout(const char *ip, int port, int timeout_ms);
int try_sticky_node(int verbose);
void save_sticky_node(const char *ip, int port);
void invalidate_sticky_node();

#endif
