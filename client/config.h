/*
BSD 3-Clause License
Copyright (c) 2025, Alexander Shcheglov
All rights reserved.
*/
#ifndef GORGONA_CLIENT_CONFIG_H
#define GORGONA_CLIENT_CONFIG_H

#include <stdbool.h>

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

void read_config(const char *config_path, Config *config, int verbose);

int connect_with_timeout(const char *ip, int port, int timeout_ms);
int try_sticky_node(int verbose);
void save_sticky_node(const char *ip, int port);
void invalidate_sticky_node();

#endif
