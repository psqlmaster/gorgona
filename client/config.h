/* 
* BSD 3-Clause License
* Copyright (c) 2025, Alexander Shcheglov
* All rights reserved. 
*/
#include <stdbool.h>
#include <time.h>

#ifndef CONFIG_H
#define CONFIG_H
#define DEFAULT_SERVER_IP "192.168.1.200"
#define DEFAULT_SERVER_PORT 7777
#define MAX_EXEC_COMMANDS 100 
#define STICKY_NODE_PATH "/dev/shm/gorgona_sticky_node"

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
    int exec_count;  /* Number of entries */
    char sync_psk[64];
} Config;

void read_config(Config *config, int verbose);
int connect_with_timeout(const char *ip, int port, int timeout_ms);
int try_sticky_node(int verbose);
void save_sticky_node(const char *ip, int port);
void invalidate_sticky_node();
int perform_l2_auth(int sock, const char *psk, int verbose);
#endif
