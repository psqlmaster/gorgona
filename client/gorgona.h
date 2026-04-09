/* 
* BSD 3-Clause License
* Copyright (c) 2025, Alexander Shcheglov
* All rights reserved. 
*/

#ifndef CONFIG_H
#define CONFIG_H

#define INET_ADDRSTRLEN 16

typedef struct {
    char server_ip[INET_ADDRSTRLEN];
    int server_port;
} Config;

int read_config(const char *filename, Config *config);

#endif
