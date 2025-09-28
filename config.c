#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void read_config(char *server_ip, int *server_port) {
    FILE *conf_fp = fopen("gargona.conf", "r");
    if (!conf_fp) {
        strcpy(server_ip, DEFAULT_SERVER_IP);
        *server_port = DEFAULT_SERVER_PORT;
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), conf_fp)) {
        if (strstr(line, "[server]")) continue;
        char *key = strtok(line, " =");
        char *value = strtok(NULL, " =");
        if (value) value[strcspn(value, "\n")] = '\0';
        if (key && strcmp(key, "ip") == 0) {
            strcpy(server_ip, value);
        } else if (key && strcmp(key, "port") == 0) {
            *server_port = atoi(value);
        }
    }
    fclose(conf_fp);
}
