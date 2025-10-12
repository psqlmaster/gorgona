#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void read_config(Config *config, int verbose) {
    strcpy(config->server_ip, DEFAULT_SERVER_IP);
    config->server_port = DEFAULT_SERVER_PORT;
    config->exec_count = 0;

    FILE *conf_fp = fopen("/etc/gargona/gargona.conf", "r");
    if (!conf_fp) {
        if (verbose) fprintf(stderr, "Warning: Failed to open config file /etc/gargona/gargona.conf\n");
        return;
    }

    int in_server_section = 0;
    int in_exec_section = 0;
    char line[512];
    while (fgets(line, sizeof(line), conf_fp)) {
        line[strcspn(line, "\n\r")] = '\0';
        if (strlen(line) == 0 || line[0] == '#') continue;

        if (strstr(line, "[server]")) {
            in_server_section = 1;
            in_exec_section = 0;
            continue;
        } else if (strstr(line, "[exec_commands]")) {
            in_server_section = 0;
            in_exec_section = 1;
            continue;
        }

        char *trimmed = line;
        while (*trimmed == ' ' || *trimmed == '\t') trimmed++;

        char *key = strtok(trimmed, "=");
        char *value = strtok(NULL, "=");
        if (key && value) {
            while (*key == ' ' || *key == '\t') key++;
            char *end = key + strlen(key) - 1;
            while (end > key && (*end == ' ' || *end == '\t')) *end-- = '\0';

            while (*value == ' ' || *value == '\t') value++;
            end = value + strlen(value) - 1;
            while (end > value && (*end == ' ' || *end == '\t')) *end-- = '\0';

            if (in_server_section) {
                if (strcmp(key, "ip") == 0) {
                    strcpy(config->server_ip, value);
                    if (verbose) printf("Config: Loaded server_ip='%s'\n", value);
                } else if (strcmp(key, "port") == 0) {
                    config->server_port = atoi(value);
                    if (verbose) printf("Config: Loaded server_port=%d\n", config->server_port);
                }
            } else if (in_exec_section && config->exec_count < MAX_EXEC_COMMANDS) {
                strcpy(config->exec_commands[config->exec_count].key, key);
                strcpy(config->exec_commands[config->exec_count].value, value);
                if (verbose) printf("Config: Loaded exec_command[%d]: key='%s' value='%s'\n", 
                                    config->exec_count, key, value);
                config->exec_count++;
            }
        }
    }
    fclose(conf_fp);

    if (config->server_ip[0] == '\0') {
        strcpy(config->server_ip, DEFAULT_SERVER_IP);
        if (verbose) printf("Config: Using default server_ip='%s'\n", config->server_ip);
    }
}
