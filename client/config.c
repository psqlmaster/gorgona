#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void read_config(Config *config, int verbose) {
    strcpy(config->server_ip, DEFAULT_SERVER_IP);
    config->server_port = DEFAULT_SERVER_PORT;
    config->exec_count = 0;

    FILE *conf_fp = fopen("/etc/gorgona/gorgona.conf", "r");
    if (!conf_fp) {
        if (verbose) fprintf(stderr, "Warning: Failed to open config file /etc/gorgona/gorgona.conf\n");
        return;
    }

    int in_server_section = 0;
    int in_exec_section = 0;
    char current_required_key[256] = "";
    char line[512];

    while (fgets(line, sizeof(line), conf_fp)) {
        line[strcspn(line, "\n\r")] = '\0';

        /* Trim leading whitespace */
        char *trimmed = line;
        while (*trimmed == ' ' || *trimmed == '\t') trimmed++;
        if (strlen(trimmed) == 0 || trimmed[0] == '#') continue;

        /* Section header parsing: support [server], [exec_commands] and
           [exec_commands:KEY] where KEY is the pubkey_hash (base64) that
           will be applied to all commands in that section. */
        if (trimmed[0] == '[') {
            char *end = strchr(trimmed, ']');
            if (end) {
                size_t sec_len = (size_t)(end - (trimmed + 1));
                char sec[256];
                if (sec_len >= sizeof(sec)) sec_len = sizeof(sec) - 1;
                memcpy(sec, trimmed + 1, sec_len);
                sec[sec_len] = '\0';

                /* Trim whitespace in section name */
                char *s = sec;
                while (*s == ' ' || *s == '\t') s++;
                char *t = s + strlen(s) - 1;
                while (t > s && (*t == ' ' || *t == '\t')) *t-- = '\0';

                if (strncmp(s, "exec_commands", 13) == 0) {
                    in_exec_section = 1;
                    in_server_section = 0;
                    char *colon = strchr(s, ':');
                    if (colon) {
                        char *keyval = colon + 1;
                        while (*keyval == ' ' || *keyval == '\t') keyval++;
                        if (*keyval == '\0') {
                            current_required_key[0] = '\0';
                        } else {
                            strncpy(current_required_key, keyval, sizeof(current_required_key) - 1);
                            current_required_key[sizeof(current_required_key) - 1] = '\0';
                        }
                    } else {
                        current_required_key[0] = '\0';
                    }
                    if (verbose) printf("Config: Entering exec_commands section, required_key='%s'\n", current_required_key[0] ? current_required_key : "(none)");
                    continue;
                } else if (strcmp(s, "server") == 0) {
                    in_server_section = 1;
                    in_exec_section = 0;
                    current_required_key[0] = '\0';
                    continue;
                } else {
                    in_server_section = 0;
                    in_exec_section = 0;
                    current_required_key[0] = '\0';
                    continue;
                }
            }
        }

        /* Parse key=value lines inside sections */
        char *key = strtok(trimmed, "=");
        char *value = NULL;
        if (key) {
            value = strtok(NULL, ""); /* rest of the line */
        }
        if (key && value) {
            /* Trim spaces */
            while (*key == ' ' || *key == '\t') key++;
            char *end = key + strlen(key) - 1;
            while (end > key && (*end == ' ' || *end == '\t')) *end-- = '\0';

            while (*value == ' ' || *value == '\t') value++;
            end = value + strlen(value) - 1;
            while (end > value && (*end == ' ' || *end == '\t')) *end-- = '\0';

            if (in_server_section) {
                if (strcmp(key, "ip") == 0) {
                    strncpy(config->server_ip, value, sizeof(config->server_ip) - 1);
                    config->server_ip[sizeof(config->server_ip) - 1] = '\0';
                    if (verbose) printf("Config: Loaded server_ip='%s'\n", value);
                } else if (strcmp(key, "port") == 0) {
                    config->server_port = atoi(value);
                    if (verbose) printf("Config: Loaded server_port=%d\n", config->server_port);
                }
            } else if (in_exec_section) {
                /* Legacy: support 'key = <value>' inside section to set required key */
                if (strcmp(key, "key") == 0) {
                    strncpy(current_required_key, value, sizeof(current_required_key) - 1);
                    current_required_key[sizeof(current_required_key) - 1] = '\0';
                    if (verbose) printf("Config: Set current required key='%s' for subsequent commands\n", current_required_key);
                    continue;
                }

                if (config->exec_count < MAX_EXEC_COMMANDS) {
                    strncpy(config->exec_commands[config->exec_count].key, key, sizeof(config->exec_commands[config->exec_count].key) - 1);
                    config->exec_commands[config->exec_count].key[sizeof(config->exec_commands[config->exec_count].key) - 1] = '\0';
                    strncpy(config->exec_commands[config->exec_count].value, value, sizeof(config->exec_commands[config->exec_count].value) - 1);
                    config->exec_commands[config->exec_count].value[sizeof(config->exec_commands[config->exec_count].value) - 1] = '\0';
                    /* Associate the command with the currently active required key (if any) */
                    strncpy(config->exec_commands[config->exec_count].required_key, current_required_key, sizeof(config->exec_commands[config->exec_count].required_key) - 1);
                    config->exec_commands[config->exec_count].required_key[sizeof(config->exec_commands[config->exec_count].required_key) - 1] = '\0';
                    if (verbose) printf("Config: Loaded exec_command[%d]: key='%s' value='%s' required_key='%s'\n",
                                        config->exec_count, key, value, config->exec_commands[config->exec_count].required_key[0] ? config->exec_commands[config->exec_count].required_key : "(none)");
                    config->exec_count++;
                } else if (verbose) {
                    fprintf(stderr, "Config: exec_commands capacity exceeded, ignoring '%s'\n", key);
                }
            }
        }
    }

    fclose(conf_fp);

    if (config->server_ip[0] == '\0') {
        strcpy(config->server_ip, DEFAULT_SERVER_IP);
        if (verbose) printf("Config: Using default server_ip='%s'\n", config->server_ip);
    }
}
