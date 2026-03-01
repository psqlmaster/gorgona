#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

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

void read_config(Config *config, int verbose) {
    /* Set default values */
    strncpy(config->server_ip, DEFAULT_SERVER_IP, sizeof(config->server_ip) - 1);
    config->server_ip[sizeof(config->server_ip) - 1] = '\0';
    config->server_port = DEFAULT_SERVER_PORT;
    config->exec_count = 0;

    FILE *conf_fp = fopen("/etc/gorgona/gorgona.conf", "r");
    if (!conf_fp) {
        if (verbose) fprintf(stderr, "Warning: Failed to open config file /etc/gorgona/gorgona.conf\n");
        return;
    }

    int in_server_section = 0;
    int in_exec_section = 0;
    char current_required_key[256] = ""; /* Empty string means "allow for any valid sender" */
    char line[512];

    while (fgets(line, sizeof(line), conf_fp)) {
        char *trimmed = trim_spaces(line);
        
        /* Skip empty lines and comments */
        if (*trimmed == '\0' || *trimmed == '#') continue;

        /* Parse section headers [section] */
        if (trimmed[0] == '[') {
            char *end = strchr(trimmed, ']');
            if (end) {
                *end = '\0';
                char *sec = trim_spaces(trimmed + 1);

                /* Handle exec_commands sections. Supports both:
                   [exec_commands] -> commands available to everyone
                   [exec_commands:KEY] -> commands available only for KEY */
                if (strncmp(sec, "exec_commands", 13) == 0) {
                    in_exec_section = 1;
                    in_server_section = 0;
                    
                    char *colon = strchr(sec, ':');
                    if (colon) {
                        /* Specific key required */
                        strncpy(current_required_key, trim_spaces(colon + 1), sizeof(current_required_key) - 1);
                        current_required_key[sizeof(current_required_key) - 1] = '\0';
                    } else {
                        /* No specific key (public section) */
                        current_required_key[0] = '\0';
                    }
                    
                    if (verbose) printf("Config: Entering exec_commands section, required_key='%s'\n", 
                                       current_required_key[0] ? current_required_key : "(any)");
                } 
                else if (strcmp(sec, "server") == 0) {
                    in_server_section = 1;
                    in_exec_section = 0;
                    current_required_key[0] = '\0';
                } 
                else {
                    /* Reset flags for any other sections */
                    in_server_section = 0;
                    in_exec_section = 0;
                }
                continue;
            }
        }

        /* Parse key = value pairs */
        char *delimiter = strchr(trimmed, '=');
        if (delimiter) {
            *delimiter = '\0';
            char *key = trim_spaces(trimmed);
            char *value = trim_spaces(delimiter + 1);

            if (in_server_section) {
                if (strcmp(key, "ip") == 0) {
                    strncpy(config->server_ip, value, sizeof(config->server_ip) - 1);
                    config->server_ip[sizeof(config->server_ip) - 1] = '\0';
                } else if (strcmp(key, "port") == 0) {
                    config->server_port = atoi(value);
                }
            } 
            else if (in_exec_section) {
                /* Inline 'key = value' support for backward compatibility */
                if (strcmp(key, "key") == 0) {
                    strncpy(current_required_key, value, sizeof(current_required_key) - 1);
                    current_required_key[sizeof(current_required_key) - 1] = '\0';
                    continue;
                }

                if (config->exec_count < MAX_EXEC_COMMANDS) {
                    ExecCommand *cmd = &config->exec_commands[config->exec_count];
                    
                    strncpy(cmd->key, key, sizeof(cmd->key) - 1);
                    cmd->key[sizeof(cmd->key) - 1] = '\0';
                    
                    strncpy(cmd->value, value, sizeof(cmd->value) - 1);
                    cmd->value[sizeof(cmd->value) - 1] = '\0';
                    
                    /* Store the key required for this specific command */
                    strncpy(cmd->required_key, current_required_key, sizeof(cmd->required_key) - 1);
                    cmd->required_key[sizeof(cmd->required_key) - 1] = '\0';

                    if (verbose) {
                        printf("Config: Loaded exec_command[%d]: key='%s' required_key='%s'\n",
                               config->exec_count, cmd->key, 
                               cmd->required_key[0] ? cmd->required_key : "(any)");
                    }
                    config->exec_count++;
                }
            }
        }
    }
    fclose(conf_fp);
}
