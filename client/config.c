#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

/* Helper function to trim leading and trailing whitespace */
static char *trim_spaces(char *str) {
    if (!str) return NULL;
    /* Trim leading space */
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    /* Trim trailing space */
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    /* Write new null terminator */
    end[1] = '\0';
    return str;
}

void read_config(Config *config, int verbose) {
    /* Initialize defaults */
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
    char current_required_key[256] = "";
    char line[512];

    /* Process the configuration file line by line */
    while (fgets(line, sizeof(line), conf_fp)) {
        char *trimmed = trim_spaces(line);
        
        /* Skip empty lines and comments */
        if (*trimmed == '\0' || *trimmed == '#') continue;

        /* Parse section headers: [section_name] */
        if (trimmed[0] == '[') {
            char *end = strchr(trimmed, ']');
            if (end) {
                *end = '\0';
                char *sec = trim_spaces(trimmed + 1);

                /* Handle exec_commands sections (supports [exec_commands:KEY] syntax) */
                if (strncmp(sec, "exec_commands", 13) == 0) {
                    in_exec_section = 1;
                    in_server_section = 0;
                    
                    /* Check if a specific public key is assigned to this section */
                    char *colon = strchr(sec, ':');
                    if (colon) {
                        strncpy(current_required_key, trim_spaces(colon + 1), sizeof(current_required_key) - 1);
                        current_required_key[sizeof(current_required_key) - 1] = '\0';
                    } else {
                        /* No key specified for this section */
                        current_required_key[0] = '\0';
                    }
                    
                    if (verbose) printf("Config: Entering exec_commands section, required_key='%s'\n", 
                                       current_required_key[0] ? current_required_key : "(none)");
                } 
                else if (strcmp(sec, "server") == 0) {
                    in_server_section = 1;
                    in_exec_section = 0;
                    current_required_key[0] = '\0';
                } 
                else {
                    /* Reset flags for unknown sections */
                    in_server_section = 0;
                    in_exec_section = 0;
                    current_required_key[0] = '\0';
                }
                continue;
            }
        }

        /* Parse key-value pairs: key = value */
        char *delimiter = strchr(trimmed, '=');
        if (delimiter) {
            *delimiter = '\0';
            char *key = trim_spaces(trimmed);
            char *value = trim_spaces(delimiter + 1);

            if (in_server_section) {
                if (strcmp(key, "ip") == 0) {
                    strncpy(config->server_ip, value, sizeof(config->server_ip) - 1);
                    config->server_ip[sizeof(config->server_ip) - 1] = '\0';
                    if (verbose) printf("Config: Loaded server_ip='%s'\n", value);
                } else if (strcmp(key, "port") == 0) {
                    config->server_port = atoi(value);
                    if (verbose) printf("Config: Loaded server_port=%d\n", config->server_port);
                }
            } 
            else if (in_exec_section) {
                /* Legacy support: 'key = <value>' inside section to set required key for subsequent commands */
                if (strcmp(key, "key") == 0) {
                    strncpy(current_required_key, value, sizeof(current_required_key) - 1);
                    current_required_key[sizeof(current_required_key) - 1] = '\0';
                    if (verbose) printf("Config: Set current required key='%s'\n", current_required_key);
                    continue;
                }

                /* Store the command in the configuration array */
                if (config->exec_count < MAX_EXEC_COMMANDS) {
                    ExecCommand *cmd = &config->exec_commands[config->exec_count];
                    
                    strncpy(cmd->key, key, sizeof(cmd->key) - 1);
                    cmd->key[sizeof(cmd->key) - 1] = '\0';
                    
                    strncpy(cmd->value, value, sizeof(cmd->value) - 1);
                    cmd->value[sizeof(cmd->value) - 1] = '\0';
                    
                    /* Assign the currently active section key to this command */
                    strncpy(cmd->required_key, current_required_key, sizeof(cmd->required_key) - 1);
                    cmd->required_key[sizeof(cmd->required_key) - 1] = '\0';

                    if (verbose) {
                        printf("Config: Loaded exec_command[%d]: key='%s' value='%s' required_key='%s'\n",
                               config->exec_count, cmd->key, cmd->value, 
                               cmd->required_key[0] ? cmd->required_key : "(none)");
                    }
                    config->exec_count++;
                } else if (verbose) {
                    fprintf(stderr, "Config: exec_commands capacity exceeded, ignoring '%s'\n", key);
                }
            }
        }
    }

    fclose(conf_fp);

    /* Fallback to default IP if none was loaded */
    if (config->server_ip[0] == '\0') {
        strncpy(config->server_ip, DEFAULT_SERVER_IP, sizeof(config->server_ip) - 1);
        if (verbose) printf("Config: Using default server_ip='%s'\n", config->server_ip);
    }
}
