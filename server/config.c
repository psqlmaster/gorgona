#include "gorgona_utils.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

/* Reads configuration from gorgonad.conf */
void read_config(int *port, int *max_alerts, int *max_clients, size_t *max_log_size, char *log_level,
                 size_t *max_message_size, int *use_disk_db) {
    /* Set default values */
    *port = DEFAULT_SERVER_PORT;
    *max_alerts = DEFAULT_MAX_ALERTS;
    *max_clients = MAX_CLIENTS;
    *max_log_size = DEFAULT_MAX_LOG_SIZE;
    *max_message_size = DEFAULT_MAX_MESSAGE_SIZE;
    *use_disk_db = 0; /* false by default */
    if (log_level) {
          snprintf(log_level, 32, "%s", DEFAULT_LOG_LEVEL);
    }
    /* Open config file */
    FILE *conf_fp = fopen("/etc/gorgona/gorgonad.conf", "r");
    if (!conf_fp) {
        return;
    }
    char line[256];
    while (fgets(line, sizeof(line), conf_fp)) {
        /* Remove inline comments (everything after '#') */
        char *comment = strchr(line, '#');
        if (comment) {
            *comment = '\0';
        }
        /* Skip leading whitespace */
        char *start = line;
        while (*start && isspace((unsigned char)*start)) {
            start++;
        }
        /* Skip empty or whitespace-only lines */
        if (*start == '\0') {
            continue;
        }
        /* Skip section headers like [server] */
        if (*start == '[') {
            continue;
        }
        /* Tokenize key and value */
        char *key = strtok(start, " =\t");
        char *value = strtok(NULL, " =\t");
        if (!key || !value) {
            continue;
        }
        /* Remove trailing newline from value */
        value[strcspn(value, "\r\n")] = '\0';
        /* Trim whitespace from both ends */
        trim_string(key);
        trim_string(value);
        /* Parse known configuration keys */
        if (strcmp(key, "port") == 0) {
            *port = atoi(value);
        } else if (strcmp(key, "max_alerts") == 0) {
            *max_alerts = atoi(value);
        } else if (strcmp(key, "max_clients") == 0) {
            *max_clients = atoi(value);
        } else if (strcmp(key, "max_log_size") == 0) {
            long mb = atol(value);
            *max_log_size = (size_t)(mb * 1024 * 1024); 
        } else if (strcmp(key, "max_message_size") == 0) {
            long mb = atol(value);
            *max_message_size = (size_t)(mb * 1024 * 1024);
        } else if (strcmp(key, "use_disk_db") == 0) {
            *use_disk_db = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
        } else if (strcmp(key, "log_level") == 0) {
            if (log_level) {
                strncpy(log_level, value, 31);
                log_level[31] = '\0';
            }
        }
    }
    fclose(conf_fp);
}
