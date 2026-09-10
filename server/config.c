#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "config.h"
#include "common.h"
#include "gorgona_utils.h"
#include "admin_mesh.h"

char config_file_path[512] = DEFAULT_CONFIG_FILE;

typedef enum {
    SECTION_NONE,
    SECTION_SERVER,
    SECTION_REPLICATION
} ConfigSection;

void read_config(const char *config_path, int *port, int *max_alerts, int *max_clients, size_t *max_log_size,
                 char *log_level, size_t *max_message_size, int *use_disk_db, int *vacuum_threshold, 
                 int *sync_interval, int *max_ttl) {
    
    *port = DEFAULT_SERVER_PORT;
    *max_alerts = DEFAULT_MAX_ALERTS;
    *max_clients = MAX_CLIENTS;
    *max_log_size = DEFAULT_MAX_LOG_SIZE;
    *max_message_size = DEFAULT_MAX_MESSAGE_SIZE;
    *use_disk_db = 0;
    *vacuum_threshold = DEFAULT_VACUUM_THRESHOLD;
    *sync_interval = DEFAULT_SYNC_INTERVAL;
    *max_ttl = DEFAULT_MAX_ALERT_TTL;

    strncpy(gorgona_data_dir, DEFAULT_DATA_DIR, sizeof(gorgona_data_dir) - 1);
    gorgona_data_dir[sizeof(gorgona_data_dir) - 1] = '\0';
    strncpy(gorgona_conf_dir, DEFAULT_CONF_DIR, sizeof(gorgona_conf_dir) - 1);
    gorgona_conf_dir[sizeof(gorgona_conf_dir) - 1] = '\0';

    remote_peer_count = 0;
    static bool first_init = true;
    if (first_init) {
        remote_peer_count = 0;
        cluster_node_count = 0;
        first_init = false;
    }

    memset(sync_psk, 0, sizeof(sync_psk));
    strncpy(sync_psk, DEFAULT_SYNC_PSK, sizeof(sync_psk) - 1);
    if (log_level) {
        snprintf(log_level, 32, "%s", DEFAULT_LOG_LEVEL);
    }

    FILE *conf_fp = fopen(config_path, "r");
    if (!conf_fp) {
        return;
    }

    char line[512];
    ConfigSection current_section = SECTION_NONE;

    while (fgets(line, sizeof(line), conf_fp)) {
        char *comment = strchr(line, '#');
        if (comment) *comment = '\0';

        char *start = line;
        while (*start && isspace((unsigned char)*start)) start++;
        if (*start == '\0') continue;

        if (*start == '[') {
            if (strncmp(start, "[server]", 8) == 0) current_section = SECTION_SERVER;
            else if (strncmp(start, "[replication]", 13) == 0) current_section = SECTION_REPLICATION;
            else current_section = SECTION_NONE;
            continue;
        }

        char *key = strtok(start, " =\t\r\n");
        char *value = strtok(NULL, " =\t\r\n");
        if (!key || !value) continue;

        trim_string(key);
        trim_string(value);

        if (current_section == SECTION_SERVER) {
            if (strcmp(key, "port") == 0) *port = atoi(value);
            else if (strcmp(key, "max_alerts") == 0) *max_alerts = atoi(value);
            else if (strcmp(key, "max_clients") == 0) *max_clients = atoi(value);
            else if (strcmp(key, "max_log_size") == 0) {
                long mb = atol(value);
                *max_log_size = (size_t)(mb * 1024 * 1024);
            }
            else if (strcmp(key, "max_message_size") == 0) {
                long mb = atol(value);
                *max_message_size = (size_t)(mb * 1024 * 1024);
            }
            else if (strcmp(key, "use_disk_db") == 0) {
                *use_disk_db = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
            }
            else if (strcmp(key, "vacuum_threshold_percent") == 0) {
                *vacuum_threshold = atoi(value);
                if (*vacuum_threshold < 1) *vacuum_threshold = 1;
                if (*vacuum_threshold > 100) *vacuum_threshold = 100;
            }
            else if (strcmp(key, "log_level") == 0) {
                if (log_level) {
                    strncpy(log_level, value, 31);
                    log_level[31] = '\0';
                }
            }
            else if (strcmp(key, "max_alert_ttl") == 0) {
                *max_ttl = atoi(value);
                if (*max_ttl < 60) *max_ttl = 60;
            }
            else if (strcmp(key, "data_dir") == 0) {
                strncpy(gorgona_data_dir, value, sizeof(gorgona_data_dir) - 1);
                gorgona_data_dir[sizeof(gorgona_data_dir) - 1] = '\0';
            }
            else if (strcmp(key, "conf_dir") == 0) {
                strncpy(gorgona_conf_dir, value, sizeof(gorgona_conf_dir) - 1);
                gorgona_conf_dir[sizeof(gorgona_conf_dir) - 1] = '\0';
            }
            else if (strcmp(key, "log_file") == 0) {   // ← НОВЫЙ БЛОК
                strncpy(gorgona_log_file, value, sizeof(gorgona_log_file) - 1);
                gorgona_log_file[sizeof(gorgona_log_file) - 1] = '\0';
            }
        }
        else if (current_section == SECTION_REPLICATION) {
            if (strcmp(key, "sync_interval") == 0) {
                *sync_interval = atoi(value);
                if (*sync_interval < 1) *sync_interval = 1;
            }
            else if (strcmp(key, "sync_psk") == 0) {
                strncpy(sync_psk, value, sizeof(sync_psk) - 1);
                sync_psk[sizeof(sync_psk) - 1] = '\0';
            }
            else if (strcmp(key, "peer") == 0) {
                char *colon = strchr(value, ':');
                if (colon) {
                    *colon = '\0';
                    int p_port = atoi(colon + 1);
                    if (cluster_node_count < (MAX_PEERS * 4)) {
                        MeshNode *n = &cluster_nodes[cluster_node_count++];
                        memset(n, 0, sizeof(MeshNode));
                        strncpy(n->addr, value, sizeof(n->addr) - 1);
                        n->addr[sizeof(n->addr) - 1] = '\0';
                        n->port = p_port;
                        n->is_seed = true;
                        n->status = PEER_STATUS_OFFLINE;
                        n->discovered_at = time(NULL);
                        n->last_seen = time(NULL);
                    }
                    if (remote_peer_count < MAX_PEERS) {
                        strncpy(remote_peers[remote_peer_count].addr, value, sizeof(remote_peers[remote_peer_count].addr) - 1);
                        remote_peers[remote_peer_count].port = p_port;
                        remote_peers[remote_peer_count].sd = -1;
                        remote_peers[remote_peer_count].active = false;
                        remote_peer_count++;
                    }
                }
            }
        }
    }
    fclose(conf_fp);
}
