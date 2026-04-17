/* 
* BSD 3-Clause License
* Copyright (c) 2025, Alexander Shcheglov
* All rights reserved. 
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "config.h"
#include "gorgona_utils.h"
#include "admin_mesh.h"

/**
 * Section identifiers for the configuration file parser.
 */
typedef enum {
    SECTION_NONE,
    SECTION_SERVER,
    SECTION_REPLICATION
} ConfigSection;

/**
 * Reads and parses the gorgonad.conf configuration file.
 * 
 * Supports two main sections:
 * [server]      - General server settings (port, limits, logging, etc.)
 * [replication] - P2P synchronization settings (PSK, peer list)
 * 
 * @param port Output for server listen port
 * @param max_alerts Output for max alerts per recipient
 * @param max_clients Output for max simultaneous connections
 * @param max_log_size Output for log rotation threshold (in bytes)
 * @param log_level Output buffer for the logging verbosity level
 * @param max_message_size Output for max allowed incoming payload size
 * @param use_disk_db Output flag for persistent storage (boolean)
 * @param vacuum_threshold Output for the database auto-cleanup percentage
 */
void read_config(int *port, int *max_alerts, int *max_clients, size_t *max_log_size, 
                 char *log_level, size_t *max_message_size, int *use_disk_db, int *vacuum_threshold, int *sync_interval) {
    
    /* Initialize default values in case the config file is missing or incomplete */
    *port = DEFAULT_SERVER_PORT;
    *max_alerts = DEFAULT_MAX_ALERTS;
    *max_clients = MAX_CLIENTS;
    *max_log_size = DEFAULT_MAX_LOG_SIZE;
    *max_message_size = DEFAULT_MAX_MESSAGE_SIZE;
    *use_disk_db = 0; 
    *vacuum_threshold = DEFAULT_VACUUM_THRESHOLD;
    *sync_interval = DEFAULT_SYNC_INTERVAL;
    
    /* Reset replication globals before parsing */
    remote_peer_count = 0;
    memset(sync_psk, 0, sizeof(sync_psk));
    strncpy(sync_psk, DEFAULT_SYNC_PSK, sizeof(sync_psk) - 1);

    if (log_level) {
        snprintf(log_level, 32, "%s", DEFAULT_LOG_LEVEL);
    }

    /* Attempt to open the configuration file */
    FILE *conf_fp = fopen("/etc/gorgona/gorgonad.conf", "r");
    if (!conf_fp) {
        /* If file is not found, we proceed with defaults initialized above */
        return;
    }

    char line[512];
    ConfigSection current_section = SECTION_NONE;

    /* Line-by-line parsing loop */
    while (fgets(line, sizeof(line), conf_fp)) {
        /* Remove inline comments (anything after #) */
        char *comment = strchr(line, '#');
        if (comment) {
            *comment = '\0';
        }

        /* Skip leading whitespace to find the start of the key or section */
        char *start = line;
        while (*start && isspace((unsigned char)*start)) {
            start++;
        }

        /* Skip empty lines or lines that were only comments */
        if (*start == '\0') {
            continue;
        }

        /* Detect and switch between [sections] */
        if (*start == '[') {
            if (strncmp(start, "[server]", 8) == 0) {
                current_section = SECTION_SERVER;
            } else if (strncmp(start, "[replication]", 13) == 0) {
                current_section = SECTION_REPLICATION;
            } else {
                current_section = SECTION_NONE;
            }
            continue;
        }

        /* Tokenize the line into Key and Value using '=' as the primary delimiter */
        char *key = strtok(start, " =\t\r\n");
        char *value = strtok(NULL, " =\t\r\n");
        
        if (!key || !value) {
            continue;
        }

        /* Sanitize key and value by trimming trailing whitespace */
        trim_string(key);
        trim_string(value);

        /* Parse keys based on the active section context */
        if (current_section == SECTION_SERVER) {
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
            } else if (strcmp(key, "vacuum_threshold_percent") == 0) {
                *vacuum_threshold = atoi(value);
                if (*vacuum_threshold < 1) *vacuum_threshold = 1;
                if (*vacuum_threshold > 100) *vacuum_threshold = 100;
            } else if (strcmp(key, "log_level") == 0) {
                if (log_level) {
                    strncpy(log_level, value, 31);
                    log_level[31] = '\0';
                }
            }
        } 
        else if (current_section == SECTION_REPLICATION) {
            if (strcmp(key, "sync_interval") == 0) {
                *sync_interval = atoi(value);
                if (*sync_interval < 1) *sync_interval = 1;
            }
            else if (strcmp(key, "sync_psk") == 0) { 
                /* Pre-shared key for inter-server authentication */
                strncpy(sync_psk, value, sizeof(sync_psk) - 1);
                sync_psk[sizeof(sync_psk) - 1] = '\0';
            } 
            else if (strcmp(key, "peer") == 0) {
                /* Peer format: IP:PORT (e.g., 127.0.0.1:7777) */
                char *colon = strchr(value, ':');
                if (colon) {
                    *colon = '\0'; // Теперь 'value' указывает на IP, а 'colon + 1' на порт
                    int p_port = atoi(colon + 1);

                    /* 1. Инициализируем узел в новой Mesh-таблице (Layer 2) */
                    if (cluster_node_count < (MAX_PEERS * 4)) {
                        MeshNode *n = &cluster_nodes[cluster_node_count++];
                        memset(n, 0, sizeof(MeshNode));
                        
                        strncpy(n->ip, value, INET_ADDRSTRLEN - 1);
                        n->port = p_port;
                        n->is_seed = true;            // Эти узлы из конфига — скелет сети
                        n->status = PEER_STATUS_OFFLINE;
                        n->discovered_at = time(NULL); // Для GC и отладки
                        n->last_seen = time(NULL);
                        
                        // Лог для отладки (будет виден в режиме verbose)
                        if (verbose) {
                            printf("Config: Added seed node %s:%d to Layer 2 table\n", n->ip, n->port);
                        }
                    }
                    /* 2. Сохраняем в старый массив для совместимости (legacy connection loop) */
                    /* Важно: здесь проверяем старую границу MAX_PEERS */
                    if (remote_peer_count < MAX_PEERS) {
                        strncpy(remote_peers[remote_peer_count].ip, value, INET_ADDRSTRLEN - 1);
                        remote_peers[remote_peer_count].port = p_port;
                        remote_peers[remote_peer_count].sd = -1;
                        remote_peers[remote_peer_count].active = false;
                        remote_peer_count++;
                    }
                }
            }
        }
    }

    /* Cleanup */
    fclose(conf_fp);
}
