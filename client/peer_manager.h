/* 
* client/peer_manager.h - Autonomous Connectivity Engine Header
* BSD 3-Clause License
* Copyright (c) 2025, Alexander Shcheglov
*/

#ifndef PEER_MANAGER_H
#define PEER_MANAGER_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include "config.h"

/**
 * Shared path with gorgonad for peer synchronization.
 */
extern int peer_count; /* Global variable for reporting */

#define PEERS_CACHE_PATH "/var/lib/gorgona/peers.cache"
#define MAX_PEER_TARGETS 32
#define PROBE_TIMEOUT_MS 2000

typedef struct {
    char ip[INET_ADDRSTRLEN];
    int port;
} PeerAddr;

/**
 * Loads peers into the internal table.
 */
void peer_manager_load_cache(Config *config);

/**
 * Executes a parallel non-blocking probe (Happy Eyeballs).
 */
int peer_manager_get_best_connection(void);

void peer_manager_update_cache(const char *payload);
void peer_manager_mark_bad(const char *ip);

#endif /* PEER_MANAGER_H */
