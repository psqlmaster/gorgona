/* 
* client/peer_manager.c - Autonomous Connectivity Engine Implementation
* BSD 3-Clause License
* Copyright (c) 2025, Alexander Shcheglov
*/

#define _GNU_SOURCE
#include "peer_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <time.h>

extern int verbose;
void trim_string(char *str); 

static PeerAddr known_peers[MAX_PEER_TARGETS];
static char penalty_ips[MAX_PEER_TARGETS][INET_ADDRSTRLEN];
static time_t penalty_times[MAX_PEER_TARGETS];
static int penalty_count = 0;
int peer_count = 0;

/**
 * Helper to add unique peer addresses and prevent duplicates.
 */
static void add_peer(const char *ip, int port) {
    if (peer_count >= MAX_PEER_TARGETS || !ip || strlen(ip) < 7) return;
    
    char clean_ip[64];
    strncpy(clean_ip, ip, sizeof(clean_ip)-1);
    clean_ip[sizeof(clean_ip)-1] = '\0';
    trim_string(clean_ip);

    for (int i = 0; i < peer_count; i++) {
        if (strcmp(known_peers[i].ip, clean_ip) == 0 && known_peers[i].port == port) return;
    }

    strncpy(known_peers[peer_count].ip, clean_ip, INET_ADDRSTRLEN - 1);
    known_peers[peer_count].ip[INET_ADDRSTRLEN - 1] = '\0';
    known_peers[peer_count].port = port;
    peer_count++;
}

/**
 * Populates the internal candidate table with prioritized endpoints.
 * 
 * Logic workflow for Smart Mesh mode:
 * 1. MESH CACHE: Highest priority. Proven peers discovered via Gossip/PEX are 
 *    probed first to leverage network proximity and performance scores.
 * 2. STATIC CONFIG: Secondary priority. Serves as a fallback if the dynamic 
 *    cache is empty or all cached nodes are unreachable.
 * @param config Pointer to the initialized client configuration.
 */
void peer_manager_load_cache(Config *config) {
    peer_count = 0;
    memset(known_peers, 0, sizeof(known_peers));

    /* Case A: Legacy mode fallback when Layer 2 (PSK) is not defined */
    if (config->sync_psk[0] == '\0') {
        if (config->server_ip[0] != '\0') {
            add_peer(config->server_ip, config->server_port);
        }
        return; 
    }

    /* Case B: Smart Mesh mode connectivity logic */

    /* PRIORITY 1: Distributed Intelligence (Gossip Cache) */
    FILE *fp = fopen(PEERS_CACHE_PATH, "r");
    if (fp) {
        char line[128];
        while (fgets(line, sizeof(line), fp) && peer_count < MAX_PEER_TARGETS) {
            trim_string(line);
            char *colon = strchr(line, ':');
            if (colon) {
                *colon = '\0';
                /* Add dynamic peer. Due to sorting on the server side, 
                   high-score peers appear early in the file. */
                add_peer(line, atoi(colon + 1));
            }
        }
        fclose(fp);
    }

    /* PRIORITY 2: Administrative Bootstrap (Static IP from gorgona.conf) */
    if (config->server_ip[0] != '\0') {
        add_peer(config->server_ip, config->server_port);
    }
    
    if (verbose) {
        printf("Mesh Status: Orchestration candidates loaded (Count: %d, Head: %s)\n", 
               peer_count, peer_count > 0 ? known_peers[0].ip : "None");
    }
}

/**
 * High-performance connection selector with Migration Intelligence.
 * 
 * Logic:
 * 1. Checks if a 'Sticky' node exists.
 * 2. Compares the Sticky node with the current Top Priority candidate from Mesh.
 * 3. If they differ, the Sticky cache is ignored to allow 'migration' to a 
 *    better performing node discovered via PEX.
 */
int peer_manager_get_best_connection(void) {
    char sticky_ip[INET_ADDRSTRLEN] = "";
    int sticky_port = 0;
    bool has_sticky = false;

    /* Read current sticky node metadata without connecting yet */
    int s_fd = open(STICKY_NODE_PATH, O_RDONLY);
    if (s_fd >= 0) {
        char buf[64];
        ssize_t n = read(s_fd, buf, sizeof(buf)-1);
        close(s_fd);
        if (n > 0) {
            buf[n] = '\0';
            char *colon = strchr(buf, ':');
            if (colon) {
                *colon = '\0';
                strncpy(sticky_ip, buf, INET_ADDRSTRLEN - 1);
                sticky_port = atoi(colon + 1);
                has_sticky = true;
            }
        }
    }

    /* 
     * MIGRATION CHECK:
     * If we have mesh candidates and the Top Priority node (Head) is 
     * different from our Sticky node, we trigger a fresh probe cycle.
     */
    if (has_sticky && peer_count > 0) {
        if (strcmp(sticky_ip, known_peers[0].ip) != 0) {
            if (verbose) {
                printf("Mesh: Migration triggered. Better candidate [%s] found (Current sticky: %s)\n", 
                       known_peers[0].ip, sticky_ip);
            }
            has_sticky = false; /* Ignore sticky to force the loop below */
        }
    }

    /* Fast path: Use sticky node only if it's still our best choice */
    if (has_sticky) {
        if (verbose) printf("Mesh: Using sticky node [%s:%d]\n", sticky_ip, sticky_port);
        int sd = connect_with_timeout(sticky_ip, sticky_port, PROBE_TIMEOUT_MS);
        if (sd >= 0) return sd;
    }

    /* Slow path: Standard Probing Cycle */
    time_t now = time(NULL);
    if (peer_count == 0) return -1;

    for (int i = 0; i < peer_count; i++) {
        /* 1. Skip nodes currently in the Penalty Box */
        bool punished = false;
        for (int p = 0; p < penalty_count; p++) {
            if (strcmp(known_peers[i].ip, penalty_ips[p]) == 0) {
                if (now - penalty_times[p] < 300) { punished = true; break; }
            }
        }
        if (punished) continue;

        int sd = socket(AF_INET, SOCK_STREAM, 0);
        if (sd < 0) continue;

        int flags = fcntl(sd, F_GETFL, 0);
        fcntl(sd, F_SETFL, flags | O_NONBLOCK);

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(known_peers[i].port);
        inet_pton(AF_INET, known_peers[i].ip, &addr.sin_addr);

        if (verbose) {
            printf("  -> Probing: %s:%d... ", known_peers[i].ip, known_peers[i].port);
            fflush(stdout);
        }

        int res = connect(sd, (struct sockaddr *)&addr, sizeof(addr));
        if (res < 0 && errno == EINPROGRESS) {
            struct timeval tv = { .tv_sec = 1, .tv_usec = 0 }; // 1s timeout for migration probe
            fd_set wfds; FD_ZERO(&wfds); FD_SET(sd, &wfds);
            res = select(sd + 1, NULL, &wfds, NULL, &tv);
            if (res > 0) {
                int error = 0; socklen_t len = sizeof(error);
                getsockopt(sd, SOL_SOCKET, SO_ERROR, &error, &len);
                res = (error == 0) ? 0 : -1;
            } else res = -1;
        }

        if (res == 0) {
            if (verbose) printf("CONNECTED\n");
            int f = fcntl(sd, F_GETFL, 0);
            fcntl(sd, F_SETFL, f & ~O_NONBLOCK);
            
            /* Update sticky memory to the new best peer */
            save_sticky_node(known_peers[i].ip, known_peers[i].port);
            return sd; 
        }

        if (verbose) printf("FAILED (%s)\n", strerror(errno));
        close(sd);
    }

    return -1;
}

/**
 * Updates the peer cache with discovered nodes from Mesh gossip.
 */
void peer_manager_update_cache(const char *payload) {
    if (!payload || strlen(payload) == 0) return;

    char *list_start = strchr(payload, '|');
    if (!list_start) return;
    list_start++; 

    FILE *fp = fopen(PEERS_CACHE_PATH, "a+");
    if (!fp) return;

    char *copy = strdup(list_start);
    char *token = strtok(copy, "|");

    while (token) {
        if (strchr(token, ':')) {
            fseek(fp, 0, SEEK_SET);
            char line[128];
            bool duplicate = false;
            while (fgets(line, sizeof(line), fp)) {
                trim_string(line);
                if (strcmp(line, token) == 0) { duplicate = true; break; }
            }

            if (!duplicate) {
                fseek(fp, 0, SEEK_END);
                fprintf(fp, "%s\n", token);
                if (verbose) printf("Mesh: Cached new peer via Gossip [%s]\n", token);
            }
        }
        token = strtok(NULL, "|");
    }

    fclose(fp);
    free(copy);
}

/**
 * Penalizes a node for protocol/auth failure to avoid retrying it.
 */
void peer_manager_mark_bad(const char *ip) {
    if (!ip) return;
    time_t now = time(NULL);
    
    for (int i = 0; i < penalty_count; i++) {
        if (strcmp(penalty_ips[i], ip) == 0) {
            penalty_times[i] = now;
            return;
        }
    }

    if (penalty_count < MAX_PEER_TARGETS) {
        strncpy(penalty_ips[penalty_count], ip, INET_ADDRSTRLEN - 1);
        penalty_times[penalty_count] = now;
        penalty_count++;
        if (verbose) printf("Mesh: Applied 5m penalty to node %s\n", ip);
    }
}
