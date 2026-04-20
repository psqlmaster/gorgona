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
 * Loads peers into the local candidate table.
 * Logic:
 * 1. If sync_psk is missing: Legacy mode (Static IP only).
 * 2. If sync_psk is present: Smart Mesh mode. Config IP has top priority, then cache.
 */
void peer_manager_load_cache(Config *config) {
    peer_count = 0;
    memset(known_peers, 0, sizeof(known_peers));

    /* CASE 1: LEGACY MODE (L2 Disabled) */
    if (config->sync_psk[0] == '\0') {
        if (config->server_ip[0] != '\0') {
            add_peer(config->server_ip, config->server_port);
        }
        if (verbose) {
            printf("Mesh Status: L2 disabled. Fallback to legacy static node [%s:%d]\n", 
                   config->server_ip, config->server_port);
        }
        return; 
    }

    /* CASE 2: SMART MESH MODE (L2 Enabled) */
    if (verbose) {
        printf("Mesh Status: L2 enabled. Compiling endpoint candidates...\n");
    }

    /* Priority 1: User-defined IP from config. This is our primary target. */
    if (config->server_ip[0] != '\0') {
        add_peer(config->server_ip, config->server_port);
    }

    /* Priority 2: Previously cached nodes from Mesh PEX intelligence */
    FILE *fp = fopen(PEERS_CACHE_PATH, "r");
    if (fp) {
        char line[128];
        while (fgets(line, sizeof(line), fp) && peer_count < MAX_PEER_TARGETS) {
            trim_string(line);
            char *colon = strchr(line, ':');
            if (colon) {
                *colon = '\0';
                add_peer(line, atoi(colon + 1));
            }
        }
        fclose(fp);
    }
}

/**
 * High-performance connection selector.
 * Implements 'Sticky Node' logic to bypass scanning in loop executions.
 */
int peer_manager_get_best_connection(void) {
    /* Step 0: Try to reuse a proven node from the RAM-based sticky cache */
    int sticky_sock = try_sticky_node(verbose);
    if (sticky_sock >= 0) {
        /* Already in blocking mode and verified by try_sticky_node */
        return sticky_sock;
    }

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

        /* 2. Setup Socket */
        int sd = socket(AF_INET, SOCK_STREAM, 0);
        if (sd < 0) continue;

        int flags = fcntl(sd, F_GETFL, 0);
        fcntl(sd, F_SETFL, flags | O_NONBLOCK);

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(known_peers[i].port);
        if (inet_pton(AF_INET, known_peers[i].ip, &addr.sin_addr) <= 0) {
            close(sd); continue;
        }

        if (verbose) {
            printf("  -> Probing: %s:%d... ", known_peers[i].ip, known_peers[i].port);
            fflush(stdout);
        }

        /* 3. Connection attempt with timeout */
        int res = connect(sd, (struct sockaddr *)&addr, sizeof(addr));
        if (res < 0 && errno == EINPROGRESS) {
            struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
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

            /* Restore blocking mode for data transmission */
            int f = fcntl(sd, F_GETFL, 0);
            fcntl(sd, F_SETFL, f & ~O_NONBLOCK);
            
            struct timeval rtv = { .tv_sec = 10, .tv_usec = 0 };
            setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof(rtv));
            
            /* Save this successful node as 'Sticky' for future calls */
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
