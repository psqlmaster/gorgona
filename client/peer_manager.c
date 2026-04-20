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

/* Helper to add unique peer addresses and prevent duplicates */
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
 * 
 * Logic flow:
 * 1. If config->sync_psk is EMPTY (missing or commented out): 
 *    Enters Legacy Mode. Connects strictly to the static IP defined in config.
 * 2. If config->sync_psk is PRESENT:
 *    Enters Smart Mesh Mode. Loads all available targets for parallel probes.
 * 
 * @param config Pointer to the client's configuration structure.
 */
void peer_manager_load_cache(Config *config) {
    peer_count = 0;
    memset(known_peers, 0, sizeof(known_peers));
    /* OPTION A: LEGACY MODE */
    if (config->sync_psk[0] == '\0') {
        if (config->server_ip[0] != '\0') {
            add_peer(config->server_ip, config->server_port);
        }
        
        if (verbose) {
            printf("Mesh Status: L2 disabled (no sync_psk). Fallback to legacy static node [%s:%d]\n", 
                   config->server_ip, config->server_port);
        }
        return; /* Stop right here. No sidecar, no cache, just one node */
    }
    /* OPTION B: SMART MESH MODE */
    if (verbose) {
        printf("Mesh Status: L2 enabled. Compiling endpoint candidates...\n");
    }
    /* Priority 1: Sidecar Mode (Always check local loopback first) */
    add_peer("127.0.0.1", config->server_port);
    /* Priority 2: Configured Static IP */
    if (config->server_ip[0] != '\0' && strcmp(config->server_ip, "127.0.0.1") != 0) {
        add_peer(config->server_ip, config->server_port);
    }
    /* Priority 3: Cached nodes from Mesh PEX intelligence */
    FILE *fp = fopen(PEERS_CACHE_PATH, "r");
    if (fp) {
        char line[128];
        while (fgets(line, sizeof(line), fp) && peer_count < MAX_PEER_TARGETS) {
            trim_string(line);
            char *colon = strchr(line, ':');
            if (colon) {
                *colon = '\0';
                char *ip = line;
                
                /* Guard: Filter out loopback duplicates from cache */
                if (strcmp(ip, "127.0.0.1") != 0 && strcmp(ip, "localhost") != 0) {
                    add_peer(ip, atoi(colon + 1));
                }
            }
        }
        fclose(fp);
    }
}

/**
 * Iterative best connection finder.
 * Tries candidates one by one with a non-blocking timeout.
 */
int peer_manager_get_best_connection(void) {
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

        /* Non-blocking mode for connect timeout control */
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

        /* 3. Attempt Connection */
        int res = connect(sd, (struct sockaddr *)&addr, sizeof(addr));
        
        if (res < 0 && errno == EINPROGRESS) {
            struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
            fd_set wfds; FD_ZERO(&wfds); FD_SET(sd, &wfds);
            
            res = select(sd + 1, NULL, &wfds, NULL, &tv);
            if (res > 0) {
                int error = 0; socklen_t len = sizeof(error);
                getsockopt(sd, SOL_SOCKET, SO_ERROR, &error, &len);
                res = (error == 0) ? 0 : -1;
            } else {
                res = -1; /* Timeout or generic failure */
            }
        }

        /* 4. Handle Result */
        if (res == 0) {
            if (verbose) printf("CONNECTED\n");

            /* Restore BLOCKING mode for regular operation */
            int f = fcntl(sd, F_GETFL, 0);
            fcntl(sd, F_SETFL, f & ~O_NONBLOCK);
            
            /* Apply a protection timeout for data receipt */
            struct timeval rtv = { .tv_sec = 10, .tv_usec = 0 };
            setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof(rtv));
            
            return sd; /* Winner found */
        }

        if (verbose) {
            printf("FAILED (%s)\n", strerror(errno));
        } 
        close(sd);
    }

    return -1;
}

/**
 * Ingests a decrypted PEX_LIST and updates /var/lib/gorgona/peers.cache
 * Expected payload: "REPORTED_PORT|IP1:PORT1|IP2:PORT2|..."
 */
void peer_manager_update_cache(const char *payload) {
    if (!payload || strlen(payload) == 0) return;

    /* 1. Skip the first part (the reported port of the sender) */
    char *list_start = strchr(payload, '|');
    if (!list_start) return;
    list_start++; /* Now points to IP:PORT list */

    /* 2. Open cache for checking and appending */
    FILE *fp = fopen(PEERS_CACHE_PATH, "a+");
    if (!fp) return;

    char *copy = strdup(list_start);
    char *token = strtok(copy, "|");

    while (token) {
        if (strchr(token, ':')) {
            /* Check if we already have this record to avoid duplicates */
            fseek(fp, 0, SEEK_SET);
            char line[128];
            bool duplicate = false;
            while (fgets(line, sizeof(line), fp)) {
                trim_string(line);
                if (strcmp(line, token) == 0) {
                    duplicate = true;
                    break;
                }
            }

            /* Add only new unique peers */
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
 * Flags the node as “problematic” 
 * He won't be participating in the Happy Eyeballs race for the next 5 minutes. 
 */
void peer_manager_mark_bad(const char *ip) {
    if (!ip) return;
    time_t now = time(NULL);
    
    /* If it's already on the list, update the time */
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
        if (verbose) printf("Mesh: Applied 5m penalty to node %s (Auth/Protocol failure)\n", ip);
    }
}
