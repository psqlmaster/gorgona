/* 
 * admin_mesh.c - Synchronized Progressive Layer 2
 * BSD 3-Clause License
 * Copyright (c) 2025, Alexander Shcheglov
 */
#define _GNU_SOURCE
#define PEERS_CACHE_FILE "/var/lib/gorgona/peers.cache"
#define MAX_CACHE_PEERS 10
#include "admin_mesh.h"
#include "common.h" 
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <ifaddrs.h>
#include <netdb.h>

static uint8_t mgmt_key[MGMT_K_LEN];
MeshNode cluster_nodes[MAX_PEERS * 4];
int cluster_node_count = 0;
bool mesh_force_save = false; 

void mesh_init(const char *psk) {
    SHA256((const unsigned char*)psk, strlen(psk), mgmt_key);
    log_event("INFO", -1, NULL, 0, "Layer 2 Mesh: Init successful (Key derived from PSK)");
    if (verbose) {
        printf("DEBUG: Mesh key initialized, cluster slots available: %d\n", MAX_PEERS * 4);
    }
}

void mesh_get_hmac(const uint8_t *nonce, uint8_t *out_hmac) {
    unsigned int len;
    HMAC(EVP_sha256(), mgmt_key, MGMT_K_LEN, nonce, CHALLENGE_LEN, out_hmac, &len);
}

/* Comparison function for qsort: descending by score */
static int mesh_cmp_nodes(const void *a, const void *b) {
    const MeshNode *nodeA = (const MeshNode *)a;
    const MeshNode *nodeB = (const MeshNode *)b;
    
    if (nodeA->metrics.gorgona_score > nodeB->metrics.gorgona_score) return -1;
    if (nodeA->metrics.gorgona_score < nodeB->metrics.gorgona_score) return 1;
    return 0;
}

void mesh_recalculate_scores() {
    time_t now = time(NULL);
    extern int sync_interval;

    for (int i = 0; i < cluster_node_count; i++) {
        MeshNode *n = &cluster_nodes[i];
        
        /* [DEAD NODE PROTECTION] 
         * If the node is offline or has not responded for more than 2 sync_interval cycles - Score = 0 */
        if (n->status == PEER_STATUS_OFFLINE || (now - n->last_seen > sync_interval * 2)) {
            n->metrics.gorgona_score = 0.0;
            continue;
        }

        /* Speed Score: Reference 10 MB/s */
        double s_score = n->metrics.rolling_avg_speed / (10.0 * 1024.0 * 1024.0);
        if (s_score > 1.0) s_score = 1.0;

        /* [FIXED] Latency Score: 
         * If RTT is undefined (0), the latency score is 0, not 1.0 */
        double l_score = 0.0;
        if (n->metrics.last_rtt > 0.1) {
            l_score = exp(-n->metrics.last_rtt / 100.0);
        }

        n->metrics.gorgona_score = (s_score * WEIGHT_SPEED) + (l_score * WEIGHT_LATENCY);
        /* Sort nodes so the most reliable/fastest appear at the top of the array */
        if (cluster_node_count > 1) {
            qsort(cluster_nodes, cluster_node_count, sizeof(MeshNode), mesh_cmp_nodes);
        }
    }
}

void mesh_update_speed(const char *ip, size_t bytes, double seconds) {
    if (seconds < 0.001) return;
    double sample = (double)bytes / seconds;

    for (int i = 0; i < cluster_node_count; i++) {
        if (strcmp(cluster_nodes[i].ip, ip) == 0) {
            MeshMetrics *m = &cluster_nodes[i].metrics;
            m->rolling_avg_speed = (m->rolling_avg_speed < 1.0) ? sample : (m->rolling_avg_speed * 0.7 + sample * 0.3);
            m->last_success = time(NULL);
            cluster_nodes[i].last_seen = time(NULL);
            return;
        }
    }
}

void mesh_update_rtt(const char *ip, double rtt_ms) {
    for (int i = 0; i < cluster_node_count; i++) {
        if (strcmp(cluster_nodes[i].ip, ip) == 0) {
            cluster_nodes[i].metrics.last_rtt = rtt_ms;
            cluster_nodes[i].last_seen = time(NULL);
            cluster_nodes[i].metrics.last_success = time(NULL);
            cluster_nodes[i].metrics.fail_count = 0;
            /* Если мы получили PONG - нода жива и проверена */
            cluster_nodes[i].status = PEER_STATUS_AUTHENTICATED;
            return;
        }
    }
}

void mesh_run_garbage_collector() {
    time_t now = time(NULL);
    extern int sync_interval;

    mesh_recalculate_scores();

    for (int i = 0; i < cluster_node_count; ) {
        MeshNode *n = &cluster_nodes[i];
        bool evict = false;
        /* SEED nodes have complete immunity */
        if (n->is_seed) {
            /* If the user is offline, simply reset the score to zero, but do not delete the entry */
            if (now - n->last_seen > sync_interval * 3) {
                n->status = PEER_STATUS_OFFLINE;
                n->metrics.gorgona_score = 0.0;
            }
            i++;
            continue;
        }
        /* [DELETION POLICY FOR CACHE AND PEX] */
        /* 1. If a node has been marked as offline for too long */
        if (now - n->last_seen > PEER_TTL) {
            evict = true;
        } 
        /* 2. If a node has accumulated too many connection errors */
        else if (n->metrics.fail_count > (n->is_cached ? 20 : 5)) {
            /* We give cached nodes 20 chances, but new (PEX) nodes only 5 */
            evict = true;
        }
        /* 3. If the connection feels “toxic” (low chemistry) after 10 minutes of getting to know each other */
        else if (now - n->discovered_at > 600 && n->metrics.gorgona_score < 0.01) {
            evict = true;
        }
        if (evict) {
            log_event("INFO", -1, n->ip, n->port, "Layer 2 GC: Removing %s node from memory", 
                      n->is_cached ? "stale CACHED" : "unresponsive PEX");
            if (i < cluster_node_count - 1) 
                memcpy(&cluster_nodes[i], &cluster_nodes[cluster_node_count - 1], sizeof(MeshNode));
            cluster_node_count--;
        } else {
            i++;
        }
    }
}

/**
 * Helper: Checks if the given IP address is assigned to any local network interface.
 * Prevents the node from adding itself to the Mesh topology table.
 */
static bool is_local_ip(const char *ip) {
    if (strcmp(ip, "127.0.0.1") == 0 || strcmp(ip, "localhost") == 0) {
        return true;
    }

    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        return false;
    }

    bool found = false;
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET) {
            continue;
        }

        char host[NI_MAXHOST];
        if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) == 0) {
            if (strcmp(host, ip) == 0) {
                found = true;
                break;
            }
        }
    }

    freeifaddrs(ifaddr);
    return found;
}

/**
 * Ingests cluster topology lists from neighbors (Peer Exchange - PEX).
 * Enhanced with Self-Filtering to ensure a clean global map.
 * 
 * @param payload The raw string of nodes (IP:PORT|IP:PORT...)
 * @param sender_ip The IP address of the peer who sent this list (used as an extra self-check)
 */
void mesh_discover_nodes(const char *payload, const char *sender_ip) {
    if (!payload) return;
    
    char *copy = strdup(payload);
    if (!copy) return;

    char *token = strtok(copy, "|");
    while (token) {
        char *colon = strchr(token, ':');
        if (!colon) { 
            /* This might be the reported port part "PEX_LIST|PORT|...", skip it */
            token = strtok(NULL, "|"); 
            continue; 
        }

        *colon = '\0';
        char *ip = token; 
        int p = atoi(colon + 1);

        /* --- INTELLIGENT FILTERING --- */
        
        /* 1. Skip if it's a loopback or one of our own physical IP addresses */
        if (is_local_ip(ip)) {
            token = strtok(NULL, "|");
            continue;
        }

        /* 2. Skip if the IP matches how the sender sees us (useful behind NAT) */
        if (sender_ip && strcmp(ip, sender_ip) == 0) {
            token = strtok(NULL, "|");
            continue;
        }

        /* --- TABLE MANAGEMENT --- */
        
        bool found = false;
        for (int i = 0; i < cluster_node_count; i++) {
            if (strcmp(cluster_nodes[i].ip, ip) == 0) {
                /* Found existing entry: Update listener port if it changed */
                if (cluster_nodes[i].port != p && p > 0) {
                    cluster_nodes[i].port = p;
                }
                /* Update activity timestamp */
                cluster_nodes[i].last_seen = time(NULL);
                found = true; 
                break;
            }
        }

        /* 3. Add as a new mesh member if not already in the table */
        if (!found && cluster_node_count < (MAX_PEERS * 4)) {
            MeshNode *n = &cluster_nodes[cluster_node_count++];
            memset(n, 0, sizeof(MeshNode));
            
            strncpy(n->ip, ip, INET_ADDRSTRLEN - 1);
            n->ip[INET_ADDRSTRLEN - 1] = '\0';
            n->port = p;
            n->discovered_at = time(NULL);
            n->last_seen = time(NULL);
            n->status = PEER_STATUS_OFFLINE;
            n->is_seed = false; /* PEX discovered nodes are dynamic */
            
            log_event("INFO", -1, ip, p, "L2 Mesh: New neighbor discovered via gossip");

            if (mesh_force_save) {
                mesh_save_peers_cache();
            }
        }

        token = strtok(NULL, "|");
    }

    free(copy);
}

int mesh_encrypt(const uint8_t *plain, int len, uint8_t *out_cipher, uint8_t *out_iv, uint8_t *out_tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen, final_len;
    RAND_bytes(out_iv, MGMT_IV_LEN);
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, mgmt_key, out_iv);
    EVP_EncryptUpdate(ctx, out_cipher, &outlen, plain, len);
    EVP_EncryptFinal_ex(ctx, out_cipher + outlen, &final_len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, MGMT_TAG_LEN, out_tag);
    EVP_CIPHER_CTX_free(ctx);
    return outlen + final_len;
}

uint8_t* mesh_decrypt(const uint8_t *cipher, int len, const uint8_t *iv, const uint8_t *tag, int *out_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    uint8_t *out = malloc(len + 1);
    int dlen, final_len;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, mgmt_key, iv);
    EVP_DecryptUpdate(ctx, out, &dlen, cipher, len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, MGMT_TAG_LEN, (void*)tag);
    if (EVP_DecryptFinal_ex(ctx, out + dlen, &final_len) <= 0) {
        free(out); EVP_CIPHER_CTX_free(ctx); return NULL;
    }
    *out_len = dlen + final_len;
    out[*out_len] = '\0';
    EVP_CIPHER_CTX_free(ctx);
    return out;
}

const char* mesh_get_best_peer_ip() {
    double top_score = -1.0;
    int best_idx = -1;
    mesh_recalculate_scores(); 

    for (int i = 0; i < cluster_node_count; i++) {
        if (cluster_nodes[i].status == PEER_STATUS_AUTHENTICATED) {
            if (cluster_nodes[i].metrics.gorgona_score > top_score) {
                top_score = cluster_nodes[i].metrics.gorgona_score;
                best_idx = i;
            }
        }
    }
    if (best_idx != -1) return cluster_nodes[best_idx].ip;
    return NULL;
}

/**
 * Persists the mesh topology to the cache file.
 * Logic differs between Client (force save everything) and Server (save high-quality peers).
 */
void mesh_save_peers_cache() {
    int nodes_to_save = 0;
    
    /* 1. Count nodes based on role */
    for (int i = 0; i < cluster_node_count; i++) {
        if (mesh_force_save) {
            /* CLIENT ROLE: Save every node discovered via PEX (we trust the server's encryption) */
            nodes_to_save++;
        } else {
            /* SERVER ROLE: Save only stable, performant peers to avoid cache pollution */
            if (cluster_nodes[i].status == PEER_STATUS_AUTHENTICATED && 
                cluster_nodes[i].metrics.gorgona_score > 0.05) {
                nodes_to_save++;
            }
        }
    }

    /* 2. Guard: If no valid nodes found, skip file I/O to protect existing cache */
    if (nodes_to_save == 0) {
        if (verbose) {
            log_event("DEBUG", -1, NULL, 0, "Mesh: Peer cache save skipped (Table empty)");
        }
        return;
    }

    /* 3. Write to file */
    FILE *fp = fopen(PEERS_CACHE_FILE, "w");
    if (!fp) {
        log_event("ERROR", -1, NULL, 0, "Mesh: Failed to open %s for writing", PEERS_CACHE_FILE);
        return;
    }

    int saved = 0;
    for (int i = 0; i < cluster_node_count && saved < MAX_CACHE_PEERS; i++) {
        MeshNode *n = &cluster_nodes[i];
        
        bool should_write = false;
        if (mesh_force_save) {
            /* Client saves everyone we know */
            should_write = true;
        } else if (n->status == PEER_STATUS_AUTHENTICATED) {
            /* Server saves only those who are alive right now */
            should_write = true;
        }

        if (should_write) {
            fprintf(fp, "%s:%d\n", n->ip, n->port);
            saved++;
        }
    }

    fclose(fp);
    if (verbose) {
        log_event("INFO", -1, NULL, 0, "Mesh: Cache file updated (%d nodes saved)", saved);
    }
}

/**
 * Loads previously cached peers into the mesh table.
 * These nodes are treated as temporary seeds to ensure stability.
 */
void mesh_load_peers_cache() {
    FILE *fp = fopen(PEERS_CACHE_FILE, "r");
    if (!fp) return;

    char line[128];
    int loaded = 0;
    while (fgets(line, sizeof(line), fp)) {
        trim_string(line);
        if (strlen(line) == 0) continue;

        char *colon = strchr(line, ':');
        if (!colon) continue;
        *colon = '\0';
        char *ip = line;
        int port = atoi(colon + 1);

        bool exists = false;
        for (int i = 0; i < cluster_node_count; i++) {
            if (strcmp(cluster_nodes[i].ip, ip) == 0) {
                exists = true; break;
            }
        }

        if (!exists && cluster_node_count < (MAX_PEERS * 4)) {
            MeshNode *n = &cluster_nodes[cluster_node_count++];
            memset(n, 0, sizeof(MeshNode));
            strncpy(n->ip, ip, INET_ADDRSTRLEN - 1);
            n->port = port;
            n->is_seed = false;
            n->is_cached = true; /* Помечаем как КЭШ */
            n->status = PEER_STATUS_OFFLINE;
            n->last_seen = time(NULL);
            n->discovered_at = time(NULL);
            loaded++;
        }
    }
    fclose(fp);
    if (loaded > 0) {
        log_event("INFO", -1, NULL, 0, "Mesh: Bootstrapped from cache (%d nodes as temporary seeds)", loaded);
    }
}

int mesh_get_logical_port_by_ip(const char *ip) {
    for (int n = 0; n < cluster_node_count; n++) {
        if (strcmp(cluster_nodes[n].ip, ip) == 0) {
            return cluster_nodes[n].port;
        }
    }
    return 0;
}
