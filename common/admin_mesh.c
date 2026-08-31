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

/**
 * Вспомогательная функция для обновления кэша IP узла.
 * Вызывается при добавлении узла или периодически.
 */
void mesh_resolve_node(MeshNode *n) {
    if (!n || n->addr[0] == '\0') return;

    /* Очищаем старый кэш */
    memset(n->resolved_ip, 0, sizeof(n->resolved_ip));

    /* [FIX] inet_pton ОБЯЗАТЕЛЬНО требует буфер для записи результата */
    struct in_addr tmp_addr;
    if (inet_pton(AF_INET, n->addr, &tmp_addr) == 1) {
        /* Если это IP, просто копируем его в кэш и выходим */
        strncpy(n->resolved_ip, n->addr, sizeof(n->resolved_ip) - 1);
        return;
    }

    /* Если это не IP, значит это FQDN (DNS имя) — идем в getaddrinfo */
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(n->addr, NULL, &hints, &res) == 0) {
        if (res && res->ai_addr) {
            getnameinfo(res->ai_addr, res->ai_addrlen, n->resolved_ip, 
                        sizeof(n->resolved_ip), NULL, 0, NI_NUMERICHOST);
        }
        freeaddrinfo(res);
    }
}

/**
 * Теперь это МГНОВЕННАЯ функция без сетевых запросов.
 */
bool mesh_addr_compare(MeshNode *n, const char *phys_ip) {
    if (!n || !phys_ip) return false;
    /* 1. Сравнение с логическим адресом */
    if (strcmp(n->addr, phys_ip) == 0) return true;
    /* 2. Сравнение с закэшированным IP */
    if (n->resolved_ip[0] != '\0' && strcmp(n->resolved_ip, phys_ip) == 0) return true;
    return false;
}

void mesh_init(const char *psk) {
    SHA256((const unsigned char*)psk, strlen(psk), mgmt_key);
    /* Резолвим все статические ноды из конфига при старте */
    for (int i = 0; i < cluster_node_count; i++) {
        mesh_resolve_node(&cluster_nodes[i]);
    }
    log_event("INFO", -1, NULL, 0, "Layer 2 Mesh: Init successful");
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
        if (n->status == PEER_STATUS_OFFLINE || (now - n->last_seen > sync_interval * 2)) {
            n->metrics.gorgona_score = 0.0;
            continue;
        }
        /* --- Calculating the Speed Score with Decay --- */
        double effective_speed = n->metrics.rolling_avg_speed;
        time_t idle_time = now - n->metrics.last_success;
        /* If no data has been received for more than 30 seconds, we begin to reduce the effective speed */
        if (idle_time > 30) {
            /* If no data has been received for more than 30 seconds, we begin to reduce the effective speed */
            effective_speed *= exp(-(double)(idle_time - 30) / 60.0);
        }
        /* Reference speed of 10 MB/s for rating 1.0 */
        double s_score = effective_speed / (10.0 * 1024.0 * 1024.0);
        if (s_score > 1.0) s_score = 1.0;
        /* --- Latency Score --- */
        double l_score = 0.0;
        if (n->metrics.last_rtt > 0.1) {
            l_score = exp(-n->metrics.last_rtt / 100.0);
        }
        double seed_bonus = n->is_seed ? 0.2 : 0.0;
        n->metrics.gorgona_score = (s_score * WEIGHT_SPEED) + (l_score * WEIGHT_LATENCY) + seed_bonus;
    }
    if (cluster_node_count > 1) {
        qsort(cluster_nodes, cluster_node_count, sizeof(MeshNode), mesh_cmp_nodes);
    }
}

void mesh_update_speed(const char *ip, size_t bytes, double seconds) {
    if (seconds < 0.000001) seconds = 0.000001;
    for (int i = 0; i < cluster_node_count; i++) {
        /* [FIX] Передаем указатель на узел &cluster_nodes[i] */
        if (mesh_addr_compare(&cluster_nodes[i], ip)) {
            MeshMetrics *m = &cluster_nodes[i].metrics;
            m->window_bytes += bytes;
            m->window_time += seconds;
            if (m->window_bytes >= 262144 || m->window_time >= 0.5) {
                double current_sample = (double)m->window_bytes / m->window_time;
                m->rolling_avg_speed = (m->rolling_avg_speed < 1.0) ? 
                                        current_sample : (m->rolling_avg_speed * 0.7) + (current_sample * 0.3);
                m->window_bytes = 0;
                m->window_time = 0;
            }
            cluster_nodes[i].last_seen = time(NULL);
            m->last_success = time(NULL);
            return;
        }
    }
}

void mesh_update_rtt(const char *ip, double rtt_ms) {
    for (int i = 0; i < cluster_node_count; i++) {
        /* [FIX] Передаем указатель на узел &cluster_nodes[i] */
        if (mesh_addr_compare(&cluster_nodes[i], ip)) {
            cluster_nodes[i].metrics.last_rtt = rtt_ms;
            cluster_nodes[i].last_seen = time(NULL);
            cluster_nodes[i].metrics.last_success = time(NULL);
            cluster_nodes[i].metrics.fail_count = 0;
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
            log_event("INFO", -1, n->addr, n->port, "Layer 2 GC: Removing %s node from memory", 
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
 * Now fully DNS-aware and FQDN compatible.
 */
void mesh_discover_nodes(const char *payload, const char *sender_ip) {
    if (!payload) return;
    char *copy = strdup(payload);
    if (!copy) return;
    char *token = strtok(copy, "|");
    while (token) {
        char *colon = strchr(token, ':');
        if (colon) { 
            *colon = '\0';
            char *ip = token; 
            int p = atoi(colon + 1);

            if (is_local_ip(ip)) { token = strtok(NULL, "|"); continue; }
            if (sender_ip && strcmp(ip, sender_ip) == 0) { token = strtok(NULL, "|"); continue; }

            bool found = false;
            for (int i = 0; i < cluster_node_count; i++) {
                /* [FIX] Передаем указатель на узел */
                if (mesh_addr_compare(&cluster_nodes[i], ip)) {
                    if (cluster_nodes[i].port != p && p > 0) cluster_nodes[i].port = p;
                    cluster_nodes[i].last_seen = time(NULL);
                    found = true; 
                    break;
                }
            }

            if (!found && cluster_node_count < CLUSTER_MAX_NODES) {
                MeshNode *n = &cluster_nodes[cluster_node_count++];
                memset(n, 0, sizeof(MeshNode));
                strncpy(n->addr, ip, sizeof(n->addr) - 1);
                n->port = p;
                mesh_resolve_node(n); /* [NEW] Сразу резолвим для кэша IP Pinning */
                n->discovered_at = time(NULL);
                n->last_seen = time(NULL);
                n->status = PEER_STATUS_OFFLINE;
                if (mesh_force_save) mesh_save_peers_cache();
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

/* Error logging function (to be called if connect/auth fails) */
void mesh_mark_node_bad(const char *ip) {
    for (int i = 0; i < cluster_node_count; i++) {
        /* [FIX] Используем умное сравнение для согласованности */
        if (mesh_addr_compare(&cluster_nodes[i], ip)) {
            cluster_nodes[i].status = PEER_STATUS_OFFLINE;
            cluster_nodes[i].consecutive_fails++;
            int delay = 30 * (1 << (cluster_nodes[i].consecutive_fails - 1));
            if (delay > 3600) delay = 3600; 
            cluster_nodes[i].penalty_until = time(NULL) + delay;
            return;
        }
    }
}

/* Penalty Waived in Case of Success */
void mesh_mark_node_good(const char *ip) {
    for (int i = 0; i < cluster_node_count; i++) {
        if (mesh_addr_compare(&cluster_nodes[i], ip)) {
            cluster_nodes[i].consecutive_fails = 0;
            cluster_nodes[i].penalty_until = 0;
            cluster_nodes[i].status = PEER_STATUS_AUTHENTICATED;
            return;
        }
    }
}

/* Choosing the Best Node */
const char* mesh_get_best_peer_ip() {
    double top_score = -1.0;
    int best_idx = -1;
    time_t now = time(NULL);
    mesh_recalculate_scores(); 
    for (int i = 0; i < cluster_node_count; i++) {
        /* Noda shouldn't be in the ban */
        if (cluster_nodes[i].penalty_until > now) continue;
        /* For the server, we can try to bring back nodes that are OFFLINE once the penalty time has expired */ 
        if (cluster_nodes[i].status == PEER_STATUS_AUTHENTICATED || 
            cluster_nodes[i].status == PEER_STATUS_OFFLINE) {
            if (cluster_nodes[i].metrics.gorgona_score > top_score) {
                top_score = cluster_nodes[i].metrics.gorgona_score;
                best_idx = i;
            }
        }
    }
    if (best_idx != -1) return cluster_nodes[best_idx].addr;
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
            fprintf(fp, "%s:%d\n", n->addr, n->port);
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
            if (mesh_addr_compare(&cluster_nodes[i], ip)) {
                exists = true; break;
            }
        }

        if (!exists && cluster_node_count < (MAX_PEERS * 4)) {
            MeshNode *n = &cluster_nodes[cluster_node_count++];
            memset(n, 0, sizeof(MeshNode));
            strncpy(n->addr, ip, sizeof(n->addr) - 1);
            n->port = port;
            mesh_resolve_node(n);
            n->status = PEER_STATUS_OFFLINE;
            n->last_seen = time(NULL);
            n->discovered_at = time(NULL);
            loaded++;
        }
    }
    fclose(fp);
}

int mesh_get_logical_port_by_ip(const char *ip) {
    for (int n = 0; n < cluster_node_count; n++) {
        if (mesh_addr_compare(&cluster_nodes[n], ip)) {
            return cluster_nodes[n].port;
        }
    }
    return 0;
}
