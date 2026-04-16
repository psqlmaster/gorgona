/* 
 * admin_mesh.c - Synchronized Progressive Layer 2
 * BSD 3-Clause License
 * Copyright (c) 2025, Alexander Shcheglov
 */
#define _GNU_SOURCE
#include "admin_mesh.h"
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

void mesh_recalculate_scores() {
    time_t now = time(NULL);
    extern int sync_interval;

    for (int i = 0; i < cluster_node_count; i++) {
        MeshNode *n = &cluster_nodes[i];
        
        /* [DEAD NODE PROTECTION] 
         * Если нода оффлайн или не отвечала дольше 2-х циклов sync_interval - Score = 0 */
        if (n->status == PEER_STATUS_OFFLINE || (now - n->last_seen > sync_interval * 2)) {
            n->metrics.gorgona_score = 0.0;
            continue;
        }

        /* Speed Score: Reference 10 MB/s */
        double s_score = n->metrics.rolling_avg_speed / (10.0 * 1024.0 * 1024.0);
        if (s_score > 1.0) s_score = 1.0;

        /* [FIXED] Latency Score: 
         * Если RTT не определен (0), балл за задержку равен 0, а не 1.0 */
        double l_score = 0.0;
        if (n->metrics.last_rtt > 0.1) {
            l_score = exp(-n->metrics.last_rtt / 100.0);
        }

        n->metrics.gorgona_score = (s_score * WEIGHT_SPEED) + (l_score * WEIGHT_LATENCY);
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

    /* Сначала обновляем баллы на основе актуального времени */
    mesh_recalculate_scores();

    for (int i = 0; i < cluster_node_count; ) {
        MeshNode *n = &cluster_nodes[i];
        bool evict = false;

        /* Если нода ОЧЕНЬ долго не выходила на связь - переводим в оффлайн */
        if (n->status != PEER_STATUS_OFFLINE && (now - n->last_seen > sync_interval * 3)) {
            n->status = PEER_STATUS_OFFLINE;
            n->metrics.gorgona_score = 0.0;
        }

        /* Удаление динамических (PEX) записей */
        if (!n->is_seed) {
            if (n->metrics.fail_count >= PEER_MAX_FAILURES) evict = true;
            else if (now - n->last_seen > PEER_TTL) evict = true;
        }

        if (evict) {
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


