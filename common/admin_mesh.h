/* 
 * common/admin_mesh.h - Global Mesh & Layer 2 Logic
 * BSD 3-Clause License
 * Copyright (c) 2025, Alexander Shcheglov
 */

#ifndef ADMIN_MESH_H
#define ADMIN_MESH_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <arpa/inet.h>
#include <stdarg.h>

/* --- Mesh Cluster Limits --- */
#ifndef MAX_PEERS
#define MAX_PEERS 8
#endif

/* Total table size for dynamic discovery (PEX) */
#define CLUSTER_MAX_NODES (MAX_PEERS * 4)

/* --- Layer 2 Protocol Constants --- */
#define MGMT_K_LEN    32  /* AES-256 key size */
#define MGMT_IV_LEN   12  /* GCM Nonce size */
#define MGMT_TAG_LEN  16  /* GCM Auth Tag size */
#define CHALLENGE_LEN 32  /* Handshake nonce size */

/* --- Mesh Maintenance & Garbage Collection --- */
#define PEER_MAX_FAILURES 5
#define PEER_TTL 3600             /* 1 hour for PEX-discovered nodes */
#define WEIGHT_SPEED 0.5
#define WEIGHT_LATENCY 0.5

/* Shared Peer States */
typedef enum {
    PEER_STATUS_OFFLINE,
    PEER_STATUS_HANDSHAKE,
    PEER_STATUS_AUTHENTICATED,
    PEER_STATUS_BANNED
} MeshStatus;

/* Metrics for Intelligent Routing (The Gorgona Score) */
typedef struct {
    double rolling_avg_speed;    /* Bytes/sec */
    double last_rtt;             /* Latency in ms */
    double gorgona_score;        /* Health metric 0.0 to 1.0 */
    uint32_t fail_count;
    time_t last_success;
} MeshMetrics;

/* Shared Mesh Node structure */
typedef struct MeshNode {
    char ip[INET_ADDRSTRLEN];
    int port;
    bool is_seed;               /* Hardcoded in config */
    bool is_cached;             /* Loaded from peers.cache */
    MeshStatus status;
    MeshMetrics metrics;
    time_t discovered_at;
    time_t last_seen;
    uint8_t remote_nonce[CHALLENGE_LEN];
} MeshNode;

/* --- Global Mesh State --- */
/* Now accessible by both Server and Client modules */
extern MeshNode cluster_nodes[CLUSTER_MAX_NODES];
extern int cluster_node_count;
extern bool mesh_force_save; 

/* External global variables for logging */
extern int sync_interval;
extern int verbose;

/* --- API Prototypes --- */

/* Core Lifecycle */
void mesh_init(const char *psk);
void mesh_run_garbage_collector(void);
void mesh_discover_nodes(const char *payload, const char *sender_ip);

/* Scoring & Performance */
void mesh_recalculate_scores(void);
void mesh_update_speed(const char *ip, size_t bytes, double seconds);
void mesh_update_rtt(const char *ip, double rtt_ms);
const char* mesh_get_best_peer_ip(void);

/* Crypto Wrappers */
int mesh_encrypt(const uint8_t *plain, int len, uint8_t *out_cipher, uint8_t *out_iv, uint8_t *out_tag);
uint8_t* mesh_decrypt(const uint8_t *cipher, int len, const uint8_t *iv, const uint8_t *tag, int *out_len);
void mesh_get_hmac(const uint8_t *nonce, uint8_t *out_hmac);

/* Persistence (Bootstrapping) */
void mesh_load_peers_cache(void);
void mesh_save_peers_cache(void);

#endif /* ADMIN_MESH_H */
