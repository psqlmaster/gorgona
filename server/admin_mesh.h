/* 
 * admin_mesh.h - Synchronized Layer 2 Header
 */
#ifndef ADMIN_MESH_H
#define ADMIN_MESH_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <arpa/inet.h> 
#include "gorgona_utils.h"

#define MGMT_K_LEN 32
#define MGMT_IV_LEN 12
#define MGMT_TAG_LEN 16
#define CHALLENGE_LEN 32

#define PEER_MAX_FAILURES 5
#define PEER_TTL 3600             
#define WEIGHT_SPEED 0.5
#define WEIGHT_LATENCY 0.5

typedef enum {
    PEER_STATUS_OFFLINE,
    PEER_STATUS_HANDSHAKE,
    PEER_STATUS_AUTHENTICATED,
    PEER_STATUS_BANNED
} MeshStatus;

typedef struct {
    double rolling_avg_speed;    /* Bytes/sec */
    double last_rtt;             /* Latency in ms */
    double gorgona_score;        /* 0.0 to 1.0 */
    uint32_t fail_count;
    time_t last_success;
} MeshMetrics;

typedef struct {
    char ip[INET_ADDRSTRLEN];
    int port;
    bool is_seed;               
    MeshStatus status;
    MeshMetrics metrics;
    time_t discovered_at;        /* Added to fix error */
    time_t last_seen;            /* Added to fix error */
    uint8_t remote_nonce[CHALLENGE_LEN];
} MeshNode;

extern MeshNode cluster_nodes[MAX_PEERS * 4];
extern int cluster_node_count;

void mesh_init(const char *psk);
void mesh_run_garbage_collector(void);
void mesh_discover_nodes(const char *payload, const char *sender_ip);
void mesh_update_speed(const char *ip, size_t bytes, double seconds);
void mesh_recalculate_scores(void);
int mesh_encrypt(const uint8_t *plain, int len, uint8_t *out_cipher, uint8_t *out_iv, uint8_t *out_tag);
uint8_t* mesh_decrypt(const uint8_t *cipher, int len, const uint8_t *iv, const uint8_t *tag, int *out_len);
void mesh_get_hmac(const uint8_t *nonce, uint8_t *out_hmac);
void mesh_update_rtt(const char *ip, double rtt_ms);

#endif
