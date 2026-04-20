/* 
* BSD 3-Clause License
* Copyright (c) 2025, Alexander Shcheglov
* All rights reserved. 
*/

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <inttypes.h>
#include <sys/time.h> 
#include "gorgona_utils.h"
#include "commands.h"
#include "snowflake.h"
#include "admin_mesh.h"

/* Helpers for command processing */

/*
 * Handles the "SEND|" command logic
 */
static void process_send(int i, char *buffer) {
    Subscriber *sub = &subscribers[i];
    int sd = sub->sock;

    char *rest = strdup(buffer + 5);
    if (!rest) {
        char *error_msg = "Error: Memory allocation failed";
        enqueue_message(i, error_msg, strlen(error_msg));
        return;
    }

    char *pubkey_hash_b64 = strtok(rest, "|");
    char *unlock_at_str = strtok(NULL, "|");
    char *expire_at_str = strtok(NULL, "|");
    char *base64_text = strtok(NULL, "|");
    char *base64_encrypted_key = strtok(NULL, "|");
    char *base64_iv = strtok(NULL, "|");
    char *base64_tag = strtok(NULL, "|");

    if (!pubkey_hash_b64 || !unlock_at_str || !expire_at_str || !base64_text || !base64_encrypted_key || !base64_iv || !base64_tag) {
        char *error_msg = "Error: Incomplete data in SEND";
        enqueue_message(i, error_msg, strlen(error_msg));
        
        /* Log error using the new centralized logging system */
        log_event("WARN", sd, sub->ip_address, sub->port, "Incomplete SEND data received");
        
        free(rest);
        return;
    }

    trim_string(pubkey_hash_b64);
    if (strlen(pubkey_hash_b64) == 0) {
        char *error_msg = "Error: Empty pubkey hash in SEND";
        enqueue_message(i, error_msg, strlen(error_msg));
        free(rest);
        return;
    }

    size_t pubkey_hash_len;
    unsigned char *pubkey_hash = base64_decode(pubkey_hash_b64, &pubkey_hash_len);
    if (!pubkey_hash || pubkey_hash_len != PUBKEY_HASH_LEN) {
        char *error_msg = "Error: Invalid pubkey hash";
        enqueue_message(i, error_msg, strlen(error_msg));
        if (pubkey_hash) free(pubkey_hash);
        free(rest);
        return;
    }

    log_event("DEBUG", sd, sub->ip_address, sub->port, 
              "Parsed SEND: Hash=%s, Unlock=%s, Expire=%s", 
              pubkey_hash_b64, unlock_at_str, expire_at_str);

    time_t unlock_at = atol(unlock_at_str);
    time_t expire_at = atol(expire_at_str);

    /* Add alert to database and catch the return value */
    int result = add_alert(pubkey_hash, unlock_at, expire_at, base64_text, 
                       base64_encrypted_key, base64_iv, base64_tag, sd, 0, 0); 

    if (result == 0) {
        char *success_msg = "Alert added successfully";
        enqueue_message(i, success_msg, strlen(success_msg));
        
        Recipient *rec = find_recipient(pubkey_hash);
        if (rec) {
            Alert *new_a = &rec->alerts[rec->count - 1];
            notify_subscribers(pubkey_hash, new_a);
            
            /* INSTANT DATA TRANSMISSION */
            broadcast_replication(pubkey_hash, new_a, sd);

            /* INSTANT NOTIFICATION (Anti-Entropy Push) 
             * We're sending a small MGMT package with our new MaxID 
             * Even if the node is slow and we skipped the BROADCAST above,  
             * This short message will prompt him to sync whenever he can. 
             */
            uint64_t my_new_max = get_max_alert_id();
            char nudge[64];
            snprintf(nudge, sizeof(nudge), "MAXID_NUDGE|%" PRIu64, my_new_max);
            
            for (int p = 0; p < max_clients; p++) {
                if (client_sockets[p] > 0 && 
                    subscribers[p].type == SUB_TYPE_PEER && 
                    subscribers[p].auth_state == AUTH_OK &&
                    client_sockets[p] != sd) { // Не шлем тому, кто прислал
                    
                    send_mgmt_command(p, nudge);
                }
            }
        }
    } else if (result == -1) {
        char *err = "Error: Stale alert (unlock_at time is too old)";
        enqueue_message(i, err, strlen(err));
    } else if (result == -2) {
        char *err = "Error: Replay attack detected (duplicate payload)";
        enqueue_message(i, err, strlen(err));
    } else {
        char *err = "Error: Failed to add alert";
        enqueue_message(i, err, strlen(err));
    }

    free(pubkey_hash);
    free(rest);
}

/*
 * Handles the "LISTEN|" command logic
 */
static void process_listen(int i, char *buffer) {
    Subscriber *sub = &subscribers[i];

    char *rest = strdup(buffer + 7);
    if (!rest) {
        char *error_msg = "Error: Memory allocation failed ";
        enqueue_message(i, error_msg, strlen(error_msg));
        return;
    }
    
    char *pubkey_hash_b64 = strtok(rest, "| ");
    char *mode_str = strtok(NULL, "| ");
    char *count_str = strtok(NULL, "| ");
    
    int sub_mode = MODE_SINGLE;
    if (mode_str) {
        trim_string(mode_str);
        char upper_mode[16];
        strncpy(upper_mode, mode_str, sizeof(upper_mode) - 1);
        upper_mode[sizeof(upper_mode) - 1] = '\0';
        for (char *p = upper_mode; *p; p++) *p = toupper(*p); 
        if (strcmp(upper_mode, "LAST") == 0) sub_mode = MODE_LAST;
        else if (strcmp(upper_mode, "NEW") == 0) sub_mode = MODE_NEW;
    }
    
    int count = 1;
    if (count_str) {
        trim_string(count_str);
        count = atoi(count_str);
        if (count <= 0) count = 1;
    }
    
    trim_string(pubkey_hash_b64);
    if (strlen(pubkey_hash_b64) == 0 && sub_mode != MODE_LAST) {
        char *error_msg = "Error: Empty pubkey hash in LISTEN ";
        enqueue_message(i, error_msg, strlen(error_msg));
        free(rest);
        return;
    }

    if (strlen(pubkey_hash_b64) > 0) {
        strncpy(sub->pubkey_hash, pubkey_hash_b64, sizeof(sub->pubkey_hash) - 1);
        sub->pubkey_hash[sizeof(sub->pubkey_hash) - 1] = '\0';
    } else {
        sub->pubkey_hash[0] = '\0';
    }
    
    sub->mode = sub_mode;
    
    if (sub_mode != MODE_NEW) {
        send_current_alerts(i, sub_mode, pubkey_hash_b64, count);
    }
    
    char sub_msg[512];
    snprintf(sub_msg, sizeof(sub_msg), "Subscribed to [%s] %s mode [%d]", 
             (pubkey_hash_b64 && strlen(pubkey_hash_b64) > 0) ? pubkey_hash_b64 : "ALL KEYS",
             mode_str ? mode_str : "SINGLE",
             count);
    enqueue_message(i, sub_msg, strlen(sub_msg));
    
    free(rest);
}

/*
 * Handles the legacy "SUBSCRIBE " command logic
 */
static void process_subscribe(int i, char *buffer) {
    Subscriber *sub = &subscribers[i];

    char *rest = strdup(buffer + 10);
    if (!rest) return;

    char *mode_str = strtok(rest, "|");
    char *pubkey_hash_b64 = strtok(NULL, "|");

    if (!mode_str) {
        enqueue_message(i, "Error: Missing mode in SUBSCRIBE", 31);
        free(rest);
        return;
    }

    trim_string(mode_str);
    int sub_mode = 0;
    char upper_mode[16];
    strncpy(upper_mode, mode_str, sizeof(upper_mode) - 1);
    upper_mode[sizeof(upper_mode) - 1] = '\0';
    for (char *p = upper_mode; *p; p++) *p = toupper(*p);

    if (strcmp(upper_mode, "LIVE") == 0) sub_mode = MODE_LIVE;
    else if (strcmp(upper_mode, "ALL") == 0) sub_mode = MODE_ALL;
    else if (strcmp(upper_mode, "LOCK") == 0) sub_mode = MODE_LOCK;
    else if (strcmp(upper_mode, "LAST") == 0) sub_mode = MODE_LAST;
    else if (strcmp(upper_mode, "NEW") == 0) sub_mode = MODE_NEW;
    else {
        enqueue_message(i, "Error: Unknown mode", 18);
        free(rest);
        return;
    }

    sub->mode = sub_mode;
    if (pubkey_hash_b64 && strlen(pubkey_hash_b64) > 0) {
        trim_string(pubkey_hash_b64);
        strncpy(sub->pubkey_hash, pubkey_hash_b64, sizeof(sub->pubkey_hash) - 1);
    } else {
        sub->pubkey_hash[0] = '\0';
    }

    if (sub_mode != MODE_NEW) {
        send_current_alerts(i, sub_mode, pubkey_hash_b64, 1);
    }
    enqueue_message(i, "Subscription updated", 20);
    free(rest);
}

/*
 * Command processing AUTH|psk
 * Called on the server side when a PIR client connects to it
 */
static void process_auth(int i, char *buffer) {
    Subscriber *sub = &subscribers[i];
    char *copy = strdup(buffer + 5); 
    if (!copy) return;

    char *psk = strtok(copy, "|");
    char *max_alerts_str = strtok(NULL, "|");

    if (!psk || !max_alerts_str) {
        cleanup_subscriber(i);
        free(copy);
        return;
    }

    int peer_max_alerts = atoi(max_alerts_str);

    /* 1. Проверка пароля */
    if (strcmp(psk, sync_psk) != 0) {
        log_event("ERROR", sub->sock, sub->ip_address, sub->port, "Auth failed: Wrong PSK");
        enqueue_message(i, "Error: Wrong PSK", 15);
        sub->close_after_send = true;
    } 
    /* 2. Проверка лимита базы (max_alerts) */
    /* ИЗМЕНЕНИЕ: Если пришел 0 — это КЛИЕНТ. Если > 0 — это ПИР. */
    else if (peer_max_alerts > 0 && peer_max_alerts != max_alerts) {
        log_event("ERROR", sub->sock, sub->ip_address, sub->port, 
                  "Cluster capacity mismatch! Peer: %d, Local: %d", peer_max_alerts, max_alerts);
        enqueue_message(i, "Error: max_alerts mismatch", 26);
        sub->close_after_send = true;
    } 
    else {
        /* Успех */
        if (peer_max_alerts == 0) {
            sub->type = SUB_TYPE_CLIENT;
            log_event("INFO", sub->sock, sub->ip_address, sub->port, "Client authenticated via PSK");
        } else {
            sub->type = SUB_TYPE_PEER;
            log_event("INFO", sub->sock, sub->ip_address, sub->port, "Peer authenticated (Capacity: %d)", max_alerts);
        }
        
        sub->auth_state = AUTH_OK;
        
        char resp[64];
        int r_len = snprintf(resp, sizeof(resp), "AUTH_SUCCESS|%d", max_alerts);
        enqueue_message(i, resp, r_len);

        /* Если это ПИР (сервер), он запросит SYNC сам. 
           Если это КЛИЕНТ, мы просто подтвердили вход. */
    }
    free(copy);
}

/**
 * Handles the "REPL|" command for alert replication between peers.
 * Also measures throughput to calculate peer performance scores.
 * 
 * Note: Features "Anti-Entropy Storm Protection" to distinguish between 
 * real-time events and historical state transfers.
 */
static void process_repl(int i, char *buffer) {
    struct timeval start_tv, end_tv;
    gettimeofday(&start_tv, NULL);

    Subscriber *sub = &subscribers[i];
    
    /* Security: Ensure the peer is authorized to replicate data */
    if (sub->auth_state != AUTH_OK) return;

    size_t raw_len = strlen(buffer);
    char *rest = strdup(buffer + 5); /* Skip "REPL|" */
    if (!rest) return;

    /* Parse REPL parameters from the protocol frame */
    char *id_str      = strtok(rest, "|");
    char *create_str  = strtok(NULL, "|");
    char *unlock_str  = strtok(NULL, "|");
    char *expire_str  = strtok(NULL, "|");
    char *hash_b64    = strtok(NULL, "|");
    char *text_b64    = strtok(NULL, "|");
    char *key_b64     = strtok(NULL, "|");
    char *iv_b64      = strtok(NULL, "|");
    char *tag_b64     = strtok(NULL, "|");

    /* Validation: Ensure the mandatory GCM authentication tag is present */
    if (tag_b64) {
        uint64_t original_id = strtoull(id_str, NULL, 10);
        time_t c_at = (time_t)atol(create_str);
        time_t u_at = (time_t)atol(unlock_str);
        time_t e_at = (time_t)atol(expire_str);

        size_t h_len;
        unsigned char *ph = base64_decode(hash_b64, &h_len);

        /* Validate recipient hash length before proceeding */
        if (ph && h_len == PUBKEY_HASH_LEN) {
            
            /* Attempt to add the replicated alert to the local database */
            int res = add_alert(ph, u_at, e_at, text_b64, key_b64, iv_b64, tag_b64, 
                                sub->sock, original_id, c_at);
            
            if (res == 0) {
                /* --- PERFORMANCE TRACKING --- */
                gettimeofday(&end_tv, NULL);
                double delta = (double)(end_tv.tv_sec - start_tv.tv_sec) + 
                               (double)(end_tv.tv_usec - start_tv.tv_usec) / 1000000.0;
                
                /* Update mesh metrics with recent throughput data */
                mesh_update_speed(sub->ip_address, raw_len, delta);

                Recipient *rec = find_recipient(ph);
                if (rec) {
                    Alert *new_a = &rec->alerts[rec->count - 1];
                    
                    /* Notify any local clients subscribed to this key */
                    notify_subscribers(ph, new_a);
                    
                    /**
                     * --- GOSSIP SUPPRESSION LOGIC ---
                     * To prevent infinite loops and "synchronization storms" in segmented networks,
                     * we only broadcast alerts that are considered "Fresh" (real-time events).
                     * 
                     * If the alert's creation time is older than the STALE_THRESHOLD, it is 
                     * treated as a historical sync (State Transfer) and will NOT be re-broadcast.
                     */
                    time_t now = time(NULL);
                    if ((now - c_at) < STALE_THRESHOLD_SEC) {
                        /* Active real-time event: propagate to the rest of the cluster */
                        broadcast_replication(ph, new_a, sub->sock);
                    } else {
                        /* Historical sync: silent ingestion only to protect network bandwidth */
                        if (verbose) {
                            log_event("DEBUG", sub->sock, sub->ip_address, sub->port, 
                                      "Suppressed gossip for historical ID %" PRIu64 " (Catch-up sync)", 
                                      original_id);
                        }
                    }
                }
            }
            free(ph);
        }
    }
    
    /* Clean up the temporary buffer copy */
    free(rest);
}

/**
 * Handles the "SYNC|last_id" command.
 * IMPROVED: Only transfers ACTIVE alerts to minimize network waste.
 */
static void process_sync(int i, char *buffer) {
    Subscriber *sub = &subscribers[i];
    
    if (sub->auth_state != AUTH_OK) {
        log_event("WARN", sub->sock, sub->ip_address, sub->port, "Unauthorized sync request ignored");
        return;
    }

    uint64_t last_id = strtoull(buffer + 5, NULL, 10);
    int count = 0;

    /* Iterate through all recipients managed by this node */
    for (int r = 0; r < recipient_count; r++) {
        Recipient *rec = &recipients[r];
        for (int a = 0; a < rec->count; a++) {
            /* 
             * CRITICAL FIX: Only send alerts that are:
             * 1. Newer than the requested ID.
             * 2. Actually ACTIVE (not expired or deactivated).
             */
            if (rec->alerts[a].id > last_id && rec->alerts[a].active) {
                send_alert_to_peer(i, rec->hash, &rec->alerts[a]);
                count++;
            }
        }
    }

    log_event("INFO", sub->sock, sub->ip_address, sub->port, 
              "Sync completed: %d active alerts transferred to peer (ID > %" PRIu64 ")", 
              count, last_id);
}

void send_mgmt_command(int sub_index, const char *cmd_plain) {
    uint8_t cipher[2048], iv[12], tag[16];
    int len = mesh_encrypt((uint8_t*)cmd_plain, strlen(cmd_plain), cipher, iv, tag);
    
    char *c_b64 = base64_encode(cipher, len);
    char *i_b64 = base64_encode(iv, 12);
    char *t_b64 = base64_encode(tag, 16);
    
    char frame[4096];
    int f_len = snprintf(frame, sizeof(frame), "MGMT|%s|%s|%s", i_b64, t_b64, c_b64);
    
    enqueue_message(sub_index, frame, f_len);
    
    free(c_b64); free(i_b64); free(t_b64);
}

/**
 * Handles decrypted Management Plane (Layer 2) frames.
 * Features: Silent Auto-discovery, Port Correction, and Continuous Anti-Entropy.
 */
static void process_mgmt_frame(int sub_index, char *frame) {
    Subscriber *sub = &subscribers[sub_index];
    
    char *iv_b64 = strtok(frame, "|");
    char *tag_b64 = strtok(NULL, "|");
    char *payload_b64 = strtok(NULL, "|");
    
    if (!iv_b64 || !tag_b64 || !payload_b64) return;
    
    size_t iv_len, tag_len, p_len;
    uint8_t *iv = base64_decode(iv_b64, &iv_len);
    uint8_t *tag = base64_decode(tag_b64, &tag_len);
    uint8_t *payload = base64_decode(payload_b64, &p_len);
    
    int decrypted_len;
    uint8_t *plain = mesh_decrypt(payload, (int)p_len, iv, tag, &decrypted_len);
    
    if (plain) {
        /* [SAFE TOKENIZATION] */
        char *plain_copy = strdup((char*)plain);
        char *cmd = strtok(plain_copy, "|");
        char *val1 = strtok(NULL, "|"); // PING/PONG: TS | PEX: reported_port
        char *val2 = strtok(NULL, "|"); // PING/PONG: reported_port | PEX: first IP:PORT
        char *val3 = strtok(NULL, "|"); // PING/PONG: remote_max_id 

        int reported_port = 0;
        uint64_t remote_max_id = 0;

        if (cmd) {
            if (strcmp(cmd, "PING") == 0 || strcmp(cmd, "PONG") == 0) {
                if (val2) reported_port = atoi(val2);
                if (val3) remote_max_id = strtoull(val3, NULL, 10);
            } else if (strcmp(cmd, "PEX_LIST") == 0) {
                if (val1) reported_port = atoi(val1);
            }
        }

        /* [ANTI-ENTROPY CORE] 
         * Trigger SYNC if the peer has more alerts than we do.
         */
        uint64_t my_max_id = get_max_alert_id();
        if (remote_max_id > my_max_id && sub->auth_state == AUTH_OK) {
            char sync_req[64];
            int s_len = snprintf(sync_req, sizeof(sync_req), "SYNC|%" PRIu64, my_max_id);
            enqueue_message(sub_index, sync_req, (size_t)s_len);
            
            log_event("INFO", sub->sock, sub->ip_address, sub->port, 
                      "Anti-Entropy: Detected newer data on peer (Remote: %" PRIu64 "). Sync triggered.", remote_max_id);
        }

        /* [MESH TOPOLOGY UPDATE] */
        bool exists = false;
        for (int n = 0; n < cluster_node_count; n++) {
            if (strcmp(cluster_nodes[n].ip, sub->ip_address) == 0) {
                exists = true;
                if (reported_port > 0 && reported_port < 65535) {
                    cluster_nodes[n].port = reported_port;
                }
                cluster_nodes[n].last_seen = time(NULL);
                /* If we received an encrypted frame, the peer is authenticated */
                cluster_nodes[n].status = PEER_STATUS_AUTHENTICATED;
                break;
            }
        }

        /* Silent Auto-discovery if node is unknown */
        if (!exists && cluster_node_count < (MAX_PEERS * 4)) {
            MeshNode *n = &cluster_nodes[cluster_node_count++];
            memset(n, 0, sizeof(MeshNode));
            strncpy(n->ip, sub->ip_address, INET_ADDRSTRLEN - 1);
            n->port = (reported_port > 0) ? reported_port : sub->port;
            n->discovered_at = time(NULL);
            n->last_seen = time(NULL);
            n->status = PEER_STATUS_AUTHENTICATED;
            log_event("INFO", sub->sock, sub->ip_address, sub->port, "L2 Mesh: Dynamic join via encrypted MGMT traffic");
        }

        /* [COMMAND HANDLING] */
        if (cmd && strcmp(cmd, "PING") == 0) {
            char pong[128];
            extern int port;
            /* Reply with PONG | TS | PORT | MY_MAX_ID */
            snprintf(pong, sizeof(pong), "PONG|%s|%d|%" PRIu64, val1 ? val1 : "0", port, my_max_id);
            send_mgmt_command(sub_index, pong);
        }
        else if (cmd && strcmp(cmd, "PONG") == 0) {
            uint64_t ts = val1 ? strtoull(val1, NULL, 10) : 0;
            struct timeval now_tv; gettimeofday(&now_tv, NULL);
            uint64_t now_ms = (uint64_t)now_tv.tv_sec * 1000 + (now_tv.tv_usec / 1000);
            mesh_update_rtt(sub->ip_address, (double)(now_ms - ts));
        }
        else if (cmd && strcmp(cmd, "PEX_LIST") == 0) {
            /* Shift payload to skip "PEX_LIST|PORT|" and get to the peer list */
            char *list_start = strchr((char*)plain + 9, '|');
            if (list_start) mesh_discover_nodes(list_start + 1, sub->ip_address);
        }

        if (strncmp((char*)plain, "MAXID_NUDGE|", 12) == 0) {
            uint64_t remote_max = strtoull((char*)plain + 12, NULL, 10);
            uint64_t my_local_max = get_max_alert_id();

            if (remote_max > my_local_max) {
                /* Ого! У соседа есть что-то новое. Не ждем интервала, просим SYNC сейчас! */
                char sync_req[64];
                snprintf(sync_req, sizeof(sync_req), "SYNC|%" PRIu64, my_local_max);
                enqueue_message(sub_index, sync_req, strlen(sync_req));
                
                if (verbose) {
                    log_event("DEBUG", sub->sock, sub->ip_address, sub->port, 
                              "Event-driven SYNC triggered by NUDGE (Remote ID: %" PRIu64 ")", remote_max);
                }
            }
        }

        free(plain_copy);
        free(plain);
    } else {
        log_event("WARN", sub->sock, sub->ip_address, sub->port, "L2: Management Frame decryption failed");
    }
    
    if (iv) {
        free(iv);
    }
    if (tag) {
        free(tag);
    }
    if (payload) {
        free(payload);
    } 
}

/**
 * THE DISPATCHER
 * Routes received messages to appropriate command handlers.
 * Updated to synchronize Layer 1 (Protocol) and Layer 2 (Mesh) states.
 */
void handle_command(int sub_index, char *buffer) {
    Subscriber *sub = &subscribers[sub_index];

    /* 0. MGMT DISPATCHER (Layer 2 High Priority) 
     * Encapsulated GCM frames are decrypted here. 
     */
    if (strncmp(buffer, "MGMT|", 5) == 0) {
        process_mgmt_frame(sub_index, buffer + 5);
        return;
    }

    /* 1. PEER RESPONSES 
     * Handling messages from other servers in the cluster.
     */

    /* Event: A remote peer accepted our AUTH request */
    if (strncmp(buffer, "AUTH_SUCCESS|", 13) == 0) {
        int peer_max = atoi(buffer + 13);
        
        if (peer_max != max_alerts) {
            log_event("ERROR", sub->sock, sub->ip_address, sub->port, 
                      "Cluster capacity mismatch during handshake! Local: %d, Remote: %d", 
                      max_alerts, peer_max);
            cleanup_subscriber(sub_index);
            return;
        }

        log_event("INFO", sub->sock, sub->ip_address, sub->port, "Remote peer confirmed authentication");
        
        /* Layer 1 State */
        sub->auth_state = AUTH_OK;
        
        /* [MESH SYNCHRONIZATION] 
         * Notify Layer 2 that this peer is now a trusted mesh member.
         */
        for (int n = 0; n < cluster_node_count; n++) {
            if (strcmp(cluster_nodes[n].ip, sub->ip_address) == 0) {
                cluster_nodes[n].status = PEER_STATUS_AUTHENTICATED;
                cluster_nodes[n].last_seen = time(NULL);
                break;
            }
        }
        
        /* Initial Catch-up: Request missing history from this reliable node */
        uint64_t my_max = get_max_alert_id();
        char sync_req[64];
        int len = snprintf(sync_req, sizeof(sync_req), "SYNC|%" PRIu64, my_max);
        enqueue_message(sub_index, sync_req, (size_t)len);
        return; 
    }
    
    /* Event: Authentication rejected */
    if (strcmp(buffer, "AUTH_FAILED") == 0) {
        log_event("ERROR", sub->sock, sub->ip_address, sub->port, "Remote peer rejected our PSK!");
        cleanup_subscriber(sub_index);
        return;
    }

    /* Event: Log specific error messages from peers */
    if (strncmp(buffer, "Error:", 6) == 0) {
        log_event("WARN", sub->sock, sub->ip_address, sub->port, "Peer returned: %s", buffer);
        return; 
    }

    /* Event: Noise filtering (Ignore success confirmations from standard commands) */
    if (strncmp(buffer, "Alert added successfully", 24) == 0 || 
        strncmp(buffer, "Subscribed to", 13) == 0 ||
        strncmp(buffer, "Subscription updated", 20) == 0) {
        return;
    }

    /* 2. INBOUND COMMANDS 
     * Parsing commands from clients or peers.
     */
    if (verbose) {
        log_event("DEBUG", sub->sock, sub->ip_address, sub->port, "Processing command: %.32s...", buffer);
    }

    if (strncmp(buffer, "SEND|", 5) == 0) {
        process_send(sub_index, buffer);
    } 
    else if (strncmp(buffer, "REPL|", 5) == 0) {
        process_repl(sub_index, buffer);
    }
    else if (strncmp(buffer, "AUTH|", 5) == 0) {
        /* [MESH INTEGRATION]
         * After process_auth succeeds, it should ideally set sub->auth_state = AUTH_OK.
         * We ensure that the mesh table is aware of this IP as well.
         */
        process_auth(sub_index, buffer);
        
        if (sub->auth_state == AUTH_OK) {
            for (int n = 0; n < cluster_node_count; n++) {
                if (strcmp(cluster_nodes[n].ip, sub->ip_address) == 0) {
                    cluster_nodes[n].status = PEER_STATUS_AUTHENTICATED;
                    break;
                }
            }
        }
    }
    else if (strncmp(buffer, "SYNC|", 5) == 0) {
        process_sync(sub_index, buffer);
    }
    else if (strncmp(buffer, "LISTEN|", 7) == 0) {
        process_listen(sub_index, buffer);
    } 
    else if (strncmp(buffer, "SUBSCRIBE ", 10) == 0) {
        process_subscribe(sub_index, buffer);
    } 
    else {
        /* Protocol Violation: Unknown payload type */
        char *error_msg = "Error: Unknown command";
        enqueue_message(sub_index, error_msg, strlen(error_msg));
        log_event("WARN", sub->sock, sub->ip_address, sub->port, "Unknown command: %.64s", buffer);
    }
}
