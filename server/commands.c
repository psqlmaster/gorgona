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
#include "admin_mesh.h"
#include "alert_db.h"

static void process_get_chain_sample(int i, char *buffer) {
    char *copy = strdup(buffer + 17); /* Skip "GET_CHAIN_SAMPLE|" */
    char *hash_b64 = strtok(copy, "|");
    char *offset_str = strtok(NULL, "|");
    char *limit_str = strtok(NULL, "|");

    if (!hash_b64 || !offset_str || !limit_str) { free(copy); return; }

    int offset = atoi(offset_str);
    int limit = atoi(limit_str);
    size_t hlen;
    unsigned char *raw_hash = base64_decode(hash_b64, &hlen);
    Recipient *rec = find_recipient(raw_hash);

    if (rec && rec->count > 0) {
        char resp[4096]; /* 4 KB is enough for ~100 hashes */
        int pos = snprintf(resp, sizeof(resp), "CHAIN_SAMPLE|%s|%d|%d|", hash_b64, offset, limit);
        
        int end_idx = rec->count - 1 - offset;
        int start_idx = end_idx - limit + 1;
        if (start_idx < 0) start_idx = 0;

        for (int j = end_idx; j >= start_idx; j--) {
            if (pos > (int)sizeof(resp) - 64) break;
            pos += snprintf(resp + pos, sizeof(resp) - pos, "%" PRIu64 ":%" PRIx64 "|", 
                           rec->alerts[j].id, rec->alerts[j].curr_hash);
        }
        enqueue_message(i, resp, (size_t)pos);
    }
    free(raw_hash); free(copy);
}

static void process_chain_sample(int i, char *buffer) {
    Subscriber *sub = &subscribers[i];
    char *rest = strdup(buffer + 13);
    if (!rest) return;

    char *hash_b64 = strtok(rest, "|");
    char *offset_str = strtok(NULL, "|");
    char *limit_str = strtok(NULL, "|");
    
    if (!hash_b64 || !offset_str || !limit_str) { free(rest); return; }
    int current_offset = atoi(offset_str);
    int current_limit = atoi(limit_str);

    size_t hlen;
    unsigned char *raw_hash = base64_decode(hash_b64, &hlen);
    Recipient *rec = find_recipient(raw_hash);
    if (!rec) { 
        if (raw_hash) free(raw_hash); 
        free(rest); 
        return; 
    }

    uint64_t ancestor_id = 0;
    char *pair;
    /* Let's go through the list ID:HASH|ID:HASH... */
    while ((pair = strtok(NULL, "|")) != NULL) {
        char *colon = strchr(pair, ':');
        if (!colon) continue;
        *colon = '\0';
        uint64_t r_id = strtoull(pair, NULL, 10);
        uint64_t r_hash = strtoull(colon + 1, NULL, 16);

        /* We look for this ID in our system and check to see if the hash matches */
        for (int j = rec->count - 1; j >= 0; j--) {
            if (rec->alerts[j].id == r_id) {
                if (rec->alerts[j].curr_hash == r_hash) {
                    ancestor_id = r_id;
                    goto found;
                }
            }
        }
    }

found:
    if (ancestor_id > 0) {
        /* COMMON ANCESTOR FOUND! Please provide only the delta. */
        char req[512];
        snprintf(req, sizeof(req), "SYNC_RANGE|%s|%" PRIu64, hash_b64, ancestor_id);
        enqueue_message(i, req, strlen(req));
        
        if (verbose) {
            log_event("DEBUG", sub->sock, sub->ip_address, sub->port, 
                      "Chain Sync: Ancestor found at ID %" PRIu64 ". Requesting Range Sync.", ancestor_id);
        }
    } else {
        /* NO ANCESTOR FOUND in the current window. Let's expand the search. */
        int next_offset = current_offset + current_limit;
        int next_limit = current_limit * 5; 

        if (next_offset < rec->count && next_limit <= 500) {
            char req[512];
            snprintf(req, sizeof(req), "GET_CHAIN_SAMPLE|%s|%d|%d", hash_b64, next_offset, next_limit);
            enqueue_message(i, req, strlen(req));
            
            if (verbose) {
                log_event("DEBUG", sub->sock, sub->ip_address, sub->port, 
                          "Chain Sync: Ancestor not found. Widening search (offset %d, limit %d)", 
                          next_offset, next_limit);
            }
        } else {
            /* The gap is too big. Let's give up and download everything. */
            char req[512];
            snprintf(req, sizeof(req), "SYNC_REC|%s", hash_b64);
            enqueue_message(i, req, strlen(req));
            
            log_event("WARN", sub->sock, sub->ip_address, sub->port, 
                      "Chain Sync: Divergence too deep for %s. Falling back to Full Sync.", hash_b64);
        }
    }
    
    if (raw_hash) free(raw_hash);
    free(rest);
}

static void process_sync_range(int i, char *buffer) {
    char *rest = strdup(buffer + 11);
    char *hash_b64 = strtok(rest, "|");
    char *id_str = strtok(NULL, "|");
    if (!hash_b64 || !id_str) { free(rest); return; }

    uint64_t start_id = strtoull(id_str, NULL, 10);
    size_t hlen;
    unsigned char *raw_hash = base64_decode(hash_b64, &hlen);
    Recipient *rec = find_recipient(raw_hash);

    if (rec) {
        int sent = 0;
        for (int j = 0; j < rec->count; j++) {
            if (rec->alerts[j].id > start_id) {
                send_alert_to_peer(i, rec->hash, &rec->alerts[j]);
                sent++;
            }
        }
        if (verbose) log_event("DEBUG", -1, NULL, 0, "Range Sync: Sent %d alerts after ID %" PRIu64, sent, start_id);
    }
    free(raw_hash); free(rest);
}

/**
 * Sends all alerts for a specific recipient.
 * Used for chain healing when a fork/gap is detected.
 */
static void process_sync_rec(int i, char *buffer) {
    char *hash_b64 = buffer + 9; /* Skip "SYNC_REC|" */
    if (!hash_b64) return;
    size_t hlen;
    unsigned char *raw_hash = base64_decode(hash_b64, &hlen);
    if (!raw_hash) return;
    Recipient *rec = find_recipient(raw_hash);
    if (rec) {
        for (int j = 0; j < rec->count; j++) {
            send_alert_to_peer(i, rec->hash, &rec->alerts[j]);
        }
    }
    free(raw_hash);
}

void mesh_request_chain_sync(int sub_index) {
    for (int r = 0; r < recipient_count; r++) {
        Recipient *rec = &recipients[r];
        if (rec->count == 0) continue;

        char *hash_b64 = base64_encode(rec->hash, PUBKEY_HASH_LEN);
        if (!hash_b64) continue;

        char sync_cmd[512];
        /* We're sending the top of our feast chain */
        int len = snprintf(sync_cmd, sizeof(sync_cmd), "SYNC_CHAIN|%s|%" PRIu64 "|%" PRIu64,
                           hash_b64, 
                           rec->alerts[rec->count - 1].id, 
                           rec->last_hash);
        
        enqueue_message(sub_index, sync_cmd, (size_t)len);
        free(hash_b64);
    }
    
    /* Global MaxID Nudge for Empty Nodes */
    uint64_t my_max = get_max_alert_id();
    char nudge[64];
    int n_len = snprintf(nudge, sizeof(nudge), "SYNC|%" PRIu64, my_max);
    enqueue_message(sub_index, nudge, (size_t)n_len);
}

/*
 * Handles the "SEND|" command logic.
 * Updated to use the insertion index from add_alert for precise notification.
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
        log_event("WARN", sd, sub->ip_address, sub->port, "Incomplete SEND data received");
        free(rest);
        return;
    }

    trim_string(pubkey_hash_b64);
    size_t pubkey_hash_len;
    unsigned char *pubkey_hash = base64_decode(pubkey_hash_b64, &pubkey_hash_len);
    if (!pubkey_hash || pubkey_hash_len != PUBKEY_HASH_LEN) {
        char *error_msg = "Error: Invalid pubkey hash";
        enqueue_message(i, error_msg, strlen(error_msg));
        if (pubkey_hash) free(pubkey_hash);
        free(rest);
        return;
    }

    time_t unlock_at = atol(unlock_at_str);
    time_t expire_at = atol(expire_at_str);

    /* Capture insertion index (res >= 0) */
    int res = add_alert(pubkey_hash, unlock_at, expire_at, base64_text, 
                       base64_encrypted_key, base64_iv, base64_tag, sd, 0, 0); 

    if (res >= 0) {
        Recipient *rec = find_recipient(pubkey_hash);
        if (rec && res < rec->count) {
            Alert *new_a = &rec->alerts[res];
            uint64_t assigned_id = new_a->id;

            /* 1. Confirm to sender */
            char success_msg[128];
            int s_len = snprintf(success_msg, sizeof(success_msg), 
                                 "Alert ID: %" PRIu64 " added successfully", assigned_id);
            enqueue_message(i, success_msg, (size_t)s_len);
            
            /* 2. Notify other subscribers and peers using the CORRECT index */
            notify_subscribers(pubkey_hash, new_a);
            broadcast_replication(pubkey_hash, new_a, sd);

            /* 3. Anti-Entropy Push (Nudge) */
            uint64_t my_new_max = get_max_alert_id();
            char nudge[64];
            snprintf(nudge, sizeof(nudge), "MAXID_NUDGE|%" PRIu64, my_new_max);
            
            for (int p = 0; p < max_clients; p++) {
                if (client_sockets[p] > 0 && 
                    subscribers[p].type == SUB_TYPE_PEER && 
                    subscribers[p].auth_state == AUTH_OK &&
                    client_sockets[p] != sd) {
                    send_mgmt_command(p, nudge);
                }
            }
        }
    } else if (res == -1) {
        char *err = "Error: Stale alert (unlock_at time is too old)";
        enqueue_message(i, err, strlen(err));
    } else if (res == -2) {
        char *err = "Error: Replay attack detected (duplicate payload)";
        enqueue_message(i, err, strlen(err));
    } else if (res == -4) {
        char *err = "Error: Alert already exists (Duplicate ID)";
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
    if (!rest) return;

    char *pubkey_hash_b64 = rest;
    char *mode_str = NULL;
    char *count_str = NULL;

    char *p1 = strchr(pubkey_hash_b64, '|');
    if (p1) {
        *p1 = '\0';
        mode_str = p1 + 1;
        char *p2 = strchr(mode_str, '|');
        if (p2) {
            *p2 = '\0';
            count_str = p2 + 1;
        }
    }

    int sub_mode = MODE_SINGLE;
    if (mode_str && strlen(mode_str) > 0) {
        trim_string(mode_str);
        char upper_mode[16];
        strncpy(upper_mode, mode_str, sizeof(upper_mode) - 1);
        upper_mode[sizeof(upper_mode) - 1] = '\0';
        for (char *p = upper_mode; *p; p++) *p = toupper(*p);
        if (strcmp(upper_mode, "LAST") == 0) sub_mode = MODE_LAST;
        else if (strcmp(upper_mode, "NEW") == 0) sub_mode = MODE_NEW;
    }

    int count = 1;
    if (count_str && strlen(count_str) > 0) {
        count = atoi(count_str);
        if (count <= 0) count = 1;
    }

    if (pubkey_hash_b64 && strlen(pubkey_hash_b64) > 0) {
        trim_string(pubkey_hash_b64);
        strncpy(sub->pubkey_hash, pubkey_hash_b64, sizeof(sub->pubkey_hash) - 1);
    } else {
        sub->pubkey_hash[0] = '\0';
    }

    sub->mode = sub_mode;
    if (sub_mode != MODE_NEW) {
        send_current_alerts(i, sub_mode, sub->pubkey_hash, count);
    }
    
    char sub_msg[256];
    snprintf(sub_msg, sizeof(sub_msg), "Subscribed to [%s] mode", 
             (sub->pubkey_hash[0] != '\0') ? sub->pubkey_hash : "ALL");
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

    /* Надежный парсинг полей mode|hash|count */
    char *mode_str = rest;
    char *pubkey_hash_b64 = NULL;
    char *count_str = NULL;

    char *first_delim = strchr(mode_str, '|');
    if (first_delim) {
        *first_delim = '\0';
        pubkey_hash_b64 = first_delim + 1;
        
        char *second_delim = strchr(pubkey_hash_b64, '|');
        if (second_delim) {
            *second_delim = '\0';
            count_str = second_delim + 1;
        }
    }

    if (!mode_str || strlen(mode_str) == 0) {
        enqueue_message(i, "Error: Missing mode in SUBSCRIBE", 31);
        free(rest);
        return;
    }

    int count = 0;
    if (count_str && strlen(count_str) > 0) {
        count = atoi(count_str);
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
    
    /* If the hash is empty (between ||), the subscription applies to all keys */
    if (pubkey_hash_b64 && strlen(pubkey_hash_b64) > 0) {
        trim_string(pubkey_hash_b64);
        strncpy(sub->pubkey_hash, pubkey_hash_b64, sizeof(sub->pubkey_hash) - 1);
    } else {
        sub->pubkey_hash[0] = '\0';
    }

    if (sub_mode != MODE_NEW) {
        send_current_alerts(i, sub_mode, sub->pubkey_hash, count);
    }
    
    enqueue_message(i, "Subscription updated", 20);
    free(rest);
}

/**
 * Processes the AUTH|psk handshake command.
 * Called when a remote entity (Client or Peer) attempts to join the Mesh.
 * Updated to trigger Hash Chain Sync immediately for Peers.
 */
static void process_auth(int i, char *buffer) {
    Subscriber *sub = &subscribers[i];
    char *copy = strdup(buffer + 5); /* Skip "AUTH|" */
    if (!copy) return;

    /* Strict tokenization: all 4 fields must be present */
    char *psk             = strtok(copy, "|");
    char *max_alerts_str  = strtok(NULL, "|");
    char *max_ttl_str     = strtok(NULL, "|");
    char *port_str        = strtok(NULL, "|");

    /* 1. Protocol Integrity Check */
    if (!psk || !max_alerts_str || !max_ttl_str || !port_str) {
        log_event("WARN", sub->sock, sub->ip_address, sub->port, "Auth failed: Truncated handshake");
        cleanup_subscriber(i);
        free(copy);
        return;
    }

    int peer_max_alerts = atoi(max_alerts_str);
    int peer_max_ttl    = atoi(max_ttl_str);
    int peer_port       = atoi(port_str);

    /* 2. PSK Verification (Management Plane Security) */
    if (strcmp(psk, sync_psk) != 0) {
        log_event("ERROR", sub->sock, sub->ip_address, sub->port, "Auth failed: Invalid PSK");
        enqueue_message(i, "Error: Wrong PSK", 15);
        sub->close_after_send = true;
    } 
    /* 3. Cluster Consistency Check (Only for Peers) */
    else if (peer_max_alerts > 0 && peer_max_alerts != max_alerts) {
        log_event("ERROR", sub->sock, sub->ip_address, sub->port, 
                  "Cluster capacity mismatch! Peer: %d, Local: %d", peer_max_alerts, max_alerts);
        enqueue_message(i, "Error: max_alerts mismatch", 26);
        sub->close_after_send = true;
    } 
    else {
        /* Authentication Success Path */
        if (peer_max_alerts == 0) {
            /* Standard Binary Client */
            sub->type = SUB_TYPE_CLIENT;
            
            if (sub->node_ptr && sub->node_ptr->port > 0) {
                sub->port = sub->node_ptr->port;
            }
        } else {
            /* Full Mesh Peer (Server) */
            sub->type = SUB_TYPE_PEER;
            
            /* Mandatory port sync for replication routing */
            if (peer_port > 0 && peer_port < 65535) {
                sub->port = peer_port;
                if (sub->node_ptr) {
                    sub->node_ptr->port = peer_port;
                }
            }

            if (peer_max_ttl != max_alert_ttl) {
                log_event("INFO", sub->sock, sub->ip_address, sub->port, 
                          "Policy Notice: Peer TTL (%d) differs from Local TTL (%d)", 
                          peer_max_ttl, max_alert_ttl);
            }

            /* 
             * Если к нам подключился пир, мы должны ТУТ ЖЕ инициировать 
             * проверку хеш-цепочек со своей стороны.
             */
            mesh_request_chain_sync(i);
        }
        
        sub->auth_state = AUTH_OK;
        
        log_event("INFO", sub->sock, sub->ip_address, sub->port, "Auth OK [%s]", 
                  (sub->type == SUB_TYPE_PEER) ? "Mesh Peer" : "Binary Client");
        
        /* Symmetric strictly-formatted response */
        char resp[128];
        int r_len = snprintf(resp, sizeof(resp), "AUTH_SUCCESS|%d|%d", max_alerts, max_alert_ttl);
        enqueue_message(i, resp, (size_t)r_len);
    }

    free(copy);
}

/**
 * Handles the "REPL|" command for alert replication between peers.
 * FIXED: Prevents gossip storms by only broadcasting NEW (append-only) alerts.
 */
static void process_repl(int i, char *buffer) {
    struct timeval start_tv, end_tv;
    gettimeofday(&start_tv, NULL);

    Subscriber *sub = &subscribers[i];
    if (sub->auth_state != AUTH_OK) return;

    char *rest = strdup(buffer + 5); 
    if (!rest) return;

    /* Tokenization */
    char *id_str      = strtok(rest, "|");
    char *create_str  = strtok(NULL, "|");
    char *unlock_str  = strtok(NULL, "|");
    char *expire_str  = strtok(NULL, "|");
    char *active_str  = strtok(NULL, "|"); 
    char *hash_b64    = strtok(NULL, "|");
    char *text_b64    = strtok(NULL, "|");
    char *key_b64     = strtok(NULL, "|");
    char *iv_b64      = strtok(NULL, "|");
    char *tag_b64     = strtok(NULL, "|");

    if (tag_b64) {
        uint64_t original_id = strtoull(id_str, NULL, 10);
        time_t c_at = (time_t)atol(create_str);
        time_t u_at = (time_t)atol(unlock_str);
        time_t e_at = (time_t)atol(expire_str);
        int is_active = atoi(active_str);

        size_t h_len;
        unsigned char *ph = base64_decode(hash_b64, &h_len);

        if (ph && h_len == PUBKEY_HASH_LEN) {
            /* add_alert returns the insertion index */
            int res = add_alert(ph, u_at, e_at, text_b64, key_b64, iv_b64, tag_b64, 
                                sub->sock, original_id, c_at);
            
            Recipient *rec = find_recipient(ph);
            if (rec && res >= 0) {
                Alert *inserted_a = &rec->alerts[res];
                
                /* Update metrics for successful ingestion */
                gettimeofday(&end_tv, NULL);
                double delta = (double)(end_tv.tv_sec - start_tv.tv_sec) + 
                               (double)(end_tv.tv_usec - start_tv.tv_usec) / 1000000.0;
                mesh_update_speed(sub->ip_address, strlen(buffer), delta);

                /* 1. Notify local connected clients (they always want to know) */
                notify_subscribers(ph, inserted_a);

                /* 
                 * 2. STRATEGIC GOSSIP (Anti-Storm):
                 * ONLY broadcast to other peers if:
                 * - This was an APPEND (inserted at the very end of our list).
                 * - The alert is not ancient (freshness check).
                 * 
                 * If res < rec->count - 1, it's a BACKFILL. 
                 * We do NOT broadcast backfills because it causes infinite loops 
                 * during mesh synchronization.
                 */
                if (res == (rec->count - 1)) {
                    time_t now = time(NULL);
                    if (is_active && (now - c_at) < STALE_THRESHOLD_SEC) {
                        broadcast_replication(ph, inserted_a, sub->sock);
                    }
                }
            } 
            
            /* CASE 3: Sync 'active' status for revocations (even if already exists) */
            if (rec && (res >= 0 || res == -4)) {
                for (int j = 0; j < rec->count; j++) {
                    if (rec->alerts[j].id == original_id) {
                        if (!is_active && rec->alerts[j].active) {
                            alert_db_deactivate_alert(&rec->alerts[j]);
                            rec->waste_count++;
                            
                            /* Relay revocation */
                            char notify_cmd[64];
                            snprintf(notify_cmd, sizeof(notify_cmd), "REVOKE|%" PRIu64, original_id);
                            for (int s = 0; s < max_clients; s++) {
                                if (client_sockets[s] > 0 && subscribers[s].type == SUB_TYPE_CLIENT) {
                                    if (subscribers[s].pubkey_hash[0] == '\0' || strcmp(subscribers[s].pubkey_hash, hash_b64) == 0) {
                                        enqueue_message(s, notify_cmd, strlen(notify_cmd));
                                    }
                                }
                            }
                        }
                        break;
                    }
                }
            }
            free(ph);
        }
    }
    free(rest);
}

/**
 * Handles the "SYNC|last_id" command.
 * Updated to transfer both active and inactive alerts to ensure MaxID consistency.
 */
static void process_sync(int i, char *buffer) {
    Subscriber *sub = &subscribers[i];
    if (sub->auth_state != AUTH_OK) return;

    uint64_t last_id = strtoull(buffer + 5, NULL, 10);
    int count = 0;

    for (int r = 0; r < recipient_count; r++) {
        Recipient *rec = &recipients[r];
        for (int a = 0; a < rec->count; a++) {
            /* 
             * CRITICAL: We send ALL alerts with ID > last_id, regardless of 'active' status.
             * This ensures the peer's MaxID moves forward even if messages were revoked.
             */
            if (rec->alerts[a].id > last_id) {
                send_alert_to_peer(i, rec->hash, &rec->alerts[a]);
                count++;
            }
        }
    }

    log_event("INFO", sub->sock, sub->ip_address, sub->port, 
              "Sync completed: %d alerts transferred to peer (ID > %" PRIu64 ")", 
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

        /* [ANTI-ENTROPY CORE] */
        uint64_t my_max_id = get_max_alert_id();
        bool is_fresh_connection = (sub->auth_state == 99);

        if (is_fresh_connection || (remote_max_id > my_max_id)) {
            if (is_fresh_connection) {
                sub->auth_state = AUTH_OK;
                log_event("INFO", sub->sock, sub->ip_address, sub->port, "Auth OK [Mesh Peer via L2]");
            }

            char sync_req[64];
            int s_len = snprintf(sync_req, sizeof(sync_req), "SYNC|%" PRIu64, my_max_id);
            enqueue_message(sub_index, sync_req, (size_t)s_len);
            
            log_event("INFO", sub->sock, sub->ip_address, sub->port, 
                      "Anti-Entropy: %s sync triggered (Remote: %" PRIu64 ", Local: %" PRIu64 ")", 
                      is_fresh_connection ? "Initial" : "Delta", remote_max_id, my_max_id);
        }

        /* [MESH TOPOLOGY UPDATE] */
        bool exists = false;
        for (int n = 0; n < cluster_node_count; n++) {
            if (strcmp(cluster_nodes[n].ip, sub->ip_address) == 0) {
                exists = true;
                if (reported_port > 0 && reported_port < 65535) {
                    cluster_nodes[n].port = reported_port;
                    /* SYNC PORT IN SUBSCRIBER STRUCT FOR CLEAN LOGS */
                    sub->port = reported_port; 
                }
                cluster_nodes[n].last_seen = time(NULL);
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
            
            /* SYNC PORT IN SUBSCRIBER STRUCT FOR CLEAN LOGS */
            if (reported_port > 0) sub->port = reported_port;

            n->discovered_at = time(NULL);
            n->last_seen = time(NULL);
            n->status = PEER_STATUS_AUTHENTICATED;
            log_event("INFO", sub->sock, sub->ip_address, sub->port, "L2 Mesh: Dynamic join via encrypted MGMT traffic");
        }

        /* [COMMAND HANDLING] */
        if (cmd && strcmp(cmd, "PING") == 0) {
            char pong[128];
            extern int port;
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
            char *list_start = strchr((char*)plain + 9, '|');
            if (list_start) mesh_discover_nodes(list_start + 1, sub->ip_address);
        }

        if (strncmp((char*)plain, "MAXID_NUDGE|", 12) == 0) {
            uint64_t remote_max = strtoull((char*)plain + 12, NULL, 10);
            uint64_t my_local_max = get_max_alert_id();

            if (remote_max > my_local_max) {
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
    
    if (iv) free(iv);
    if (tag) free(tag);
    if (payload) free(payload);
}

/**
 * Processing the initial cancellation request from the client.
 * Format: REVOKE|ID|HASH_B64|PUBKEY_B64|SIG_B64
 */
static void process_revoke(int i, char *buffer) {
    Subscriber *sub = &subscribers[i];
    char *rest = strdup(buffer + 7); // Пропускаем "REVOKE|"
    if (!rest) return;

    char *id_str = strtok(rest, "|");
    char *hash_b64 = strtok(NULL, "|");
    char *pubkey_b64 = strtok(NULL, "|");
    char *sig_b64 = strtok(NULL, "|");

    if (!id_str || !hash_b64 || !pubkey_b64 || !sig_b64) {
        enqueue_message(i, "Error: Incomplete REVOKE data", 28);
        free(rest);
        return;
    }

    uint64_t alert_id = strtoull(id_str, NULL, 10);
    
    /* Ownership verification: The hash of the submitted key must match the target hash */
    size_t pub_len;
    unsigned char *pub_raw = base64_decode(pubkey_b64, &pub_len);
    if (!pub_raw) {
        enqueue_message(i, "Error: Invalid PubKey encoding", 28);
        free(rest);
        return;
    }
    
    unsigned char calculated_hash[PUBKEY_HASH_LEN];
    compute_raw_pubkey_hash(pub_raw, pub_len, calculated_hash);
    char *calc_hash_b64 = base64_encode(calculated_hash, PUBKEY_HASH_LEN);

    if (strcmp(calc_hash_b64, hash_b64) != 0) {
        enqueue_message(i, "Error: Key ownership mismatch", 28);
        free(pub_raw); free(calc_hash_b64); free(rest);
        return;
    }

    /* Cryptographic verification of a message ID signature */
    if (verify_id_signature(alert_id, pub_raw, pub_len, sig_b64) != 0) {
        enqueue_message(i, "Error: Invalid signature", 23);
        free(pub_raw); free(calc_hash_b64); free(rest);
        return;
    }

    /* Deactivation in the local database */
    Recipient *rec = find_recipient(calculated_hash);
    int res = alert_db_revoke_by_id(rec, alert_id);

    if (res == 0) {
        enqueue_message(i, "OK: Alert revoked", 16);
        log_event("INFO", sub->sock, sub->ip_address, sub->port, "Alert %" PRIu64 " revoked by owner", alert_id);
        
        /* P2P Replication of Cancellations to Other Nodes */
        size_t push_max = strlen(pubkey_b64) + strlen(sig_b64) + 256;
        char *push_msg = malloc(push_max);
        if (push_msg) {
            int p_len = snprintf(push_msg, push_max, "REVOKE_PUSH|%" PRIu64 "|%s|%s|%s", 
                                 alert_id, hash_b64, pubkey_b64, sig_b64);
            
            for (int p = 0; p < max_clients; p++) {
                if (client_sockets[p] > 0 && subscribers[p].type == SUB_TYPE_PEER && 
                    subscribers[p].auth_state == AUTH_OK && client_sockets[p] != sub->sock) {
                    enqueue_message(p, push_msg, (size_t)p_len);
                }
            }
            free(push_msg);
        }
        
        /* Notification to local subscribers (customers) */
        char notify_cmd[64];
        int n_len = snprintf(notify_cmd, sizeof(notify_cmd), "REVOKE|%" PRIu64, alert_id);
        for (int s = 0; s < max_clients; s++) {
            if (client_sockets[s] > 0 && subscribers[s].type == SUB_TYPE_CLIENT) {
                if (subscribers[s].pubkey_hash[0] == '\0' || strcmp(subscribers[s].pubkey_hash, hash_b64) == 0) {
                    enqueue_message(s, notify_cmd, (size_t)n_len);
                }
            }
        }
    } else {
        enqueue_message(i, "Error: Alert not found or already inactive", 43);
    }

    free(pub_raw); 
    free(calc_hash_b64); 
    free(rest);
}

/**
 * Processing a replicated rollback command from another node (P2P).
 * Format: REVOKE_PUSH|ID|HASH_B64|PUBKEY_B64|SIG_B64
 */
static void process_revoke_push(int i, char *buffer) {
    Subscriber *sub = &subscribers[i];
    
    /* Parsing data (we use a copy, since `strtok` modifies the string) */
    char *rest = strdup(buffer + 12); /* Skip "REVOKE_PUSH|" */
    if (!rest) return;

    char *id_str      = strtok(rest, "|");
    char *hash_b64    = strtok(NULL, "|");
    char *pubkey_b64  = strtok(NULL, "|");
    char *sig_b64     = strtok(NULL, "|");

    if (!id_str || !hash_b64 || !pubkey_b64 || !sig_b64) {
        log_event("WARN", sub->sock, sub->ip_address, sub->port, "P2P: Received truncated REVOKE_PUSH packet");
        free(rest);
        return;
    }

    uint64_t alert_id = strtoull(id_str, NULL, 10);

    /* Cryptographic verification before deletion */
    size_t pub_len;
    unsigned char *pub_raw = base64_decode(pubkey_b64, &pub_len);
    if (!pub_raw) {
        free(rest);
        return;
    }

    /* Verifying the signature: Did the key owner actually initiate the revocation? */
    if (verify_id_signature(alert_id, pub_raw, pub_len, sig_b64) != 0) {
        log_event("ERROR", sub->sock, sub->ip_address, sub->port, 
                  "P2P: Revocation signature check failed for ID %" PRIu64, alert_id);
        free(pub_raw);
        free(rest);
        return;
    }

    /* Checking if the key matches the hash */
    unsigned char calculated_hash[PUBKEY_HASH_LEN];
    compute_raw_pubkey_hash(pub_raw, pub_len, calculated_hash);
    
    /* Deletion from the local database */
    Recipient *rec = find_recipient(calculated_hash);
    int res = alert_db_revoke_by_id(rec, alert_id);

    if (res == 0) {
        log_event("INFO", sub->sock, sub->ip_address, sub->port, 
                  "P2P: Alert %" PRIu64 " revoked via mesh sync", alert_id);

        /* Notifying local clients (those that are ‘listening’) */
        char notify_cmd[64];
        int n_len = snprintf(notify_cmd, sizeof(notify_cmd), "REVOKE|%" PRIu64, alert_id);

        for (int s = 0; s < max_clients; s++) {
            if (client_sockets[s] > 0 && subscribers[s].type == SUB_TYPE_CLIENT) {
                /* Send a notification if the client is listening on this hash or is listening on all keys */
                if (subscribers[s].pubkey_hash[0] == '\0' || strcmp(subscribers[s].pubkey_hash, hash_b64) == 0) {
                    enqueue_message(s, notify_cmd, (size_t)n_len);
                }
            }
        }
    }

    free(pub_raw);
    free(rest);
}

/**
 * Processes incoming SYNC_CHAIN command.
 * Analyzes the Tip of the remote chain.
 */
static void process_sync_chain(int i, char *buffer) {
    Subscriber *sub = &subscribers[i];
    char *rest = strdup(buffer + 11);
    if (!rest) return;

    char *hash_b64 = strtok(rest, "|");
    char *id_str = strtok(NULL, "|");
    char *hash_str = strtok(NULL, "|");

    if (!hash_b64 || !id_str || !hash_str) { 
        free(rest); 
        return; 
    }

    size_t hlen;
    unsigned char *raw_hash = base64_decode(hash_b64, &hlen);
    if (!raw_hash) {
        free(rest);
        return;
    }

    uint64_t remote_last_id = strtoull(id_str, NULL, 10);
    uint64_t remote_last_hash = strtoull(hash_str, NULL, 10);

    Recipient *rec = find_recipient(raw_hash);
    if (rec && rec->count > 0) {
        /* Check if we are already in sync */
        if (rec->alerts[rec->count - 1].id == remote_last_id && 
            rec->alerts[rec->count - 1].curr_hash == remote_last_hash) {
            free(raw_hash);
            free(rest);
            return;
        }

        /* Hash mismatch: Request Level 1 sample (last 20) */
        char req[512];
        snprintf(req, sizeof(req), "GET_CHAIN_SAMPLE|%s|0|20", hash_b64);
        enqueue_message(i, req, strlen(req));
        
        if (verbose) {
            log_event("DEBUG", sub->sock, sub->ip_address, sub->port, 
                      "Chain mismatch for %s. Level 1 search (20 nodes).", hash_b64);
        }
    } else {
        /* We are empty: request full history */
        char heal_cmd[512];
        snprintf(heal_cmd, sizeof(heal_cmd), "SYNC_REC|%s", hash_b64);
        enqueue_message(i, heal_cmd, strlen(heal_cmd));
    }
    
    free(raw_hash);
    free(rest);
}

/**
 * THE DISPATCHER
 * Routes received messages to appropriate command handlers.
 * FIXED: Combined all conditions into a single if-else-if chain.
 */
void handle_command(int sub_index, char *buffer) {
    Subscriber *sub = &subscribers[sub_index];

    /* 0. MGMT DISPATCHER (Layer 2 High Priority) */
    if (strncmp(buffer, "MGMT|", 5) == 0) {
        process_mgmt_frame(sub_index, buffer + 5);
        return;
    }

    /* 1. PEER RESPONSES */
    if (strncmp(buffer, "AUTH_SUCCESS|", 13) == 0) {
        int peer_max = atoi(buffer + 13);
        if (peer_max != max_alerts) {
            log_event("ERROR", sub->sock, sub->ip_address, sub->port, "Cluster capacity mismatch!");
            cleanup_subscriber(sub_index);
            return;
        }
        log_event("INFO", sub->sock, sub->ip_address, sub->port, "Remote peer confirmed auth");
        sub->auth_state = AUTH_OK;
        
        for (int n = 0; n < cluster_node_count; n++) {
            if (strcmp(cluster_nodes[n].ip, sub->ip_address) == 0) {
                cluster_nodes[n].status = PEER_STATUS_AUTHENTICATED;
                cluster_nodes[n].last_seen = time(NULL);
                break;
            }
        }
        mesh_request_chain_sync(sub_index); 
        return; 
    }
    
    if (strcmp(buffer, "AUTH_FAILED") == 0) {
        log_event("ERROR", sub->sock, sub->ip_address, sub->port, "Remote peer rejected PSK!");
        cleanup_subscriber(sub_index);
        return;
    }

    if (strncmp(buffer, "Error:", 6) == 0) {
        log_event("WARN", sub->sock, sub->ip_address, sub->port, "Peer returned: %s", buffer);
        return; 
    }

    if (strncmp(buffer, "Alert added successfully", 24) == 0 || 
        strncmp(buffer, "Subscribed to", 13) == 0 ||
        strncmp(buffer, "Subscription updated", 20) == 0) {
        return;
    }

    /* 2. INBOUND COMMANDS - Consolidated Chain */
    if (verbose) {
        log_event("DEBUG", sub->sock, sub->ip_address, sub->port, "Processing command: %.32s...", buffer);
    }

    if (strncmp(buffer, "SYNC_CHAIN|", 11) == 0) {
        process_sync_chain(sub_index, buffer);
    }
    else if (strncmp(buffer, "GET_CHAIN_SAMPLE|", 17) == 0) {
        process_get_chain_sample(sub_index, buffer);
    }
    else if (strncmp(buffer, "CHAIN_SAMPLE|", 13) == 0) {
        process_chain_sample(sub_index, buffer);
    }
    else if (strncmp(buffer, "SYNC_RANGE|", 11) == 0) {
        process_sync_range(sub_index, buffer);
    }
    else if (strncmp(buffer, "SYNC_REC|", 9) == 0) {
        process_sync_rec(sub_index, buffer);
    }
    else if (strncmp(buffer, "SYNC|", 5) == 0) {
        process_sync(sub_index, buffer);
    }
    else if (strncmp(buffer, "REPL|", 5) == 0) {
        process_repl(sub_index, buffer);
    }
    else if (strncmp(buffer, "AUTH|", 5) == 0) {
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
    else if (strncmp(buffer, "SEND|", 5) == 0) {
        process_send(sub_index, buffer);
    } 
    else if (strncmp(buffer, "REVOKE|", 7) == 0) { 
        process_revoke(sub_index, buffer);
    }
    else if (strncmp(buffer, "REVOKE_PUSH|", 12) == 0) {
        process_revoke_push(sub_index, buffer);
    }
    else if (strncmp(buffer, "LISTEN|", 7) == 0) {
        process_listen(sub_index, buffer);
    } 
    else if (strncmp(buffer, "SUBSCRIBE ", 10) == 0) {
        process_subscribe(sub_index, buffer);
    } 
    else {
        /* Protocol Violation */
        char *error_msg = "Error: Unknown command";
        enqueue_message(sub_index, error_msg, strlen(error_msg));
        log_event("WARN", sub->sock, sub->ip_address, sub->port, "Unknown command: %.64s", buffer);
    }
}

