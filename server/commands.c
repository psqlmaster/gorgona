/* 
* BSD 3-Clause License
* Copyright (c) 2025, Alexander Shcheglov
* All rights reserved. 
*/

#include "gorgona_utils.h"
#include "commands.h"
#include "snowflake.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <inttypes.h>

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
        
        /* Notify subscribers only on REAL success */
        Recipient *rec = find_recipient(pubkey_hash);
        if (rec) {
            Alert *new_a = &rec->alerts[rec->count - 1];
            notify_subscribers(pubkey_hash, new_a);
            /* Рассылаем всем пирам, кроме того, кто прислал (если это был пир) */
            broadcast_replication(pubkey_hash, new_a, sd);
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
    char *copy = strdup(buffer + 5); /* Пропускаем "AUTH|" */
    if (!copy) return;

    char *psk = strtok(copy, "|");
    char *max_alerts_str = strtok(NULL, "|");

    if (!psk || !max_alerts_str) {
        log_event("WARN", sub->sock, sub->ip_address, sub->port, "Malformed AUTH packet received");
        cleanup_subscriber(i);
        free(copy);
        return;
    }

    int peer_max_alerts = atoi(max_alerts_str);

    /* 1. Проверка пароля */
    if (strcmp(psk, sync_psk) != 0) {
        log_event("ERROR", sub->sock, sub->ip_address, sub->port, "Peer authentication failed: Wrong PSK");
        enqueue_message(i, "Error: Wrong PSK", 15);
        sub->close_after_send = true;
    } 
    /* 2. Проверка лимита базы (max_alerts) */
    else if (peer_max_alerts != max_alerts) {
        log_event("ERROR", sub->sock, sub->ip_address, sub->port, 
                  "Cluster capacity mismatch! Local: %d, Peer: %d. Closing connection.", 
                  max_alerts, peer_max_alerts);
        
        char err_msg[128];
        int err_len = snprintf(err_msg, sizeof(err_msg), 
                               "Error: max_alerts mismatch. Cluster expects %d", max_alerts);
        enqueue_message(i, err_msg, err_len);
        sub->close_after_send = true;
    } 
    else {
        /* Все совпало */
        sub->type = SUB_TYPE_PEER;
        sub->auth_state = AUTH_OK;
        log_event("INFO", sub->sock, sub->ip_address, sub->port, "Peer authenticated (Capacity: %d)", max_alerts);
        
        /* Отвечаем успехом и своим лимитом для взаимной проверки */
        char resp[64];
        int r_len = snprintf(resp, sizeof(resp), "AUTH_SUCCESS|%d", max_alerts);
        enqueue_message(i, resp, r_len);

        /* Запрашиваем историю */
        uint64_t my_max = get_max_alert_id();
        char sync_req[64];
        int len = snprintf(sync_req, sizeof(sync_req), "SYNC|%" PRIu64, my_max);
        enqueue_message(i, sync_req, (size_t)len);
    }
    free(copy);
}

/*
 * Handles the "REPL|" command.
 * Used for receiving replicated alerts from peers.
 * Preserves the original ID and creation timestamp.
 */
static void process_repl(int i, char *buffer) {
    Subscriber *sub = &subscribers[i];
    if (sub->auth_state != AUTH_OK) {
        enqueue_message(i, "Error: Peer not authorized", 26);
        return;
    }

    char *rest = strdup(buffer + 5);
    if (!rest) return;

    char *id_str = strtok(rest, "|");
    char *create_str = strtok(NULL, "|");
    char *unlock_str = strtok(NULL, "|");
    char *expire_str = strtok(NULL, "|");
    char *hash_b64 = strtok(NULL, "|");
    char *text_b64 = strtok(NULL, "|");
    char *key_b64 = strtok(NULL, "|");
    char *iv_b64 = strtok(NULL, "|");
    char *tag_b64 = strtok(NULL, "|");

    if (!tag_b64) {
        free(rest);
        return;
    }

    uint64_t original_id = strtoull(id_str, NULL, 10);
    time_t create_at = (time_t)atol(create_str);
    time_t unlock_at = (time_t)atol(unlock_str);
    time_t expire_at = (time_t)atol(expire_str);

    size_t h_len;
    unsigned char *pubkey_hash = base64_decode(hash_b64, &h_len);

    if (pubkey_hash && h_len == PUBKEY_HASH_LEN) {
        int res = add_alert(pubkey_hash, unlock_at, expire_at, text_b64, 
                            key_b64, iv_b64, tag_b64, sub->sock, original_id, create_at);
        
        if (res == 0) {
            /* Only if the message is new */
            log_event("INFO", sub->sock, sub->ip_address, sub->port, 
                      "Alert %" PRIu64 " replicated (Recipient: %.12s...)", 
                      original_id, hash_b64);

            Recipient *rec = find_recipient(pubkey_hash);
            if (rec) {
                Alert *new_a = &rec->alerts[rec->count - 1];
                notify_subscribers(pubkey_hash, new_a);
                /* We forward only new data */
                broadcast_replication(pubkey_hash, new_a, sub->sock);
            }
        } 
        else if (res == 1) {
            /* This is a duplicate. We've already seen it. 
               We won't log anything or forward it. The loop has been broken. */
            if (verbose) {
                log_event("DEBUG", sub->sock, sub->ip_address, sub->port, 
                          "Ignored redundant replication for ID %" PRIu64, original_id);
            }
        }
    }

    if (pubkey_hash) free(pubkey_hash);
    free(rest);
}

/**
 * Handles the "SYNC|last_id" command.
 * The remote peer requests all historical alerts created after the specified last_id.
 * This ensures that a newly connected or previously offline node can catch up 
 * with the current state of the cluster.
 */
static void process_sync(int i, char *buffer) {
    Subscriber *sub = &subscribers[i];
    
    /* Ensure the peer is authenticated before processing synchronization */
    if (sub->auth_state != AUTH_OK) {
        log_event("WARN", sub->sock, sub->ip_address, sub->port, "Unauthorized sync request ignored");
        return;
    }

    /* Parse the last known ID provided by the peer */
    uint64_t last_id = strtoull(buffer + 5, NULL, 10);
    log_event("INFO", sub->sock, sub->ip_address, sub->port, 
              "Peer requested historical sync starting from ID: %" PRIu64, last_id);

    int count = 0;

    /* Iterate through all recipients and their alert records */
    for (int r = 0; r < recipient_count; r++) {
        Recipient *rec = &recipients[r];
        for (int a = 0; a < rec->count; a++) {
            /* Only send alerts that are newer than the peer's last known ID */
            if (rec->alerts[a].id > last_id) {
                send_alert_to_peer(i, rec->hash, &rec->alerts[a]);
                count++;
            }
        }
    }

    /* Log the completion of the synchronization task */
    log_event("INFO", sub->sock, sub->ip_address, sub->port, 
              "Sync completed: %d historical alerts transferred to peer", count);
}

/*
 * THE DISPATCHER
 * Routes received messages to appropriate command handlers.
 */
void handle_command(int sub_index, char *buffer) {
    Subscriber *sub = &subscribers[sub_index];

    /* 1. RESPONSES (Ответы других серверов - просто логируем и выходим) */
    if (strncmp(buffer, "AUTH_SUCCESS|", 13) == 0) {
        int peer_max = atoi(buffer + 13);
        
        if (peer_max != max_alerts) {
            log_event("ERROR", sub->sock, sub->ip_address, sub->port, 
                      "Cluster capacity mismatch during handshake! Local: %d, Remote: %d", 
                      max_alerts, peer_max);
            cleanup_subscriber(sub_index);
            return;
        }

        log_event("INFO", sub->sock, sub->ip_address, sub->port, "Remote peer confirmed authentication and capacity match");
        sub->auth_state = AUTH_OK;
        
        /* Запрашиваем историю */
        uint64_t my_max = get_max_alert_id();
        char sync_req[64];
        int len = snprintf(sync_req, sizeof(sync_req), "SYNC|%" PRIu64, my_max);
        enqueue_message(sub_index, sync_req, (size_t)len);
        return; 
    }
    
    if (strcmp(buffer, "AUTH_FAILED") == 0) {
        log_event("ERROR", sub->sock, sub->ip_address, sub->port, "Remote peer rejected our authentication!");
        return;
    }

    if (strncmp(buffer, "Error:", 6) == 0) {
        log_event("WARN", sub->sock, sub->ip_address, sub->port, "Remote peer returned error: %s", buffer);
        return; 
    }

    if (strncmp(buffer, "Alert added successfully", 24) == 0 || 
        strncmp(buffer, "Subscribed to", 13) == 0 ||
        strncmp(buffer, "Subscription updated", 20) == 0 ||
        strncmp(buffer, "AUTH_SUCCESS", 12) == 0) {
        return;
    }

    /* 2. COMMANDS (Parsing incoming commands) */
    log_event("DEBUG", sub->sock, sub->ip_address, sub->port, "Processing command: %s", buffer);

    if (strncmp(buffer, "SEND|", 5) == 0) {
        process_send(sub_index, buffer);
    } 
    else if (strncmp(buffer, "REPL|", 5) == 0) {
        process_repl(sub_index, buffer);
    }
    else if (strncmp(buffer, "AUTH|", 5) == 0) {
        process_auth(sub_index, buffer);
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
        /* Unknown protocol - return an error only if it is not a response to our request */
        char *error_msg = "Error: Unknown command";
        enqueue_message(sub_index, error_msg, strlen(error_msg));
        log_event("WARN", sub->sock, sub->ip_address, sub->port, "Unknown command received: %s", buffer);
    }
}
