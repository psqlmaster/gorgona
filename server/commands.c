/* BSD 3-Clause License
Copyright (c) 2025, Alexander Shcheglov
All rights reserved. */

#include "gorgona_utils.h"
#include "commands.h"
#include "snowflake.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <inttypes.h>

/* Helpers for command processing */

/**
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
    int result = add_alert(pubkey_hash, unlock_at, expire_at, base64_text, base64_encrypted_key, base64_iv, base64_tag, sd);

    if (result == 0) {
        char *success_msg = "Alert added successfully";
        enqueue_message(i, success_msg, strlen(success_msg));
        
        /* Notify subscribers only on REAL success */
        Recipient *rec = find_recipient(pubkey_hash);
        if (rec) {
            notify_subscribers(pubkey_hash, &rec->alerts[rec->count - 1]);
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

/**
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

/**
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

/**
 * THE DISPATCHER
 * Routes received messages to appropriate command handlers.
 */
void handle_command(int sub_index, char *buffer) {
    log_event("DEBUG", subscribers[sub_index].sock, subscribers[sub_index].ip_address, 
              subscribers[sub_index].port, "Processing command payload: %s", buffer);
    if (strncmp(buffer, "SEND|", 5) == 0) {
        process_send(sub_index, buffer);
    } 
    else if (strncmp(buffer, "LISTEN|", 7) == 0) {
        process_listen(sub_index, buffer);
    } 
    else if (strncmp(buffer, "SUBSCRIBE ", 10) == 0) {
        process_subscribe(sub_index, buffer);
    } 
    else {
        /* Unknown command in binary/message mode */
        char *error_msg = "Error: Unknown command";
        enqueue_message(sub_index, error_msg, strlen(error_msg));
        
        /* Log unknown command with context */
        log_event("WARN", subscribers[sub_index].sock, subscribers[sub_index].ip_address, subscribers[sub_index].port, 
                  "Unknown command received: %s", buffer);
    }
}
