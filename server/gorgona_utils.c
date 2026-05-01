/* 
* BSD 3-Clause License
* Copyright (c) 2025, Alexander Shcheglov
* All rights reserved. 
*/

#include "config.h"
#include "gorgona_utils.h"
#include "alert_db.h"
#include "snowflake.h"
#include "admin_mesh.h"
#include "common.h"
#include "commands.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdarg.h>
#include <strings.h> 
#include <sys/time.h>

FILE *log_file = NULL;
Recipient *recipients = NULL;
int recipient_count = 0;
int recipient_capacity = 0;
int client_sockets[MAX_CLIENTS];
Subscriber subscribers[MAX_CLIENTS];
int max_alerts = DEFAULT_MAX_ALERTS;
int max_clients = MAX_CLIENTS;
size_t max_log_size = DEFAULT_MAX_LOG_SIZE;
char log_level[32] = DEFAULT_LOG_LEVEL;
size_t max_message_size = DEFAULT_MAX_MESSAGE_SIZE;
int use_disk_db = 0;
static time_t last_rotation_check = 0;
ReplLogEntry repl_ring[REPL_RING_SIZE];
int repl_ring_head = 0;
PeerConfig remote_peers[MAX_PEERS];
int remote_peer_count = 0;
char sync_psk[64] = DEFAULT_SYNC_PSK;
uint64_t global_max_alert_id = 0;

/**
 * Main logging function.
 * Handles independent output to the log file (based on config level)
 * and the system console (based on the verbose flag).
 */
void log_event(const char *level, int fd, const char *ip, int port, const char *fmt, ...) {
    char time_str[32];
    char header[256];
    bool write_to_file = false;

    get_utc_time_str(time_str, sizeof(time_str));

    /* 1. Format the log prefix: [Time] [Level] [Source Info] */
    if (ip != NULL && port > 0) {
        snprintf(header, sizeof(header), "%s [%s] [fd:%d] [%s:%d] ", time_str, level, fd, ip, port);
    } else if (fd > 0) {
        snprintf(header, sizeof(header), "%s [%s] [fd:%d] ", time_str, level, fd);
    } else {
        snprintf(header, sizeof(header), "%s [%s] [SERVER] ", time_str, level);
    }

    /* 2. Determine if the event should be recorded in the log file based on log_level */
    if (strcasecmp(log_level, "debug") == 0) {
        /* In DEBUG mode, all events are recorded */
        write_to_file = true;
    } 
    else if (strcasecmp(log_level, "info") == 0) {
        /* In INFO mode, record everything except DEBUG messages */
        if (strcmp(level, "DEBUG") != 0) {
            write_to_file = true;
        }
    } 
    else if (strcasecmp(log_level, "error") == 0) {
        /* In ERROR mode, record only messages with ERROR priority */
        if (strcmp(level, "ERROR") == 0) {
            write_to_file = true;
        }
    }

    /* 3. Output to the log file */
    if (log_file && write_to_file) {
        rotate_log(); /* Check if rotation is necessary before writing */
        fprintf(log_file, "%s", header);
        
        va_list args_file;
        va_start(args_file, fmt);
        vfprintf(log_file, fmt, args_file);
        va_end(args_file);
        
        fprintf(log_file, "\n");
        fflush(log_file);
    }

    /* 4. Output to the system console if verbose mode is enabled.
       This bypasses log_level filters to provide full debug visibility in the terminal. */
    if (verbose) {
        printf("%s", header);
        
        va_list args_stdout;
        va_start(args_stdout, fmt);
        vfprintf(stdout, fmt, args_stdout);
        va_end(args_stdout);
        
        printf("\n");
        fflush(stdout); /* Ensure immediate output to terminal */
    }
} 

void format_time(time_t timestamp, char *buffer, size_t buffer_size) {
    struct tm *tm_info = gmtime(&timestamp);
    strftime(buffer, buffer_size, "%Y-%m-%d %H:%M:%S UTC", tm_info);
}

void free_alert(Alert *alert) {
    if (!alert->is_mmaped) {
        free(alert->text);
        free(alert->encrypted_key);
        free(alert->iv);
    }
    alert->text = NULL;
    alert->encrypted_key = NULL;
    alert->iv = NULL;
    alert->active = 0;
    alert->active_ptr = NULL;
}

Recipient *find_recipient(const unsigned char *hash) {
    if (!hash) return NULL;
    for (int i = 0; i < recipient_count; i++) {
        if (memcmp(recipients[i].hash, hash, PUBKEY_HASH_LEN) == 0) {
            return &recipients[i];
        }
    }
    return NULL;
}

Recipient *add_recipient(const unsigned char *hash) {
    if (!hash) return NULL;
    Recipient *existing = find_recipient(hash);
    if (existing) return existing;

    if (recipient_count >= recipient_capacity) {
        int new_cap = recipient_capacity + INITIAL_RECIPIENT_CAPACITY;
        Recipient *new_recipients = realloc(recipients, sizeof(Recipient) * new_cap);
        if (!new_recipients) return NULL;
        recipients = new_recipients;
        recipient_capacity = new_cap;
    }

    Recipient *rec = &recipients[recipient_count];
    memset(rec, 0, sizeof(Recipient));
    memcpy(rec->hash, hash, PUBKEY_HASH_LEN);
    rec->fd = -1; /* Important: Initialize to -1, not 0 */
    rec->capacity = max_alerts;
    rec->alerts = malloc(sizeof(Alert) * rec->capacity);
    if (!rec->alerts) return NULL;
    
    recipient_count++;
    return rec;
}

/**
 * Removes a recipient from the global array using "Swap with Last" logic.
 * This is O(1) and safe for single-threaded event loops.
 */
void remove_recipient_at_index(int index) {
    if (index < 0 || index >= recipient_count) return;
    /* We are clearing the alerts and the alert array for this recipient */
    for (int j = 0; j < recipients[index].count; j++) {
        free_alert(&recipients[index].alerts[j]);
    }
    free(recipients[index].alerts);

    if (index < recipient_count - 1) {
        memcpy(&recipients[index], &recipients[recipient_count - 1], sizeof(Recipient));
    }
    recipient_count--;
}

/**
 * Updated cleanup function. 
 * Note: Must handle index externally if called in a loop.
 */
void clean_expired_alerts_logic(Recipient *rec, time_t reference_time) {
    int changes_made = 0; /* We detect any data deletion from RAM */
    for (int i = 0; i < rec->count; ) {
        /* Delete if it is NO LONGER active (Revoke) OR if the time has expired */
        if (!rec->alerts[i].active || rec->alerts[i].expire_at <= reference_time) {
            
            if (use_disk_db && rec->alerts[i].active) {
                /* If an alert was active but has expired, we mark it as inactive in the database before removing it from memory */
                alert_db_deactivate_alert(&rec->alerts[i]);
                rec->waste_count++;
            }

            free_alert(&rec->alerts[i]);
            memmove(&rec->alerts[i], &rec->alerts[i + 1], sizeof(Alert) * (rec->count - i - 1));
            rec->count--;
            
            changes_made++; /* was deleted from RAM */
        } else {
            i++;
        }
    }
    if (use_disk_db && changes_made > 0) {
        int waste_limit = (max_alerts * vacuum_threshold) / 100;
         /* We call sync if: 
         * A lot of waste has accumulated (waste_count >= waste_limit) */ 
        if (rec->waste_count >= waste_limit) {
            alert_db_sync(rec);
        }
    }
}

void clean_expired_alerts(Recipient *rec) {
    clean_expired_alerts_logic(rec, time(NULL));
}

void remove_oldest_alert(Recipient *rec) {
    if (rec->count == 0) return;

    int oldest_idx = 0;
    uint64_t min_id = rec->alerts[0].id;
    for (int i = 1; i < rec->count; i++) {
        if (rec->alerts[i].id < min_id) {
            min_id = rec->alerts[i].id;
            oldest_idx = i;
        }
    }

    if (use_disk_db) {
        alert_db_deactivate_alert(&rec->alerts[oldest_idx]);
        rec->waste_count++;
    }

    free_alert(&rec->alerts[oldest_idx]);
    memmove(&rec->alerts[oldest_idx], &rec->alerts[oldest_idx + 1], 
            sizeof(Alert) * (rec->count - oldest_idx - 1));
    rec->count--;

    /* Calculate the threshold based on the configuration */
    int waste_limit = (max_alerts * vacuum_threshold) / 100;
    
    /* Trigger sync if threshold reached, too much junk, or recipient became empty */
    if (use_disk_db && (rec->waste_count >= waste_limit || rec->waste_count > 50000 || rec->count == 0)) {
        if (verbose) {
            fprintf(stderr, "Vacuum trigger (overflow): waste=%d (limit=%d%% of %d), count=%d\n", 
                    rec->waste_count, vacuum_threshold, max_alerts, rec->count);
        }
        alert_db_sync(rec);
    }
}

/**
 * Adds a new encrypted alert to the recipient's record.
 * 
 * Supports both locally generated alerts (from clients via SEND) and 
 * replicated alerts (from peers via REPL/SYNC).
 * 
 * Logic flow:
 * 1. Time Synchronization: Derives cluster-wide logical time from the Snowflake pulse.
 * 2. Layer 1 Anti-Replay: Staleness check against the cluster pulse (skipped for replication).
 * 3. Layer 2 Anti-Replay: Content-based and ID-based deduplication (scans even inactive records).
 * 4. Sliding Window: Protects current alerts by rejecting historical data that exceeds the window.
 * 5. Housekeeping: Synchronous cleanup using logical time to prevent P2P data drift.
 * 6. Persistence: Saves to mmap-backed storage.
 * 
 * @return 0 on success, 1 if duplicate, -1 if stale, -2 if replay attack, -3 on error.
 */
int add_alert(const unsigned char *pubkey_hash, time_t unlock_at, time_t expire_at,
               char *base64_text, char *base64_encrypted_key, char *base64_iv, char *base64_tag, 
               int client_fd, uint64_t forced_id, time_t forced_create_at) {
    
    /* 1. Recipient Management: Find or create the recipient record in memory */
    Recipient *rec = find_recipient(pubkey_hash);
    if (!rec) rec = add_recipient(pubkey_hash);
    if (!rec) return -3;

    /* 2. Logical Time Derivation:
     * To prevent P2P drift caused by local clock skew, we use the highest 
     * known Snowflake ID as the 'Cluster Pulse'. This ensures all nodes 
     * reach the same consensus on expiration and windowing. */
    uint64_t current_max = get_max_alert_id();
    time_t cluster_now = (current_max > 0) ? snowflake_to_timestamp(current_max) : time(NULL);

    /* 3. Metadata: Identify sender context for logging purposes */
    const char *client_ip = NULL;
    int client_port = 0;
    for (int i = 0; i < max_clients; i++) {
        if (subscribers[i].sock == client_fd) {
            client_ip = subscribers[i].ip_address;
            client_port = subscribers[i].port;
            break;
        }
    }

    /* --- ANTI-REPLAY LAYER 1: Staleness Check --- 
     * Rejects new alerts that are significantly behind the current cluster pulse.
     * Crucial: Skip this for replication (forced_id > 0) to allow node catch-up. */
    if (forced_id == 0 && unlock_at < (cluster_now - STALE_THRESHOLD_SEC)) {
        log_event("WARN", client_fd, client_ip, client_port, 
                  "Rejected stale alert (unlock_at is %ld seconds behind cluster pulse)", 
                  (long)(cluster_now - unlock_at));
        return -1;
    }

    /* 4. Pre-check: Decode the primary payload for deduplication */
    size_t new_text_len;
    unsigned char *decoded_text = base64_decode(base64_text, &new_text_len);
    if (!decoded_text) return -3;

    /* --- ANTI-REPLAY LAYER 2: Full-Record Idempotency --- 
     * We verify the alert against the entire dataset, including inactive (active=0) 
     * tombstone records. This prevents "zombie" alerts from being re-accepted 
     * after revocation or expiration, stopping circular gossip loops.
     */
    for (int j = 0; j < rec->count; j++) {
        /* A. Identity Check: Ensure Snowflake IDs are globally unique. */
        if (forced_id > 0 && rec->alerts[j].id == forced_id) {
            free(decoded_text);
            return 1; /* Duplicate ID: stop replication relay */
        }

        /* B. Content-Based Check: Compare raw binary payloads.
         * Identical ciphertext implies a replay attack or redundant transmission. */
        if (rec->alerts[j].text_len == new_text_len) {
            if (memcmp(rec->alerts[j].text, decoded_text, new_text_len) == 0) {
                free(decoded_text);
                if (forced_id > 0) return 1; /* Redundant P2P replication */
                
                log_event("WARN", client_fd, client_ip, client_port, 
                          "Replay attack detected: Duplicate binary payload found.");
                return -2;
            }
        }
    }

    /* --- SLIDING WINDOW PROTECTION --- 
     * If the recipient's buffer is at capacity, we reject incoming data that is 
     * chronologically older than our current oldest ACTIVE alert. This prevents 
     * historical syncs from displacing recent, high-priority tasks.
     */
    if (forced_id > 0 && rec->count >= max_alerts) {
        uint64_t min_active_id = 0xFFFFFFFFFFFFFFFFULL;
        bool has_active = false;

        for (int j = 0; j < rec->count; j++) {
            if (rec->alerts[j].active && rec->alerts[j].id < min_active_id) {
                min_active_id = rec->alerts[j].id;
                has_active = true;
            }
        }

        if (has_active && forced_id < min_active_id) {
            if (verbose) {
                log_event("DEBUG", client_fd, client_ip, client_port, 
                          "Suppressed out-of-window replication for ID %" PRIu64, forced_id);
            }
            free(decoded_text);
            return 1; 
        }
    }

    /* --- DETERMINISTIC HOUSEKEEPING --- 
     * 1. Clean up expired records first.
     * 2. If the count still exceeds max_alerts, aggressively remove oldest IDs 
     *    until there is room for the new record. Using 'while' instead of 'if' 
     *    fixes overflows caused by database loading or rapid P2P sync. */
    clean_expired_alerts_logic(rec, cluster_now);
    
    while (rec->count >= max_alerts && rec->count > 0) {
        remove_oldest_alert(rec);
    }

    /* --- INITIALIZATION --- 
     * Place the new Alert at the end of the current array. */
    Alert *alert = &rec->alerts[rec->count];
    memset(alert, 0, sizeof(Alert));
    
    alert->text = decoded_text;
    alert->text_len = new_text_len;
    alert->encrypted_key = base64_decode(base64_encrypted_key, &alert->encrypted_key_len);
    alert->iv = base64_decode(base64_iv, &alert->iv_len);
    
    /* Securely copy the GCM Authentication Tag */
    size_t actual_tag_len;
    unsigned char *tag_raw = base64_decode(base64_tag, &actual_tag_len);
    if (tag_raw && actual_tag_len == GCM_TAG_LEN) {
        memcpy(alert->tag, tag_raw, GCM_TAG_LEN);
    }
    if (tag_raw) free(tag_raw);

    /* --- IDENTITY ASSIGNMENT --- */
    if (forced_id > 0) {
        alert->id = forced_id;
        alert->create_at = forced_create_at;
    } else {
        alert->id = generate_snowflake_id();
        alert->create_at = time(NULL);
    }

    alert->unlock_at = unlock_at;
    alert->expire_at = expire_at;
    alert->active = 1;

    /* Add to the replication ring for peer discovery */
    add_to_repl_ring(alert->id, pubkey_hash);

    /* --- PERSISTENCE --- 
     * If disk storage is enabled, alert_db_save_alert will handle memory-mapping 
     * and transition heap-allocated buffers to the mmap region. */
    if (use_disk_db) {
        if (alert_db_save_alert(rec, alert) != 0) {
            log_event("ERROR", client_fd, client_ip, client_port, "Persistence failed: mmap I/O error");
        }
    } else {
        alert->is_mmaped = false;
    }

    rec->count++;
    
    if (alert->id > global_max_alert_id) {
        global_max_alert_id = alert->id;
    }

    log_event("DEBUG", client_fd, client_ip, client_port, 
              "Alert %" PRIu64 " added successfully...", alert->id);

    return 0; /* Success: Alert ingested and ready for replication */
}


void notify_subscribers(const unsigned char *pubkey_hash, Alert *new_alert) {
    if (!new_alert || !new_alert->active) return;

    char *pubkey_hash_b64 = base64_encode(pubkey_hash, PUBKEY_HASH_LEN);
    char *bt = base64_encode(new_alert->text, new_alert->text_len);
    char *bk = base64_encode(new_alert->encrypted_key, new_alert->encrypted_key_len);
    char *bi = base64_encode(new_alert->iv, new_alert->iv_len);
    char *bg = base64_encode(new_alert->tag, GCM_TAG_LEN);

    if (!pubkey_hash_b64 || !bt || !bk || !bi || !bg) {
        free(pubkey_hash_b64); free(bt); free(bk); free(bi); free(bg);
        return;
    }
    size_t needed_len = strlen("ALERT|") + strlen(pubkey_hash_b64) + 1024 + 
                        strlen(bt) + strlen(bk) + strlen(bi) + strlen(bg);
    char *response = malloc(needed_len);
    if (response) {
        int len = snprintf(response, needed_len, "ALERT|%s|%" PRIu64 "|%ld|%ld|%s|%s|%s|%s",
                           pubkey_hash_b64, new_alert->id, (long)new_alert->unlock_at, 
                           (long)new_alert->expire_at, bt, bk, bi, bg);
        if (len > 0) {
            size_t actual_len = (size_t)len;
            for (int j = 0; j < max_clients; j++) {
                if (client_sockets[j] > 0 && subscribers[j].mode != 0) {
                    bool match_hash = (subscribers[j].pubkey_hash[0] == '\0' || 
                                       strcmp(subscribers[j].pubkey_hash, pubkey_hash_b64) == 0);
                    if (!match_hash) continue;
                    bool send_it = false;
                    int mode = subscribers[j].mode;
                    uint64_t m_id = get_max_alert_id();
                    time_t cluster_time = (m_id > 0) ? snowflake_to_timestamp(m_id) : time(NULL);
                    bool is_locked = (new_alert->unlock_at > cluster_time); 
                    if (mode == MODE_LIVE || mode == MODE_ALL || mode == MODE_NEW) {
                        send_it = true;
                    } 
                    else if (mode == MODE_LOCK && is_locked) {
                        send_it = true;
                    } else if (mode == MODE_SINGLE && !is_locked) {
                        send_it = true;
                    }
                    if (send_it) {
                        enqueue_message(j, response, actual_len);
                    }
                }
            }
        }
        free(response);
    }
    free(pubkey_hash_b64); free(bt); free(bk); free(bi); free(bg);
} 

/**
 * Iterates through all recipients and sends relevant encrypted alerts to a subscriber.
 * 
 * This function handles various listening modes (LIVE, ALL, LOCK, LAST, SINGLE)
 * and applies filters based on recipient public key hashes. It also performs
 * proactive maintenance by cleaning expired alerts before transmission.
 *
 * For MODE_ALL, an optional 'count' can be provided to send the 'N' most
 * recent historical alerts before entering the live subscription state.
 * 
 * @param sub_index Index of the client in the global subscribers array.
 * @param mode The subscription mode (determines which alerts are sent).
 * @param pubkey_hash_b64_filter Optional filter for a specific recipient.
 * @param count Maximum number of historical alerts to send (used in MODE_LAST and counted MODE_ALL).
 */
void send_current_alerts(int sub_index, int mode, const char *pubkey_hash_b64_filter, int count) {
    time_t now = time(NULL);

    /* 
     * Use a manual index increment to safely handle cases where a 
     * recipient is removed from the global array during the maintenance phase.
     */
    for (int r = 0; r < recipient_count; ) {
        Recipient *rec = &recipients[r];
        
        /* 1. Maintenance: Purge expired alerts before processing the transmission */
        clean_expired_alerts(rec);

        /* 2. Cleanup: If the recipient is now empty, sync/delete the file and remove from memory */
        if (rec->count == 0 && use_disk_db) {
            if (alert_db_sync(rec) == 1) {
                remove_recipient_at_index(r);
                /* Do not increment index: the next recipient has shifted into the current slot */
                continue; 
            }
        }

        /* 3. Filtering: Encode hash to Base64 and compare with requested filter */
        char *pubkey_hash_b64 = base64_encode(rec->hash, PUBKEY_HASH_LEN);
        if (!pubkey_hash_b64) {
            r++;
            continue;
        }

        if (pubkey_hash_b64_filter && strlen(pubkey_hash_b64_filter) > 0) {
            if (strcmp(pubkey_hash_b64, pubkey_hash_b64_filter) != 0) {
                free(pubkey_hash_b64);
                r++;
                continue;
            }
        }

        /* 4. Ordering: Sort alerts by ID (descending) if historical data is requested */
        /* We sort based on whether it is LAST, SINGLE, or ALL with a specified limit */
        if (mode == MODE_LAST || mode == MODE_SINGLE || (mode == MODE_ALL && count > 0)) {
            qsort(rec->alerts, rec->count, sizeof(Alert), alert_cmp_desc);
        }

        /* 5. Transmission: Process alerts in the recipient's buffer */
        int limit;
        if (mode == MODE_LAST || (mode == MODE_ALL && count > 0)) {
            limit = count; 
        } else {
            limit = rec->count; /* If count == 0, return everything */
        }
        
        int sent_count = 0;
        for (int i = 0; i < rec->count && sent_count < limit; i++) {
            Alert *a = &rec->alerts[i];
            
            /* Skip inactive or expired alerts that haven't been vacuumed yet */
            if (!a->active || a->expire_at <= now) continue;

            bool is_locked = (a->unlock_at > now);
            bool send_it = false;

            /* Apply mode-specific visibility rules */
            if (mode == MODE_ALL || mode == MODE_LAST) {
                send_it = true;
            } else if (mode == MODE_LIVE || mode == MODE_SINGLE) {
                send_it = !is_locked;
            } else if (mode == MODE_LOCK) {
                send_it = is_locked;
            }

            if (send_it) {
                /* Encode binary fields for network transmission */
                char *bt = base64_encode(a->text, a->text_len);
                char *bk = base64_encode(a->encrypted_key, a->encrypted_key_len);
                char *bi = base64_encode(a->iv, a->iv_len);
                char *bg = base64_encode(a->tag, GCM_TAG_LEN);

                if (bt && bk && bi && bg) {
                    size_t resp_len = 2048 + strlen(bt) + strlen(bk) + strlen(bi) + strlen(bg);
                    char *resp = malloc(resp_len);
                    if (resp) {
                        /* Format the ALERT message according to protocol spec */
                        int l = snprintf(resp, resp_len, "ALERT|%s|%" PRIu64 "|%ld|%ld|%s|%s|%s|%s",
                                         pubkey_hash_b64, a->id, (long)a->unlock_at, (long)a->expire_at, 
                                         bt, bk, bi, bg);
                        if (l > 0) {
                            enqueue_message(sub_index, resp, (size_t)l);
                        }
                        free(resp);
                    }
                }
                
                free(bt); free(bk); free(bi); free(bg);
                sent_count++;
            }
        }

        free(pubkey_hash_b64); 
        r++; /* Move to the next recipient in the list */
    }

    /* 6. Post-processing: Handle one-time requests by flagging connection for closure.
     * Note: MODE_ALL is a subscription, so it is intentionally excluded here. */
    if (mode == MODE_LAST || mode == MODE_SINGLE) {
        subscribers[sub_index].close_after_send = true;
    }
}

void rotate_log() {
    time_t now = time(NULL);
    if (now - last_rotation_check < 5) return;
    last_rotation_check = now;

    struct stat st;
    if (stat("gorgonad.log", &st) == 0 && (size_t)st.st_size > max_log_size) {
        if (log_file) {
            char time_str[32];
            get_utc_time_str(time_str, sizeof(time_str));
            fprintf(log_file, "%s Rotating log file\n", time_str);
            fflush(log_file);
            fclose(log_file);
        }
        rename("gorgonad.log", "gorgonad.log.1");
        log_file = fopen("gorgonad.log", "a");
        if (!log_file) {
            perror("Failed to open new log file");
        }
    }
}

int alert_cmp_asc(const void *a, const void *b) {
    uint64_t id_a = ((Alert *)a)->id;
    uint64_t id_b = ((Alert *)b)->id;
    if (id_a < id_b) return -1;
    if (id_a > id_b) return 1;
    return 0;
}

int alert_cmp_desc(const void *a, const void *b) {
    return alert_cmp_asc(b, a);
}

/*
 * Adds an entry for a new alert to the circular log. 
 */
void add_to_repl_ring(uint64_t id, const unsigned char *hash) {
    repl_ring[repl_ring_head].id = id;
    memcpy(repl_ring[repl_ring_head].pubkey_hash, hash, PUBKEY_HASH_LEN);
    
    repl_ring_head = (repl_ring_head + 1) % REPL_RING_SIZE;
}

/**
 * Broadcasts a new alert to all authorized peers.
 * Now includes the 'active' status to propagate revocations (tombstones).
 */
void broadcast_replication(const unsigned char *pubkey_hash, Alert *alert, int exclude_fd) {
    char *ph_b64 = base64_encode(pubkey_hash, PUBKEY_HASH_LEN);
    char *bt     = base64_encode(alert->text, alert->text_len);
    char *bk     = base64_encode(alert->encrypted_key, alert->encrypted_key_len);
    char *bi     = base64_encode(alert->iv, alert->iv_len);
    char *bg     = base64_encode(alert->tag, GCM_TAG_LEN);

    if (!ph_b64 || !bt || !bk || !bi || !bg) {
        free(ph_b64); free(bt); free(bk); free(bi); free(bg);
        return;
    }

    size_t msg_capacity = max_message_size + 2048; 
    char *repl_msg = malloc(msg_capacity);
    if (!repl_msg) {
        free(ph_b64); free(bt); free(bk); free(bi); free(bg);
        return;
    }

    /* Protocol Update: Added |%d| for alert->active status */
    int len = snprintf(repl_msg, msg_capacity, "REPL|%" PRIu64 "|%ld|%ld|%ld|%d|%s|%s|%s|%s|%s",
                       alert->id, (long)alert->create_at, (long)alert->unlock_at, (long)alert->expire_at,
                       alert->active, ph_b64, bt, bk, bi, bg);

    if (len > 0) {
        int sent_to_ips_count = 0;
        char sent_to_ips[MAX_PEERS * 4][INET_ADDRSTRLEN]; 
        memset(sent_to_ips, 0, sizeof(sent_to_ips));

        char sender_ip[INET_ADDRSTRLEN] = "";
        if (exclude_fd > 0) {
            for (int k = 0; k < max_clients; k++) {
                if (client_sockets[k] == exclude_fd) {
                    strncpy(sender_ip, subscribers[k].ip_address, INET_ADDRSTRLEN - 1);
                    break;
                }
            }
        }

        for (int i = 0; i < max_clients; i++) {
            if (client_sockets[i] > 0 && subscribers[i].type == SUB_TYPE_PEER && subscribers[i].auth_state == AUTH_OK) {
                if (strcmp(subscribers[i].ip_address, sender_ip) == 0) continue;

                bool already_sent_to_ip = false;
                for (int j = 0; j < sent_to_ips_count; j++) {
                    if (strcmp(sent_to_ips[j], subscribers[i].ip_address) == 0) {
                        already_sent_to_ip = true; break;
                    }
                }
                if (already_sent_to_ip) continue;

                enqueue_message(i, repl_msg, (size_t)len);
                if (sent_to_ips_count < (MAX_PEERS * 4)) {
                    strncpy(sent_to_ips[sent_to_ips_count++], subscribers[i].ip_address, INET_ADDRSTRLEN - 1);
                }
            }
        }
    }

    free(repl_msg);
    free(ph_b64); free(bt); free(bk); free(bi); free(bg);
}

/*
 * Finds the largest Snowflake ID in the entire database.
 * Returns 0 if the database is empty.
 */
uint64_t get_max_alert_id() {
    return global_max_alert_id;
}

/* 
 * Sends a specific alert to a specific peer including its active status.
 */
void send_alert_to_peer(int sub_index, const unsigned char *pubkey_hash, Alert *alert) {
    char *ph_b64 = base64_encode(pubkey_hash, PUBKEY_HASH_LEN);
    char *bt     = base64_encode(alert->text, alert->text_len);
    char *bk     = base64_encode(alert->encrypted_key, alert->encrypted_key_len);
    char *bi     = base64_encode(alert->iv, alert->iv_len);
    char *bg     = base64_encode(alert->tag, GCM_TAG_LEN);

    if (!ph_b64 || !bt || !bk || !bi || !bg) {
        free(ph_b64); free(bt); free(bk); free(bi); free(bg);
        return;
    }

    size_t msg_capacity = max_message_size + 2048;
    char *repl_msg = malloc(msg_capacity);
    if (repl_msg) {
        /* Protocol Update: Added |%d| for alert->active status after expire_at */
        int len = snprintf(repl_msg, msg_capacity, "REPL|%" PRIu64 "|%ld|%ld|%ld|%d|%s|%s|%s|%s|%s",
                           alert->id, (long)alert->create_at, (long)alert->unlock_at, (long)alert->expire_at,
                           alert->active, ph_b64, bt, bk, bi, bg);
        if (len > 0) {
            enqueue_message(sub_index, repl_msg, (size_t)len);
        }
        free(repl_msg);
    }
    free(ph_b64); free(bt); free(bk); free(bi); free(bg);
}

/**
 * Global Maintenance Cycle
 * Handles Layer 1 (Storage cleanup) and Layer 2 (Aggressive Mesh Sync).
 */
void run_global_maintenance(void) {
    time_t now = time(NULL); /* Системное время для сетевых таймаутов */
    
    /* 1. Определяем "Логическое время кластера" по Pulse */
    uint64_t max_id = get_max_alert_id();
    time_t cluster_now = (max_id > 0) ? snowflake_to_timestamp(max_id) : now;
    
    /* --- LAYER 1: Storage & Memory Cleanup --- */
    for (int i = 0; i < recipient_count; ) {
        Recipient *rec = &recipients[i];
        
        /* 1. Purge expired alerts based on cluster logical time */
        clean_expired_alerts_logic(rec, cluster_now);

        /* 2. Enforce hard limit on alert count per key */
        while (rec->count > max_alerts && rec->count > 0) {
            remove_oldest_alert(rec);
        }

        int waste_limit = (max_alerts * vacuum_threshold) / 100;
        if (rec->count == 0 || rec->waste_count >= waste_limit) {
            if (alert_db_sync(rec) == 1) {
                remove_recipient_at_index(i);
                continue;
            }
        }
        i++;
    }

    /* --- LAYER 2: Administrative Mesh Maintenance --- */
    static time_t last_mesh_task = 0;

    /* We use the system ‘now’ function, since this involves working with sockets */
    if (now - last_mesh_task >= sync_interval) { 
        last_mesh_task = now;
        
        /* 1. Recalculate scores and evict dead nodes */
        mesh_run_garbage_collector();

        extern int port;
        
        /* 2. Build Peer Exchange (PEX) list */
        char pex_payload[2048];
        int p_len = snprintf(pex_payload, sizeof(pex_payload), "PEX_LIST|%d|", port);
        
        int neighbors_count = 0;
        for (int n = 0; n < cluster_node_count; n++) {
            /* Проверка таймаута ноды по системному времени */
            if (cluster_nodes[n].status == PEER_STATUS_AUTHENTICATED && cluster_nodes[n].last_seen > (now - 300)) {
                if (p_len < (int)sizeof(pex_payload) - 64) {
                    p_len += snprintf(pex_payload + p_len, sizeof(pex_payload) - p_len,
                                     "%s:%d|", cluster_nodes[n].ip, cluster_nodes[n].port);
                    neighbors_count++;
                }
            }
        }

        /* 3. Anti-Entropy: Get our highest Alert ID to share with cluster */
        uint64_t my_max_id = get_max_alert_id();

        /* 4. Disseminate management data to all authorized entities */
        for (int i = 0; i < max_clients; i++) {
            /* 
             * CRITICAL CHANGE: We check for AUTH_OK only. 
             * This allows both Peers (Servers) and Authorized Clients to receive L2 updates.
             */
            if (client_sockets[i] > 0 && subscribers[i].auth_state == AUTH_OK) {
                
                /* [PING / HEARTBEAT] 
                 * We send PINGs only to other Nodes (Peers) to calculate RTT/Score. 
                 * Standard clients don't need their latency measured by the server.
                 */
                if (subscribers[i].type == SUB_TYPE_PEER) {
                    struct timeval tv;
                    gettimeofday(&tv, NULL);
                    uint64_t ts = (uint64_t)tv.tv_sec * 1000 + (tv.tv_usec / 1000);
                    
                    char ping_cmd[128];
                    /* Format: CMD | TS | PORT | MAX_ID */
                    snprintf(ping_cmd, sizeof(ping_cmd), "PING|%" PRIu64 "|%d|%" PRIu64, ts, port, my_max_id);
                    send_mgmt_command(i, ping_cmd);
                }

                /* [PEX / GOSSIP] 
                 * Send the cluster map to anyone who knows the sync_psk.
                 * This allows the Client to update its /var/lib/gorgona/peers.cache file.
                 */
                if (neighbors_count > 0) {
                    send_mgmt_command(i, pex_payload);
                }
            }
        }

        if (verbose) {
            log_event("DEBUG", -1, NULL, 0, 
                      "L2 Mesh: Sync cycle complete (Interval: %ds, Neighbors: %d, MaxID: %" PRIu64 ")", 
                      sync_interval, neighbors_count, my_max_id);
        }
    }
    static time_t last_cache_dump = 0;
    /* We save the best peers to peers.cache every 60 minutes */
    if (now - last_cache_dump >= 3600) { 
        mesh_save_peers_cache();
        last_cache_dump = now;
    }
}

