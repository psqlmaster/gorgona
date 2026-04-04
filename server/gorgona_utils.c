/* BSD 3-Clause License
Copyright (c) 2025, Alexander Shcheglov
All rights reserved. */

#include "config.h"
#include "gorgona_utils.h"
#include "alert_db.h"
#include "snowflake.h"
#include "common.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdarg.h>
#include <strings.h> 

#define REPLAY_WINDOW_SIZE 50    /* Number of recent alerts to check for duplicates */
#define STALE_THRESHOLD_SEC 120  /* Max allowed clock drift/staleness (2 minutes) */

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

/* void get_utc_time_str(char *buffer, size_t buffer_size) {
    time_t now = time(NULL);
    struct tm *utc_time = gmtime(&now);
    strftime(buffer, buffer_size, "[%Y-%m-%d %H:%M:%S UTC]", utc_time);
} */

void trim_string(char *str) {
    size_t len = strlen(str);
    while (len > 0 && (str[len - 1] == ' ' || str[len - 1] == '\n' || str[len - 1] == '\r')) {
        str[len - 1] = '\0';
        len--;
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

void clean_expired_alerts(Recipient *rec) {
    time_t now = time(NULL);
    int expired_found = 0;

    for (int i = 0; i < rec->count; ) {
        if (rec->alerts[i].active && rec->alerts[i].expire_at <= now) {
            if (use_disk_db) {
                alert_db_deactivate_alert(&rec->alerts[i]);
                rec->waste_count++;
            }
            free_alert(&rec->alerts[i]);
            memmove(&rec->alerts[i], &rec->alerts[i + 1], sizeof(Alert) * (rec->count - i - 1));
            rec->count--;
            expired_found++;
        } else {
            i++;
        }
    }

    /* activate the vacuum only when the threshold is reached */
    if (use_disk_db && expired_found > 0) {
        if (rec->waste_count > max_alerts / 4 || rec->waste_count > 100) {
            alert_db_sync(rec);
            rec->waste_count = 0;
        }
    }
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
    
    /* Protection: The vacuum will run in any case if there is too much junk data (>50,000 entries) 
       or if it exceeds the specified percentage */
    if (use_disk_db && (rec->waste_count >= waste_limit || rec->waste_count > 50000)) {
        if (verbose) {
            fprintf(stderr, "Vacuum trigger: waste=%d (limit=%d%% of %d)\n", 
                    rec->waste_count, vacuum_threshold, max_alerts);
        }
        alert_db_sync(rec);
        rec->waste_count = 0;
    }
}

/**
 * Adds a new encrypted alert to the recipient's record.
 * 
 * Supports both locally generated alerts (from clients) and replicated alerts (from peers).
 * Includes Anti-Replay protection via staleness threshold and binary payload deduplication.
 * 
 * @param pubkey_hash Binary hash of the recipient's public key.
 * @param unlock_at Timestamp when the alert becomes decryptable.
 * @param expire_at Timestamp when the alert should be deleted.
 * @param base64_text Base64 encoded encrypted message body.
 * @param base64_encrypted_key Base64 encoded encrypted AES key.
 * @param base64_iv Base64 encoded Initialization Vector.
 * @param base64_tag Base64 encoded GCM authentication tag.
 * @param client_fd Socket descriptor of the sender.
 * @param forced_id Original Snowflake ID (used for replication, 0 for new local alerts).
 * @param forced_create_at Original creation timestamp (used for replication, 0 for new local alerts).
 * 
 * @return 0 on success (new), 1 if duplicate (ignore), -1 if stale, -2 if replay attack, -3 on error.
 */
int add_alert(const unsigned char *pubkey_hash, time_t unlock_at, time_t expire_at,
               char *base64_text, char *base64_encrypted_key, char *base64_iv, char *base64_tag, 
               int client_fd, uint64_t forced_id, time_t forced_create_at) {
    
    /* Ensure the recipient exists in memory; create if necessary */
    Recipient *rec = find_recipient(pubkey_hash);
    if (!rec) rec = add_recipient(pubkey_hash);
    if (!rec) return -3;

    /* Identify sender metadata for security logging context */
    const char *client_ip = NULL;
    int client_port = 0;
    for (int i = 0; i < max_clients; i++) {
        if (subscribers[i].sock == client_fd) {
            client_ip = subscribers[i].ip_address;
            client_port = subscribers[i].port;
            break;
        }
    }

    time_t now = time(NULL);

    /* --- ANTI-REPLAY LAYER 1: Staleness Check --- 
       Reject alerts that are too far in the past to prevent processing of old captures. 
       Bypassed for replication (forced_id > 0) to allow historical data sync. */
    if (forced_id == 0 && unlock_at < (now - STALE_THRESHOLD_SEC)) {
        log_event("WARN", client_fd, client_ip, client_port, 
                  "Rejected stale alert (unlock_at is %ld seconds behind)", (long)(now - unlock_at));
        return -1;
    }

    /* Decode the primary payload for deduplication check */
    size_t new_text_len;
    unsigned char *decoded_text = base64_decode(base64_text, &new_text_len);
    if (!decoded_text) return -3;

    /* --- ANTI-REPLAY LAYER 2: Sliding Window Deduplication & Gossip Suppression --- 
       Check the most recent alerts for this recipient to catch duplicate binary payloads. */
    int start_check = (rec->count > REPLAY_WINDOW_SIZE) ? (rec->count - REPLAY_WINDOW_SIZE) : 0;
    for (int j = start_check; j < rec->count; j++) {
        if (rec->alerts[j].active && rec->alerts[j].text_len == new_text_len) {
            if (memcmp(rec->alerts[j].text, decoded_text, new_text_len) == 0) {
                free(decoded_text);
                
                if (forced_id > 0) {
                    /* Peer duplicate: Signal the caller to stop propagation (Gossip Suppression) */
                    if (verbose) {
                        log_event("DEBUG", client_fd, client_ip, client_port, 
                                  "Ignored redundant replication for ID %" PRIu64, forced_id);
                    }
                    return 1; 
                }

                /* Client duplicate: Flag as a potential replay attack */
                log_event("WARN", client_fd, client_ip, client_port, 
                          "Replay attack detected: Duplicate binary payload found.");
                return -2;
            }
        }
    }

    /* --- HOUSEKEEPING --- 
       Remove expired alerts and enforce capacity limits before adding new data. */
    clean_expired_alerts(rec);
    if (rec->count >= max_alerts) {
        remove_oldest_alert(rec);
    }

    /* --- INITIALIZATION --- 
       Prepare the Alert structure. Pointer is assigned only after housekeeping to avoid 
       invalid memory references if the array was shifted. */
    Alert *alert = &rec->alerts[rec->count];
    memset(alert, 0, sizeof(Alert));
    
    alert->text = decoded_text;
    alert->text_len = new_text_len;
    alert->encrypted_key = base64_decode(base64_encrypted_key, &alert->encrypted_key_len);
    alert->iv = base64_decode(base64_iv, &alert->iv_len);
    
    /* Decode and store GCM Authentication Tag */
    size_t tag_len_actual;
    unsigned char *tag_raw = base64_decode(base64_tag, &tag_len_actual);
    if (tag_raw && tag_len_actual == GCM_TAG_LEN) {
        memcpy(alert->tag, tag_raw, GCM_TAG_LEN);
    }
    free(tag_raw);

    /* --- IDENTITY ASSIGNMENT --- 
       Replicated alerts preserve their original ID. Local alerts generate a new Snowflake ID. */
    if (forced_id > 0) {
        alert->id = forced_id;
        alert->create_at = forced_create_at;
    } else {
        alert->id = generate_snowflake_id();
        alert->create_at = now;
    }

    /* Log in the replication ring to allow other peers to SYNC this new entry */
    add_to_repl_ring(alert->id, pubkey_hash);

    alert->unlock_at = unlock_at;
    alert->expire_at = expire_at;
    alert->active = 1;

    /* --- PERSISTENCE --- */
    if (use_disk_db) {
        if (alert_db_save_alert(rec, alert) != 0) {
            log_event("ERROR", client_fd, client_ip, client_port, "Failed to persist alert via mmap");
        }
    } else {
        alert->is_mmaped = false;
    }

    rec->count++;
    
    log_event("DEBUG", client_fd, client_ip, client_port, 
              "Alert %" PRIu64 " added successfully [Recipient: %.12s...]", 
              alert->id, base64_text);

    return 0; /* New alert successfully committed to memory/disk */
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
                    time_t now = time(NULL);
                    bool is_locked = (new_alert->unlock_at > now);
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

void send_current_alerts(int sub_index, int mode, const char *pubkey_hash_b64_filter, int count) {
    time_t now = time(NULL);
    for (int r = 0; r < recipient_count; r++) {
        Recipient *rec = &recipients[r];
        char *pubkey_hash_b64 = base64_encode(rec->hash, PUBKEY_HASH_LEN);
        if (!pubkey_hash_b64) continue;

        if (pubkey_hash_b64_filter && strlen(pubkey_hash_b64_filter) > 0) {
            if (strcmp(pubkey_hash_b64, pubkey_hash_b64_filter) != 0) {
                free(pubkey_hash_b64);
                continue;
            }
        }

        clean_expired_alerts(rec);
 
        if (mode == MODE_LAST || mode == MODE_SINGLE) {
            qsort(rec->alerts, rec->count, sizeof(Alert), alert_cmp_desc);
        }

        int limit = (mode == MODE_LAST) ? count : rec->count;
        int sent_count = 0;

        for (int i = 0; i < rec->count && sent_count < limit; i++) {
            Alert *a = &rec->alerts[i];
            if (!a->active || a->expire_at <= now) continue;

            bool is_locked = (a->unlock_at > now);
            bool send_it = false;

            if (mode == MODE_ALL || mode == MODE_LAST) send_it = true;
            else if (mode == MODE_LIVE || mode == MODE_SINGLE) send_it = !is_locked;
            else if (mode == MODE_LOCK) send_it = is_locked;

            if (send_it) {
                char *bt = base64_encode(a->text, a->text_len);
                char *bk = base64_encode(a->encrypted_key, a->encrypted_key_len);
                char *bi = base64_encode(a->iv, a->iv_len);
                char *bg = base64_encode(a->tag, GCM_TAG_LEN);

                if (bt && bk && bi && bg) {
                    size_t resp_len = 2048 + strlen(bt) + strlen(bk) + strlen(bi) + strlen(bg);
                    char *resp = malloc(resp_len);
                    if (!resp) {
                         free(bt); free(bk); free(bi); free(bg);
                        continue;
                    }
                    
                    int l = snprintf(resp, resp_len, "ALERT|%s|%" PRIu64 "|%ld|%ld|%s|%s|%s|%s ",
                                     pubkey_hash_b64, a->id, (long)a->unlock_at, (long)a->expire_at, 
                                     bt, bk, bi, bg);
                    if (l > 0) enqueue_message(sub_index, resp, l);
                    free(resp);
                }
                free(bt); free(bk); free(bi); free(bg);
                sent_count++;
            }
        }
        free(pubkey_hash_b64); 
    }
    if (mode == MODE_LAST) {
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

/*
 * Sends a new alert to all connected and authorized peers. 
 */
void broadcast_replication(const unsigned char *pubkey_hash, Alert *alert, int exclude_fd) {
    char *ph_b64 = base64_encode(pubkey_hash, PUBKEY_HASH_LEN);
    char *bt = base64_encode(alert->text, alert->text_len);
    char *bk = base64_encode(alert->encrypted_key, alert->encrypted_key_len);
    char *bi = base64_encode(alert->iv, alert->iv_len);
    char *bg = base64_encode(alert->tag, GCM_TAG_LEN);

    if (!ph_b64 || !bt || !bk || !bi || !bg) {
        free(ph_b64); free(bt); free(bk); free(bi); free(bg);
        return;
    }

    /* We use dynamic memory for replication messages  */
    size_t msg_capacity = max_message_size + 2048; 
    char *repl_msg = malloc(msg_capacity);
    if (!repl_msg) {
        free(ph_b64); free(bt); free(bk); free(bi); free(bg);
        return;
    }

    int len = snprintf(repl_msg, msg_capacity, "REPL|%" PRIu64 "|%ld|%ld|%ld|%s|%s|%s|%s|%s",
                       alert->id, (long)alert->create_at, (long)alert->unlock_at, (long)alert->expire_at,
                       ph_b64, bt, bk, bi, bg);

    if (len > 0) {
        for (int i = 0; i < max_clients; i++) {
            /* We only send to authorized PIRAMs and do not send back to the sender */
            if (client_sockets[i] > 0 && 
                subscribers[i].type == SUB_TYPE_PEER && 
                subscribers[i].auth_state == AUTH_OK &&
                client_sockets[i] != exclude_fd) {
                
                enqueue_message(i, repl_msg, (size_t)len);
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
    uint64_t max_id = 0;
    for (int r = 0; r < recipient_count; r++) {
        for (int i = 0; i < recipients[r].count; i++) {
            if (recipients[r].alerts[i].id > max_id) {
                max_id = recipients[r].alerts[i].id;
            }
        }
    }
    return max_id;
}

/*
 * Sends a specific alert to a specific peer.
 * (Move the logic from `broadcast_replication` to a separate function)
 */
void send_alert_to_peer(int sub_index, const unsigned char *pubkey_hash, Alert *alert) {
    char *ph_b64 = base64_encode(pubkey_hash, PUBKEY_HASH_LEN);
    char *bt = base64_encode(alert->text, alert->text_len);
    char *bk = base64_encode(alert->encrypted_key, alert->encrypted_key_len);
    char *bi = base64_encode(alert->iv, alert->iv_len);
    char *bg = base64_encode(alert->tag, GCM_TAG_LEN);

    if (!ph_b64 || !bt || !bk || !bi || !bg) {
        free(ph_b64); free(bt); free(bk); free(bi); free(bg);
        return;
    }

    size_t msg_capacity = max_message_size + 2048;
    char *repl_msg = malloc(msg_capacity);
    if (repl_msg) {
        int len = snprintf(repl_msg, msg_capacity, "REPL|%" PRIu64 "|%ld|%ld|%ld|%s|%s|%s|%s|%s",
                           alert->id, (long)alert->create_at, (long)alert->unlock_at, (long)alert->expire_at,
                           ph_b64, bt, bk, bi, bg);
        if (len > 0) {
            enqueue_message(sub_index, repl_msg, (size_t)len);
        }
        free(repl_msg);
    }
    free(ph_b64); free(bt); free(bk); free(bi); free(bg);
}
