/* BSD 3-Clause License
Copyright (c) 2025, Alexander Shcheglov
All rights reserved. */
#include "config.h"
#include "gorgona_utils.h"
#include "alert_db.h"
#include "snowflake.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdarg.h>

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

void log_event(const char *level, int fd, const char *ip, int port, const char *fmt, ...) {
    if (!log_file) return;

    /* Check if log rotation is needed */
    rotate_log();

    char time_str[32];
    get_utc_time_str(time_str, sizeof(time_str));

    /* Print header: [Time] [Level] [fd] [IP:Port] */
    if (ip != NULL && port > 0) {
        fprintf(log_file, "%s [%s] [fd:%d] [%s:%d] ", time_str, level, fd, ip, port);
    } else if (fd > 0) {
        fprintf(log_file, "%s [%s] [fd:%d] ", time_str, level, fd);
    } else {
        fprintf(log_file, "%s [%s] [SERVER] ", time_str, level);
    }

    /* Print the actual message using variadic arguments */
    va_list args;
    va_start(args, fmt);
    vfprintf(log_file, fmt, args);
    va_end(args);

    fprintf(log_file, "\n");
    fflush(log_file);
}

void get_utc_time_str(char *buffer, size_t buffer_size) {
    time_t now = time(NULL);
    struct tm *utc_time = gmtime(&now);
    strftime(buffer, buffer_size, "[%Y-%m-%d %H:%M:%S UTC]", utc_time);
}

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
    rec->fd = -1; /* Важно: инициализируем -1, а не 0 */
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

    /* Запускаем вакуум только по порогу */
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

    /* Рассчитываем порог на основе конфига */
    int waste_limit = (max_alerts * vacuum_threshold) / 100;
    
    /* Защита: вакуум сработает в любом случае, если мусора слишком много (> 50000 записей) 
       или если он превысил заданный процент */
    if (use_disk_db && (rec->waste_count >= waste_limit || rec->waste_count > 50000)) {
        if (verbose) {
            fprintf(stderr, "Vacuum trigger: waste=%d (limit=%d%% of %d)\n", 
                    rec->waste_count, vacuum_threshold, max_alerts);
        }
        alert_db_sync(rec);
        rec->waste_count = 0;
    }
}

void add_alert(const unsigned char *pubkey_hash, time_t unlock_at, time_t expire_at,
               char *base64_text, char *base64_encrypted_key, char *base64_iv, char *base64_tag, int client_fd) {
    Recipient *rec = find_recipient(pubkey_hash);
    if (!rec) rec = add_recipient(pubkey_hash);
    if (!rec) return;

    clean_expired_alerts(rec);

    if (rec->count >= max_alerts) remove_oldest_alert(rec);

    Alert *alert = &rec->alerts[rec->count];
    memset(alert, 0, sizeof(Alert));
    
    alert->text = base64_decode(base64_text, &alert->text_len);
    alert->encrypted_key = base64_decode(base64_encrypted_key, &alert->encrypted_key_len);
    alert->iv = base64_decode(base64_iv, &alert->iv_len);
    
    size_t tag_len;
    unsigned char *tag_raw = base64_decode(base64_tag, &tag_len);
    if (tag_raw && tag_len == GCM_TAG_LEN) memcpy(alert->tag, tag_raw, GCM_TAG_LEN);
    free(tag_raw);

    alert->create_at = time(NULL);
    alert->unlock_at = unlock_at;
    alert->expire_at = expire_at;
    alert->id = generate_snowflake_id();
    alert->active = 1;

    if (use_disk_db) {
        if (alert_db_save_alert(rec, alert) != 0) {
            fprintf(stderr, "Failed to save alert via mmap\n");
        }
    } else {
        alert->is_mmaped = false;
    }
    rec->count++;
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
