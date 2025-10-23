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
#include <ctype.h>

/* Get current UTC time as string in format [YYYY-MM-DDThh:mm:ss UTC] */
void get_utc_time_str(char *buffer, size_t buffer_size) {
    time_t now = time(NULL);
    struct tm *utc_time = gmtime(&now);
    strftime(buffer, buffer_size, "[%Y-%m-%d %H:%M:%S UTC]", utc_time);
}

/* Global variables */
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

/* Function to check for HTTP request */
int is_http_request(const char *buffer) {
    if (strncmp(buffer, "GET ", 4) == 0 ||
        strncmp(buffer, "HEAD ", 5) == 0 ||
        strncmp(buffer, "POST ", 5) == 0 ||
        strncmp(buffer, "OPTIONS ", 8) == 0 ||
        strncmp(buffer, "CONNECT ", 8) == 0 ||
        strncmp(buffer, "PUT ", 4) == 0 ||
        strncmp(buffer, "DELETE ", 7) == 0 ||
        strncmp(buffer, "TRACE ", 6) == 0 ||
        strncmp(buffer, "PATCH ", 6) == 0) {
        return 1;
    }
    return 0;
}

/* Removes trailing spaces, \n, \r from a string */
void trim_string(char *str) {
    size_t len = strlen(str);
    while (len > 0 && (str[len - 1] == ' ' || str[len - 1] == '\n' || str[len - 1] == '\r')) {
        str[len - 1] = '\0';
        len--;
    }
}

/* Reads configuration from gorgonad.conf */
void read_config(int *port, int *max_alerts, int *max_clients, size_t *max_log_size, char *log_level,
                 size_t *max_message_size, int *use_disk_db) {
    /* Set default values */
    *port = DEFAULT_SERVER_PORT;
    *max_alerts = DEFAULT_MAX_ALERTS;
    *max_clients = MAX_CLIENTS;
    *max_log_size = DEFAULT_MAX_LOG_SIZE;
    *max_message_size = DEFAULT_MAX_MESSAGE_SIZE;
    *use_disk_db = 0; /* false by default */
    if (log_level) {
          snprintf(log_level, 32, "%s", DEFAULT_LOG_LEVEL);
    }
    /* Open config file */
    FILE *conf_fp = fopen("/etc/gorgona/gorgonad.conf", "r");
    if (!conf_fp) {
        return;
    }
    char line[256];
    while (fgets(line, sizeof(line), conf_fp)) {
        /* Remove inline comments (everything after '#') */
        char *comment = strchr(line, '#');
        if (comment) {
            *comment = '\0';
        }
        /* Skip leading whitespace */
        char *start = line;
        while (*start && isspace((unsigned char)*start)) {
            start++;
        }
        /* Skip empty or whitespace-only lines */
        if (*start == '\0') {
            continue;
        }
        /* Skip section headers like [server] */
        if (*start == '[') {
            continue;
        }
        /* Tokenize key and value */
        char *key = strtok(start, " =\t");
        char *value = strtok(NULL, " =\t");
        if (!key || !value) {
            continue;
        }
        /* Remove trailing newline from value */
        value[strcspn(value, "\r\n")] = '\0';
        /* Trim whitespace from both ends */
        trim_string(key);
        trim_string(value);
        /* Parse known configuration keys */
        if (strcmp(key, "port") == 0) {
            *port = atoi(value);
        } else if (strcmp(key, "max_alerts") == 0) {
            *max_alerts = atoi(value);
        } else if (strcmp(key, "max_clients") == 0) {
            *max_clients = atoi(value);
        } else if (strcmp(key, "max_log_size") == 0) {
            *max_log_size = (size_t)atoi(value);
        } else if (strcmp(key, "max_message_size") == 0) {
            long mb = atol(value);
            *max_message_size = (size_t)(mb * 1024 * 1024);
        } else if (strcmp(key, "use_disk_db") == 0) {
            *use_disk_db = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
        } else if (strcmp(key, "log_level") == 0) {
            if (log_level) {
                strncpy(log_level, value, 31);
                log_level[31] = '\0';
            }
        }
    }

    fclose(conf_fp);
}

/* Formats a timestamp into a string */
void format_time(time_t timestamp, char *buffer, size_t buffer_size) {
    struct tm *tm_info = gmtime(&timestamp);
    strftime(buffer, buffer_size, "%Y-%m-%d %H:%M:%S UTC", tm_info);
}

/* Frees resources of an alert */
void free_alert(Alert *alert) {
    free(alert->text);
    free(alert->encrypted_key);
    free(alert->iv);
    alert->text = NULL;
    alert->encrypted_key = NULL;
    alert->iv = NULL;
    alert->active = 0;
}

/* Finds a recipient by hash */
Recipient *find_recipient(const unsigned char *hash) {
    for (int i = 0; i < recipient_count; i++) {
        if (memcmp(recipients[i].hash, hash, PUBKEY_HASH_LEN) == 0) {
            return &recipients[i];
        }
    }
    return NULL;
}

/* Adds a new recipient */
Recipient *add_recipient(const unsigned char *hash) {
    Recipient *existing = find_recipient(hash);
    if (existing) {
        return existing;
    }
    if (recipient_count >= recipient_capacity) {
        recipient_capacity += INITIAL_RECIPIENT_CAPACITY;
        recipients = realloc(recipients, sizeof(Recipient) * recipient_capacity);
        if (!recipients) {
            perror("Failed to allocate memory for recipients");
            exit(1);
        }
    }
    Recipient *rec = &recipients[recipient_count];
    memcpy(rec->hash, hash, PUBKEY_HASH_LEN);
    rec->count = 0;
    rec->capacity = max_alerts;
    rec->alerts = malloc(sizeof(Alert) * rec->capacity);
    if (!rec->alerts) {
        perror("Failed to allocate memory for alerts");
        exit(1);
    }
    recipient_count++;
    return rec;
}

/* Removes expired alerts for a recipient */
void clean_expired_alerts(Recipient *rec) {
    time_t now = time(NULL);
    int original_count = rec->count;
    for (int i = 0; i < rec->count; ) {
        if (rec->alerts[i].expire_at <= now && rec->alerts[i].active) {
            free_alert(&rec->alerts[i]);
            memmove(&rec->alerts[i], &rec->alerts[i + 1], sizeof(Alert) * (rec->count - i - 1));
            rec->count--;
        } else {
            i++;
        }
    }
    if (use_disk_db && rec->count < original_count) { // Условно синхронизируем
        if (alert_db_sync(rec) != 0) {
            fprintf(stderr, "Failed to sync after cleaning expired alerts\n");
        }
    }
}

/* Removes the oldest alert for a recipient */
void remove_oldest_alert(Recipient *rec) {
    if (rec->count == 0) return;
    int oldest = 0;
    uint64_t min_id = rec->alerts[0].id;
    for (int i = 1; i < rec->count; i++) {
        if (rec->alerts[i].id < min_id) {
            min_id = rec->alerts[i].id;
            oldest = i;
        }
    }
    free_alert(&rec->alerts[oldest]);
    memmove(&rec->alerts[oldest], &rec->alerts[oldest + 1], sizeof(Alert) * (rec->count - oldest - 1));
    rec->count--;
    if (use_disk_db) { 
        if (alert_db_sync(rec) != 0) {
            fprintf(stderr, "Failed to sync after removing oldest alert\n");
        }
    }
}

/* Adds a new alert for a recipient */
void add_alert(const unsigned char *pubkey_hash, time_t unlock_at, time_t expire_at,
               char *base64_text, char *base64_encrypted_key, char *base64_iv, char *base64_tag, int client_fd) {
    trim_string(base64_text);
    trim_string(base64_encrypted_key);
    trim_string(base64_iv);
    trim_string(base64_tag);

    Recipient *rec = find_recipient(pubkey_hash);
    if (!rec) {
        rec = add_recipient(pubkey_hash);
    }

    clean_expired_alerts(rec); /* already include sync if needed */

    if (rec->count >= max_alerts) {
        remove_oldest_alert(rec); /* already include sync if needed */
    }

    if (rec->count >= max_alerts) {
        char *error_msg = "Error: Failed to add alert, limit reached even after cleanup";
        uint32_t error_len_net = htonl(strlen(error_msg));
        send(client_fd, &error_len_net, sizeof(uint32_t), 0);
        send(client_fd, error_msg, strlen(error_msg), 0);
        return;
    }

    Alert *alert = &rec->alerts[rec->count];
    alert->text_len = 0;
    alert->text = base64_decode(base64_text, &alert->text_len);
    alert->encrypted_key_len = 0;
    alert->encrypted_key = base64_decode(base64_encrypted_key, &alert->encrypted_key_len);
    alert->iv_len = 0;
    alert->iv = base64_decode(base64_iv, &alert->iv_len);

    // Decode base64_tag into alert->tag (fixed-size array of GCM_TAG_LEN)
    size_t decoded_tag_len = 0;
    unsigned char *decoded_tag = base64_decode(base64_tag, &decoded_tag_len);
    if (!decoded_tag || decoded_tag_len != GCM_TAG_LEN) {
        free(decoded_tag);
        free_alert(alert);
        char *error_msg = "Error: Invalid base64 tag data";
        uint32_t error_len_net = htonl(strlen(error_msg));
        send(client_fd, &error_len_net, sizeof(uint32_t), 0);
        send(client_fd, error_msg, strlen(error_msg), 0);
        return;
    }
    memcpy(alert->tag, decoded_tag, GCM_TAG_LEN);
    free(decoded_tag);

    if (!alert->text || !alert->encrypted_key || !alert->iv) {
        free_alert(alert);
        char *error_msg = "Error: Invalid base64 data in alert";
        uint32_t error_len_net = htonl(strlen(error_msg));
        send(client_fd, &error_len_net, sizeof(uint32_t), 0);
        send(client_fd, error_msg, strlen(error_msg), 0);
        return;
    }

    alert->create_at = time(NULL);
    alert->unlock_at = unlock_at;
    alert->expire_at = expire_at;
    alert->id = generate_snowflake_id();
    alert->active = 1;

    rec->count++;

    if (use_disk_db) {
        if (alert_db_save_alert(rec, alert) != 0) {
            fprintf(stderr, "Failed to save alert to DB\n");
        }
    }
}

/* Notifies subscribers about a new alert */
void notify_subscribers(const unsigned char *pubkey_hash, Alert *new_alert) {
    if (!new_alert->active) return;

    time_t now = time(NULL);
    bool is_locked = (new_alert->unlock_at > now);

    char *pubkey_hash_b64 = base64_encode(pubkey_hash, PUBKEY_HASH_LEN);
    if (!pubkey_hash_b64) return;

    char *base64_text = base64_encode(new_alert->text, new_alert->text_len);
    char *base64_encrypted_key = base64_encode(new_alert->encrypted_key, new_alert->encrypted_key_len);
    char *base64_iv = base64_encode(new_alert->iv, new_alert->iv_len);
    char *base64_tag = base64_encode(new_alert->tag, GCM_TAG_LEN);

    if (!base64_text || !base64_encrypted_key || !base64_iv || !base64_tag) {
        free(pubkey_hash_b64);
        free(base64_text);
        free(base64_encrypted_key);
        free(base64_iv);
        free(base64_tag);
        return;
    }

    size_t needed_len = strlen("ALERT|") + strlen(pubkey_hash_b64) + 4*20 + strlen(base64_text) + strlen(base64_encrypted_key) + strlen(base64_iv) + strlen(base64_tag) + 8;
    char *response = malloc(needed_len);
    if (!response) {
        free(pubkey_hash_b64);
        free(base64_text);
        free(base64_encrypted_key);
        free(base64_iv);
        free(base64_tag);
        return;
    }
    int len = snprintf(response, needed_len, "ALERT|%s|%" PRIu64 "|%ld|%ld|%s|%s|%s|%s",
                       pubkey_hash_b64, new_alert->id, new_alert->unlock_at, new_alert->expire_at,
                       base64_text, base64_encrypted_key, base64_iv, base64_tag);

    free(base64_text);
    free(base64_encrypted_key);
    free(base64_iv);
    free(base64_tag);
    if (len <= 0 || (size_t)len >= needed_len) {
        free(pubkey_hash_b64);
        free(response);
        return;
    }

    for (int j = 0; j < max_clients; j++) {
        if (client_sockets[j] > 0 && subscribers[j].mode != 0) {
            bool match_hash = (subscribers[j].pubkey_hash[0] == '\0' || strcmp(subscribers[j].pubkey_hash, pubkey_hash_b64) == 0);
            bool send_it = false;
            if (subscribers[j].mode == MODE_LIVE && !is_locked) send_it = true;
            else if (subscribers[j].mode == MODE_ALL) send_it = true;
            else if (subscribers[j].mode == MODE_LOCK && is_locked) send_it = true;
            else if (subscribers[j].mode == MODE_SINGLE && !is_locked) send_it = true;
            else if (subscribers[j].mode == MODE_NEW) send_it = true;

            if (match_hash && send_it) {
                enqueue_message(j, response, len);
            }
        }
    }

    free(pubkey_hash_b64);
    free(response);
}

/* Sends current alerts to a subscriber */
void send_current_alerts(int sub_index, int mode, const char *pubkey_hash_b64_filter, int count) {
    time_t now = time(NULL);

    if (mode == MODE_LAST || mode == MODE_SINGLE) {
        if (!pubkey_hash_b64_filter || strlen(pubkey_hash_b64_filter) == 0) {
            subscribers[sub_index].close_after_send = true; // Close if no valid filter
            return;
        }
        size_t hash_len;
        unsigned char *hash = base64_decode(pubkey_hash_b64_filter, &hash_len);
        if (!hash || hash_len != PUBKEY_HASH_LEN) {
            free(hash);
            subscribers[sub_index].close_after_send = true; // Close on invalid hash
            return;
        }
        Recipient *target_rec = find_recipient(hash);
        free(hash);
        if (!target_rec) {
            subscribers[sub_index].close_after_send = true; // Close if no recipient
            return;
        }

        clean_expired_alerts(target_rec);

        if (target_rec->count == 0) {
            subscribers[sub_index].close_after_send = true; // Close if no alerts
            return;
        }

        qsort(target_rec->alerts, target_rec->count, sizeof(Alert), alert_cmp_desc);

        int messages_to_send = (mode == MODE_LAST) ? count : target_rec->count;
        messages_to_send = (messages_to_send > target_rec->count) ? target_rec->count : messages_to_send;

        Alert *recent_alerts = malloc(sizeof(Alert) * messages_to_send);
        if (!recent_alerts) {
            fprintf(stderr, "Failed to allocate memory for recent_alerts\n");
            subscribers[sub_index].close_after_send = true; // Close on allocation failure
            return;
        }

        /* Copy the most recent messages (already sorted descending) */
        int sent = 0;
        for (int j = 0; j < target_rec->count && sent < messages_to_send; j++) {
            Alert *a = &target_rec->alerts[j];
            if (!a->active || a->expire_at <= now) {
                if (verbose) {
                    fprintf(stderr, "Skipping alert %" PRIu64 ": active=%d, expire_at=%ld, now=%ld\n",
                            a->id, a->active, a->expire_at, now);
                }
                continue;
            }
            recent_alerts[sent] = *a;
            if (verbose) {
                fprintf(stderr, "Including alert %" PRIu64 " in recent_alerts[%d]\n", a->id, sent);
            }
            sent++;
        }
        messages_to_send = sent;

        if (messages_to_send > 0) {
            /* Sort the selected messages by id ascending for sending */
            qsort(recent_alerts, messages_to_send, sizeof(Alert), alert_cmp_asc);
            if (verbose) {
                fprintf(stderr, "Sending %d messages in ascending order:\n", messages_to_send);
            }
            for (int j = 0; j < messages_to_send; j++) {
                Alert *a = &recent_alerts[j];
                char *pubkey_hash_b64 = base64_encode(target_rec->hash, PUBKEY_HASH_LEN);
                if (!pubkey_hash_b64) {
                    fprintf(stderr, "Failed to encode hash for sending\n");
                    continue;
                }

                char *base64_text = base64_encode(a->text, a->text_len);
                char *base64_encrypted_key = base64_encode(a->encrypted_key, a->encrypted_key_len);
                char *base64_iv = base64_encode(a->iv, a->iv_len);
                char *base64_tag = base64_encode(a->tag, GCM_TAG_LEN);

                if (base64_text && base64_encrypted_key && base64_iv && base64_tag) {
                    size_t needed_len = strlen("ALERT|") + strlen(pubkey_hash_b64) + 4*20 + strlen(base64_text) + strlen(base64_encrypted_key) + strlen(base64_iv) + strlen(base64_tag) + 8;
                    char *response = malloc(needed_len);
                    if (response) {
                        int len = snprintf(response, needed_len, "ALERT|%s|%" PRIu64 "|%ld|%ld|%s|%s|%s|%s",
                                           pubkey_hash_b64, a->id, a->unlock_at, a->expire_at,
                                           base64_text, base64_encrypted_key, base64_iv, base64_tag);
                        if (len > 0 && (size_t)len < needed_len) {
                            enqueue_message(sub_index, response, len);
                            if (verbose) {
                                fprintf(stderr, "Successfully enqueued alert %" PRIu64 " to subscriber %d\n", a->id, sub_index);
                            }
                        } else {
                            fprintf(stderr, "Failed to format response for alert %" PRIu64 "\n", a->id);
                        }
                        free(response);
                    }
                } else {
                    fprintf(stderr, "Failed to base64 encode alert %" PRIu64 " data\n", a->id);
                }
                
                free(base64_text);
                free(base64_encrypted_key);
                free(base64_iv);
                free(base64_tag);
                free(pubkey_hash_b64);
            }
        }
        free(recent_alerts);
        if (mode == MODE_LAST) {
            subscribers[sub_index].close_after_send = true; // Ensure close after sending
        }
        return;
    }

    int messages_sent = 0; // Track messages sent for MODE_LAST without filter
    for (int r = 0; r < recipient_count; r++) {
        Recipient *rec = &recipients[r];
        clean_expired_alerts(rec);
        if (rec->count == 0) continue;

        qsort(rec->alerts, rec->count, sizeof(Alert), alert_cmp_desc);

        char *pubkey_hash_b64 = base64_encode(rec->hash, PUBKEY_HASH_LEN);
        if (!pubkey_hash_b64) continue;

        if (pubkey_hash_b64_filter && strcmp(pubkey_hash_b64, pubkey_hash_b64_filter) != 0) {
            free(pubkey_hash_b64);
            continue;
        }

        int messages_to_send = (mode == MODE_LAST) ? count : rec->count;
        messages_to_send = (messages_to_send > rec->count) ? rec->count : messages_to_send;

        Alert *recent_alerts = malloc(sizeof(Alert) * messages_to_send);
        if (!recent_alerts) {
            fprintf(stderr, "Failed to allocate memory for recent_alerts\n");
            free(pubkey_hash_b64);
            continue;
        }

        int sent = 0;
        for (int j = 0; j < rec->count && sent < messages_to_send; j++) {
            Alert *a = &rec->alerts[j];
            if (!a->active || a->expire_at <= now) continue;
            recent_alerts[sent] = *a;
            sent++;
        }
        messages_to_send = sent;

        if (messages_to_send > 0) {
            qsort(recent_alerts, messages_to_send, sizeof(Alert), alert_cmp_asc);
            for (int j = 0; j < messages_to_send; j++) {
                Alert *a = &recent_alerts[j];
                bool send_it = false;
                if (mode == MODE_ALL) send_it = true;
                else if (mode == MODE_LIVE || mode == MODE_SINGLE) send_it = (a->unlock_at <= now);
                else if (mode == MODE_LOCK) send_it = (a->unlock_at > now);

                if (send_it) {
                    char *base64_text = base64_encode(a->text, a->text_len);
                    char *base64_encrypted_key = base64_encode(a->encrypted_key, a->encrypted_key_len);
                    char *base64_iv = base64_encode(a->iv, a->iv_len);
                    char *base64_tag = base64_encode(a->tag, GCM_TAG_LEN);

                    if (base64_text && base64_encrypted_key && base64_iv && base64_tag) {
                        size_t needed_len = strlen("ALERT|") + strlen(pubkey_hash_b64) + 4*20 + strlen(base64_text) + strlen(base64_encrypted_key) + strlen(base64_iv) + strlen(base64_tag) + 8;
                        char *response = malloc(needed_len);
                        if (!response) {
                            free(base64_text);
                            free(base64_encrypted_key);
                            free(base64_iv);
                            free(base64_tag);
                            free(pubkey_hash_b64);
                            free(recent_alerts);
                            return;
                        }
                        int len = snprintf(response, needed_len, "ALERT|%s|%" PRIu64 "|%ld|%ld|%s|%s|%s|%s",
                                           pubkey_hash_b64, a->id, a->unlock_at, a->expire_at,
                                           base64_text, base64_encrypted_key, base64_iv, base64_tag);
                        free(base64_text);
                        free(base64_encrypted_key);
                        free(base64_iv);
                        free(base64_tag);
                        if (len > 0 && (size_t)len < needed_len) {
                            enqueue_message(sub_index, response, len);
                            messages_sent++; // Increment sent count
                        }
                        free(response);
                    }
                }
            }
        }
        free(recent_alerts);
        free(pubkey_hash_b64);
    }

    if (mode == MODE_LAST) {
        subscribers[sub_index].close_after_send = true; // Ensure close after sending all alerts
    }
}



void rotate_log() {
    time_t now = time(NULL);
    // Проверяем не чаще 1 раза в секунду
    if (now - last_rotation_check < 5) {
        return;
    }
    last_rotation_check = now;

    struct stat st;
    if (stat("gorgonad.log", &st) == 0 && st.st_size > max_log_size) {
        if (log_file) fclose(log_file);
        rename("gorgonad.log", "gorgonad.log.1");
        log_file = fopen("gorgonad.log", "a");
        if (!log_file) {
            perror("Failed to open new gorgonad.log after rotation");
        } else {
            fprintf(log_file, "[%ld] Log rotated\n", (long)now);
            fflush(log_file);
        }
    }
}

/* Comparator for sorting alerts ascending by ID */
int alert_cmp_asc(const void *a, const void *b) {
    const Alert *alert_a = a;
    const Alert *alert_b = b;
    if (alert_a->id < alert_b->id) return -1;
    if (alert_a->id > alert_b->id) return 1;
    return 0;
}

/* Comparator for sorting alerts descending by ID */
int alert_cmp_desc(const void *a, const void *b) {
    return alert_cmp_asc(b, a);
}
