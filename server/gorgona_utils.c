#include "gorgona_utils.h"
#include "alert_db.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <inttypes.h>

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
size_t max_message_size = DEFAULT_MAX_MESSAGE_SIZE;
int use_disk_db = 0;

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
void read_config(int *port, int *max_alerts, int *max_clients, size_t *max_message_size, int *use_disk_db) {
    *port = DEFAULT_SERVER_PORT;
    *max_alerts = DEFAULT_MAX_ALERTS;
    *max_clients = MAX_CLIENTS;
    *max_message_size = DEFAULT_MAX_MESSAGE_SIZE;
    *use_disk_db = 0; // По умолчанию false

    FILE *conf_fp = fopen("/etc/gorgona/gorgonad.conf", "r");
    if (!conf_fp) {
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), conf_fp)) {
        if (strstr(line, "[server]")) continue;
        char *key = strtok(line, " =");
        char *value = strtok(NULL, " =");
        if (value) value[strcspn(value, "\n")] = '\0';
        if (key) {
            trim_string(key);
            trim_string(value);
            if (strcmp(key, "port") == 0) {
                *port = atoi(value);
            } else if (strcmp(key, "MAX_ALERTS") == 0) {
                *max_alerts = atoi(value);
            } else if (strcmp(key, "MAX_CLIENTS") == 0) {
                *max_clients = atoi(value);
            } else if (strcmp(key, "max_message_size") == 0) {
                *max_message_size = atol(value);
            } else if (strcmp(key, "use_disk_db") == 0) {
                *use_disk_db = (strcmp(value, "true") == 0 || strcmp(value, "1") == 0);
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
    if (use_disk_db) { // Условно синхронизируем
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

    clean_expired_alerts(rec); // Уже включает sync при необходимости

    if (rec->count >= max_alerts) {
        remove_oldest_alert(rec); // Уже включает sync при необходимости
    }

    if (rec->count >= max_alerts) {
        char *error_msg = "Error: Failed to add alert, limit reached even after cleanup";
        uint32_t error_len_net = htonl(strlen(error_msg));
        send(client_fd, &error_len_net, sizeof(uint32_t), 0);
        send(client_fd, error_msg, strlen(error_msg), 0);
        return;
    }

    Alert *alert = &rec->alerts[rec->count];
    alert->text = base64_decode(base64_text, &alert->text_len);
    if (!alert->text) {
        char *error_msg = "Error: Failed to decode base64_text";
        uint32_t error_len_net = htonl(strlen(error_msg));
        send(client_fd, &error_len_net, sizeof(uint32_t), 0);
        send(client_fd, error_msg, strlen(error_msg), 0);
        return;
    }
    alert->encrypted_key = base64_decode(base64_encrypted_key, &alert->encrypted_key_len);
    if (!alert->encrypted_key) {
        char *error_msg = "Error: Failed to decode base64_encrypted_key";
        uint32_t error_len_net = htonl(strlen(error_msg));
        send(client_fd, &error_len_net, sizeof(uint32_t), 0);
        send(client_fd, error_msg, strlen(error_msg), 0);
        free(alert->text);
        return;
    }
    alert->iv = base64_decode(base64_iv, &alert->iv_len);
    if (!alert->iv) {
        char *error_msg = "Error: Failed to decode base64_iv";
        uint32_t error_len_net = htonl(strlen(error_msg));
        send(client_fd, &error_len_net, sizeof(uint32_t), 0);
        send(client_fd, error_msg, strlen(error_msg), 0);
        free(alert->text);
        free(alert->encrypted_key);
        return;
    }
    size_t decoded_tag_len;
    unsigned char *decoded_tag = base64_decode(base64_tag, &decoded_tag_len);
    if (!decoded_tag || decoded_tag_len != GCM_TAG_LEN) {
        char *error_msg = "Error: Failed to decode base64_tag or invalid tag length";
        uint32_t error_len_net = htonl(strlen(error_msg));
        send(client_fd, &error_len_net, sizeof(uint32_t), 0);
        send(client_fd, error_msg, strlen(error_msg), 0);
        free(decoded_tag);
        free(alert->text);
        free(alert->encrypted_key);
        free(alert->iv);
        return;
    }
    memcpy(alert->tag, decoded_tag, GCM_TAG_LEN); // Копируем декодированный тег в массив tag
    free(decoded_tag); // Освобождаем временный буфер

    alert->create_at = time(NULL);
    alert->id = generate_snowflake_id();
    alert->unlock_at = unlock_at;
    alert->expire_at = expire_at;
    alert->active = 1;
    rec->count++;

    if (use_disk_db && alert_db_save_alert(rec, alert) != 0) { // Условно сохраняем
        fprintf(stderr, "Failed to save alert to database\n");
        free_alert(alert);
        rec->count--;
        char *error_msg = "Error: Failed to save alert to database";
        uint32_t error_len_net = htonl(strlen(error_msg));
        send(client_fd, &error_len_net, sizeof(uint32_t), 0);
        send(client_fd, error_msg, strlen(error_msg), 0);
        return;
    }
/*     notify_subscribers(pubkey_hash, alert); */
}

/* Notifies subscribers about a new alert */
void notify_subscribers(const unsigned char *pubkey_hash, Alert *new_alert) {
    time_t now = time(NULL);
    if (new_alert->expire_at <= now) return;
    char *pubkey_hash_b64 = base64_encode(pubkey_hash, PUBKEY_HASH_LEN);
    if (!pubkey_hash_b64) return;

    for (int i = 0; i < max_clients; i++) {
        if (subscribers[i].sock > 0 && subscribers[i].mode != 0) {
            if (subscribers[i].pubkey_hash[0] != '\0' && strcmp(subscribers[i].pubkey_hash, pubkey_hash_b64) != 0) continue;
            bool send_it = false;
            if (subscribers[i].mode == MODE_ALL || subscribers[i].mode == MODE_SINGLE) send_it = true;
            else if (subscribers[i].mode == MODE_LIVE) send_it = (new_alert->unlock_at <= now);
            else if (subscribers[i].mode == MODE_LOCK) send_it = (new_alert->unlock_at > now);
            else if (subscribers[i].mode == MODE_NEW) {
                send_it = (new_alert->create_at >= subscribers[i].connect_time);
            }
            if (send_it) {
                char *base64_text = base64_encode(new_alert->text, new_alert->text_len);
                char *base64_encrypted_key = base64_encode(new_alert->encrypted_key, new_alert->encrypted_key_len);
                char *base64_iv = base64_encode(new_alert->iv, new_alert->iv_len);
                char *base64_tag = base64_encode(new_alert->tag, GCM_TAG_LEN);

                if (base64_text && base64_encrypted_key && base64_iv && base64_tag) {
                    size_t needed_len = strlen("ALERT|") + strlen(pubkey_hash_b64) + 4*20 + strlen(base64_text) + strlen(base64_encrypted_key) + strlen(base64_iv) + strlen(base64_tag) + 8;
                    char *response = malloc(needed_len);
                    if (!response) {
                        free(base64_text);
                        free(base64_encrypted_key);
                        free(base64_iv);
                        free(base64_tag);
                        continue;
                    }
                    // REPLACE START: Исправляем формат для id
                    int len = snprintf(response, needed_len, "ALERT|%s|%" PRIu64 "|%ld|%ld|%s|%s|%s|%s",
                                       pubkey_hash_b64, new_alert->id, new_alert->unlock_at, new_alert->expire_at,
                                       base64_text, base64_encrypted_key, base64_iv, base64_tag);
                    // REPLACE END
                    free(base64_text);
                    free(base64_encrypted_key);
                    free(base64_iv);
                    free(base64_tag);
                    if (len > 0 && (size_t)len < needed_len) {
                        uint32_t len_net = htonl(len);
                        if (send(subscribers[i].sock, &len_net, sizeof(uint32_t), 0) != sizeof(uint32_t) ||
                            send(subscribers[i].sock, response, len, 0) != len) {
                            if (verbose) {
                                char time_str[32];
                                get_utc_time_str(time_str, sizeof(time_str));
                                fprintf(log_file, "%s Failed to send ALERT to socket %d: %s\n", time_str, subscribers[i].sock, strerror(errno));
                                fflush(log_file);
                            }
                            close(subscribers[i].sock);
                            client_sockets[i] = 0;
                            subscribers[i].sock = 0;
                            subscribers[i].mode = 0;
                            subscribers[i].pubkey_hash[0] = '\0';
                        } else if (verbose) {
                            char time_str[32];
                            get_utc_time_str(time_str, sizeof(time_str));
                            fprintf(log_file, "%s Sent ALERT to socket %d\n", time_str, subscribers[i].sock);
                            fflush(log_file);
                        }
                    }
                    free(response);
                }
            }
        }
    }
    free(pubkey_hash_b64);
}

/* Comparator for sorting alerts by id ascending */
int alert_cmp_asc(const void *a, const void *b) {
    uint64_t id_a = ((Alert *)a)->id;
    uint64_t id_b = ((Alert *)b)->id;
    return (id_a > id_b) - (id_a < id_b);
}

/* Comparator for sorting alerts by id descending */
int alert_cmp_desc(const void *a, const void *b) {
    uint64_t id_a = ((Alert *)a)->id;
    uint64_t id_b = ((Alert *)b)->id;
    return (id_b > id_a) - (id_b < id_a);
}

/* Sends current alerts to a subscriber based on mode */
void send_current_alerts(int sd, int mode, const char *pubkey_hash_b64_filter, int count) {
    time_t now = time(NULL);
    if (verbose) {
        fprintf(stderr, "=== DEBUG send_current_alerts ===\n");
        fprintf(stderr, "mode: %d, filter: %s, count: %d\n", 
                mode, pubkey_hash_b64_filter ? pubkey_hash_b64_filter : "NULL", count);
        fprintf(stderr, "recipient_count: %d\n", recipient_count);
    }   
    if (mode == MODE_LAST) {
        Recipient *target_rec = NULL;
        for (int r = 0; r < recipient_count; r++) {
            Recipient *rec = &recipients[r];
            if (verbose) {
                fprintf(stderr, "Checking recipient %d: alerts count=%d\n", r, rec->count);
            }
            char *pubkey_hash_b64 = base64_encode(rec->hash, PUBKEY_HASH_LEN);
            if (!pubkey_hash_b64) {
                continue;
            }
            if (verbose)  {
                fprintf(stderr, "Recipient %d hash: %s\n", r, pubkey_hash_b64);
            }
            if (pubkey_hash_b64_filter && strcmp(pubkey_hash_b64, pubkey_hash_b64_filter) != 0) {
                free(pubkey_hash_b64);
                continue;
            }
            free(pubkey_hash_b64);
            target_rec = rec;
            break;
        }

        if (!target_rec) {
            if (verbose) {
                fprintf(stderr, "ERROR: No target recipient found for filter: %s\n", pubkey_hash_b64_filter ? pubkey_hash_b64_filter : "NULL");
            }
            return;
        }

        if (verbose) {
            fprintf(stderr, "Target recipient has %d alerts\n", target_rec->count);
            for (int j = 0; j < target_rec->count; j++) {
                Alert *a = &target_rec->alerts[j];
                fprintf(stderr, "Alert %d: id=%" PRIu64 ", active=%d, unlock_at=%ld, expire_at=%ld, now=%ld\n",
                        j, a->id, a->active, a->unlock_at, a->expire_at, now);
            }
        }
        clean_expired_alerts(target_rec);
        if (verbose)  {
            fprintf(stderr, "After clean_expired_alerts: %d alerts\n", target_rec->count);
        }
        if (target_rec->count == 0) {
            fprintf(stderr, "No alerts after cleanup\n");
            return;
        }

        /* Sort by id descending to get the most recent messages */
        qsort(target_rec->alerts, target_rec->count, sizeof(Alert), alert_cmp_desc);

        /* Create a temporary array for the most recent 'count' messages */
        int messages_to_send = (target_rec->count < count) ? target_rec->count : count;
        Alert *recent_alerts = malloc(messages_to_send * sizeof(Alert));
        if (!recent_alerts) {
            fprintf(stderr, "Failed to allocate memory for recent_alerts\n");
            return;
        }

        /* Copy the most recent messages (already sorted descending) */
        int sent = 0;
        for (int j = 0; j < target_rec->count && sent < messages_to_send; j++) {
            Alert *a = &target_rec->alerts[j];
            if (!a->active || a->expire_at <= now) {
                fprintf(stderr, "Skipping alert %" PRIu64 ": active=%d, expire_at=%ld, now=%ld\n",
                        a->id, a->active, a->expire_at, now);
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
                            uint32_t len_net = htonl(len);
                            send(sd, &len_net, sizeof(uint32_t), 0);
                            send(sd, response, len, 0);
                            if (verbose)  {
                                fprintf(stderr, "Successfully sent alert %" PRIu64 " to client\n", a->id);
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
        } else {
            fprintf(stderr, "No messages to send after filtering\n");
        }
        free(recent_alerts);
        return;
    }

    for (int r = 0; r < recipient_count; r++) {
        Recipient *rec = &recipients[r];
        clean_expired_alerts(rec);
        if (rec->count > 0) {
            qsort(rec->alerts, rec->count, sizeof(Alert), alert_cmp_asc);
        }

        char *pubkey_hash_b64 = base64_encode(rec->hash, PUBKEY_HASH_LEN);
        if (!pubkey_hash_b64) continue;

        if (pubkey_hash_b64_filter && strcmp(pubkey_hash_b64, pubkey_hash_b64_filter) != 0) {
            free(pubkey_hash_b64);
            continue;
        }

        for (int j = 0; j < rec->count; j++) {
            Alert *a = &rec->alerts[j];
            if (!a->active) continue;

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
                        return;
                    }
                    // REPLACE START: Исправляем формат для id
                    int len = snprintf(response, needed_len, "ALERT|%s|%" PRIu64 "|%ld|%ld|%s|%s|%s|%s",
                                       pubkey_hash_b64, a->id, a->unlock_at, a->expire_at,
                                       base64_text, base64_encrypted_key, base64_iv, base64_tag);
                    // REPLACE END
                    free(base64_text);
                    free(base64_encrypted_key);
                    free(base64_iv);
                    free(base64_tag);
                    if (len > 0 && (size_t)len < needed_len) {
                        uint32_t len_net = htonl(len);
                        send(sd, &len_net, sizeof(uint32_t), 0);
                        send(sd, response, len, 0);
                    }
                    free(response);
                }
            }
        }
        free(pubkey_hash_b64);
    }
}

/* Helper: Rotate log if too large */
void rotate_log() {
    struct stat st;
    if (stat("gorgona.log", &st) == 0 && st.st_size > MAX_LOG_SIZE) {
        if (log_file) fclose(log_file);
        rename("gorgona.log", "gorgona.log.1");
        log_file = fopen("gorgona.log", "a");
        if (!log_file) {
            perror("Failed to open new gorgona.log after rotation");
        } else {
            fprintf(log_file, "[%ld] Log rotated\n", (long)time(NULL));
        }
    }
}

