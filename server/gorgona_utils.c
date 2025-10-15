#include "gorgona_utils.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <stdbool.h>

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
void read_config(int *port, int *max_alerts, int *max_clients, size_t *max_message_size) {
    *port = DEFAULT_SERVER_PORT;
    *max_alerts = DEFAULT_MAX_ALERTS;
    *max_clients = MAX_CLIENTS;
    *max_message_size = DEFAULT_MAX_MESSAGE_SIZE;

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
    for (int i = 0; i < rec->count; ) {
        if (rec->alerts[i].expire_at <= now && rec->alerts[i].active) {
            free_alert(&rec->alerts[i]);
            memmove(&rec->alerts[i], &rec->alerts[i + 1], sizeof(Alert) * (rec->count - i - 1));
            rec->count--;
        } else {
            i++;
        }
    }
}

/* Removes the oldest alert for a recipient */
void remove_oldest_alert(Recipient *rec) {
    if (rec->count == 0) return;
    int oldest = 0;
    time_t min_create = rec->alerts[0].create_at;
    for (int i = 1; i < rec->count; i++) {
        if (rec->alerts[i].create_at < min_create) {
            min_create = rec->alerts[i].create_at;
            oldest = i;
        }
    }
    free_alert(&rec->alerts[oldest]);
    memmove(&rec->alerts[oldest], &rec->alerts[oldest + 1], sizeof(Alert) * (rec->count - oldest - 1));
    rec->count--;
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

    clean_expired_alerts(rec);

    if (rec->count >= max_alerts) {
        remove_oldest_alert(rec);
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
    size_t tag_len;
    unsigned char *tag_dec = base64_decode(base64_tag, &tag_len);
    if (!tag_dec || tag_len != GCM_TAG_LEN) {
        char *error_msg = "Error: Failed to decode base64_tag or invalid size";
        uint32_t error_len_net = htonl(strlen(error_msg));
        send(client_fd, &error_len_net, sizeof(uint32_t), 0);
        send(client_fd, error_msg, strlen(error_msg), 0);
        free(alert->text);
        free(alert->encrypted_key);
        free(alert->iv);
        free(tag_dec);
        return;
    }
    memcpy(alert->tag, tag_dec, GCM_TAG_LEN);
    free(tag_dec);
    alert->create_at = time(NULL); // Set creation time on server
    alert->unlock_at = unlock_at;
    alert->expire_at = expire_at;
    alert->active = 1;
    rec->count++;
}

/* Comparator for sorting alerts by create_at */
int alert_cmp(const void *a, const void *b) {
    Alert *alert_a = (Alert *)a;
    Alert *alert_b = (Alert *)b;
    return (alert_a->create_at > alert_b->create_at) - (alert_a->create_at < alert_b->create_at);
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
                    size_t needed_len = strlen("ALERT|") + strlen(pubkey_hash_b64) + 3*20 + strlen(base64_text) + strlen(base64_encrypted_key) + strlen(base64_iv) + strlen(base64_tag) + 8;
                    char *response = malloc(needed_len);
                    if (!response) {
                        free(base64_text);
                        free(base64_encrypted_key);
                        free(base64_iv);
                        free(base64_tag);
                        continue;
                    }
                    int len = snprintf(response, needed_len, "ALERT|%s|%ld|%ld|%ld|%s|%s|%s|%s",
                                       pubkey_hash_b64, new_alert->create_at, new_alert->unlock_at, new_alert->expire_at,
                                       base64_text, base64_encrypted_key, base64_iv, base64_tag);
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

/* Comparator for sorting alerts by create_at descending */
int alert_cmp_desc(const void *a, const void *b) {
    Alert *alert_a = (Alert *)a;
    Alert *alert_b = (Alert *)b;
    return (alert_b->create_at > alert_a->create_at) - (alert_b->create_at < alert_a->create_at);  /* Descending order */
}

/* Comparator for sorting alerts by create_at ascending */
int alert_cmp_asc(const void *a, const void *b) {
    Alert *alert_a = (Alert *)a;
    Alert *alert_b = (Alert *)b;
    return (alert_a->create_at > alert_b->create_at) - (alert_a->create_at < alert_b->create_at);  /* Ascending order */
}

/* Sends current alerts to a subscriber based on mode */
void send_current_alerts(int sd, int mode, const char *pubkey_hash_b64_filter, int count) {
    time_t now = time(NULL);
    if (mode == MODE_LAST) {
        Recipient *target_rec = NULL;
        for (int r = 0; r < recipient_count; r++) {
            Recipient *rec = &recipients[r];
            clean_expired_alerts(rec);

            char *pubkey_hash_b64 = base64_encode(rec->hash, PUBKEY_HASH_LEN);
            if (!pubkey_hash_b64) continue;
            if (pubkey_hash_b64_filter && strcmp(pubkey_hash_b64, pubkey_hash_b64_filter) != 0) {
                free(pubkey_hash_b64);
                continue;
            }
            free(pubkey_hash_b64);

            target_rec = rec;
            break;  /* Found the target recipient (assuming hash uniqueness) */
        }

        if (!target_rec || target_rec->count == 0) {
            return;  /* No messages */
        }

        /* Sort by create_at descending to get the most recent messages */
        qsort(target_rec->alerts, target_rec->count, sizeof(Alert), alert_cmp_desc);

        /* Create a temporary array for the most recent 'count' messages */
        int messages_to_send = (target_rec->count < count) ? target_rec->count : count;
        Alert *recent_alerts = malloc(messages_to_send * sizeof(Alert));
        if (!recent_alerts) {
            return;  /* Memory allocation failed */
        }

        /* Copy the most recent messages (already sorted descending) */
        int sent = 0;
        for (int j = 0; j < target_rec->count && sent < messages_to_send; j++) {
            Alert *a = &target_rec->alerts[j];
            if (!a->active || a->expire_at <= now) continue;  /* Skip inactive/expired */
            recent_alerts[sent] = *a;  /* Copy the alert */
            sent++;
        }
        messages_to_send = sent;  /* Update with actual number of valid messages */

        /* Sort the selected messages by create_at ascending for sending */
        if (messages_to_send > 0) {
            qsort(recent_alerts, messages_to_send, sizeof(Alert), alert_cmp_asc);

            /* Send the messages in ascending order */
            for (int j = 0; j < messages_to_send; j++) {
                Alert *a = &recent_alerts[j];
                char *pubkey_hash_b64 = base64_encode(target_rec->hash, PUBKEY_HASH_LEN);
                if (!pubkey_hash_b64) continue;

                char *base64_text = base64_encode(a->text, a->text_len);
                char *base64_encrypted_key = base64_encode(a->encrypted_key, a->encrypted_key_len);
                char *base64_iv = base64_encode(a->iv, a->iv_len);
                char *base64_tag = base64_encode(a->tag, GCM_TAG_LEN);

                if (base64_text && base64_encrypted_key && base64_iv && base64_tag) {
                    size_t needed_len = strlen("ALERT|") + strlen(pubkey_hash_b64) + 3*20 + strlen(base64_text) + strlen(base64_encrypted_key) + strlen(base64_iv) + strlen(base64_tag) + 8;
                    char *response = malloc(needed_len);
                    if (response) {
                        int len = snprintf(response, needed_len, "ALERT|%s|%ld|%ld|%ld|%s|%s|%s|%s",
                                           pubkey_hash_b64, a->create_at, a->unlock_at, a->expire_at,
                                           base64_text, base64_encrypted_key, base64_iv, base64_tag);
                        if (len > 0 && (size_t)len < needed_len) {
                            uint32_t len_net = htonl(len);
                            send(sd, &len_net, sizeof(uint32_t), 0);
                            send(sd, response, len, 0);
                        }
                        free(response);
                    }
                }
                free(base64_text);
                free(base64_encrypted_key);
                free(base64_iv);
                free(base64_tag);
                free(pubkey_hash_b64);
            }
        }
        free(recent_alerts);
        return;
    }

    for (int r = 0; r < recipient_count; r++) {
        Recipient *rec = &recipients[r];
        clean_expired_alerts(rec);
        if (rec->count > 0) {
            qsort(rec->alerts, rec->count, sizeof(Alert), alert_cmp);
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
                    size_t needed_len = strlen("ALERT|") + strlen(pubkey_hash_b64) + 3*20 + strlen(base64_text) + strlen(base64_encrypted_key) + strlen(base64_iv) + strlen(base64_tag) + 8;
                    char *response = malloc(needed_len);
                    if (!response) {
                        free(base64_text);
                        free(base64_encrypted_key);
                        free(base64_iv);
                        free(base64_tag);
                        free(pubkey_hash_b64);
                        return;
                    }
                    int len = snprintf(response, needed_len, "ALERT|%s|%ld|%ld|%ld|%s|%s|%s|%s",
                                       pubkey_hash_b64, a->create_at, a->unlock_at, a->expire_at,
                                       base64_text, base64_encrypted_key, base64_iv, base64_tag);
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
