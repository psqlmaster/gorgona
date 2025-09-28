#include "encrypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <time.h>
#include <errno.h>

#define MAX_MSG_LEN 8192  // Increased buffer
#define MAX_ALERTS 1024
#define MAX_CLIENTS 100
#define DEFAULT_SERVER_PORT 5555
#define INITIAL_RECIPIENT_CAPACITY 16

/* Structure for storing an alert */
typedef struct {
    unsigned char *text; // Encrypted message
    size_t text_len;
    unsigned char *encrypted_key; // Encrypted AES key
    size_t encrypted_key_len;
    unsigned char *iv; // Initialization vector
    size_t iv_len;
    unsigned char tag[GCM_TAG_LEN]; // GCM authentication tag
    time_t create_at; // Creation time
    time_t unlock_at; // Unlock time
    time_t expire_at; // Expiration time
    int active; // Active flag
} Alert;

/* Structure for alerts by recipient */
typedef struct {
    unsigned char hash[PUBKEY_HASH_LEN];
    Alert alerts[MAX_ALERTS];
    int count;
} Recipient;

/* Global variables */
Recipient *recipients = NULL;
int recipient_count = 0;
int recipient_capacity = 0;
int client_sockets[MAX_CLIENTS];
struct {
    int sock;
    char pubkey_hash[64]; // For single mode
    int mode; // 0 = not subscribed, 1 = live, 2 = all, 3 = single
} subscribers[MAX_CLIENTS];

/* Removes trailing spaces, \n, \r from a string */
void trim_string(char *str) {
    size_t len = strlen(str);
    while (len > 0 && (str[len - 1] == ' ' || str[len - 1] == '\n' || str[len - 1] == '\r')) {
        str[len - 1] = '\0';
        len--;
    }
}

/* Reads port configuration from omen.conf */
int read_port_config() {
    FILE *conf_fp = fopen("gargona.conf", "r");
    if (!conf_fp) {
        return DEFAULT_SERVER_PORT;
    }

    char line[256];
    int port = DEFAULT_SERVER_PORT;
    while (fgets(line, sizeof(line), conf_fp)) {
        if (strstr(line, "[server]")) continue;
        char *key = strtok(line, " =");
        char *value = strtok(NULL, " =");
        if (value) value[strcspn(value, "\n")] = '\0';
        if (key && strcmp(key, "port") == 0) {
            port = atoi(value);
            break;
        }
    }
    fclose(conf_fp);
    return port;
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
        recipients = realloc(recipients, sizeof(Recipient) * recipient_capacity); // Fixed: recipient -> recipients
        if (!recipients) {
            perror("Не удалось выделить память для recipients");
            exit(1);
        }
    }
    Recipient *rec = &recipients[recipient_count];
    memcpy(rec->hash, hash, PUBKEY_HASH_LEN);
    rec->count = 0;
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
void add_alert(const unsigned char *pubkey_hash, time_t create_at, time_t unlock_at, time_t expire_at,
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

    if (rec->count >= MAX_ALERTS) {
        remove_oldest_alert(rec);
    }

    if (rec->count >= MAX_ALERTS) {
        dprintf(client_fd, "Ошибка: Не удалось добавить алерт, лимит достигнут даже после очистки\n");
        return;
    }

    Alert *alert = &rec->alerts[rec->count];
    alert->text = base64_decode(base64_text, &alert->text_len);
    if (!alert->text) {
        dprintf(client_fd, "Ошибка: Не удалось декодировать base64_text\n");
        return;
    }
    alert->encrypted_key = base64_decode(base64_encrypted_key, &alert->encrypted_key_len);
    if (!alert->encrypted_key) {
        free(alert->text);
        dprintf(client_fd, "Ошибка: Не удалось декодировать base64_encrypted_key\n");
        return;
    }
    alert->iv = base64_decode(base64_iv, &alert->iv_len);
    if (!alert->iv) {
        free(alert->text);
        free(alert->encrypted_key);
        dprintf(client_fd, "Ошибка: Не удалось декодировать base64_iv\n");
        return;
    }
    if (alert->iv_len != 12) {
        free(alert->text);
        free(alert->encrypted_key);
        free(alert->iv);
        dprintf(client_fd, "Ошибка: Неверная длина IV: %zu (ожидаемо 12)\n", alert->iv_len);
        return;
    }
    size_t tag_len;
    unsigned char *tag = base64_decode(base64_tag, &tag_len);
    if (!tag || tag_len != GCM_TAG_LEN) {
        free(alert->text);
        free(alert->encrypted_key);
        free(alert->iv);
        free(tag);
        dprintf(client_fd, "Ошибка: Неверная длина тега: %zu (ожидаемо %d)\n", tag_len, GCM_TAG_LEN);
        return;
    }
    memcpy(alert->tag, tag, GCM_TAG_LEN);
    free(tag);

    alert->create_at = create_at;
    alert->unlock_at = unlock_at;
    alert->expire_at = expire_at;
    alert->active = 1;
    rec->count++;

    char create_str[50], unlock_str[50], expire_str[50];
    format_time(create_at, create_str, sizeof(create_str));
    format_time(unlock_at, unlock_str, sizeof(unlock_str));
    format_time(expire_at, expire_str, sizeof(expire_str));
    printf("Добавлен алерт: Pubkey_Hash=");
    for (size_t i = 0; i < PUBKEY_HASH_LEN; i++) printf("%02x", pubkey_hash[i]);
    printf(", Create=%s, Unlock=%s, Expire=%s\n", create_str, unlock_str, expire_str);
}

/* Comparator for sorting alerts by create_at */
int alert_cmp(const void *a, const void *b) {
    const Alert *aa = (const Alert *)a;
    const Alert *bb = (const Alert *)b;
    if (aa->create_at < bb->create_at) return -1;
    if (aa->create_at > bb->create_at) return 1;
    return 0;
}

/* Notifies subscribers about a new alert */
void notify_subscribers(const unsigned char *pubkey_hash, Alert *new_alert) {
    time_t now = time(NULL);
    char *base64_pubkey_hash = base64_encode(pubkey_hash, PUBKEY_HASH_LEN);
    if (!base64_pubkey_hash) return;

    char create_str[50], unlock_str[50], expire_str[50];
    format_time(new_alert->create_at, create_str, sizeof(create_str));
    format_time(new_alert->unlock_at, unlock_str, sizeof(unlock_str));
    format_time(new_alert->expire_at, expire_str, sizeof(expire_str));

    char response[MAX_MSG_LEN];
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (subscribers[i].sock > 0) {
            int sd = subscribers[i].sock;
            if (subscribers[i].mode == 3) { // single
                if (strcmp(subscribers[i].pubkey_hash, base64_pubkey_hash) != 0) continue;
            } else if (subscribers[i].mode == 0) {
                continue;
            }

            if (now >= new_alert->expire_at) {
                int len = snprintf(response, MAX_MSG_LEN, "Message expired: Pubkey_Hash=%s\n", base64_pubkey_hash);
                if (len >= MAX_MSG_LEN - 20) continue;
                strcat(response, "\nEND_OF_MESSAGE\n");
            } else if (now < new_alert->unlock_at) {
                if (subscribers[i].mode == 2 || subscribers[i].mode == 3) { // all or single
                    int len = snprintf(response, MAX_MSG_LEN, "Metadata: Pubkey_Hash=%s, Create=%s, Unlock=%s, Expire=%s\n",
                             base64_pubkey_hash, create_str, unlock_str, expire_str);
                    if (len >= MAX_MSG_LEN - 20) continue;
                    strcat(response, "\nEND_OF_MESSAGE\n");
                } else {
                    continue;
                }
            } else { // unlocked, not expired
                if (subscribers[i].mode == 1 || subscribers[i].mode == 2 || subscribers[i].mode == 3) {
                    char *base64_text = base64_encode(new_alert->text, new_alert->text_len);
                    char *base64_encrypted_key = base64_encode(new_alert->encrypted_key, new_alert->encrypted_key_len);
                    char *base64_iv = base64_encode(new_alert->iv, new_alert->iv_len);
                    char *base64_tag = base64_encode(new_alert->tag, GCM_TAG_LEN);
                    if (base64_text && base64_encrypted_key && base64_iv && base64_tag) {
                        int len = snprintf(response, MAX_MSG_LEN, 
                                 "Pubkey_Hash: %s\nEncrypted Full text: %s\nEncrypted Key: %s\nIV: %s\nTag: %s\nMetadata: Pubkey_Hash=%s, Create=%s, Unlock=%s, Expire=%s\n",
                                 base64_pubkey_hash, base64_text, base64_encrypted_key, base64_iv, base64_tag, base64_pubkey_hash, create_str, unlock_str, expire_str);
                        free(base64_text);
                        free(base64_encrypted_key);
                        free(base64_iv);
                        free(base64_tag);
                        if (len >= MAX_MSG_LEN - 20) continue;
                        strcat(response, "\nEND_OF_MESSAGE\n");
                    } else {
                        free(base64_text);
                        free(base64_encrypted_key);
                        free(base64_iv);
                        free(base64_tag);
                        continue;
                    }
                } else {
                    continue;
                }
            }
            send(sd, response, strlen(response), 0);
        }
    }
    free(base64_pubkey_hash);
}

/* Sends current alerts to a subscriber based on mode */
void send_current_alerts(int sd, int mode, const char *single_hash_b64) {
    time_t now = time(NULL);
    for (int r = 0; r < recipient_count; r++) {
        Recipient *rec = &recipients[r];
        clean_expired_alerts(rec);
        if (rec->count > 0) {
            qsort(rec->alerts, rec->count, sizeof(Alert), alert_cmp);
        }
        char *base64_pubkey_hash = base64_encode(rec->hash, PUBKEY_HASH_LEN);
        if (!base64_pubkey_hash) continue;

        if (mode == 3 && strcmp(base64_pubkey_hash, single_hash_b64) != 0) {
            free(base64_pubkey_hash);
            continue;
        }

        for (int j = 0; j < rec->count; j++) {
            Alert *a = &rec->alerts[j];
            if (!a->active) continue;

            char create_str[50], unlock_str[50], expire_str[50];
            format_time(a->create_at, create_str, sizeof(create_str));
            format_time(a->unlock_at, unlock_str, sizeof(unlock_str));
            format_time(a->expire_at, expire_str, sizeof(expire_str));

            char response[MAX_MSG_LEN];
            if (now >= a->expire_at) {
                if (mode == 2 || mode == 3) {
                    int len = snprintf(response, MAX_MSG_LEN, "Message expired: Pubkey_Hash=%s\n", base64_pubkey_hash);
                    if (len >= MAX_MSG_LEN - 20) continue;
                    strcat(response, "\nEND_OF_MESSAGE\n");
                    send(sd, response, strlen(response), 0);
                }
                a->active = 0; // Mark as inactive after sending
            } else if (now < a->unlock_at) {
                if (mode == 2 || mode == 3) {
                    int len = snprintf(response, MAX_MSG_LEN, "Metadata: Pubkey_Hash=%s, Create=%s, Unlock=%s, Expire=%s\n",
                             base64_pubkey_hash, create_str, unlock_str, expire_str);
                    if (len >= MAX_MSG_LEN - 20) continue;
                    strcat(response, "\nEND_OF_MESSAGE\n");
                    send(sd, response, strlen(response), 0);
                }
            } else {
                if (mode == 1 || mode == 2 || mode == 3) {
                    char *base64_text = base64_encode(a->text, a->text_len);
                    char *base64_encrypted_key = base64_encode(a->encrypted_key, a->encrypted_key_len);
                    char *base64_iv = base64_encode(a->iv, a->iv_len);
                    char *base64_tag = base64_encode(a->tag, GCM_TAG_LEN);
                    if (base64_text && base64_encrypted_key && base64_iv && base64_tag) {
                        int len = snprintf(response, MAX_MSG_LEN, 
                                 "Pubkey_Hash: %s\nEncrypted Full text: %s\nEncrypted Key: %s\nIV: %s\nTag: %s\nMetadata: Pubkey_Hash=%s, Create=%s, Unlock=%s, Expire=%s\n",
                                 base64_pubkey_hash, base64_text, base64_encrypted_key, base64_iv, base64_tag, base64_pubkey_hash, create_str, unlock_str, expire_str);
                        free(base64_text);
                        free(base64_encrypted_key);
                        free(base64_iv);
                        free(base64_tag);
                        if (len >= MAX_MSG_LEN - 20) continue;
                        strcat(response, "\nEND_OF_MESSAGE\n");
                        send(sd, response, strlen(response), 0);
                    }
                }
            }
        }
        free(base64_pubkey_hash);
    }
}

int main() {
    int server_fd, new_socket, max_clients = MAX_CLIENTS, activity, i, valread, sd;
    int max_sd;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[MAX_MSG_LEN] = {0};
    fd_set readfds;

    // Initialize arrays
    for (i = 0; i < max_clients; i++) {
        client_sockets[i] = 0;
        subscribers[i].sock = 0;
        subscribers[i].mode = 0;
    }

    // Initialize recipients
    recipient_capacity = INITIAL_RECIPIENT_CAPACITY;
    recipients = malloc(sizeof(Recipient) * recipient_capacity);
    if (!recipients) {
        perror("Не удалось выделить память для recipients");
        exit(EXIT_FAILURE);
    }
    recipient_count = 0;

    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(read_port_config());

    // Bind socket
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("Сервер запущен на порту %d\n", read_port_config());

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);
        max_sd = server_fd;

        for (i = 0; i < max_clients; i++) {
            sd = client_sockets[i];
            if (sd > 0) FD_SET(sd, &readfds);
            if (sd > max_sd) max_sd = sd;
        }

        activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);

        if ((activity < 0) && (errno != EINTR)) {
            printf("select error");
        }

        if (FD_ISSET(server_fd, &readfds)) {
            if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
                perror("accept");
                exit(EXIT_FAILURE);
            }

            for (i = 0; i < max_clients; i++) {
                if (client_sockets[i] == 0) {
                    client_sockets[i] = new_socket;
                    subscribers[i].sock = new_socket;
                    break;
                }
            }
        }

        for (i = 0; i < max_clients; i++) {
            sd = client_sockets[i];

            if (FD_ISSET(sd, &readfds)) {
                if ((valread = read(sd, buffer, MAX_MSG_LEN)) == 0) {
                    close(sd);
                    client_sockets[i] = 0;
                    subscribers[i].sock = 0;
                    subscribers[i].mode = 0;
                } else {
                    buffer[valread] = '\0';
                    printf("Получено: %s\n", buffer);

                    if (strncmp(buffer, "SEND|", 5) == 0) {
                        char *token = strtok(buffer + 5, "|");
                        char *pubkey_hash_b64 = token;
                        token = strtok(NULL, "|");
                        time_t create_at = atol(token);
                        token = strtok(NULL, "|");
                        time_t unlock_at = atol(token);
                        token = strtok(NULL, "|");
                        time_t expire_at = atol(token);
                        token = strtok(NULL, "|");
                        char *base64_text = token;
                        token = strtok(NULL, "|");
                        char *base64_encrypted_key = token;
                        token = strtok(NULL, "|");
                        char *base64_iv = token;
                        token = strtok(NULL, "|");
                        char *base64_tag = token;

                        size_t hash_len;
                        unsigned char *pubkey_hash = base64_decode(pubkey_hash_b64, &hash_len);
                        if (!pubkey_hash || hash_len != PUBKEY_HASH_LEN) {
                            dprintf(sd, "Ошибка: Неверный хеш публичного ключа\n");
                            free(pubkey_hash);
                            continue;
                        }

                        add_alert(pubkey_hash, create_at, unlock_at, expire_at, base64_text, base64_encrypted_key, base64_iv, base64_tag, sd);
                        dprintf(sd, "Алерты успешно добавлен\n");

                        Recipient *rec = find_recipient(pubkey_hash);
                        if (rec) {
                            notify_subscribers(pubkey_hash, &rec->alerts[rec->count - 1]);
                        }

                        free(pubkey_hash);
                    } else if (strncmp(buffer, "LISTEN|", 7) == 0) {
                        char *pubkey_hash_b64 = buffer + 7;
                        trim_string(pubkey_hash_b64);
                        for (int j = 0; j < MAX_CLIENTS; j++) {
                            if (client_sockets[j] == sd) {
                                subscribers[j].mode = 3;
                                strncpy(subscribers[j].pubkey_hash, pubkey_hash_b64, sizeof(subscribers[j].pubkey_hash) - 1);
                                break;
                            }
                        }
                        send_current_alerts(sd, 3, pubkey_hash_b64);
                        dprintf(sd, "Подписан на SINGLE для %s\n", pubkey_hash_b64);
                    } else if (strncmp(buffer, "SUBSCRIBE ALL", 13) == 0) {
                        for (int j = 0; j < MAX_CLIENTS; j++) {
                            if (client_sockets[j] == sd) {
                                subscribers[j].mode = 2;
                                subscribers[j].pubkey_hash[0] = '\0';
                                break;
                            }
                        }
                        send_current_alerts(sd, 2, NULL);
                        dprintf(sd, "Подписан на ALL\n");
                    } else if (strncmp(buffer, "SUBSCRIBE LIVE", 14) == 0) {
                        for (int j = 0; j < MAX_CLIENTS; j++) {
                            if (client_sockets[j] == sd) {
                                subscribers[j].mode = 1;
                                subscribers[j].pubkey_hash[0] = '\0';
                                break;
                            }
                        }
                        send_current_alerts(sd, 1, NULL);
                        dprintf(sd, "Подписан на LIVE\n");
                    } else {
                        dprintf(sd, "Ошибка: Неизвестная команда\n");
                    }
                }
            }
        }
    }

    // Free resources
    for (int r = 0; r < recipient_count; r++) {
        for (int j = 0; j < recipients[r].count; j++) {
            free_alert(&recipients[r].alerts[j]);
        }
    }
    free(recipients); // Fixed: recipient -> recipients
    return 0;
}
