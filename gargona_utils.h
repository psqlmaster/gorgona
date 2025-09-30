#ifndef GARGONA_UTILS_H
#define GARGONA_UTILS_H

#include "encrypt.h"
#include <stdio.h>
#include <time.h>
#include <sys/socket.h>

#define MAX_MSG_LEN 8192
#define MAX_ALERTS 1024
#define MAX_CLIENTS 100
#define MODE_LIVE 1
#define MODE_ALL 2
#define MODE_SINGLE 3
#define MODE_LOCK 4
#define DEFAULT_SERVER_PORT 5555
#define INITIAL_RECIPIENT_CAPACITY 16
#define MAX_LOG_SIZE (10 * 1024 * 1024) // 10 MB

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

/* Structure for subscribers */
typedef struct {
    int sock;
    char pubkey_hash[64]; // For single mode
    int mode; // 0 = not subscribed, 1 = live, 2 = all, 3 = single
} Subscriber;

/* Global variables */
extern FILE *log_file;
extern Recipient *recipients;
extern int recipient_count;
extern int recipient_capacity;
extern int client_sockets[MAX_CLIENTS];
extern Subscriber subscribers[MAX_CLIENTS];

/* Function declarations */
int is_http_request(const char *buffer);
void trim_string(char *str);
int read_port_config(void);
void format_time(time_t timestamp, char *buffer, size_t buffer_size);
void free_alert(Alert *alert);
Recipient *find_recipient(const unsigned char *hash);
Recipient *add_recipient(const unsigned char *hash);
void clean_expired_alerts(Recipient *rec);
void remove_oldest_alert(Recipient *rec);
void add_alert(const unsigned char *pubkey_hash, time_t create_at, time_t unlock_at, time_t expire_at,
               char *base64_text, char *base64_encrypted_key, char *base64_iv, char *base64_tag, int client_fd);
int alert_cmp(const void *a, const void *b);
void notify_subscribers(const unsigned char *pubkey_hash, Alert *new_alert);
void send_current_alerts(int sd, int mode, const char *single_hash_b64);
void rotate_log(void);

#endif
