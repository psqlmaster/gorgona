/* BSD 3-Clause License
Copyright (c) 2025, Alexander Shcheglov
All rights reserved. */
#ifndef GORGONA_UTILS_H
#define GORGONA_UTILS_H

#include <stdio.h>
#include <time.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <stdint.h>
#include "encrypt.h"
#include "config.h"

#define MODE_LIVE 1
#define MODE_ALL 2
#define MODE_SINGLE 3
#define MODE_LOCK 4
#define MODE_LAST 5
#define MODE_NEW 6
#define INITIAL_RECIPIENT_CAPACITY 16

extern int max_alerts;
extern int vacuum_threshold; 

/* Structure for outgoing buffer list (linked list for queue) */
typedef struct OutBuffer {
    char *data;
    size_t len;
    size_t pos;
    struct OutBuffer *next;
} OutBuffer;

/* Structure for storing an alert */
typedef struct {
    unsigned char *text; /* Points to mmap area if is_mmaped is true */
    size_t text_len;
    unsigned char *encrypted_key; 
    size_t encrypted_key_len;
    unsigned char *iv; 
    size_t iv_len;
    unsigned char tag[GCM_TAG_LEN]; 
    time_t create_at; 
    uint64_t id;      
    time_t unlock_at; 
    time_t expire_at; 
    int active;
    int *active_ptr;   /* Pointer to 'active' field inside mmap */
    bool is_mmaped;    /* Flag: is data in mmap or heap */
} Alert;

/* Structure for alerts by recipient */
typedef struct {
    unsigned char hash[PUBKEY_HASH_LEN];
    Alert *alerts; 
    int count;
    int capacity;
    
    /* mmap specific fields */
    int fd;            
    void *mmap_ptr;    
    size_t mmap_size;  
    size_t used_size;  
    int waste_count;  /* Count of inactive alerts in the file */
} Recipient;

/* Structure for subscribers */
typedef struct {
    int sock;
    char pubkey_hash[64]; 
    int mode; 
    time_t connect_time;
    OutBuffer *out_head;
    OutBuffer *out_tail;
    enum { READ_LEN, READ_MSG } read_state;
    uint32_t expected_msg_len;
    char *in_buffer;
    size_t in_pos;
    bool close_after_send;
} Subscriber;

/* Global variables */
extern FILE *log_file;
extern Recipient *recipients;
extern int recipient_count;
extern int recipient_capacity;
extern int client_sockets[MAX_CLIENTS];
extern Subscriber subscribers[MAX_CLIENTS];
extern int max_alerts;
extern int max_clients;
extern size_t max_log_size;
extern char log_level[32]; 
extern size_t max_message_size;
extern int verbose;
extern int use_disk_db;

/* Function declarations */
void trim_string(char *str);
void read_config(int *port, int *max_alerts, int *max_clients, size_t *max_log_size, char *log_level, size_t *max_message_size, int *use_disk_db, int *vacuum_threshold_config);
void format_time(time_t timestamp, char *buffer, size_t buffer_size);
void free_alert(Alert *alert);
Recipient *find_recipient(const unsigned char *hash);
Recipient *add_recipient(const unsigned char *hash);
void clean_expired_alerts(Recipient *rec);
void remove_oldest_alert(Recipient *rec);
void add_alert(const unsigned char *pubkey_hash, time_t unlock_at, time_t expire_at,
               char *base64_text, char *base64_encrypted_key, char *base64_iv, char *base64_tag, int client_fd);
void notify_subscribers(const unsigned char *pubkey_hash, Alert *new_alert);
void send_current_alerts(int sub_index, int mode, const char *single_hash_b64, int count);
void rotate_log(void);
void get_utc_time_str(char *buffer, size_t buffer_size);
void run_server(int server_fd);

/* alert_db.c functions sync */
int alert_db_init(void);
int alert_db_load_recipients(void);
int alert_db_save_alert(Recipient *rec, Alert *alert);
int alert_db_sync(Recipient *rec);
void alert_db_deactivate_alert(Alert *alert);

/* for sort id */
int alert_cmp_asc(const void *a, const void *b);
int alert_cmp_desc(const void *a, const void *b);

/* Out queue */
void enqueue_message(int sub_index, const char *msg, size_t msg_len);
void process_out(int sub_index, int sd);
int has_pending_data(int sub_index);
void free_out_queue(int sub_index);

#endif
