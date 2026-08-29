#ifndef ALERT_CHAINING_H
#define ALERT_CHAINING_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>
#include "encrypt.h"

/* Structure for storing an alert */
typedef struct {
    unsigned char *text;
    size_t text_len;
    unsigned char *encrypted_key; 
    size_t encrypted_key_len;
    unsigned char *iv; 
    size_t iv_len;
    unsigned char tag[16]; // GCM_TAG_LEN
    time_t create_at; 
    uint64_t id;      
    time_t unlock_at; 
    time_t expire_at; 
    int active;
    uint64_t *active_ptr;
    bool is_mmaped;

    /* XXH3 Hash Chain fields */
    uint64_t content_hash; /* Хеш полезной нагрузки */
    uint64_t prev_hash;    /* Хеш предыдущего звена */
    uint64_t curr_hash;    /* Хеш текущего звена */
} Alert;

/* Structure for alerts by recipient */
typedef struct {
    unsigned char hash[32]; // PUBKEY_HASH_LEN
    Alert *alerts; 
    int count;
    int capacity;
    
    /* Chain tracking */
    uint64_t last_hash;    /* Хеш самого свежего алерта */
    uint64_t genesis_id;   /* ID первого алерта в окне (для контроля разрывов) */

    /* mmap specific fields */
    int fd;            
    void *mmap_ptr;    
    size_t mmap_size;  
    size_t used_size;  
    int waste_count;
} Recipient;

/* Прототипы функций */
uint64_t alert_chain_compute_content(Alert *a);
uint64_t alert_chain_compute_link(uint64_t id, uint64_t prev_h, uint64_t cont_h);
void alert_chain_process_insertion(Recipient *rec, Alert *new_alert);

#endif
