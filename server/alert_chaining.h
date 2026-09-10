#ifndef ALERT_CHAINING_H
#define ALERT_CHAINING_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

/* ============================================================
 * ВАЖНО: структуры ИМЕНОВАННЫЕ (struct Alert, struct Recipient).
 * Это позволяет делать forward declarations в gorgona_utils.h
 * без создания циклической зависимости.
 * ============================================================ */

/* Structure for storing an alert */
typedef struct Alert {
    unsigned char *text;
    size_t text_len;
    unsigned char *encrypted_key;
    size_t encrypted_key_len;
    unsigned char *iv;
    size_t iv_len;
    unsigned char tag[16]; /* GCM_TAG_LEN */
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
typedef struct Recipient {
    unsigned char hash[32]; /* PUBKEY_HASH_LEN */
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

/* ============================================================
 * Функции обработки цепочки
 * ============================================================ */

/* Вычисляет хеш содержимого алерта (payload) */
uint64_t alert_chain_compute_content(const Alert *a);

/* Вычисляет хеш звена цепи */
uint64_t alert_chain_compute_link(uint64_t id, uint64_t prev_h, uint64_t cont_h);

/*
 * Главная функция вставки с учётом Chain Healing.
 * Если remote_curr_hash != 0 — доверяем хешам пира (репликация).
 * Иначе считаем локально (SEND от клиента).
 * Re-chaining хвоста выполняется ТОЛЬКО для локальных вставок.
 */
void alert_chain_process_insertion(Recipient *rec, Alert *new_alert,
                                   uint64_t remote_prev_hash,
                                   uint64_t remote_curr_hash);

void alert_chain_recompute_all(Recipient *rec);

#endif /* ALERT_CHAINING_H */
