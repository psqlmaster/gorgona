#include <stdint.h>
#include <stdbool.h>
#define XXH_INLINE_ALL
#include "xxhash.h"
#include "alert_chaining.h"
#include "gorgona_utils.h" 

/* Единая точка вычисления content_hash */
uint64_t alert_chain_compute_content(const Alert *a) {
    XXH3_state_t state;
    XXH3_64bits_reset(&state);
    XXH3_64bits_update(&state, a->text, a->text_len);
    XXH3_64bits_update(&state, a->encrypted_key, a->encrypted_key_len);
    XXH3_64bits_update(&state, a->iv, a->iv_len);
    XXH3_64bits_update(&state, a->tag, 16);
    return XXH3_64bits_digest(&state);
}

/* Единая точка вычисления link_hash */
uint64_t alert_chain_compute_link(uint64_t id, uint64_t prev_h, uint64_t cont_h) {
    uint64_t data[3] = { id, prev_h, cont_h };
    return XXH3_64bits_withSeed(data, sizeof(data), 0);
}

/* 
 * Главная функция — заменяет весь inline-блок хеширования в add_alert().
 * Поддерживает Chain Healing и условный re-chaining.
 */
void alert_chain_process_insertion(Recipient *rec, Alert *new_alert,
                                   uint64_t remote_prev_hash,
                                   uint64_t remote_curr_hash) {
    /* 1. Вычисляем content_hash (всегда локально — это хеш payload) */
    new_alert->content_hash = alert_chain_compute_content(new_alert);

    /* 2. Находим позицию вставки (по ID) */
    int pos = 0;
    while (pos < rec->count && rec->alerts[pos].id < new_alert->id) {
        pos++;
    }

    /* 3. Вычисление хешей цепи — два режима */
    bool is_replication = (remote_curr_hash != 0);
    
    if (is_replication) {
        /* РЕПЛИКАЦИЯ: доверяем хешам от пира (Chain Healing) */
        new_alert->prev_hash = remote_prev_hash;
        new_alert->curr_hash = remote_curr_hash;
    } else {
        /* ЛОКАЛЬНАЯ ВСТАВКА: считаем сами */
        if (pos == 0) {
            new_alert->prev_hash = 0;
        } else {
            new_alert->prev_hash = rec->alerts[pos - 1].curr_hash;
        }
        new_alert->curr_hash = alert_chain_compute_link(
            new_alert->id, new_alert->prev_hash, new_alert->content_hash);
    }

    /* 4. RE-CHAINING хвоста — ТОЛЬКО для локальных вставок */
    if (!is_replication && pos < rec->count) {
        uint64_t running_prev_hash = new_alert->curr_hash;
        for (int i = pos; i < rec->count; i++) {
            Alert *current = &rec->alerts[i];
            current->prev_hash = running_prev_hash;
            current->curr_hash = alert_chain_compute_link(
                current->id, current->prev_hash, current->content_hash);
            running_prev_hash = current->curr_hash;
        }
    }

    /* 5. Обновляем last_hash */
    if (rec->count > 0) {
        rec->last_hash = rec->alerts[rec->count - 1].curr_hash;
    } else {
        rec->last_hash = new_alert->curr_hash;
    }
}
