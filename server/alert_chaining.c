#include <stdint.h>
#include <stdbool.h>
#define XXH_INLINE_ALL
#include "xxhash.h"
#include "alert_chaining.h"
#include "gorgona_utils.h" 

/* Пересчитывает prev_hash / curr_hash для всех алертов recipient'а.
 * Должна вызываться после vacuum и после загрузки с диска.
 * Делает цепь полностью детерминированной от текущего упорядоченного набора.
 */
void alert_chain_recompute_all(Recipient *rec) {
    if (!rec || rec->count == 0) {
        rec->last_hash = 0;
        return;
    }

    uint64_t running_prev = 0;
    for (int i = 0; i < rec->count; i++) {
        Alert *a = &rec->alerts[i];
        a->content_hash = alert_chain_compute_content(a);   // на всякий случай
        a->prev_hash = running_prev;
        a->curr_hash = alert_chain_compute_link(a->id, a->prev_hash, a->content_hash);
        running_prev = a->curr_hash;
    }
    rec->last_hash = rec->alerts[rec->count - 1].curr_hash;
}

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
 * Главная функция > заменяет весь inline-блок хеширования в add_alert().
 * Поддерживает Chain Healing и условный re-chaining.
 *
 * ОПТИМИЗАЦИЯ: использует бинарный поиск find_insert_position() из gorgona_utils.c
 * вместо линейного перебора. Сложность: O(log N) вместо O(N).
 * Для 1000 алертов: ~10 сравнений вместо ~500 в среднем.
 */
void alert_chain_process_insertion(Recipient *rec, Alert *new_alert,
                                    uint64_t remote_prev_hash,
                                    uint64_t remote_curr_hash) {
    (void)remote_prev_hash;  /* Игнорируем — цепь детерминистична */
    (void)remote_curr_hash;
    /* content_hash — всегда локально пересчитываем */
    new_alert->content_hash = alert_chain_compute_content(new_alert);
    /* Находим позицию вставки по ID через БИНАРНЫЙ ПОИСК (O(log N)) */
    int pos = find_insert_position(rec, new_alert->id);
    /* ВСЕГДА пересчитываем цепь локально для всех последующих алертов */
    if (pos == 0) {
        new_alert->prev_hash = 0;
    } else {
        new_alert->prev_hash = rec->alerts[pos - 1].curr_hash;
    }
    new_alert->curr_hash = alert_chain_compute_link(
        new_alert->id, new_alert->prev_hash, new_alert->content_hash);
    /* Re-chaining ВСЕХ последующих алертов */
    uint64_t running_prev = new_alert->curr_hash;
    for (int i = pos; i < rec->count; i++) {
        Alert *cur = &rec->alerts[i];
        cur->prev_hash = running_prev;
        cur->curr_hash = alert_chain_compute_link(
            cur->id, cur->prev_hash, cur->content_hash);
        running_prev = cur->curr_hash;
    }
    /* Обновляем last_hash */
    if (rec->count > 0) {
        rec->last_hash = rec->alerts[rec->count - 1].curr_hash;
    } else {
        rec->last_hash = new_alert->curr_hash;
    }
}
