#include <stdint.h>
#define XXH_INLINE_ALL
#include "xxhash.h"
#include "alert_chaining.h"

/**
 * Computes the hash of the alert's content (payload).
 */
uint64_t alert_chain_compute_content(Alert *a) {
    XXH3_state_t state;
    XXH3_64bits_reset(&state);
    
    XXH3_64bits_update(&state, a->text, a->text_len);
    XXH3_64bits_update(&state, a->encrypted_key, a->encrypted_key_len);
    XXH3_64bits_update(&state, a->iv, a->iv_len);
    XXH3_64bits_update(&state, a->tag, 16);
    
    return XXH3_64bits_digest(&state);
}

/**
 * Computes the final link hash for the chain.
 */
uint64_t alert_chain_compute_link(uint64_t id, uint64_t prev_h, uint64_t cont_h) {
    uint64_t data[3];
    data[0] = id;
    data[1] = prev_h;
    data[2] = cont_h;
    
    /* Исправлено: используем XXH3_64bits_withSeed для 3 аргументов */
    return XXH3_64bits_withSeed(data, sizeof(data), 0);
}

/**
 * Main insertion and re-chaining logic.
 */
void alert_chain_process_insertion(Recipient *rec, Alert *new_alert) {
    new_alert->content_hash = alert_chain_compute_content(new_alert);
    
    int pos = 0;
    while (pos < rec->count && rec->alerts[pos].id < new_alert->id) {
        pos++;
    }

    if (pos == 0) {
        new_alert->prev_hash = 0; 
    } else {
        new_alert->prev_hash = rec->alerts[pos - 1].curr_hash;
    }

    new_alert->curr_hash = alert_chain_compute_link(
        new_alert->id, 
        new_alert->prev_hash, 
        new_alert->content_hash
    );

    if (pos < rec->count) {
        uint64_t running_prev_hash = new_alert->curr_hash;
        for (int i = pos; i < rec->count; i++) {
            Alert *current = &rec->alerts[i];
            current->prev_hash = running_prev_hash;
            current->curr_hash = alert_chain_compute_link(
                current->id, 
                current->prev_hash, 
                current->content_hash
            );
            running_prev_hash = current->curr_hash;
        }
    }

    if (rec->count > 0) {
        rec->last_hash = rec->alerts[rec->count - 1].curr_hash;
    } else {
        rec->last_hash = new_alert->curr_hash;
    }
}
