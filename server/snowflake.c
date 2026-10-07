/* 
* BSD 3-Clause License
* Copyright (c) 2025, Alexander Shcheglov
* All rights reserved. 
*/
#define XXH_INLINE_ALL
#include "xxhash.h"
#include "snowflake.h"
#include "gorgona_utils.h"
#include <time.h>
#include <unistd.h>
#include <string.h>

/* Internal state for ID generation */
atomic_uint_least16_t sequence = 0;
uint64_t last_timestamp = 0;

/* Node ID for distributed uniqueness (11 bits = 0-2047) */
static uint64_t node_id = 0;
static bool node_id_initialized = false;

/* Initializes Node ID from hostname hash (cross-platform: Linux/BSD) */
static void init_node_id(void) {
    if (node_id_initialized) return;
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        strcpy(hostname, "unknown");
    }
    /* Deterministic hash from hostname using xxhash */
    uint64_t hash = XXH3_64bits(hostname, strlen(hostname));
    node_id = hash & 0x3FF; /* 10 bits mask (0-1023) */
    node_id_initialized = true;
    /* Always log at INFO level — this is critical startup information */
    log_event("INFO", -1, NULL, 0, 
              "Snowflake Node ID initialized: %" PRIu64 " (from hostname: %s)", 
              node_id, hostname);
}

/* Public initialization function — call at server startup */
void snowflake_init(void) {
    init_node_id();
}

/**
 * Returns current monotonic time in milliseconds since the Unix epoch.
 */
static uint64_t current_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/**
 * Generates a unique 64-bit Snowflake ID.
 * Layout: 41 bits timestamp (ms since SNOWFLAKE_EPOCH) | 12 bits sequence.
 * This implementation provides up to 4096 unique IDs per millisecond.
 */
uint64_t generate_snowflake_id(void) {
    /* Initialize Node ID on first use */
    if (!node_id_initialized) {
        init_node_id();
    }
    uint64_t timestamp = current_ms() - SNOWFLAKE_EPOCH;
    /* 1. CLOCK SKEW PROTECTION */
    if (timestamp < last_timestamp) {
        if (verbose) {
            log_event("WARN", -1, NULL, 0,
                     "Clock skew detected! Waiting %" PRIu64 "ms", (last_timestamp - timestamp));
        }
        while ((current_ms() - SNOWFLAKE_EPOCH) <= last_timestamp) {
            /* Busy-wait */
        }
        timestamp = current_ms() - SNOWFLAKE_EPOCH;
    }
    /* 2. SEQUENCE MANAGEMENT */
    if (timestamp == last_timestamp) {
        sequence = (sequence + 1) & 0xFFF;
        if (sequence == 0) {
            while ((current_ms() - SNOWFLAKE_EPOCH) <= last_timestamp) {
                /* Wait for the clock to tick */
            }
            timestamp = current_ms() - SNOWFLAKE_EPOCH;
        }
    } else {
        sequence = 0;
    }
    last_timestamp = timestamp;
    /* 3. ID COMPOSITION (Standard Twitter Snowflake Layout)
     * Layout: [1 bit sign(0)][41 bits timestamp][10 bits node_id][12 bits sequence]
     * Total: 64 bits. 
     * CRITICAL: Timestamp is in the MOST significant bits, ensuring that 
     * NEWER IDs are ALWAYS numerically larger, preserving chronological sorting!
     */
    return (timestamp << 22) | (node_id << 12) | (uint16_t)sequence;
}

time_t snowflake_to_timestamp(uint64_t id) {
    if (id == 0) return 0;
    /* NEW LAYOUT extraction (timestamp in bits 22-62) */
    uint64_t ms_new = (id >> 22) & 0x1FFFFFFFFFFULL;
    time_t ts_new = (time_t)((ms_new + SNOWFLAKE_EPOCH) / 1000);
    /* OLD LAYOUT extraction (timestamp in bits 12-52) */
    uint64_t ms_old = (id >> 12) & 0x1FFFFFFFFFFULL;
    time_t ts_old = (time_t)((ms_old + SNOWFLAKE_EPOCH) / 1000);
    /* Heuristic detection: valid timestamps are between 2024 and 2030 */
    time_t min_valid = 1704067200; /* Jan 1, 2024 */
    time_t max_valid = 1893456000; /* Jan 1, 2030 */
    if (ts_new >= min_valid && ts_new <= max_valid) {
        return ts_new; /* It's a new layout ID */
    }
    if (ts_old >= min_valid && ts_old <= max_valid) {
        return ts_old; /* It's an old layout ID (backward compatibility) */
    }
    /* Fallback to new layout if both are out of range */
    return ts_new;
}

/* Возвращает логическое время кластера (Cluster Pulse) */
time_t get_cluster_logical_time(void) {
    uint64_t max_id = get_max_alert_id();
    if (max_id > 0) {
        return snowflake_to_timestamp(max_id);
    }
    /* Фоллбэк на локальное время, если база Completely empty (Cold Start) */
    return time(NULL); 
}
