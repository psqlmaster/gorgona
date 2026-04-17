/* 
* BSD 3-Clause License
* Copyright (c) 2025, Alexander Shcheglov
* All rights reserved. 
*/

#include "snowflake.h"
#include "gorgona_utils.h"
#include <time.h>

/* Internal state for ID generation */
atomic_uint_least16_t sequence = 0;
uint64_t last_timestamp = 0;

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
    uint64_t timestamp = current_ms() - SNOWFLAKE_EPOCH;

    /* 1. CLOCK SKEW PROTECTION
       If the system clock moved backward (e.g., NTP sync), we must wait 
       until the real time catches up to prevent ID collisions. */
    if (timestamp < last_timestamp) {
        if (verbose) {
            log_event("WARN", -1, NULL, 0, 
                      "Clock skew detected! Waiting %" PRIu64 "ms", (last_timestamp - timestamp));
        }
        
        while ((current_ms() - SNOWFLAKE_EPOCH) <= last_timestamp) {
            /* Busy-wait: high precision but consumes CPU for a few ms */
        }
        timestamp = current_ms() - SNOWFLAKE_EPOCH;
    }

    /* 2. SEQUENCE MANAGEMENT
       If multiple IDs are requested in the same millisecond, increment the sequence. */
    if (timestamp == last_timestamp) {
        /* Mask to 12 bits (0-4095) */
        sequence = (sequence + 1) & 0xFFF; 
        
        /* SEQUENCE OVERFLOW
           If we exceed 4096 IDs in 1ms, we wait for the next millisecond. */
        if (sequence == 0) {
            while ((current_ms() - SNOWFLAKE_EPOCH) <= last_timestamp) {
                /* Wait for the clock to tick */
            }
            timestamp = current_ms() - SNOWFLAKE_EPOCH;
        }
    } else {
        /* New millisecond started: reset sequence to 0 */
        sequence = 0;
    }

    last_timestamp = timestamp;

    /* 3. ID COMPOSITION
       Shift timestamp 12 bits to the left and pack the sequence into the lower bits. */
    return (timestamp << 12) | (uint16_t)sequence;
}

/**
 * Extracts the UNIX timestamp from a Snowflake ID.
 * 1. Uses 12-bit shift to match the generator logic.
 * 2. Converts milliseconds back to seconds for time_t.
 */
time_t snowflake_to_timestamp(uint64_t id) {
    if (id == 0) return 0;
    uint64_t ms_from_custom_epoch = (id >> 12);
    return (time_t)((ms_from_custom_epoch + SNOWFLAKE_EPOCH) / 1000);
}
