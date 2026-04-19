/* 
* BSD 3-Clause License
* Copyright (c) 2025, Alexander Shcheglov
*/

#ifndef CLIENT_HISTORY_H
#define CLIENT_HISTORY_H

#include <stdint.h>
#include <stdbool.h>

/* Fixed line length for the log (48 bytes including newline) */
#define LOG_LINE_LEN    48
/* Number of unique entries to track for duplicate detection */
#define LOG_MAX_ENTRIES 1024 

/**
 * Initializes the history tracker. 
 * Maps /var/lib/gorgona/history.log into memory.
 */
void client_history_init(void);

/**
 * Checks if the Alert ID has been processed before.
 * Uses both a MaxID pulse check and a scan of the sliding window.
 * 
 * @return true if the ID is new, false if it's a duplicate.
 */
bool client_history_is_new(uint64_t id);

/**
 * Records an Alert ID as processed. 
 * Updates the global MaxID and adds the ID to the text ring buffer.
 */
void client_history_record(uint64_t id);

#endif
