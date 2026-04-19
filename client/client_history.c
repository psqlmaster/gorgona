/* 
* BSD 3-Clause License
* Copyright (c) 2025, Alexander Shcheglov
*/

#define _GNU_SOURCE
#include "client_history.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <inttypes.h>
#include <stdarg.h>

#define HISTORY_PATH "/var/lib/gorgona/history.log"

/* Fixed offsets for the header line (Length: 48 bytes) */
typedef struct {
    char label[8];       // "MAX_ID: "
    char id_str[20];     // "00000167..."
    char ptr_lbl[6];     // " PTR: "
    char ptr_str[4];     // "0000"
    char padding[9];     // spaces
    char nl;             // '\n'
} LogHeader;

/* Fixed offsets for a log entry line (Length: 48 bytes) 
 * Structure: ENTRY: (7) + ID (20) + | (1) + TIME (19) + \n (1) = 48 bytes 
 */
typedef struct {
    char prefix[7];      // "ENTRY: "
    char id_str[20];     // "00000167..."
    char sep[1];         // "|"
    char time_str[19];   // "2026-04-19 10:24:05"
    char nl;             // '\n'
} LogLine;

static uint8_t *mapped_data = NULL;
static size_t mapped_size = 0;
static int history_fd = -1;

/**
 * Internal helper to write digits without adding a null terminator.
 */
static void write_fixed_str(char *dest, int len, const char *fmt, ...) {
    char tmp[64];
    va_list args;
    va_start(args, fmt);
    int written = vsnprintf(tmp, sizeof(tmp), fmt, args);
    va_end(args);
    
    if (written > 0) {
        memcpy(dest, tmp, (written > len) ? len : written);
    }
}

void client_history_init(void) {
    mapped_size = sizeof(LogHeader) + (sizeof(LogLine) * LOG_MAX_ENTRIES);
    
    history_fd = open(HISTORY_PATH, O_RDWR | O_CREAT, 0644);
    if (history_fd < 0) return;

    if (ftruncate(history_fd, mapped_size) == -1) {
        close(history_fd);
        return;
    }

    mapped_data = mmap(NULL, mapped_size, PROT_READ | PROT_WRITE, MAP_SHARED, history_fd, 0);
    if (mapped_data == MAP_FAILED) {
        mapped_data = NULL;
        close(history_fd);
        return;
    }

    LogHeader *hdr = (LogHeader *)mapped_data;
    /* Initialize file with clean template if it's a new log */
    if (strncmp(hdr->label, "MAX_ID:", 7) != 0) {
        memset(mapped_data, ' ', mapped_size);
        
        memcpy(hdr->label,   "MAX_ID: ", 8);
        memcpy(hdr->id_str,  "00000000000000000000", 20);
        memcpy(hdr->ptr_lbl, " PTR: ", 6);
        memcpy(hdr->ptr_str, "0000", 4);
        hdr->nl = '\n';

        for (int i = 0; i < LOG_MAX_ENTRIES; i++) {
            LogLine *line = (LogLine *)(mapped_data + sizeof(LogHeader) + (i * sizeof(LogLine)));
            memcpy(line->prefix, "ENTRY: ", 7);
            memcpy(line->sep,    "|", 1);
            line->nl = '\n';
        }
    }
}

bool client_history_is_new(uint64_t id) {
    if (!mapped_data) return true;

    char search_id[21];
    snprintf(search_id, sizeof(search_id), "%020" PRIu64, id);

    for (int i = 0; i < LOG_MAX_ENTRIES; i++) {
        LogLine *line = (LogLine *)(mapped_data + sizeof(LogHeader) + (i * sizeof(LogLine)));
        /* Using memcmp for maximum speed and NULL-safety */
        if (memcmp(line->id_str, search_id, 20) == 0) {
            return false;
        }
    }

    return true;
}

void client_history_record(uint64_t id) {
    if (!mapped_data) return;

    LogHeader *hdr = (LogHeader *)mapped_data;
    
    char tmp_ptr[5] = {0};
    memcpy(tmp_ptr, hdr->ptr_str, 4);
    unsigned int current_idx = (unsigned int)atoi(tmp_ptr);
    if (current_idx >= LOG_MAX_ENTRIES) current_idx = 0;

    /* Update the Pulse ID */
    uint64_t old_max = strtoull(hdr->id_str, NULL, 10);
    if (id > old_max) {
        write_fixed_str(hdr->id_str, 20, "%020" PRIu64, id);
    }

    /* Target the current ring buffer entry */
    LogLine *line = (LogLine *)(mapped_data + sizeof(LogHeader) + (current_idx * sizeof(LogLine)));
    
    /* Write Alert ID */
    write_fixed_str(line->id_str, 20, "%020" PRIu64, id);
    
    /* Write timestamp including SECONDS */
    time_t now = time(NULL);
    struct tm tm_info;
    if (gmtime_r(&now, &tm_info)) {
        char t_buf[24];
        strftime(t_buf, sizeof(t_buf), "%Y-%m-%d %H:%M:%S", &tm_info);
        memcpy(line->time_str, t_buf, 19);
    }
    
    /* Increment pointer */
    current_idx = (current_idx + 1) % LOG_MAX_ENTRIES;
    write_fixed_str(hdr->ptr_str, 4, "%04u", current_idx);
}
