/* 
* BSD 3-Clause License
* Copyright (c) 2025, Alexander Shcheglov
* All rights reserved. 
*/

#ifndef ALERT_DB_H
#define ALERT_DB_H

#include "gorgona_utils.h"
#include <stdint.h>
#include <sys/file.h>
#include <sys/mman.h>

/* Path to the database directory */
#define ALERT_DB_DIR "/var/lib/gorgona/alerts/"
/* The magic number for the file header */
#define ALERT_FILE_MAGIC 0xCAFEBABE
/* Delimiter for separating records */
#define ALERT_RECORD_DELIMITER 0xDEADBEEF

/* File header structure */
typedef struct {
    uint32_t magic; /* ALERT_FILE_MAGIC */
    uint32_t count; /* Number of alerts */
} AlertFileHeader;

/* Database initialization (creating a directory) */
int alert_db_init(void);

/* Import all alerts from files into recipients */
int alert_db_load_recipients(void);

/* Saving a single alert to a recipient file via mmap */
int alert_db_save_alert(Recipient *rec, Alert *alert);

/* Instant deactivation of an alert based on a pointer in mmap */
void alert_db_deactivate_alert(Alert *alert);

/* Clearing expired alerts and compressing the file (Vacuum) */
int alert_db_sync(Recipient *rec);

void alert_db_close_all(void);

int alert_db_revoke_by_id(Recipient *rec, uint64_t id);

#endif
