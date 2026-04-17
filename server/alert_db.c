/* 
* BSD 3-Clause License
* Copyright (c) 2025, Alexander Shcheglov
* All rights reserved. 
*/

#include "alert_db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
/* include <errno.h> */
#include <sys/mman.h>
#include <fcntl.h>
#include "encrypt.h"

extern int verbose;
extern int max_alerts;

/* A helper function for synchronizing mmap with memory pages */
static int safe_msync(void *addr, size_t len, int flags) {
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) page_size = 4096;
    uintptr_t start = (uintptr_t)addr & ~(page_size - 1);
    size_t full_len = (uintptr_t)addr + len - start;
    return msync((void *)start, full_len, flags);
}

void alert_db_close_all() {
    if (verbose) fprintf(stderr, "Closing alert database and syncing mmap regions...\n");
    for (int r = 0; r < recipient_count; r++) {
        if (recipients[r].mmap_ptr) {
            safe_msync(recipients[r].mmap_ptr, recipients[r].mmap_size, MS_SYNC);
            munmap(recipients[r].mmap_ptr, recipients[r].mmap_size);
            recipients[r].mmap_ptr = NULL;
        }
        if (recipients[r].fd >= 0) {
            fsync(recipients[r].fd);
            close(recipients[r].fd);
            recipients[r].fd = -1;
        }
    }
}

static void update_alert_pointers(Recipient *rec, unsigned char *old_base, unsigned char *new_base) {
    if (!old_base || !new_base || old_base == new_base) return;
    for (int i = 0; i < rec->count; i++) {
        Alert *a = &rec->alerts[i];
        if (a->is_mmaped) {
            if (a->active_ptr) a->active_ptr = (uint64_t *)(new_base + ((unsigned char *)a->active_ptr - old_base));
            if (a->text) a->text = new_base + (a->text - old_base);
            if (a->encrypted_key) a->encrypted_key = new_base + (a->encrypted_key - old_base);
            if (a->iv) a->iv = new_base + (a->iv - old_base);
        }
    }
}

int alert_db_init(void) {
    struct stat st = {0};
    if (stat(ALERT_DB_DIR, &st) == -1) {
        if (mkdir(ALERT_DB_DIR, 0700) == -1) return -1;
    }     
    return 0;
}

/*
 * Ensure_mmap_capacity,
 * The function does not truncate the file if it is larger on disk than in memory. 
 */
static int ensure_mmap_capacity(Recipient *rec, size_t additional_size) {
    if (rec->fd < 0) {
        char filename[512];
        char *hash_b64 = base64_encode(rec->hash, PUBKEY_HASH_LEN);
        snprintf(filename, sizeof(filename), "%s%s.alerts", ALERT_DB_DIR, hash_b64);
        free(hash_b64);
        rec->fd = open(filename, O_RDWR | O_CREAT, 0600);
        if (rec->fd < 0) return -1;
    }

    struct stat st;
    fstat(rec->fd, &st);
    size_t current_disk_size = st.st_size;
    size_t required = rec->used_size + additional_size;

    /* We only expand the file if there really isn't enough space */
    if (required > current_disk_size || !rec->mmap_ptr) {
        size_t target_size = (required > current_disk_size) ? required : current_disk_size;
        size_t new_size = ((target_size / (1024 * 1024)) + 1) * (1024 * 1024);
        
        if (new_size > current_disk_size) {
            if (ftruncate(rec->fd, new_size) != 0) return -1;
            fsync(rec->fd);
        }

        unsigned char *old_ptr = rec->mmap_ptr;
        unsigned char *new_ptr = mmap(NULL, new_size, PROT_READ | PROT_WRITE, MAP_SHARED, rec->fd, 0);
        if (new_ptr == MAP_FAILED) return -1;

        update_alert_pointers(rec, old_ptr, new_ptr);
        if (old_ptr) munmap(old_ptr, rec->mmap_size);
        
        rec->mmap_ptr = new_ptr;
        rec->mmap_size = new_size;
    }
    return 0;
}

void alert_db_deactivate_alert(Alert *alert) {
    alert->active = 0;
    if (alert->active_ptr) {
        *(alert->active_ptr) = 0;
        safe_msync(alert->active_ptr, 8, MS_ASYNC);
    }
}

int alert_db_save_alert(Recipient *rec, Alert *alert) {
    /* Header layout (Fixed 64 bytes): ID(8)+C(8)+U(8)+E(8)+ACT(8)+TL(8)+KL(8)+IL(8) */
    size_t record_size = 64 + alert->text_len + alert->encrypted_key_len + alert->iv_len + GCM_TAG_LEN + 4;

    if (ensure_mmap_capacity(rec, record_size) != 0) return -1;
    flock(rec->fd, LOCK_EX);

    unsigned char *base = (unsigned char *)rec->mmap_ptr + rec->used_size;
    unsigned char *p = base;

    uint64_t v64;
    v64 = alert->id; memcpy(p, &v64, 8); p += 8;
    v64 = (uint64_t)alert->create_at; memcpy(p, &v64, 8); p += 8;
    v64 = (uint64_t)alert->unlock_at; memcpy(p, &v64, 8); p += 8;
    v64 = (uint64_t)alert->expire_at; memcpy(p, &v64, 8); p += 8;
    
    alert->active_ptr = (uint64_t *)p; 
    v64 = (uint64_t)alert->active; memcpy(p, &v64, 8); p += 8;

    v64 = (uint64_t)alert->text_len; memcpy(p, &v64, 8); p += 8;
    v64 = (uint64_t)alert->encrypted_key_len; memcpy(p, &v64, 8); p += 8;
    v64 = (uint64_t)alert->iv_len; memcpy(p, &v64, 8); p += 8;

    memcpy(p, alert->text, alert->text_len); p += alert->text_len;
    memcpy(p, alert->encrypted_key, alert->encrypted_key_len); p += alert->encrypted_key_len;
    memcpy(p, alert->iv, alert->iv_len); p += alert->iv_len;
    memcpy(p, alert->tag, GCM_TAG_LEN); p += GCM_TAG_LEN;

    uint32_t del = ALERT_RECORD_DELIMITER;
    memcpy(p, &del, 4); 

    if (!alert->is_mmaped) {
        free(alert->text); free(alert->encrypted_key); free(alert->iv);
    }

    alert->text = base + 64;
    alert->encrypted_key = alert->text + alert->text_len;
    alert->iv = alert->encrypted_key + alert->encrypted_key_len;
    alert->is_mmaped = true;

    rec->used_size += record_size;
    safe_msync(base, record_size, MS_SYNC);
    
    flock(rec->fd, LOCK_UN);
    return 0;
}

int alert_db_load_recipients(void) {
    DIR *dir = opendir(ALERT_DB_DIR);
    if (!dir) return -1;
    struct dirent *entry;
    while ((entry = readdir(dir))) {
        char *ext = strstr(entry->d_name, ".alerts");
        if (ext && strcmp(ext, ".alerts") == 0) {
            char b64[256]; strncpy(b64, entry->d_name, ext - entry->d_name);
            b64[ext - entry->d_name] = '\0';
            size_t dlen; unsigned char *raw = base64_decode(b64, &dlen);
            if (!raw) continue;
            unsigned char hash[PUBKEY_HASH_LEN] = {0};
            memcpy(hash, raw, (dlen < PUBKEY_HASH_LEN) ? dlen : PUBKEY_HASH_LEN);
            free(raw);
            Recipient *rec = add_recipient(hash);
            /* Important: Map the existing file WITHOUT changing its size */
            if (!rec || ensure_mmap_capacity(rec, 0) != 0 || !rec->mmap_ptr) continue;

            struct stat st; fstat(rec->fd, &st);
            unsigned char *base = (unsigned char *)rec->mmap_ptr;
            size_t offset = 0;
            int corrupted = 0;

            while (offset + 64 <= (size_t)st.st_size) {
                unsigned char *p = base + offset;
                uint64_t id; memcpy(&id, p, 8);
                if (id == 0) break; 

                if (rec->count >= rec->capacity) {
                    rec->capacity += 128;
                    rec->alerts = realloc(rec->alerts, rec->capacity * sizeof(Alert));
                }

                Alert *a = &rec->alerts[rec->count];
                memset(a, 0, sizeof(Alert));
                a->id = id; p += 8;
                uint64_t t64;
                memcpy(&t64, p, 8); a->create_at = (time_t)t64; p += 8;
                memcpy(&t64, p, 8); a->unlock_at = (time_t)t64; p += 8;
                memcpy(&t64, p, 8); a->expire_at = (time_t)t64; p += 8;
                a->active_ptr = (uint64_t *)p;
                memcpy(&t64, p, 8); a->active = (int)t64; p += 8;
                memcpy(&t64, p, 8); a->text_len = (size_t)t64; p += 8;
                memcpy(&t64, p, 8); a->encrypted_key_len = (size_t)t64; p += 8;
                memcpy(&t64, p, 8); a->iv_len = (size_t)t64; p += 8;

                size_t payload = a->text_len + a->encrypted_key_len + a->iv_len + GCM_TAG_LEN + 4;
                if (offset + 64 + payload > (size_t)st.st_size) { corrupted = 1; break; }

                a->text = base + offset + 64;
                a->encrypted_key = a->text + a->text_len;
                a->iv = a->encrypted_key + a->encrypted_key_len;
                memcpy(a->tag, a->iv + a->iv_len, GCM_TAG_LEN);
                uint32_t del; memcpy(&del, a->iv + a->iv_len + GCM_TAG_LEN, 4);

                if (del != ALERT_RECORD_DELIMITER) { corrupted = 1; break; }
                a->is_mmaped = true; rec->count++; offset += (64 + payload);
            }
            rec->used_size = offset;
            if (corrupted) {
                if (verbose) fprintf(stderr, "Auto-healing corrupted database: %s\n", b64);
                alert_db_sync(rec);
            }
        }
    }
    closedir(dir);
    return 0;
}

/**
 * Synchronizes the recipient's alert database.
 * This function performs a "Vacuum" operation: it removes inactive/expired alerts,
 * rebuilds the file to reclaim space, and updates memory-mapped pointers.
 * 
 * @return 1 if the recipient was empty and deleted from disk (memory structure remains), 
 *         0 if synchronization was successful and recipient remains on disk,
 *        -1 on critical I/O error.
 */
int alert_db_sync(Recipient *rec) {
    char filename[512], tmp[512];
    char *hash_b64 = base64_encode(rec->hash, PUBKEY_HASH_LEN);
    
    snprintf(filename, sizeof(filename), "%s%s.alerts", ALERT_DB_DIR, hash_b64);
    snprintf(tmp, sizeof(tmp), "%s%s.alerts.tmp", ALERT_DB_DIR, hash_b64);
    free(hash_b64);

    /* Count active alerts to determine if the file should be kept or deleted */
    int active_count = 0;
    for (int i = 0; i < rec->count; i++) {
        if (rec->alerts[i].active) active_count++;
    }

    /* CASE 1: No active alerts left. Remove the physical file. */
    if (active_count == 0) {
        if (verbose) {
            fprintf(stderr, "No active alerts left for recipient. Deleting file: %s\n", filename);
        }
        
        /* Unmap memory and close file descriptor to release the file lock */
        if (rec->mmap_ptr) {
            munmap(rec->mmap_ptr, rec->mmap_size);
            rec->mmap_ptr = NULL;
        }
        if (rec->fd >= 0) {
            close(rec->fd);
            rec->fd = -1;
        }
        
        /* Remove files from the filesystem */
        unlink(filename); 
        unlink(tmp);      

        /* 
         * IMPORTANT: We do NOT free(rec->alerts) here. 
         * This function is often called by add_alert(). If we free the array now, 
         * add_alert() will crash when it tries to write the new alert to memory.
         * The memory will be freed later by the global maintenance loop.
         */
        
        /* Reset tracking metrics but keep the recipient "alive" in memory */
        rec->count = 0;
        rec->used_size = 0;
        rec->waste_count = 0;

        return 1; /* Signal: File deleted, but memory structure is still needed */
    }

    /* CASE 2: Active alerts exist. Rebuild the file to reclaim space (Vacuuming). */
    int t_fd = open(tmp, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (t_fd < 0) return -1;

    /* Write only active alerts to the temporary file */
    for (int i = 0; i < rec->count; i++) {
        Alert *a = &rec->alerts[i];
        if (!a->active) continue;
        
        uint64_t v64;
        v64 = a->id; write(t_fd, &v64, 8);
        v64 = (uint64_t)a->create_at; write(t_fd, &v64, 8);
        v64 = (uint64_t)a->unlock_at; write(t_fd, &v64, 8);
        v64 = (uint64_t)a->expire_at; write(t_fd, &v64, 8);
        v64 = (uint64_t)a->active; write(t_fd, &v64, 8);
        v64 = (uint64_t)a->text_len; write(t_fd, &v64, 8);
        v64 = (uint64_t)a->encrypted_key_len; write(t_fd, &v64, 8);
        v64 = (uint64_t)a->iv_len; write(t_fd, &v64, 8);
        write(t_fd, a->text, a->text_len);
        write(t_fd, a->encrypted_key, a->encrypted_key_len);
        write(t_fd, a->iv, a->iv_len);
        write(t_fd, a->tag, GCM_TAG_LEN);
        uint32_t del = ALERT_RECORD_DELIMITER; write(t_fd, &del, 4);
    }

    /* Sync to physical disk and close */
    fsync(t_fd); 
    close(t_fd);

    /* Close old handles before replacement */
    if (rec->mmap_ptr) munmap(rec->mmap_ptr, rec->mmap_size);
    if (rec->fd >= 0) close(rec->fd);

    /* Atomic swap */
    rename(tmp, filename);

    /* Re-open and re-map the optimized file */
    rec->fd = open(filename, O_RDWR, 0600);
    if (rec->fd < 0) return -1;

    struct stat st; 
    fstat(rec->fd, &st);
    rec->used_size = st.st_size;
    
    /* Re-allocate mmap space (1MB aligned) */
    rec->mmap_size = ((rec->used_size / (1024*1024)) + 1) * (1024*1024);
    if (ftruncate(rec->fd, rec->mmap_size) != 0) return -1;
    fsync(rec->fd);

    rec->mmap_ptr = mmap(NULL, rec->mmap_size, PROT_READ|PROT_WRITE, MAP_SHARED, rec->fd, 0);
    if (rec->mmap_ptr == MAP_FAILED) {
        rec->mmap_ptr = NULL;
        return -1;
    }
    
    size_t off = 0; 
    int j = 0;
    unsigned char *base = (unsigned char *)rec->mmap_ptr;
    
    /* Update memory pointers for the existing Alert array to point into the new mmap */
    for (int i = 0; i < rec->count; i++) {
        if (!rec->alerts[i].active) continue;
        
        Alert *a = &rec->alerts[j]; 
        if (i != j) *a = rec->alerts[i];
        
        unsigned char *p = base + off;
        a->active_ptr = (uint64_t *)(p + 32); 
        a->text = p + 64;
        a->encrypted_key = a->text + a->text_len;
        a->iv = a->encrypted_key + a->encrypted_key_len;
        a->is_mmaped = true;
        
        off += (64 + a->text_len + a->encrypted_key_len + a->iv_len + GCM_TAG_LEN + 4);
        j++;
    }
    
    rec->count = j;
    rec->waste_count = 0; 
    
    return 0; /* Sync complete, recipient remains active */
}
