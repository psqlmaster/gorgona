/* BSD 3-Clause License
Copyright (c) 2025, Alexander Shcheglov
All rights reserved. */
#include "alert_db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <sys/mman.h>
#include <fcntl.h>
#include "encrypt.h"

extern int verbose;
extern int max_alerts;

/* Закрытие всех файловых дескрипторов и mmap при выходе */
void alert_db_close_all() {
    for (int r = 0; r < recipient_count; r++) {
        if (recipients[r].mmap_ptr) {
            munmap(recipients[r].mmap_ptr, recipients[r].mmap_size);
            recipients[r].mmap_ptr = NULL;
        }
        if (recipients[r].fd >= 0) {
            close(recipients[r].fd);
            recipients[r].fd = -1;
        }
    }
}

/* Обновление указателей в памяти Alert при изменении адреса mmap (реаллокация файла) */
static void update_alert_pointers(Recipient *rec, unsigned char *old_base, unsigned char *new_base) {
    if (!old_base || !new_base || old_base == new_base) return;
    
    for (int i = 0; i < rec->count; i++) {
        Alert *a = &rec->alerts[i];
        if (a->is_mmaped) {
            if (a->active_ptr) {
                size_t offset = (unsigned char *)a->active_ptr - old_base;
                a->active_ptr = (int *)(new_base + offset);
            }
            if (a->text) {
                size_t offset = a->text - old_base;
                a->text = new_base + offset;
            }
            if (a->encrypted_key) {
                size_t offset = a->encrypted_key - old_base;
                a->encrypted_key = new_base + offset;
            }
            if (a->iv) {
                size_t offset = a->iv - old_base;
                a->iv = new_base + offset;
            }
        }
    }
}

int alert_db_init(void) {
    struct stat st = {0};
    if (stat(ALERT_DB_DIR, &st) == -1) {
        if (mkdir(ALERT_DB_DIR, 0700) == -1) {
            fprintf(stderr, "Failed to create directory %s: %s\n", ALERT_DB_DIR, strerror(errno));
            return -1;
        }
    }     
    return 0;
}

static int ensure_mmap_capacity(Recipient *rec, size_t additional_size) {
    if (rec->fd < 0) {
        char filename[512];
        char *hash_b64 = base64_encode(rec->hash, PUBKEY_HASH_LEN);
        snprintf(filename, sizeof(filename), "%s%s.alerts", ALERT_DB_DIR, hash_b64);
        free(hash_b64);
        rec->fd = open(filename, O_RDWR | O_CREAT, 0600);
        if (rec->fd < 0) return -1;
    }

    size_t required = rec->used_size + additional_size;
    if (required > rec->mmap_size || !rec->mmap_ptr) {
        /* Расширяем файл блоками по 1 МБ */
        size_t new_size = ((required / (1024 * 1024)) + 1) * (1024 * 1024);
        if (ftruncate(rec->fd, new_size) != 0) return -1;

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
    }
}

int alert_db_save_alert(Recipient *rec, Alert *alert) {
    /* Фиксированные размеры полей для стабильности бинарного формата */
    size_t record_size = 8 + (8 * 3) + sizeof(int) + (8 * 3) + 
                         alert->text_len + alert->encrypted_key_len + alert->iv_len + 
                         GCM_TAG_LEN + 4;

    if (ensure_mmap_capacity(rec, record_size) != 0) return -1;
    flock(rec->fd, LOCK_EX);

    unsigned char *base = (unsigned char *)rec->mmap_ptr + rec->used_size;
    unsigned char *p = base;

    uint64_t tmp64;
    tmp64 = alert->id; memcpy(p, &tmp64, 8); p += 8;
    tmp64 = (uint64_t)alert->create_at; memcpy(p, &tmp64, 8); p += 8;
    tmp64 = (uint64_t)alert->unlock_at; memcpy(p, &tmp64, 8); p += 8;
    tmp64 = (uint64_t)alert->expire_at; memcpy(p, &tmp64, 8); p += 8;
    
    alert->active_ptr = (int *)p;
    memcpy(p, &alert->active, sizeof(int)); p += sizeof(int);

    tmp64 = (uint64_t)alert->text_len; memcpy(p, &tmp64, 8); p += 8;
    tmp64 = (uint64_t)alert->encrypted_key_len; memcpy(p, &tmp64, 8); p += 8;
    tmp64 = (uint64_t)alert->iv_len; memcpy(p, &tmp64, 8); p += 8;

    memcpy(p, alert->text, alert->text_len); p += alert->text_len;
    memcpy(p, alert->encrypted_key, alert->encrypted_key_len); p += alert->encrypted_key_len;
    memcpy(p, alert->iv, alert->iv_len); p += alert->iv_len;
    memcpy(p, alert->tag, GCM_TAG_LEN); p += GCM_TAG_LEN;

    uint32_t delimiter = ALERT_RECORD_DELIMITER;
    memcpy(p, &delimiter, 4); 

    if (!alert->is_mmaped) {
        free(alert->text); free(alert->encrypted_key); free(alert->iv);
    }

    /* Мапим Alert на область в mmap */
    unsigned char *mmap_data = base + (8 + 8*3 + sizeof(int) + 8*3);
    alert->text = mmap_data;
    alert->encrypted_key = mmap_data + alert->text_len;
    alert->iv = mmap_data + alert->text_len + alert->encrypted_key_len;
    alert->is_mmaped = true;

    rec->used_size += record_size;
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
            char b64[256];
            size_t b64_len = ext - entry->d_name;
            strncpy(b64, entry->d_name, b64_len);
            b64[b64_len] = '\0';

            size_t decoded_len;
            unsigned char *decoded_raw = base64_decode(b64, &decoded_len);
            if (!decoded_raw) continue;

            unsigned char fixed_hash[PUBKEY_HASH_LEN] = {0};
            memcpy(fixed_hash, decoded_raw, (decoded_len < PUBKEY_HASH_LEN) ? decoded_len : PUBKEY_HASH_LEN);
            free(decoded_raw);

            Recipient *rec = add_recipient(fixed_hash);
            if (!rec) continue;
            
            if (ensure_mmap_capacity(rec, 0) != 0 || !rec->mmap_ptr) continue;

            struct stat st;
            fstat(rec->fd, &st);
            
            size_t offset = 0;
            unsigned char *base = (unsigned char *)rec->mmap_ptr;
            int corrupted_found = 0;

            while (offset + 8 <= (size_t)st.st_size) {
                unsigned char *p = base + offset;
                uint64_t test_id;
                memcpy(&test_id, p, 8);
                if (test_id == 0) break; 

                if (rec->count >= rec->capacity) {
                    int new_capacity = rec->capacity + 128;
                    Alert *new_alerts = realloc(rec->alerts, new_capacity * sizeof(Alert));
                    if (!new_alerts) break;
                    rec->alerts = new_alerts;
                    rec->capacity = new_capacity;
                }

                Alert *a = &rec->alerts[rec->count];
                memset(a, 0, sizeof(Alert));
                
                a->id = test_id; p += 8;
                uint64_t v64;
                memcpy(&v64, p, 8); a->create_at = (time_t)v64; p += 8;
                memcpy(&v64, p, 8); a->unlock_at = (time_t)v64; p += 8;
                memcpy(&v64, p, 8); a->expire_at = (time_t)v64; p += 8;
                
                a->active_ptr = (int *)p; 
                memcpy(&a->active, p, sizeof(int)); p += sizeof(int);

                memcpy(&v64, p, 8); a->text_len = (size_t)v64; p += 8;
                memcpy(&v64, p, 8); a->encrypted_key_len = (size_t)v64; p += 8;
                memcpy(&v64, p, 8); a->iv_len = (size_t)v64; p += 8;

                size_t payload_and_meta = a->text_len + a->encrypted_key_len + a->iv_len + GCM_TAG_LEN + 4;
                if ((size_t)(p - base) + payload_and_meta > (size_t)st.st_size) {
                    corrupted_found = 1;
                    break;
                }

                a->text = p; p += a->text_len;
                a->encrypted_key = p; p += a->encrypted_key_len;
                a->iv = p; p += a->iv_len;
                memcpy(a->tag, p, GCM_TAG_LEN); p += GCM_TAG_LEN;
                
                uint32_t delimiter; 
                memcpy(&delimiter, p, 4); p += 4;
                
                if (delimiter == ALERT_RECORD_DELIMITER) {
                    a->is_mmaped = true;
                    rec->count++;
                    offset = (size_t)(p - base);
                } else {
                    corrupted_found = 1;
                    break;
                }
            }
            rec->used_size = offset;

            /* АВТОМАТИЧЕСКОЕ ЛЕЧЕНИЕ: если найден мусор, перезаписываем файл без него */
            if (corrupted_found) {
                if (verbose) fprintf(stderr, "Auto-healing corrupted database for key %s\n", b64);
                alert_db_sync(rec);
            }
        }
    }
    closedir(dir);
    return 0;
}

int alert_db_sync(Recipient *rec) {
    char filename[512], tmp[512];
    char *hash_b64 = base64_encode(rec->hash, PUBKEY_HASH_LEN);
    snprintf(filename, sizeof(filename), "%s%s.alerts", ALERT_DB_DIR, hash_b64);
    snprintf(tmp, sizeof(tmp), "%s%s.alerts.tmp", ALERT_DB_DIR, hash_b64);
    free(hash_b64);

    int t_fd = open(tmp, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (t_fd < 0) return -1;

    for (int i = 0; i < rec->count; i++) {
        Alert *a = &rec->alerts[i];
        if (!a->active) continue;
        uint64_t v64;
        v64 = a->id; write(t_fd, &v64, 8);
        v64 = (uint64_t)a->create_at; write(t_fd, &v64, 8);
        v64 = (uint64_t)a->unlock_at; write(t_fd, &v64, 8);
        v64 = (uint64_t)a->expire_at; write(t_fd, &v64, 8);
        write(t_fd, &a->active, sizeof(int));
        v64 = (uint64_t)a->text_len; write(t_fd, &v64, 8);
        v64 = (uint64_t)a->encrypted_key_len; write(t_fd, &v64, 8);
        v64 = (uint64_t)a->iv_len; write(t_fd, &v64, 8);
        write(t_fd, a->text, a->text_len);
        write(t_fd, a->encrypted_key, a->encrypted_key_len);
        write(t_fd, a->iv, a->iv_len);
        write(t_fd, a->tag, GCM_TAG_LEN);
        uint32_t del = ALERT_RECORD_DELIMITER;
        write(t_fd, &del, 4);
    }
    close(t_fd);

    if (rec->mmap_ptr) munmap(rec->mmap_ptr, rec->mmap_size);
    if (rec->fd >= 0) close(rec->fd);
    
    rename(tmp, filename);
    
    rec->fd = open(filename, O_RDWR, 0600);
    struct stat st; fstat(rec->fd, &st);
    rec->used_size = st.st_size;
    /* Устанавливаем размер mmap кратным 1 МБ */
    rec->mmap_size = ((rec->used_size / (1024*1024)) + 1) * (1024*1024);
    ftruncate(rec->fd, rec->mmap_size);
    rec->mmap_ptr = mmap(NULL, rec->mmap_size, PROT_READ|PROT_WRITE, MAP_SHARED, rec->fd, 0);

    /* Перепривязываем указатели к новому mmap */
    size_t off = 0; int j = 0;
    for (int i = 0; i < rec->count; i++) {
        if (!rec->alerts[i].active) continue;
        Alert *a = &rec->alerts[j]; 
        if (i != j) *a = rec->alerts[i];
        unsigned char *p = (unsigned char *)rec->mmap_ptr + off;
        p += 8 + 8*3; // id + timestamps
        a->active_ptr = (int *)p; p += sizeof(int);
        p += 8*3; // lengths
        a->text = p; p += a->text_len;
        a->encrypted_key = p; p += a->encrypted_key_len;
        a->iv = p; p += a->iv_len;
        off = (size_t)(p + GCM_TAG_LEN + 4 - (unsigned char *)rec->mmap_ptr);
        j++;
    }
    rec->count = j;
    return 0;
}
