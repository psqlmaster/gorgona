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

void alert_db_close_all() {
    for (int r = 0; r < recipient_count; r++) {
        if (recipients[r].mmap_ptr) {
            // munmap гарантирует, что изменения будут записаны в файл
            munmap(recipients[r].mmap_ptr, recipients[r].mmap_size);
            recipients[r].mmap_ptr = NULL;
        }
        if (recipients[r].fd >= 0) {
            close(recipients[r].fd);
            recipients[r].fd = -1;
        }
    }
}

/* Вспомогательная функция для обновления указателей алертов при смене адреса mmap */
static void update_alert_pointers(Recipient *rec, unsigned char *old_base, unsigned char *new_base) {
    if (!old_base || !new_base || old_base == new_base) return;
    
    for (int i = 0; i < rec->count; i++) {
        Alert *a = &rec->alerts[i];
        if (a->is_mmaped) {
            /* Вычисляем смещение относительно старого адреса и применяем к новому */
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
        if (verbose) fprintf(stderr, "Created directory %s\n", ALERT_DB_DIR);
    }     
    return 0;
}

static int ensure_mmap_capacity(Recipient *rec, size_t additional_size) {
    if (rec->fd < 0) { /* Исправлено: FD инициализируется -1 */
        char filename[512];
        char *hash_b64 = base64_encode(rec->hash, PUBKEY_HASH_LEN);
        snprintf(filename, sizeof(filename), "%s%s.alerts", ALERT_DB_DIR, hash_b64);
        free(hash_b64);
        rec->fd = open(filename, O_RDWR | O_CREAT, 0600);
        if (rec->fd < 0) return -1;
    }

    size_t required = rec->used_size + additional_size;
    if (required > rec->mmap_size || !rec->mmap_ptr) {
        size_t new_size = ((required / (1024 * 1024)) + 1) * (1024 * 1024);
        if (ftruncate(rec->fd, new_size) != 0) return -1;

        unsigned char *old_ptr = rec->mmap_ptr;
        unsigned char *new_ptr = mmap(NULL, new_size, PROT_READ | PROT_WRITE, MAP_SHARED, rec->fd, 0);
        
        if (new_ptr == MAP_FAILED) return -1;

        /* Обновляем указатели существующих алертов на новый адрес */
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
    size_t record_size = sizeof(uint64_t) + (sizeof(time_t) * 3) + sizeof(int) + 
                         (sizeof(size_t) * 3) + alert->text_len + 
                         alert->encrypted_key_len + alert->iv_len + GCM_TAG_LEN + sizeof(uint32_t);

    if (ensure_mmap_capacity(rec, record_size) != 0) return -1;
    if (flock(rec->fd, LOCK_EX) == -1) return -1;

    unsigned char *base = (unsigned char *)rec->mmap_ptr + rec->used_size;
    unsigned char *p = base;

    memcpy(p, &alert->id, sizeof(uint64_t)); p += sizeof(uint64_t);
    memcpy(p, &alert->create_at, sizeof(time_t)); p += sizeof(time_t);
    memcpy(p, &alert->unlock_at, sizeof(time_t)); p += sizeof(time_t);
    memcpy(p, &alert->expire_at, sizeof(time_t)); p += sizeof(time_t);
    
    alert->active_ptr = (int *)p;
    memcpy(p, &alert->active, sizeof(int)); p += sizeof(int);

    memcpy(p, &alert->text_len, sizeof(size_t)); p += sizeof(size_t);
    memcpy(p, &alert->encrypted_key_len, sizeof(size_t)); p += sizeof(size_t);
    memcpy(p, &alert->iv_len, sizeof(size_t)); p += sizeof(size_t);

    memcpy(p, alert->text, alert->text_len); p += alert->text_len;
    memcpy(p, alert->encrypted_key, alert->encrypted_key_len); p += alert->encrypted_key_len;
    memcpy(p, alert->iv, alert->iv_len); p += alert->iv_len;
    memcpy(p, alert->tag, GCM_TAG_LEN); p += GCM_TAG_LEN;

    uint32_t delimiter = ALERT_RECORD_DELIMITER;
    memcpy(p, &delimiter, sizeof(uint32_t)); 

    if (!alert->is_mmaped) {
        free(alert->text); free(alert->encrypted_key); free(alert->iv);
    }

    /* Теперь указываем в Alert на память в mmap */
    unsigned char *mmap_data = base + (sizeof(uint64_t) + sizeof(time_t)*3 + sizeof(int) + sizeof(size_t)*3);
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
    if (!dir) {
        if (verbose) perror("Could not open alert database directory");
        return 0;
    }

    struct dirent *entry;
    while ((entry = readdir(dir))) {
        // Ищем только файлы с расширением .alerts
        char *extension = strstr(entry->d_name, ".alerts");
        if (extension && strcmp(extension, ".alerts") == 0) {
            
            // 1. Получаем Base64 часть имени файла
            char b64[256];
            size_t b64_len = extension - entry->d_name;
            if (b64_len >= sizeof(b64)) b64_len = sizeof(b64) - 1;
            strncpy(b64, entry->d_name, b64_len);
            b64[b64_len] = '\0';

            // 2. Декодируем хэш и нормализуем его длину
            size_t decoded_len;
            unsigned char *decoded_raw = base64_decode(b64, &decoded_len);
            if (!decoded_raw) continue;

            // Важно: создаем чистый буфер фиксированного размера
            unsigned char fixed_hash[PUBKEY_HASH_LEN] = {0};
            memcpy(fixed_hash, decoded_raw, (decoded_len < PUBKEY_HASH_LEN) ? decoded_len : PUBKEY_HASH_LEN);
            free(decoded_raw);

            // 3. Добавляем или находим реципиента в памяти
            Recipient *rec = add_recipient(fixed_hash);
            if (!rec) continue;
            
            // Открываем mmap для файла
            if (ensure_mmap_capacity(rec, 0) != 0 || !rec->mmap_ptr) continue;

            struct stat st;
            if (fstat(rec->fd, &st) != 0) continue;
            
            size_t offset = 0;
            // 4. Парсим содержимое файла
            while (offset + sizeof(uint64_t) < (size_t)st.st_size) {
                unsigned char *p = (unsigned char *)rec->mmap_ptr + offset;
                
                // Проверка на пустой заголовок (конец данных в разреженном файле)
                uint64_t test_id;
                memcpy(&test_id, p, sizeof(uint64_t));
                if (test_id == 0) break;

                // Убеждаемся, что в памяти достаточно места под структуру Alert
                if (rec->count >= rec->capacity) {
                    int new_capacity = rec->capacity + (max_alerts > 0 ? max_alerts : 100);
                    Alert *new_alerts = realloc(rec->alerts, new_capacity * sizeof(Alert));
                    if (!new_alerts) break; 
                    rec->alerts = new_alerts;
                    rec->capacity = new_capacity;
                }

                Alert *a = &rec->alerts[rec->count];
                memset(a, 0, sizeof(Alert));
                
                // Читаем фиксированные поля заголовка записи
                a->id = test_id; p += sizeof(uint64_t);
                memcpy(&a->create_at, p, sizeof(time_t)); p += sizeof(time_t);
                memcpy(&a->unlock_at, p, sizeof(time_t)); p += sizeof(time_t);
                memcpy(&a->expire_at, p, sizeof(time_t)); p += sizeof(time_t);
                
                // Указатель на поле 'active' прямо внутри mmap
                a->active_ptr = (int *)p; 
                memcpy(&a->active, p, sizeof(int)); p += sizeof(int);

                // Читаем длины переменных данных
                memcpy(&a->text_len, p, sizeof(size_t)); p += sizeof(size_t);
                memcpy(&a->encrypted_key_len, p, sizeof(size_t)); p += sizeof(size_t);
                memcpy(&a->iv_len, p, sizeof(size_t)); p += sizeof(size_t);

                // Безопасность: проверяем, не выходят ли данные за пределы файла
                size_t remaining_in_file = (size_t)st.st_size - (size_t)(p - (unsigned char *)rec->mmap_ptr);
                size_t data_needed = a->text_len + a->encrypted_key_len + a->iv_len + GCM_TAG_LEN + sizeof(uint32_t);
                
                if (data_needed > remaining_in_file) {
                    if (verbose) fprintf(stderr, "Corrupted alert record for hash %s, skipping remaining\n", b64);
                    break;
                }

                // Устанавливаем указатели прямо в область mmap
                a->text = p; p += a->text_len;
                a->encrypted_key = p; p += a->encrypted_key_len;
                a->iv = p; p += a->iv_len;
                
                memcpy(a->tag, p, GCM_TAG_LEN); p += GCM_TAG_LEN;
                
                uint32_t del; 
                memcpy(&del, p, sizeof(uint32_t)); p += sizeof(uint32_t);
                
                // Проверяем магическое число-разделитель
                if (del == ALERT_RECORD_DELIMITER) {
                    a->is_mmaped = true;
                    rec->count++;
                    offset = (size_t)(p - (unsigned char *)rec->mmap_ptr);
                } else {
                    if (verbose) fprintf(stderr, "Delimiter mismatch in database for %s at offset %zu\n", b64, offset);
                    break;
                }
            }
            rec->used_size = offset;
            if (verbose && rec->count > 0) {
                printf("Loaded %d alerts for recipient %s\n", rec->count, b64);
            }
        }
    }
    closedir(dir);
    return 0;
}

int alert_db_sync(Recipient *rec) {
    if (rec->count == 0) return 0;
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
        write(t_fd, &a->id, sizeof(uint64_t));
        write(t_fd, &a->create_at, sizeof(time_t));
        write(t_fd, &a->unlock_at, sizeof(time_t));
        write(t_fd, &a->expire_at, sizeof(time_t));
        write(t_fd, &a->active, sizeof(int));
        write(t_fd, &a->text_len, sizeof(size_t));
        write(t_fd, &a->encrypted_key_len, sizeof(size_t));
        write(t_fd, &a->iv_len, sizeof(size_t));
        write(t_fd, a->text, a->text_len);
        write(t_fd, a->encrypted_key, a->encrypted_key_len);
        write(t_fd, a->iv, a->iv_len);
        write(t_fd, a->tag, GCM_TAG_LEN);
        uint32_t del = ALERT_RECORD_DELIMITER;
        write(t_fd, &del, sizeof(uint32_t));
    }
    close(t_fd);

    if (rec->mmap_ptr) munmap(rec->mmap_ptr, rec->mmap_size);
    if (rec->fd >= 0) close(rec->fd);
    
    rename(tmp, filename);
    
    rec->fd = open(filename, O_RDWR, 0600);
    struct stat st; fstat(rec->fd, &st);
    rec->used_size = st.st_size;
    rec->mmap_size = rec->used_size;
    if (rec->mmap_size > 0) rec->mmap_ptr = mmap(NULL, rec->mmap_size, PROT_READ|PROT_WRITE, MAP_SHARED, rec->fd, 0);
    else rec->mmap_ptr = NULL;

    /* Пересчитываем указатели после сжатия файла */
    size_t off = 0; int j = 0;
    for (int i = 0; i < rec->count; i++) {
        if (!rec->alerts[i].active) continue;
        Alert *a = &rec->alerts[j]; if (i != j) *a = rec->alerts[i];
        unsigned char *p = (unsigned char *)rec->mmap_ptr + off;
        p += sizeof(uint64_t) + sizeof(time_t)*3;
        a->active_ptr = (int *)p; p += sizeof(int);
        p += sizeof(size_t)*3;
        a->text = p; p += a->text_len;
        a->encrypted_key = p; p += a->encrypted_key_len;
        a->iv = p; p += a->iv_len;
        off = (size_t)(p + GCM_TAG_LEN + sizeof(uint32_t) - (unsigned char *)rec->mmap_ptr);
        j++;
    }
    rec->count = j;
    return 0;
}
