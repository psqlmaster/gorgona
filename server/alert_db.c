#include "alert_db.h"
#include <stdio.h> /* For fileno, fprintf, fopen, etc. */
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h> /* Для fileno и других POSIX функций */
#include <dirent.h>
#include <errno.h>
#include "encrypt.h" /* For GCM_TAG_LEN, PUBKEY_HASH_LEN */

/* Объявляем max_alerts как extern */
extern int max_alerts;

// Создание директории базы данных
int alert_db_init(void) {
    struct stat st = {0};
    if (stat(ALERT_DB_DIR, &st) == -1) {
        if (mkdir(ALERT_DB_DIR, 0700) == -1) {
            fprintf(stderr, "Failed to create directory %s: %s\n", ALERT_DB_DIR, strerror(errno));
            return -1;
        }
        fprintf(stderr, "Created directory %s\n", ALERT_DB_DIR);
    }     
    return 0;
}

// Чтение алертов из файла реципиента
static int load_alerts_from_file(const char *filename, Recipient *rec) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        if (errno != ENOENT) {
            fprintf(stderr, "Failed to open %s: %s\n", filename, strerror(errno));
        } else {
            fprintf(stderr, "File %s does not exist\n", filename);
        }
        return -1;
    }

    // Применяем flock для чтения
    if (flock(fileno(file), LOCK_SH) == -1) {
        fprintf(stderr, "Failed to lock %s: %s\n", filename, strerror(errno));
        fclose(file);
        return -1;
    }

    int alert_count = 0;
    while (1) {
        if (rec->count >= rec->capacity) {
            rec->capacity += max_alerts;
            rec->alerts = realloc(rec->alerts, rec->capacity * sizeof(Alert));
            if (!rec->alerts) {
                fprintf(stderr, "Failed to allocate memory for alerts\n");
                flock(fileno(file), LOCK_UN);
                fclose(file);
                return -1;
            }
        }

        Alert *alert = &rec->alerts[rec->count];
        // Читаем фиксированные поля
        if (fread(&alert->id, sizeof(uint64_t), 1, file) != 1 ||
            fread(&alert->create_at, sizeof(time_t), 1, file) != 1 ||
            fread(&alert->unlock_at, sizeof(time_t), 1, file) != 1 ||
            fread(&alert->expire_at, sizeof(time_t), 1, file) != 1 ||
            fread(&alert->active, sizeof(int), 1, file) != 1) {
            if (feof(file)) {
                break;
            }
            fprintf(stderr, "Failed to read alert metadata from %s\n", filename);
            flock(fileno(file), LOCK_UN);
            fclose(file);
            return -1;
        }

        // Читаем длины переменных полей
        size_t text_len, encrypted_key_len, iv_len;
        if (fread(&text_len, sizeof(size_t), 1, file) != 1 ||
            fread(&encrypted_key_len, sizeof(size_t), 1, file) != 1 ||
            fread(&iv_len, sizeof(size_t), 1, file) != 1) {
            fprintf(stderr, "Failed to read alert lengths from %s\n", filename);
            flock(fileno(file), LOCK_UN);
            fclose(file);
            return -1;
        }

        // Проверка размеров
        if (iv_len != 12) {
            fprintf(stderr, "Invalid alert data sizes in %s: iv_len=%zu\n", filename, iv_len);
            flock(fileno(file), LOCK_UN);
            fclose(file);
            return -1;
        }

        // Выделяем память
        alert->text = malloc(text_len);
        alert->encrypted_key = malloc(encrypted_key_len);
        alert->iv = malloc(iv_len);
        if (!alert->text || !alert->encrypted_key || !alert->iv) {
            fprintf(stderr, "Failed to allocate memory for alert data\n");
            free(alert->text);
            free(alert->encrypted_key);
            free(alert->iv);
            flock(fileno(file), LOCK_UN);
            fclose(file);
            return -1;
        }

        // Читаем данные
        if (fread(alert->text, 1, text_len, file) != text_len ||
            fread(alert->encrypted_key, 1, encrypted_key_len, file) != encrypted_key_len ||
            fread(alert->iv, 1, iv_len, file) != iv_len ||
            fread(alert->tag, 1, GCM_TAG_LEN, file) != GCM_TAG_LEN) {
            fprintf(stderr, "Failed to read alert data from %s\n", filename);
            free(alert->text);
            free(alert->encrypted_key);
            free(alert->iv);
            flock(fileno(file), LOCK_UN);
            fclose(file);
            return -1;
        }

        alert->text_len = text_len;
        alert->encrypted_key_len = encrypted_key_len;
        alert->iv_len = iv_len;

        uint32_t delimiter;
        if (fread(&delimiter, sizeof(uint32_t), 1, file) != 1 || delimiter != ALERT_RECORD_DELIMITER) {
            if (!feof(file)) {
                fprintf(stderr, "Invalid delimiter in %s\n", filename);
            }
            free(alert->text);
            free(alert->encrypted_key);
            free(alert->iv);
            flock(fileno(file), LOCK_UN);
            fclose(file);
            return -1;
        }

        rec->count++;
        alert_count++;
        if (verbose) {
            fprintf(stderr, "Loaded alert %d: id=%lu, active=%d\n", alert_count, alert->id, alert->active);
        } 
    }

    flock(fileno(file), LOCK_UN);
    fclose(file);
    if (verbose) {
        fprintf(stderr, "DEBUG: Recipient now has %d alerts\n", rec->count);
        fprintf(stderr, "Successfully loaded %d alerts from %s\n", alert_count, filename);
    } 
    return 0;
}

// Загрузка всех реципиентов из директории
int alert_db_load_recipients(void) {
    DIR *dir = opendir(ALERT_DB_DIR);
    if (!dir) {
        if (errno != ENOENT) {
            fprintf(stderr, "Failed to open directory %s: %s\n", ALERT_DB_DIR, strerror(errno));
        } else {
            fprintf(stderr, "Directory %s does not exist\n", ALERT_DB_DIR);
        }
        return 0; // Директория может не существовать при первом запуске
    }

    struct dirent *entry;
    int recipient_count = 0;
    while ((entry = readdir(dir))) {
        if (strstr(entry->d_name, ".alerts")) {
            // Извлекаем pubkey_hash_b64 (удаляем .alerts)
            char pubkey_hash_b64[256];
            strncpy(pubkey_hash_b64, entry->d_name, sizeof(pubkey_hash_b64));
            pubkey_hash_b64[strlen(pubkey_hash_b64) - 7] = '\0'; // Удаляем ".alerts"
            size_t hash_len;
            unsigned char *hash = base64_decode(pubkey_hash_b64, &hash_len);
            if (!hash || hash_len != PUBKEY_HASH_LEN) {
                fprintf(stderr, "Invalid pubkey_hash in %s\n", entry->d_name);
                free(hash);
                continue;
            }
            // Добавляем реципиента
            Recipient *rec = add_recipient(hash);
            free(hash);
            if (!rec) {
                fprintf(stderr, "Failed to add recipient for %s\n", pubkey_hash_b64);
                continue;
            }
            recipient_count++;
            if (verbose) {
                fprintf(stderr, "Added recipient %s\n", pubkey_hash_b64);
            }
            // Загружаем алерты
            char filename[512];
            snprintf(filename, sizeof(filename), "%s%s", ALERT_DB_DIR, entry->d_name);
            if (load_alerts_from_file(filename, rec) != 0) {
                fprintf(stderr, "Failed to load alerts from %s\n", filename);
                continue;
            }
        }
    }
    if (verbose) {
        fprintf(stderr, "DEBUG: After loading - recipient_count = %d\n", recipient_count);
        for (int i = 0; i < recipient_count; i++) {
            char *hash_b64 = base64_encode(recipients[i].hash, PUBKEY_HASH_LEN);
            if (verbose) {
                fprintf(stderr, "DEBUG: Recipient %d: %s, alerts count: %d\n", i, hash_b64, recipients[i].count);
            }
            free(hash_b64);
        }
        fprintf(stderr, "Loaded %d recipients\n", recipient_count);
    }        
    // Enforce limits and cleanup after loading
    for (int i = 0; i < recipient_count; i++) {
        Recipient *rec = &recipients[i];
        int original_count = rec->count;
        clean_expired_alerts(rec);  // Cleans memory and syncs disk if changed
        while (rec->count > max_alerts) {  // Enforce MAX_ALERTS if excess loaded
            remove_oldest_alert(rec);  // Removes from memory and syncs disk
        }
        if (verbose && rec->count < original_count) {
            fprintf(stderr, "Cleaned and enforced limits for recipient %d: now %d alerts\n", i, rec->count);
        }
    }
    closedir(dir);
    return 0;
}

// Сохранение алерта в файл
int alert_db_save_alert(const Recipient *rec, const Alert *alert) {
    char filename[512];
    char *pubkey_hash_b64 = base64_encode(rec->hash, PUBKEY_HASH_LEN);
    if (!pubkey_hash_b64) {
        fprintf(stderr, "Failed to encode pubkey_hash\n");
        return -1;
    }
    snprintf(filename, sizeof(filename), "%s%s.alerts", ALERT_DB_DIR, pubkey_hash_b64);
    free(pubkey_hash_b64);

    FILE *file = fopen(filename, "ab");
    if (!file) {
        fprintf(stderr, "Failed to open %s: %s\n", filename, strerror(errno));
        return -1;
    }

    // Применяем flock для записи
    if (flock(fileno(file), LOCK_EX) == -1) {
        fprintf(stderr, "Failed to lock %s: %s\n", filename, strerror(errno));
        fclose(file);
        return -1;
    }

    // Записываем фиксированные поля
    if (fwrite(&alert->id, sizeof(uint64_t), 1, file) != 1 ||
        fwrite(&alert->create_at, sizeof(time_t), 1, file) != 1 ||
        fwrite(&alert->unlock_at, sizeof(time_t), 1, file) != 1 ||
        fwrite(&alert->expire_at, sizeof(time_t), 1, file) != 1 ||
        fwrite(&alert->active, sizeof(int), 1, file) != 1) {
        fprintf(stderr, "Failed to write alert metadata to %s\n", filename);
        flock(fileno(file), LOCK_UN);
        fclose(file);
        return -1;
    }

    // Записываем длины и данные
    if (fwrite(&alert->text_len, sizeof(size_t), 1, file) != 1 ||
        fwrite(&alert->encrypted_key_len, sizeof(size_t), 1, file) != 1 ||
        fwrite(&alert->iv_len, sizeof(size_t), 1, file) != 1 ||
        fwrite(alert->text, 1, alert->text_len, file) != alert->text_len ||
        fwrite(alert->encrypted_key, 1, alert->encrypted_key_len, file) != alert->encrypted_key_len ||
        fwrite(alert->iv, 1, alert->iv_len, file) != alert->iv_len ||
        fwrite(alert->tag, 1, GCM_TAG_LEN, file) != GCM_TAG_LEN) {
        fprintf(stderr, "Failed to write alert data to %s\n", filename);
        flock(fileno(file), LOCK_UN);
        fclose(file);
        return -1;
    }

    // Записываем делимитер
    uint32_t delimiter = ALERT_RECORD_DELIMITER;
    if (fwrite(&delimiter, sizeof(uint32_t), 1, file) != 1) {
        fprintf(stderr, "Failed to write delimiter to %s\n", filename);
        flock(fileno(file), LOCK_UN);
        fclose(file);
        return -1;
    }

    flock(fileno(file), LOCK_UN);
    fclose(file);
    if (verbose) {
        fprintf(stderr, "DEBUG: Saved alert id=%lu to %s\n", alert->id, filename);
    }
    return 0;
}

// Очистка истёкших алертов
int alert_db_clean_expired(const Recipient *rec) {
    char filename[512];
    char temp_filename[512];
    char *pubkey_hash_b64 = base64_encode(rec->hash, PUBKEY_HASH_LEN);
    if (!pubkey_hash_b64) {
        fprintf(stderr, "Failed to encode pubkey_hash\n");
        return -1;
    }
    snprintf(filename, sizeof(filename), "%s%s.alerts", ALERT_DB_DIR, pubkey_hash_b64);
    snprintf(temp_filename, sizeof(temp_filename), "%s%s.alerts.tmp", ALERT_DB_DIR, pubkey_hash_b64);
    free(pubkey_hash_b64);

    fprintf(stderr, "Cleaning expired alerts from %s\n", filename);
    FILE *in_file = fopen(filename, "rb");
    if (!in_file) {
        if (errno == ENOENT) {
            fprintf(stderr, "File %s does not exist, nothing to clean\n", filename);
            return 0; // Файл не существует, ничего не делаем
        }
        fprintf(stderr, "Failed to open %s: %s\n", filename, strerror(errno));
        return -1;
    }

    FILE *out_file = fopen(temp_filename, "wb");
    if (!out_file) {
        fprintf(stderr, "Failed to open %s: %s\n", temp_filename, strerror(errno));
        fclose(in_file);
        return -1;
    }

    if (flock(fileno(in_file), LOCK_SH) == -1 || flock(fileno(out_file), LOCK_EX) == -1) {
        fprintf(stderr, "Failed to lock files for %s\n", filename);
        fclose(in_file);
        fclose(out_file);
        return -1;
    }

    time_t now = time(NULL);
    int kept = 0;
    while (1) {
        Alert alert = {0};
        if (fread(&alert.id, sizeof(uint64_t), 1, in_file) != 1 ||
            fread(&alert.create_at, sizeof(time_t), 1, in_file) != 1 ||
            fread(&alert.unlock_at, sizeof(time_t), 1, in_file) != 1 ||
            fread(&alert.expire_at, sizeof(time_t), 1, in_file) != 1 ||
            fread(&alert.active, sizeof(int), 1, in_file) != 1) {
            if (feof(in_file)) {
                fprintf(stderr, "Reached EOF while cleaning %s, kept %d alerts\n", filename, kept);
                break;
            }
            fprintf(stderr, "Failed to read alert metadata from %s\n", filename);
            goto cleanup;
        }

        // Читаем длины
        size_t text_len, encrypted_key_len, iv_len;
        if (fread(&text_len, sizeof(size_t), 1, in_file) != 1 ||
            fread(&encrypted_key_len, sizeof(size_t), 1, in_file) != 1 ||
            fread(&iv_len, sizeof(size_t), 1, in_file) != 1) {
            fprintf(stderr, "Failed to read alert lengths from %s\n", filename);
            goto cleanup;
        }

        alert.text = malloc(text_len);
        alert.encrypted_key = malloc(encrypted_key_len);
        alert.iv = malloc(iv_len);
        if (!alert.text || !alert.encrypted_key || !alert.iv) {
            fprintf(stderr, "Failed to allocate memory for alert data\n");
            free(alert.text);
            free(alert.encrypted_key);
            free(alert.iv);
            goto cleanup;
        }

        if (fread(alert.text, 1, text_len, in_file) != text_len ||
            fread(alert.encrypted_key, 1, encrypted_key_len, in_file) != encrypted_key_len ||
            fread(alert.iv, 1, iv_len, in_file) != iv_len ||
            fread(alert.tag, 1, GCM_TAG_LEN, in_file) != GCM_TAG_LEN) {
            fprintf(stderr, "Failed to read alert data from %s\n", filename);
            free(alert.text);
            free(alert.encrypted_key);
            free(alert.iv);
            goto cleanup;
        }

        alert.text_len = text_len;
        alert.encrypted_key_len = encrypted_key_len;
        alert.iv_len = iv_len;

        uint32_t delimiter;
        if (fread(&delimiter, sizeof(uint32_t), 1, in_file) != 1 || delimiter != ALERT_RECORD_DELIMITER) {
            if (!feof(in_file)) {
                fprintf(stderr, "Invalid delimiter in %s\n", filename);
            }
            free(alert.text);
            free(alert.encrypted_key);
            free(alert.iv);
            goto cleanup;
        }

        if (alert.active && alert.expire_at > now) {
            // Сохраняем в новый файл
            if (fwrite(&alert.id, sizeof(uint64_t), 1, out_file) != 1 ||
                fwrite(&alert.create_at, sizeof(time_t), 1, out_file) != 1 ||
                fwrite(&alert.unlock_at, sizeof(time_t), 1, out_file) != 1 ||
                fwrite(&alert.expire_at, sizeof(time_t), 1, out_file) != 1 ||
                fwrite(&alert.active, sizeof(int), 1, out_file) != 1 ||
                fwrite(&alert.text_len, sizeof(size_t), 1, out_file) != 1 ||
                fwrite(&alert.encrypted_key_len, sizeof(size_t), 1, out_file) != 1 ||
                fwrite(&alert.iv_len, sizeof(size_t), 1, out_file) != 1 ||
                fwrite(alert.text, 1, alert.text_len, out_file) != alert.text_len ||
                fwrite(alert.encrypted_key, 1, alert.encrypted_key_len, out_file) != alert.encrypted_key_len ||
                fwrite(alert.iv, 1, alert.iv_len, out_file) != alert.iv_len ||
                fwrite(alert.tag, 1, GCM_TAG_LEN, out_file) != GCM_TAG_LEN ||
                fwrite(&delimiter, sizeof(uint32_t), 1, out_file) != 1) {
                fprintf(stderr, "Failed to write alert to %s\n", temp_filename);
                free(alert.text);
                free(alert.encrypted_key);
                free(alert.iv);
                goto cleanup;
            }
            kept++;
            fprintf(stderr, "Kept alert: id=%lu, active=%d\n", alert.id, alert.active);
        }
        free(alert.text);
        free(alert.encrypted_key);
        free(alert.iv);
    }

    flock(fileno(in_file), LOCK_UN);
    flock(fileno(out_file), LOCK_UN);
    fclose(in_file);
    fclose(out_file);

    // Заменяем старый файл новым
    if (kept > 0) {
        if (rename(temp_filename, filename) != 0) {
            fprintf(stderr, "Failed to rename %s to %s: %s\n", temp_filename, filename, strerror(errno));
            unlink(temp_filename);
            return -1;
        }
        fprintf(stderr, "Renamed %s to %s, kept %d alerts\n", temp_filename, filename, kept);
    } else {
        unlink(filename); // Удаляем файл, если нет активных алертов
        unlink(temp_filename);
        fprintf(stderr, "No active alerts, removed %s\n", filename);
    }
    return 0;

cleanup:
    flock(fileno(in_file), LOCK_UN);
    flock(fileno(out_file), LOCK_UN);
    fclose(in_file);
    fclose(out_file);
    unlink(temp_filename);
    fprintf(stderr, "Cleanup: removed %s\n", temp_filename);
    return -1;
}

int alert_db_sync(const Recipient *rec) {
    char filename[512];
    char temp_filename[512];
    char *pubkey_hash_b64 = base64_encode(rec->hash, PUBKEY_HASH_LEN);
    if (!pubkey_hash_b64) {
        fprintf(stderr, "Failed to encode pubkey_hash\n");
        return -1;
    }
    snprintf(filename, sizeof(filename), "%s%s.alerts", ALERT_DB_DIR, pubkey_hash_b64);
    snprintf(temp_filename, sizeof(temp_filename), "%s%s.alerts.tmp", ALERT_DB_DIR, pubkey_hash_b64);
    free(pubkey_hash_b64);

    FILE *out_file = fopen(temp_filename, "wb");
    if (!out_file) {
        fprintf(stderr, "Failed to open %s: %s\n", temp_filename, strerror(errno));
        return -1;
    }

    if (flock(fileno(out_file), LOCK_EX) == -1) {
        fprintf(stderr, "Failed to lock %s: %s\n", temp_filename, strerror(errno));
        fclose(out_file);
        return -1;
    }

    for (int j = 0; j < rec->count; j++) {
        Alert *alert = &rec->alerts[j];
        if (!alert->active) continue;

        if (fwrite(&alert->id, sizeof(uint64_t), 1, out_file) != 1 ||
            fwrite(&alert->create_at, sizeof(time_t), 1, out_file) != 1 ||
            fwrite(&alert->unlock_at, sizeof(time_t), 1, out_file) != 1 ||
            fwrite(&alert->expire_at, sizeof(time_t), 1, out_file) != 1 ||
            fwrite(&alert->active, sizeof(int), 1, out_file) != 1 ||
            fwrite(&alert->text_len, sizeof(size_t), 1, out_file) != 1 ||
            fwrite(&alert->encrypted_key_len, sizeof(size_t), 1, out_file) != 1 ||
            fwrite(&alert->iv_len, sizeof(size_t), 1, out_file) != 1 ||
            fwrite(alert->text, 1, alert->text_len, out_file) != alert->text_len ||
            fwrite(alert->encrypted_key, 1, alert->encrypted_key_len, out_file) != alert->encrypted_key_len ||
            fwrite(alert->iv, 1, alert->iv_len, out_file) != alert->iv_len ||
            fwrite(alert->tag, 1, GCM_TAG_LEN, out_file) != GCM_TAG_LEN) {
            fprintf(stderr, "Failed to write alert data to %s\n", temp_filename);
            goto cleanup_fail;
        }

        uint32_t delimiter = ALERT_RECORD_DELIMITER;
        if (fwrite(&delimiter, sizeof(uint32_t), 1, out_file) != 1) {
            fprintf(stderr, "Failed to write delimiter to %s\n", temp_filename);
            goto cleanup_fail;
        }
    }

    flock(fileno(out_file), LOCK_UN);
    fclose(out_file);

    if (rename(temp_filename, filename) != 0) {
        fprintf(stderr, "Failed to rename %s to %s: %s\n", temp_filename, filename, strerror(errno));
        unlink(temp_filename);
        return -1;
    }

    if (rec->count == 0) {
        unlink(filename);  // Remove empty file
    }

    if (verbose) {
        fprintf(stderr, "Synced %d alerts to %s\n", rec->count, filename);
    }
    return 0;

cleanup_fail:
    flock(fileno(out_file), LOCK_UN);
    fclose(out_file);
    unlink(temp_filename);
    return -1;
}
