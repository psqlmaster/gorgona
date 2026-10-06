#define XXH_INLINE_ALL
#include "xxhash.h"
#include "file_sync.h"
#include "config.h"
#include "alert_send.h"
#include "common.h"
#include "lz4.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <limits.h>
#include <errno.h>
#include <libgen.h>

/**
 * Проверяет, существует ли файл и совпадает ли его размер и XXH3 хеш.
 */
static bool file_matches_xxh3(const char *path, uint64_t expected_hash, uint64_t expected_size) {
    struct stat st;
    if (stat(path, &st) != 0) {
        return false; /* Файл не существует */
    }
    if ((uint64_t)st.st_size != expected_size) {
        return false; /* Размер изменился */
    }
    if (expected_size == 0) {
        return (expected_hash == 0);
    }
    FILE *fp = fopen(path, "rb");
    if (!fp) return false;
    XXH3_state_t *state = XXH3_createState();
    if (!state) {
        fclose(fp);
        return false;
    }
    XXH3_64bits_reset(state);
    char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        XXH3_64bits_update(state, buf, n);
    }
    uint64_t actual_hash = XXH3_64bits_digest(state);
    XXH3_freeState(state);
    fclose(fp);
    return (actual_hash == expected_hash);
}

bool file_sync_is_file_payload(const uint8_t *data, size_t len) {
    if (!data || len < sizeof(gorgona_file_hdr_t)) {
        return false;
    }
    const gorgona_file_hdr_t *hdr = (const gorgona_file_hdr_t *)data;
    return (hdr->magic == GORGONA_FILE_MAGIC && hdr->version == GORGONA_FILE_VERSION);
}

/* Защита от Path Traversal (запрет выхода за пределы рабочей папки) */
static bool is_safe_relative_path(const char *path, size_t len) {
    if (!path || len == 0 || len >= PATH_MAX) return false;
    if (path[0] == '/' || path[0] == '\\') return false;
    if (strstr(path, "../") != NULL || strstr(path, "..\\") != NULL || strcmp(path, "..") == 0) {
        return false;
    }
    return true;
}

static int mkdir_p(const char *path, mode_t mode) {
    char tmp[PATH_MAX];
    char *p = NULL;
    size_t len = snprintf(tmp, sizeof(tmp), "%s", path);
    if (len >= sizeof(tmp)) return -1;

    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) != 0 && errno != EEXIST) return -1;
    return 0;
}

int file_sync_pack(const char *filepath, const char *rel_name, uint8_t **out_buf, size_t *out_len) {
    if (!filepath || !out_buf || !out_len) return -1;

    struct stat st;
    if (stat(filepath, &st) != 0) {
        fprintf(stderr, "[sync] stat failed for %s: %s\n", filepath, strerror(errno));
        return -1;
    }

    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "[sync] %s is not a regular file\n", filepath);
        return -1;
    }

    /* 1. Читаем исходный файл */
    size_t raw_size = (size_t)st.st_size;
    uint8_t *raw_data = NULL;
    if (raw_size > 0) {
        raw_data = malloc(raw_size);
        if (!raw_data) return -1;

        FILE *f = fopen(filepath, "rb");
        if (!f) {
            free(raw_data);
            return -1;
        }
        if (fread(raw_data, 1, raw_size, f) != raw_size) {
            fclose(f);
            free(raw_data);
            return -1;
        }
        fclose(f);
    }

    /* 2. Считаем контрольный хэш XXH3-64 по оригинальным данным */
    uint64_t file_hash = raw_size > 0 ? XXH3_64bits(raw_data, raw_size) : 0;

    /* 3. Пробуем сжать алгоритмом LZ4 */
    uint16_t flags = GORGONA_FILE_FLAG_SINGLE;
    uint8_t *payload_data = raw_data;
    size_t payload_size = raw_size;

    if (raw_size > 64) { /* Для микро-файлов сжатие бессмысленно */
        int max_compressed_size = LZ4_compressBound((int)raw_size);
        char *lz4_buf = malloc(max_compressed_size);

        if (lz4_buf) {
            int comp_size = LZ4_compress_default((const char *)raw_data, lz4_buf, (int)raw_size, max_compressed_size);
            /* Применяем LZ4 только если сжатие реально уменьшило объем */
            if (comp_size > 0 && (size_t)comp_size < raw_size) {
                payload_data = (uint8_t *)lz4_buf;
                payload_size = (size_t)comp_size;
                flags |= GORGONA_FILE_FLAG_LZ4;
                free(raw_data); /* Исходный буфер больше не нужен */
            } else {
                free(lz4_buf);
            }
        }
    }

    /* 4. Формируем финальный пакет: [Header][Relative Path][Payload] */
    const char *final_rel = rel_name ? rel_name : basename((char *)filepath);
    size_t path_len = strlen(final_rel);
    size_t total_size = sizeof(gorgona_file_hdr_t) + path_len + payload_size;

    uint8_t *buf = malloc(total_size);
    if (!buf) {
        if (payload_data) free(payload_data);
        return -1;
    }

    gorgona_file_hdr_t *hdr = (gorgona_file_hdr_t *)buf;
    hdr->magic = GORGONA_FILE_MAGIC;
    hdr->version = GORGONA_FILE_VERSION;
    hdr->flags = flags;
    hdr->mode = (uint32_t)(st.st_mode & 0777);
    hdr->path_len = (uint32_t)path_len;
    hdr->uncompressed_size = (uint64_t)raw_size;
    hdr->payload_size = (uint64_t)payload_size;
    hdr->xxh3_hash = file_hash;

    memcpy(buf + sizeof(gorgona_file_hdr_t), final_rel, path_len);
    if (payload_size > 0) {
        memcpy(buf + sizeof(gorgona_file_hdr_t) + path_len, payload_data, payload_size);
        free(payload_data);
    }

    *out_buf = buf;
    *out_len = total_size;
    return 0;
}

int file_sync_handle_incoming(const char *sender_pubkey, const uint8_t *data, size_t len, int verbose) {
    if (!file_sync_is_file_payload(data, len)) return -1;

    const gorgona_file_hdr_t *hdr = (const gorgona_file_hdr_t *)data;
    if (len < sizeof(gorgona_file_hdr_t) + hdr->path_len + hdr->payload_size) {
        fprintf(stderr, "[sync] Corrupted payload: size mismatch\n");
        return -1;
    }

    const sync_config_t *cfg = config_get_sync_rule(sender_pubkey);
    if (!cfg) {
        fprintf(stderr, "[sync] No [sync:%s] rule configured. Rejecting file.\n", sender_pubkey);
        return -1;
    }

    if (strcmp(cfg->direction, "wo") == 0) {
        fprintf(stderr, "[sync] Key %s configured as write-only. Ignoring incoming file.\n", sender_pubkey);
        return -1;
    }

    if (hdr->uncompressed_size > cfg->max_file_size) {
        fprintf(stderr, "[sync] File uncompressed size (%lu) exceeds limit (%zu)\n", 
                (unsigned long)hdr->uncompressed_size, cfg->max_file_size);
        return -1;
    }

    char rel_path[PATH_MAX];
    memcpy(rel_path, data + sizeof(gorgona_file_hdr_t), hdr->path_len);
    rel_path[hdr->path_len] = '\0';

    if (!is_safe_relative_path(rel_path, hdr->path_len)) {
        fprintf(stderr, "[sync] Security alert: rejected malicious path: %s\n", rel_path);
        return -1;
    }

    /* Проверка dest_path до распаковки LZ4 === */
    char dest_path[PATH_MAX];
    char tmp_path[PATH_MAX];
    if (snprintf(dest_path, sizeof(dest_path), "%s/%s", cfg->dir, rel_path) >= (int)sizeof(dest_path)) {
        fprintf(stderr, "[sync] Path too long\n");
        return -1;
    }
    /* Если файл уже лежит на диске и его хеш совпадает — пропускаем! */
    if (file_matches_xxh3(dest_path, hdr->xxh3_hash, hdr->uncompressed_size)) {
        if (verbose) {
            printf("[sync] File already up-to-date: %s (skipping)\n", dest_path);
        }
        log_event("DEBUG", -1, NULL, 0, "[sync] File %s already up-to-date, skipping", dest_path);
        return 0; /* Успех, повторно не качаем и on_change не дергаем */
    }

    const uint8_t *payload_ptr = data + sizeof(gorgona_file_hdr_t) + hdr->path_len;
    uint8_t *uncompressed_data = NULL;

    /* 5. Декомпрессия при наличии флага LZ4 */
    if (hdr->flags & GORGONA_FILE_FLAG_LZ4) {
        uncompressed_data = malloc((size_t)hdr->uncompressed_size);
        if (!uncompressed_data) return -1;

        int decomp_bytes = LZ4_decompress_safe((const char *)payload_ptr, 
                                              (char *)uncompressed_data, 
                                              (int)hdr->payload_size, 
                                              (int)hdr->uncompressed_size);
        if (decomp_bytes < 0 || (size_t)decomp_bytes != hdr->uncompressed_size) {
            fprintf(stderr, "[sync] LZ4 decompression failed for %s\n", rel_path);
            free(uncompressed_data);
            return -1;
        }
    } else {
        uncompressed_data = (uint8_t *)payload_ptr;
    }

    /* 6. Проверка целостности через XXH3-64 */
    uint64_t actual_hash = hdr->uncompressed_size > 0 ? 
                           XXH3_64bits(uncompressed_data, (size_t)hdr->uncompressed_size) : 0;
    if (actual_hash != hdr->xxh3_hash) {
        fprintf(stderr, "[sync] XXH3 hash mismatch! Expected: %016llx, got: %016llx\n",
                (unsigned long long)hdr->xxh3_hash, (unsigned long long)actual_hash);
        if (hdr->flags & GORGONA_FILE_FLAG_LZ4) free(uncompressed_data);
        return -1;
    }

    /* 7. Атомарная запись на диск (tmp -> fsync -> rename) */
    if (snprintf(dest_path, sizeof(dest_path), "%s/%s", cfg->dir, rel_path) >= (int)sizeof(dest_path) ||
        snprintf(tmp_path, sizeof(tmp_path), "%s/%s.tmp.%d", cfg->dir, rel_path, getpid()) >= (int)sizeof(tmp_path)) {
        fprintf(stderr, "[sync] Path too long\n");
        if (hdr->flags & GORGONA_FILE_FLAG_LZ4) free(uncompressed_data);
        return -1;
    }

    char dir_copy[PATH_MAX];
    strncpy(dir_copy, dest_path, sizeof(dir_copy));
    mkdir_p(dirname(dir_copy), 0755);

    FILE *f = fopen(tmp_path, "wb");
    if (!f) {
        fprintf(stderr, "[sync] Cannot open %s: %s\n", tmp_path, strerror(errno));
        if (hdr->flags & GORGONA_FILE_FLAG_LZ4) free(uncompressed_data);
        return -1;
    }

    if (hdr->uncompressed_size > 0) {
        if (fwrite(uncompressed_data, 1, (size_t)hdr->uncompressed_size, f) != (size_t)hdr->uncompressed_size) {
            fclose(f);
            unlink(tmp_path);
            if (hdr->flags & GORGONA_FILE_FLAG_LZ4) free(uncompressed_data);
            return -1;
        }
    }
    fflush(f);
    fsync(fileno(f));
    fclose(f);

    if (hdr->flags & GORGONA_FILE_FLAG_LZ4) {
        free(uncompressed_data);
    }

    chmod(tmp_path, (mode_t)hdr->mode);

    if (rename(tmp_path, dest_path) != 0) {
        fprintf(stderr, "[sync] Atomic rename failed: %s\n", strerror(errno));
        unlink(tmp_path);
        return -1;
    }

    printf("[sync] Synced: %s (uncompressed: %lu B, wire: %lu B, XXH3: %016llx)\n",
           dest_path, (unsigned long)hdr->uncompressed_size, 
           (unsigned long)hdr->payload_size, (unsigned long long)hdr->xxh3_hash);
    log_event("INFO", -1, NULL, 0,
              "File received from %s: %s (stored %lu B, wire %lu B%s)",
              sender_pubkey,
              dest_path,
              (unsigned long)hdr->uncompressed_size,
              (unsigned long)hdr->payload_size,
              (hdr->flags & GORGONA_FILE_FLAG_LZ4) ? ", LZ4" : "");

    /* 8. Выполнение хука on_change */
    if (cfg->on_change[0] != '\0') {
        printf("[sync] Triggering on_change: %s\n", cfg->on_change);
        system(cfg->on_change);
    }

    return 0;
}

int cmd_send_file(int argc, char **argv)
{
    const char *target_key = NULL;
    const char *filepath = NULL;
    const char *rel_name = NULL;
    time_t unlock_at = 0;
    time_t expire_at = 0;
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--key") == 0 ||
             strcmp(argv[i], "--to") == 0) && i + 1 < argc) {
            target_key = argv[++i];
        }
        else if ((strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--file") == 0) && i + 1 < argc) {
            filepath = argv[++i];
        }
        else if ((strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--name") == 0) && i + 1 < argc) {
            rel_name = argv[++i];
        }
        else if (!filepath) {
            /* Пытаемся понять: это дата или путь к файлу?
               Дата всегда имеет вид YYYY-MM-DD HH:MM:SS (есть пробел и двоеточия) */
            if (strchr(argv[i], ' ') && strchr(argv[i], ':') &&
                strlen(argv[i]) >= 19) {          /* минимальная длина даты */
                unlock_at = parse_datetime(argv[i]);
                if (unlock_at == (time_t)-1) {
                    fprintf(stderr, "Invalid unlock time: %s\n", argv[i]);
                    return 1;
                }
                if (i + 1 < argc) {
                    expire_at = parse_datetime(argv[i + 1]);
                    if (expire_at == (time_t)-1) {
                        fprintf(stderr, "Invalid expire time: %s\n", argv[i + 1]);
                        return 1;
                    }
                    i++;   /* пропускаем expire */
                }
            } else {
                filepath = argv[i];   /* обычный путь к файлу */
            }
        }
        else if (!target_key) {
            target_key = argv[i];
        }
    }
    if (!target_key || !filepath) {
        fprintf(stderr,
            "Usage:\n"
            "  gorgona send-file <filepath> <pubkey>\n"
            "  gorgona send-file --name <rel_path> <filepath> <pubkey>\n"
            "  gorgona send-file \"<unlock>\" \"<expire>\" <filepath> <pubkey>\n"
            "\n"
            "Examples:\n"
            "  gorgona send-file /tmp/nginx.conf RWTPQzuhzBw=.pub\n"
            "  gorgona send-file --name conf.d/site.conf /tmp/nginx.conf RWTPQzuhzBw=.pub\n");
        return 1;
    }
    if (unlock_at == 0) unlock_at = time(NULL);
    if (expire_at == 0) expire_at = unlock_at + 3600;
    uint8_t *payload = NULL;
    size_t payload_len = 0;
    if (file_sync_pack(filepath, rel_name, &payload, &payload_len) != 0) {
        fprintf(stderr, "[sync] Error preparing file payload: %s\n", filepath);
        return 1;
    }
    int ret = alert_send_raw(target_key, payload, payload_len, unlock_at, expire_at);
    free(payload);
    if (ret == 0)
        printf("[sync] File '%s' successfully delivered to key '%s'\n", filepath, target_key);
    else
        fprintf(stderr, "[sync] Delivery failed for '%s'\n", filepath);
    return ret;
}
