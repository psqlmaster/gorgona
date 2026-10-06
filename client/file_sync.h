#ifndef FILE_SYNC_H
#define FILE_SYNC_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>

#define GORGONA_FILE_MAGIC         0x4746494C /* "GFIL" */
#define GORGONA_FILE_VERSION       1
#define DEFAULT_MAX_FILE_SIZE      (10 * 1024 * 1024) /* 10 MB */

/* Флаги обработки */
#define GORGONA_FILE_FLAG_SINGLE   0x01
#define GORGONA_FILE_FLAG_LZ4      0x04       /* Данные сжаты алгоритмом LZ4 */
#define GORGONA_FILE_FLAG_DELETE   0x08       /* Сигнал удаления (Tombstone) */

/* packed-структура без #pragma — нет предупреждений о незакрытом push */
typedef struct __attribute__((packed)) {
    uint32_t magic;               /* GORGONA_FILE_MAGIC */
    uint16_t version;             /* GORGONA_FILE_VERSION */
    uint16_t flags;               /* Флаги (сжатие, тип) */
    uint32_t mode;                /* Права доступа POSIX (st_mode & 0777) */
    uint32_t path_len;            /* Длина относительного пути */
    uint64_t uncompressed_size;   /* Оригинальный размер файла */
    uint64_t payload_size;        /* Фактический размер данных в пакете */
    uint64_t xxh3_hash;           /* XXH3-64 хеш оригинального файла */
} gorgona_file_hdr_t;

/* Проверка, является ли расшифрованный буфер файловым пакетом */
bool file_sync_is_file_payload(const uint8_t *data, size_t len);

/* Обработка входящего файла (декомпрессия, сверка XXH3, атомарная запись) */
int file_sync_handle_incoming(const char *sender_pubkey, const uint8_t *data, size_t len, int verbose);

/* Чтение, упаковка, расчет XXH3 и LZ4-сжатие файла */
int file_sync_pack(const char *filepath, const char *rel_name, uint8_t **out_buf, size_t *out_len);

/* CLI команда: gorgona send-file */
int cmd_send_file(int argc, char **argv);

#endif /* FILE_SYNC_H */
