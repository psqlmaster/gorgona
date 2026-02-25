#ifndef ALERT_DB_H
#define ALERT_DB_H

#include "gorgona_utils.h"
#include <stdint.h>
#include <sys/file.h>
#include <sys/mman.h>

/* Путь к директории базы данных */
#define ALERT_DB_DIR "/var/lib/gorgona/alerts/"
/* Магическое число для заголовка файла */
#define ALERT_FILE_MAGIC 0xCAFEBABE
/* Делимитер для разделения записей */
#define ALERT_RECORD_DELIMITER 0xDEADBEEF

/* Структура заголовка файла */
typedef struct {
    uint32_t magic; /* ALERT_FILE_MAGIC */
    uint32_t count; /* Количество алертов */
} AlertFileHeader;

/* Инициализация базы данных (создание директории) */
int alert_db_init(void);

/* Загрузка всех алертов из файлов в recipients */
int alert_db_load_recipients(void);

/* Сохранение одного алерта в файл реципиента через mmap */
int alert_db_save_alert(Recipient *rec, Alert *alert);

/* Мгновенная деактивация алерта по указателю в mmap */
void alert_db_deactivate_alert(Alert *alert);

/* Очистка истёкших алертов и сжатие файла (Vacuum) */
int alert_db_sync(Recipient *rec);

#endif
