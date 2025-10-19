#include "snowflake.h"
#include <time.h>

// Глобальные переменные
atomic_uint_least16_t sequence = 0;
uint64_t last_timestamp = 0;

// Получение текущего времени в миллисекундах
static uint64_t current_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

// Генерация Snowflake ID: 41 бит timestamp, 12 бит sequence, без machine_id
uint64_t generate_snowflake_id(void) {
    uint64_t timestamp = current_ms() - SNOWFLAKE_EPOCH;

    if (timestamp < last_timestamp) {
        // Clock skew: Ждём, пока время не догонит
        while ((current_ms() - SNOWFLAKE_EPOCH) <= last_timestamp) {
            // Можно добавить log, если verbose
        }
        timestamp = current_ms() - SNOWFLAKE_EPOCH;
    }

    if (timestamp == last_timestamp) {
        sequence = (sequence + 1) & 0xFFF;  // 12 бит: 0-4095
        if (sequence == 0) {
            // Sequence overflow: Ждём следующую ms
            while ((current_ms() - SNOWFLAKE_EPOCH) == last_timestamp) {}
            timestamp = current_ms() - SNOWFLAKE_EPOCH;
        }
    } else {
        sequence = 0;
    }

    last_timestamp = timestamp;

    // Формируем ID: timestamp (41 бит) | sequence (12 бит)
    return (timestamp << 12) | sequence;
}
